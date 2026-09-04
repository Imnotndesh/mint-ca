package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"mint-ca/internal/audit"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// postgresStore is the Postgres implementation of Store.
type postgresStore struct {
	db *sql.DB
}

var _ TenantStore = (*postgresStore)(nil)

const postgresDeltaCRLSchema = `
CREATE TABLE IF NOT EXISTS crl_delta_cache (
	id              TEXT        NOT NULL PRIMARY KEY,
	ca_id           TEXT        NOT NULL UNIQUE REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	crl_pem         TEXT        NOT NULL,
	crl_number      BIGINT      NOT NULL,
	base_crl_number BIGINT      NOT NULL,
	this_update     TIMESTAMPTZ NOT NULL,
	next_update     TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS crl_number_counters (
	ca_id       TEXT   NOT NULL PRIMARY KEY,
	next_number BIGINT NOT NULL DEFAULT 1
);
`
const postgresCrossCertSchema = `
CREATE TABLE IF NOT EXISTS ca_cross_certs (
	id            TEXT        NOT NULL PRIMARY KEY,
	target_ca_id  TEXT        NOT NULL REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	signing_ca_id TEXT        NOT NULL REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	cert_pem      TEXT        NOT NULL,
	serial        TEXT        NOT NULL,
	not_before    TIMESTAMPTZ NOT NULL,
	not_after     TIMESTAMPTZ NOT NULL,
	created_at    TIMESTAMPTZ NOT NULL,
	UNIQUE(target_ca_id, signing_ca_id)
);
`
const postgresNonceSchema = `
CREATE TABLE IF NOT EXISTS acme_nonces (
	nonce      TEXT        NOT NULL PRIMARY KEY,
	expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_nonces_expires_at ON acme_nonces(expires_at);
`

func newPostgresStore(dsn string) (*postgresStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}

	// Reasonable pool for a CA service — not high-throughput.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	s := &postgresStore{db: db}

	if err := s.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: migrate: %w", err)
	}

	return s, nil
}

func (s *postgresStore) Close() error {
	return s.db.Close()
}

func (s *postgresStore) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, postgresSchema); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, postgresNonceSchema); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
		ALTER TABLE crl_cache ADD COLUMN IF NOT EXISTS crl_number BIGINT NOT NULL DEFAULT 0;
	`); err != nil {
		return fmt.Errorf("postgres: migrate crl_number column: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, postgresDeltaCRLSchema); err != nil {
		return fmt.Errorf("postgres: migrate delta CRL schema: %w", err)
	}
	// Widen the status CHECK to accept 'superseded' for databases created
	// before re-key support. IF EXISTS guards against the constraint having a
	// different auto-generated name.
	if _, err := s.db.ExecContext(ctx, `
		ALTER TABLE certificate_authorities DROP CONSTRAINT IF EXISTS certificate_authorities_status_check;
		ALTER TABLE certificate_authorities ADD CONSTRAINT certificate_authorities_status_check
			CHECK(status IN ('active','revoked','expired','superseded'));
	`); err != nil {
		return fmt.Errorf("postgres: migrate superseded status constraint: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, postgresCrossCertSchema); err != nil {
		return fmt.Errorf("postgres: migrate cross cert schema: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		ALTER TABLE certificate_authorities ADD COLUMN IF NOT EXISTS logical_ca_id TEXT;
		UPDATE certificate_authorities SET logical_ca_id = id WHERE logical_ca_id IS NULL;
	`); err != nil {
		return fmt.Errorf("postgres: migrate logical_ca_id: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL;
	`); err != nil {
		return fmt.Errorf("postgres: migrate api_keys tenant_id: %w", err)
	}
	for _, t := range []string{"certificate_authorities", "provisioners", "profiles", "policies", "ssh_certificate_authorities"} {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE `+t+` ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL;`); err != nil {
			return fmt.Errorf("postgres: migrate %s tenant_id: %w", t, err)
		}
	}
	if err := seedDefaultTenantPostgres(ctx, s.db); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE certificate_authorities SET tenant_id = $1 WHERE tenant_id IS NULL; UPDATE provisioners SET tenant_id = $1 WHERE tenant_id IS NULL; UPDATE profiles SET tenant_id = $1 WHERE tenant_id IS NULL; UPDATE policies SET tenant_id = $1 WHERE tenant_id IS NULL; UPDATE ssh_certificate_authorities SET tenant_id = $1 WHERE tenant_id IS NULL;`, DefaultTenantID.String()); err != nil {
		return fmt.Errorf("postgres: backfill tenant_id: %w", err)
	}
	return nil
}

// seedDefaultTenantPostgres inserts the fixed default tenant if no tenant
// exists yet.
func seedDefaultTenantPostgres(ctx context.Context, db *sql.DB) error {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&count); err != nil {
		return fmt.Errorf("postgres: seed default tenant count: %w", err)
	}
	if count > 0 {
		return nil
	}
	_, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, status, created_at) VALUES ($1, 'default', 'active', $2)`, DefaultTenantID.String(), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("postgres: seed default tenant: %w", err)
	}
	return nil
}

const postgresSchema = `
CREATE TABLE IF NOT EXISTS certificate_authorities (
	id               TEXT        NOT NULL PRIMARY KEY,
	logical_ca_id    TEXT,
	parent_id        TEXT        REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
	name             TEXT        NOT NULL UNIQUE,
	type             TEXT        NOT NULL CHECK(type IN ('root','intermediate')),
	status           TEXT        NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired','superseded')),
	cert_pem         TEXT        NOT NULL,
	key_enc          BYTEA       NOT NULL,
	key_algo         TEXT        NOT NULL,
	name_constraints TEXT,
	not_before       TIMESTAMPTZ NOT NULL,
	not_after        TIMESTAMPTZ NOT NULL,
	created_at       TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
	id              TEXT        NOT NULL PRIMARY KEY,
	name            TEXT        NOT NULL,
	scope           TEXT        NOT NULL CHECK(scope IN ('ca','provisioner')),
	max_ttl_seconds BIGINT      NOT NULL DEFAULT 86400,
	allowed_domains TEXT        NOT NULL DEFAULT '[]',
	denied_domains  TEXT        NOT NULL DEFAULT '[]',
	allowed_ips     TEXT        NOT NULL DEFAULT '[]',
	allowed_sans    TEXT        NOT NULL DEFAULT '[]',
	require_san     BOOLEAN     NOT NULL DEFAULT FALSE,
	key_algos       TEXT        NOT NULL DEFAULT '[]',
	policy_oids     TEXT        NOT NULL DEFAULT '[]',
	cps_uri         TEXT        NOT NULL DEFAULT '',
	ssh_policy      TEXT        NOT NULL DEFAULT '',
	created_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
	id                TEXT        NOT NULL PRIMARY KEY,
	name              TEXT        NOT NULL UNIQUE,
	allowed_key_algos TEXT        NOT NULL DEFAULT '[]',
	min_ttl_seconds   BIGINT      NOT NULL DEFAULT 0,
	max_ttl_seconds   BIGINT      NOT NULL DEFAULT 0,
	require_san       BOOLEAN     NOT NULL DEFAULT FALSE,
	allow_wildcard    BOOLEAN     NOT NULL DEFAULT FALSE,
	created_at        TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS csr_approval_rules (
	id                 TEXT        NOT NULL PRIMARY KEY,
	provisioner_id     TEXT        NOT NULL,
	name               TEXT        NOT NULL,
	allowed_common_names TEXT     NOT NULL DEFAULT '[]',
	allowed_dns        TEXT        NOT NULL DEFAULT '[]',
	max_ttl_seconds    BIGINT      NOT NULL DEFAULT 0,
	enabled            BOOLEAN     NOT NULL DEFAULT TRUE,
	created_at         TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_csr_approval_prov ON csr_approval_rules(provisioner_id);

CREATE TABLE IF NOT EXISTS acme_authorizations (
    id               TEXT        NOT NULL PRIMARY KEY,
    order_id         TEXT        REFERENCES acme_orders(id) ON DELETE CASCADE,
    account_id       TEXT        REFERENCES acme_accounts(id) ON DELETE CASCADE,
    identifier_type  TEXT        NOT NULL CHECK(identifier_type IN ('dns')),
    identifier_value TEXT        NOT NULL,
    status           TEXT        NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','valid','invalid')),
    expires_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_authz_account_identifier
    ON acme_authorizations(account_id, identifier_type, identifier_value);

CREATE TABLE IF NOT EXISTS provisioners (
	id         TEXT        NOT NULL PRIMARY KEY,
	ca_id      TEXT        NOT NULL REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
	name       TEXT        NOT NULL,
	type       TEXT        NOT NULL CHECK(type IN ('acme','apikey','mtls')),
	config     TEXT        NOT NULL DEFAULT '{}',
	policy_id  TEXT        REFERENCES policies(id) ON DELETE SET NULL,
	status     TEXT        NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
	created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
	id             TEXT        NOT NULL PRIMARY KEY,
	ca_id          TEXT        NOT NULL REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
	serial         TEXT        NOT NULL UNIQUE,
	subject_cn     TEXT        NOT NULL,
	sans           TEXT        NOT NULL DEFAULT '{}',
	key_usage      TEXT        NOT NULL DEFAULT '[]',
	cert_pem       TEXT        NOT NULL,
	status         TEXT        NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired')),
	revoked_at     TIMESTAMPTZ,
	revoke_reason  INTEGER,
	not_before     TIMESTAMPTZ NOT NULL,
	not_after      TIMESTAMPTZ NOT NULL,
	issued_at      TIMESTAMPTZ NOT NULL,
	provisioner_id TEXT        NOT NULL REFERENCES provisioners(id) ON DELETE RESTRICT,
	requester      TEXT        NOT NULL DEFAULT '',
	metadata       TEXT        NOT NULL DEFAULT '{}',
	key_encrypted  BYTEA,
	key_pw_required BOOLEAN    NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_pg_certs_ca_id     ON certificates(ca_id);
CREATE INDEX IF NOT EXISTS idx_pg_certs_serial    ON certificates(serial);
CREATE INDEX IF NOT EXISTS idx_pg_certs_status    ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_pg_certs_not_after ON certificates(not_after);

CREATE TABLE IF NOT EXISTS eab_credentials (
	id             TEXT        NOT NULL PRIMARY KEY,
	provisioner_id TEXT        NOT NULL REFERENCES provisioners(id) ON DELETE RESTRICT,
	hmac_key       BYTEA       NOT NULL,
	key_id         TEXT        NOT NULL UNIQUE,
	used           BOOLEAN     NOT NULL DEFAULT FALSE,
	used_at        TIMESTAMPTZ,
	created_at     TIMESTAMPTZ NOT NULL,
	expires_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS acme_accounts (
	id             TEXT        NOT NULL PRIMARY KEY,
	provisioner_id TEXT        NOT NULL REFERENCES provisioners(id) ON DELETE RESTRICT,
	key_id         TEXT        NOT NULL UNIQUE,
	key_jwk        TEXT        NOT NULL DEFAULT '{}',
	eab_id         TEXT        REFERENCES eab_credentials(id) ON DELETE SET NULL,
	status         TEXT        NOT NULL DEFAULT 'valid' CHECK(status IN ('valid','deactivated','revoked')),
	contact        TEXT        NOT NULL DEFAULT '[]',
	created_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_orders (
	id             TEXT        NOT NULL PRIMARY KEY,
	account_id     TEXT        NOT NULL REFERENCES acme_accounts(id) ON DELETE RESTRICT,
	status         TEXT        NOT NULL DEFAULT 'pending'
	                           CHECK(status IN ('pending','ready','processing','valid','invalid')),
	identifiers    TEXT        NOT NULL DEFAULT '[]',
	certificate_id TEXT        REFERENCES certificates(id) ON DELETE SET NULL,
	expires_at     TIMESTAMPTZ NOT NULL,
	created_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_orders_account_id ON acme_orders(account_id);

CREATE TABLE IF NOT EXISTS acme_challenges (
	id           TEXT        NOT NULL PRIMARY KEY,
	order_id     TEXT        REFERENCES acme_orders(id) ON DELETE CASCADE,
	type         TEXT        NOT NULL CHECK(type IN ('http-01','dns-01','tls-alpn-01')),
	token        TEXT        NOT NULL,
	status       TEXT        NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','valid','invalid')),
	validated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pg_challenges_order_id ON acme_challenges(order_id);

CREATE TABLE IF NOT EXISTS audit_log (
	seq        BIGSERIAL,
	id         TEXT        NOT NULL PRIMARY KEY,
	event_type TEXT        NOT NULL,
	actor      TEXT        NOT NULL,
	ca_id      TEXT        REFERENCES certificate_authorities(id) ON DELETE SET NULL,
	cert_id    TEXT        REFERENCES certificates(id) ON DELETE SET NULL,
	payload    TEXT        NOT NULL DEFAULT '{}',
	ip_address TEXT        NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL,
	prev_hash  TEXT        NOT NULL DEFAULT '',
	entry_hash TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_pg_audit_ca_id      ON audit_log(ca_id);
CREATE INDEX IF NOT EXISTS idx_pg_audit_created_at ON audit_log(created_at);

-- audit_chain_state is a singleton row tracking the tail hash of the audit
-- log's tamper-evident chain (see internal/audit), so WriteAuditLog can
-- extend it without re-scanning the whole table.
CREATE TABLE IF NOT EXISTS audit_chain_state (
	id        INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
	last_hash TEXT    NOT NULL DEFAULT ''
);
INSERT INTO audit_chain_state (id, last_hash) VALUES (1, '') ON CONFLICT (id) DO NOTHING;

-- ha_leader_lock is a singleton row implementing an active-passive leader
-- lease (see internal/ha): a node holds leadership until expires_at passes,
-- at which point any node (including a new holder_id) may acquire it.
CREATE TABLE IF NOT EXISTS ha_leader_lock (
	id         INTEGER     NOT NULL PRIMARY KEY CHECK (id = 1),
	holder_id  TEXT        NOT NULL DEFAULT '',
	expires_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch'
);
INSERT INTO ha_leader_lock (id, holder_id, expires_at) VALUES (1, '', 'epoch') ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS crl_cache (
	id          TEXT        NOT NULL PRIMARY KEY,
	ca_id       TEXT        NOT NULL UNIQUE REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	crl_pem     TEXT        NOT NULL,
	this_update TIMESTAMPTZ NOT NULL,
	next_update TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_retired_keys (
    key_id     TEXT        NOT NULL PRIMARY KEY,
    retired_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
	id         TEXT        NOT NULL PRIMARY KEY,
	name       TEXT        NOT NULL UNIQUE,
	status     TEXT        NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),
	created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
	id         TEXT        NOT NULL PRIMARY KEY,
	name       TEXT        NOT NULL,
	key_hash   TEXT        NOT NULL UNIQUE,
	scopes     TEXT        NOT NULL DEFAULT '[]',
	ca_id      TEXT        REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	tenant_id  TEXT        REFERENCES tenants(id) ON DELETE SET NULL,
	expires_at TIMESTAMPTZ,
	last_used  TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS setup_state (
    id         INTEGER     NOT NULL PRIMARY KEY CHECK(id = 1),
    state      TEXT        NOT NULL DEFAULT 'uninitialized',
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_certificate_authorities (
	id            TEXT        NOT NULL PRIMARY KEY,
	name          TEXT        NOT NULL UNIQUE,
	key_algo      TEXT        NOT NULL,
	public_key    TEXT        NOT NULL,
	key_enc       BYTEA       NOT NULL,
	status        TEXT        NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired','superseded')),
	logical_ca_id TEXT,
	parent_id     TEXT,
	created_at    TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS ssh_krl_cache (
	id          TEXT        NOT NULL PRIMARY KEY,
	ca_id       TEXT        NOT NULL UNIQUE REFERENCES ssh_certificate_authorities(id) ON DELETE CASCADE,
	krl_data    BYTEA       NOT NULL,
	krl_version BIGINT      NOT NULL,
	this_update TIMESTAMPTZ NOT NULL,
	next_update TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS ssh_certificates (
	id             TEXT        NOT NULL PRIMARY KEY,
	ca_id          TEXT        NOT NULL REFERENCES ssh_certificate_authorities(id) ON DELETE RESTRICT,
	serial         BIGINT      NOT NULL,
	cert_type      TEXT        NOT NULL CHECK(cert_type IN ('user','host')),
	key_id         TEXT        NOT NULL DEFAULT '',
	principals     TEXT        NOT NULL DEFAULT '[]',
	public_key     TEXT        NOT NULL,
	cert_data      TEXT        NOT NULL,
	valid_after    TIMESTAMPTZ NOT NULL,
	valid_before   TIMESTAMPTZ NOT NULL,
	status         TEXT        NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired')),
	revoked_at     TIMESTAMPTZ,
	provisioner_id TEXT        NOT NULL REFERENCES provisioners(id) ON DELETE RESTRICT,
	requester      TEXT        NOT NULL DEFAULT '',
	created_at     TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limit_configs (
    name           TEXT        NOT NULL PRIMARY KEY,
    scope          TEXT        NOT NULL,
    algorithm      TEXT        NOT NULL DEFAULT 'fixed_window',
    window_seconds INTEGER     NOT NULL,
    max_requests   INTEGER     NOT NULL,
    enabled        BOOLEAN     NOT NULL DEFAULT TRUE,
    updated_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limit_counters (
    limiter_name TEXT        NOT NULL,
    bucket_key   TEXT        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    count        INTEGER     NOT NULL DEFAULT 0,
    PRIMARY KEY (limiter_name, bucket_key, window_start)
);
CREATE INDEX IF NOT EXISTS idx_pg_rl_counters_window_start ON rate_limit_counters(window_start);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pg_ssh_certs_ca_serial ON ssh_certificates(ca_id, serial);
`

func pgMarshalJSON(v interface{}) (string, error) {
	if v == nil {
		return "{}", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func pgMarshalStringSlice(v []string) (string, error) {
	if v == nil {
		return "[]", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func pgUnmarshalJSON(s string, dst interface{}) error {
	if s == "" || s == "null" {
		return nil
	}
	return json.Unmarshal([]byte(s), dst)
}

func pgUnmarshalStringSlice(s string) ([]string, error) {
	if s == "" || s == "null" || s == "[]" {
		return []string{}, nil
	}
	var out []string
	return out, json.Unmarshal([]byte(s), &out)
}
func pgUnmarshalNameConstraints(s *string) (*NameConstraints, error) {
	if s == nil || *s == "" || *s == "null" {
		return nil, nil
	}
	var nc NameConstraints
	if err := json.Unmarshal([]byte(*s), &nc); err != nil {
		return nil, err
	}
	return &nc, nil
}

func pgUUIDToSQL(id *uuid.UUID) interface{} {
	if id == nil {
		return nil
	}
	return id.String()
}

// pgUUIDNullable converts a UUID to a nullable SQL value, treating uuid.Nil as NULL.
func pgUUIDNullable(id uuid.UUID) interface{} {
	if id == uuid.Nil {
		return nil
	}
	return id.String()
}

// pgSQLToUUIDValue parses a nullable string column back to a uuid.UUID,
// returning uuid.Nil for NULL or invalid values.
func pgSQLToUUIDValue(s *string) uuid.UUID {
	if s == nil {
		return uuid.Nil
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		return uuid.Nil
	}
	return id
}

func pgSQLToUUID(s *string) *uuid.UUID {
	if s == nil {
		return nil
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		return nil
	}
	return &id
}

func (s *postgresStore) CreateCA(ctx context.Context, ca *CertificateAuthority) error {
	ncStr, err := pgMarshalNameConstraints(ca.NameConstraints)
	if err != nil {
		return fmt.Errorf("postgres: CreateCA: marshal name_constraints: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO certificate_authorities
			(id, logical_ca_id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
			 name_constraints, tenant_id, not_before, not_after, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		ca.ID.String(), pgUUIDToSQL(ca.LogicalCAID), pgUUIDToSQL(ca.ParentID), ca.Name,
		string(ca.Type), string(ca.Status), ca.CertPEM, ca.KeyEnc, ca.KeyAlgo,
		ncStr, pgUUIDNullable(ca.TenantID), ca.NotBefore.UTC(), ca.NotAfter.UTC(), ca.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateCA: %w", err)
	}
	return nil
}

func pgMarshalNameConstraints(nc *NameConstraints) (interface{}, error) {
	if nc == nil {
		return nil, nil
	}
	b, err := json.Marshal(nc)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (s *postgresStore) GetCA(ctx context.Context, id uuid.UUID) (*CertificateAuthority, error) {
	row := s.db.QueryRowContext(ctx, pgCASelectSQL+" WHERE id = $1", id.String())
	ca, err := pgScanCA(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetCA: %w", err)
	}
	return ca, nil
}

func (s *postgresStore) GetCAByName(ctx context.Context, name string) (*CertificateAuthority, error) {
	row := s.db.QueryRowContext(ctx, pgCASelectSQL+" WHERE name = $1", name)
	ca, err := pgScanCA(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetCAByName: %w", err)
	}
	return ca, nil
}

func (s *postgresStore) ListCAs(ctx context.Context) ([]*CertificateAuthority, error) {
	rows, err := s.db.QueryContext(ctx, pgCASelectSQL+" ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("postgres: ListCAs: %w", err)
	}
	defer rows.Close()
	return pgScanCAs(rows)
}

func (s *postgresStore) ListChildCAs(ctx context.Context, parentID uuid.UUID) ([]*CertificateAuthority, error) {
	rows, err := s.db.QueryContext(ctx,
		pgCASelectSQL+" WHERE parent_id = $1 ORDER BY created_at ASC",
		parentID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListChildCAs: %w", err)
	}
	defer rows.Close()
	return pgScanCAs(rows)
}

func (s *postgresStore) UpdateCAStatus(ctx context.Context, id uuid.UUID, status CAStatus) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE certificate_authorities SET status = $1 WHERE id = $2`,
		string(status), id.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateCAStatus: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("postgres: UpdateCAStatus: CA %s not found", id)
	}
	return nil
}

func (s *postgresStore) CreateCrossCert(ctx context.Context, cc *CrossCert) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ca_cross_certs
			(id, target_ca_id, signing_ca_id, cert_pem, serial, not_before, not_after, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT(target_ca_id, signing_ca_id) DO UPDATE SET
			cert_pem = EXCLUDED.cert_pem,
			serial = EXCLUDED.serial,
			not_before = EXCLUDED.not_before,
			not_after = EXCLUDED.not_after,
			created_at = EXCLUDED.created_at`,
		cc.ID.String(), cc.TargetCAID.String(), cc.SigningCAID.String(), cc.CertPEM, cc.Serial,
		cc.NotBefore.UTC(), cc.NotAfter.UTC(), cc.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("postgres: CreateCrossCert: %w", err)
	}
	return nil
}

func (s *postgresStore) GetCrossCert(ctx context.Context, targetCAID, signingCAID uuid.UUID) (*CrossCert, error) {
	row := s.db.QueryRowContext(ctx, pgCrossCertSelectSQL+" WHERE target_ca_id = $1 AND signing_ca_id = $2",
		targetCAID.String(), signingCAID.String())
	return pgScanCrossCert(row)
}

func (s *postgresStore) ListCrossCertsByTarget(ctx context.Context, targetCAID uuid.UUID) ([]*CrossCert, error) {
	rows, err := s.db.QueryContext(ctx, pgCrossCertSelectSQL+" WHERE target_ca_id = $1 ORDER BY created_at ASC", targetCAID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListCrossCertsByTarget: %w", err)
	}
	defer rows.Close()
	var out []*CrossCert
	for rows.Next() {
		cc, err := pgScanCrossCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cc)
	}
	return out, rows.Err()
}

type crossCertScannerPG interface {
	Scan(dest ...interface{}) error
}

func pgScanCrossCert(row crossCertScannerPG) (*CrossCert, error) {
	var cc CrossCert
	var idStr, targetStr, signStr string
	err := row.Scan(&idStr, &targetStr, &signStr, &cc.CertPEM, &cc.Serial, &cc.NotBefore, &cc.NotAfter, &cc.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: scanCrossCert: %w", err)
	}
	cc.ID = uuid.MustParse(idStr)
	cc.TargetCAID = uuid.MustParse(targetStr)
	cc.SigningCAID = uuid.MustParse(signStr)
	return &cc, nil
}

const pgCrossCertSelectSQL = `
	SELECT id, target_ca_id, signing_ca_id, cert_pem, serial, not_before, not_after, created_at
	FROM ca_cross_certs`

const pgCASelectSQL = `
	SELECT id, logical_ca_id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
	       name_constraints, tenant_id, not_before, not_after, created_at
	FROM certificate_authorities`

func pgScanCA(row *sql.Row) (*CertificateAuthority, error) {
	var ca CertificateAuthority
	var idStr string
	var logicalCAIDStr *string
	var parentIDStr *string
	var ncStr, tenantIDStr *string
	err := row.Scan(
		&idStr, &logicalCAIDStr, &parentIDStr, &ca.Name, &ca.Type, &ca.Status,
		&ca.CertPEM, &ca.KeyEnc, &ca.KeyAlgo,
		&ncStr,
		&tenantIDStr, &ca.NotBefore, &ca.NotAfter, &ca.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ca.ID = uuid.MustParse(idStr)
	ca.TenantID = pgSQLToUUIDValue(tenantIDStr)
	ca.LogicalCAID = pgSQLToUUID(logicalCAIDStr)
	ca.ParentID = pgSQLToUUID(parentIDStr)
	nc, err := pgUnmarshalNameConstraints(ncStr)
	if err != nil {
		return nil, fmt.Errorf("pgScanCA: unmarshal name_constraints: %w", err)
	}
	ca.NameConstraints = nc
	return &ca, nil
}

func pgScanCAs(rows *sql.Rows) ([]*CertificateAuthority, error) {
	var out []*CertificateAuthority
	for rows.Next() {
		var ca CertificateAuthority
		var idStr string
		var logicalCAIDStr *string
		var parentIDStr *string
		var ncStr, tenantIDStr *string
		if err := rows.Scan(
			&idStr, &logicalCAIDStr, &parentIDStr, &ca.Name, &ca.Type, &ca.Status,
			&ca.CertPEM, &ca.KeyEnc, &ca.KeyAlgo,
			&ncStr,
			&tenantIDStr, &ca.NotBefore, &ca.NotAfter, &ca.CreatedAt,
		); err != nil {
			return nil, err
		}
		ca.ID = uuid.MustParse(idStr)
		ca.TenantID = pgSQLToUUIDValue(tenantIDStr)
		ca.LogicalCAID = pgSQLToUUID(logicalCAIDStr)
		ca.ParentID = pgSQLToUUID(parentIDStr)
		nc, err := pgUnmarshalNameConstraints(ncStr)
		if err != nil {
			return nil, fmt.Errorf("pgScanCAs: unmarshal name_constraints: %w", err)
		}
		ca.NameConstraints = nc
		out = append(out, &ca)
	}
	return out, rows.Err()
}

func (s *postgresStore) CreateCertificate(ctx context.Context, cert *Certificate) error {
	sans, _ := pgMarshalJSON(cert.SANs)
	ku, _ := pgMarshalStringSlice(cert.KeyUsage)
	meta, _ := pgMarshalJSON(cert.Metadata)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO certificates
			(id, ca_id, serial, subject_cn, sans, key_usage, cert_pem, status,
			 not_before, not_after, issued_at, provisioner_id, requester, metadata,
			 key_encrypted, key_pw_required)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		cert.ID.String(), cert.CAID.String(), cert.Serial, cert.SubjectCN,
		sans, ku, cert.CertPEM, string(cert.Status),
		cert.NotBefore.UTC(), cert.NotAfter.UTC(), cert.IssuedAt.UTC(),
		cert.ProvisionerID.String(), cert.Requester, meta,
		cert.KeyEncrypted, cert.KeyPasscodeRequired,
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateCertificate: %w", err)
	}
	return nil
}

func (s *postgresStore) GetCertificate(ctx context.Context, id uuid.UUID) (*Certificate, error) {
	row := s.db.QueryRowContext(ctx, pgCertSelectSQL+" WHERE c.id = $1", id.String())
	cert, err := pgScanCert(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetCertificate: %w", err)
	}
	return cert, nil
}

func (s *postgresStore) GetCertificateBySerial(ctx context.Context, serial string) (*Certificate, error) {
	row := s.db.QueryRowContext(ctx, pgCertSelectSQL+" WHERE c.serial = $1", serial)
	cert, err := pgScanCert(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetCertificateBySerial: %w", err)
	}
	return cert, nil
}

func (s *postgresStore) ListCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		pgCertSelectSQL+" WHERE c.ca_id = $1 ORDER BY c.issued_at DESC",
		caID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListCertificatesByCA: %w", err)
	}
	defer rows.Close()
	return pgScanCerts(rows)
}

// ListAllCertificates returns every certificate across all CAs, newest first.
func (s *postgresStore) ListAllCertificates(ctx context.Context, limit, offset int) ([]*Certificate, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx,
		pgCertSelectSQL+" ORDER BY c.issued_at DESC LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, fmt.Errorf("postgres: ListAllCertificates: %w", err)
	}
	defer rows.Close()
	return pgScanCerts(rows)
}

func (s *postgresStore) ListRevokedByCA(ctx context.Context, caID uuid.UUID) ([]*Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		pgCertSelectSQL+" WHERE c.ca_id = $1 AND c.status = 'revoked' ORDER BY c.revoked_at DESC",
		caID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListRevokedByCA: %w", err)
	}
	defer rows.Close()
	return pgScanCerts(rows)
}

func (s *postgresStore) RevokeCertificate(ctx context.Context, id uuid.UUID, reason int) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE certificates
		SET status = 'revoked', revoked_at = $1, revoke_reason = $2
		WHERE id = $3 AND status = 'active'`,
		now, reason, id.String())
	if err != nil {
		return fmt.Errorf("postgres: RevokeCertificate: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("postgres: RevokeCertificate: certificate %s not found or already revoked", id)
	}
	return nil
}

const pgCertSelectSQL = `
	SELECT c.id, c.ca_id, c.serial, c.subject_cn, c.sans, c.key_usage, c.cert_pem,
	       c.status, c.revoked_at, c.revoke_reason,
	       c.not_before, c.not_after, c.issued_at,
	       c.provisioner_id, c.requester, c.metadata,
	       c.key_encrypted, c.key_pw_required
	FROM certificates c`

func pgScanCert(row *sql.Row) (*Certificate, error) {
	var c Certificate
	var idStr, caIDStr, provIDStr string
	var sansStr, kuStr, metaStr string
	var pwReq bool
	err := row.Scan(
		&idStr, &caIDStr, &c.Serial, &c.SubjectCN,
		&sansStr, &kuStr, &c.CertPEM, &c.Status,
		&c.RevokedAt, &c.RevokeReason,
		&c.NotBefore, &c.NotAfter, &c.IssuedAt,
		&provIDStr, &c.Requester, &metaStr,
		&c.KeyEncrypted, &pwReq,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.ID = uuid.MustParse(idStr)
	c.CAID = uuid.MustParse(caIDStr)
	c.ProvisionerID = uuid.MustParse(provIDStr)
	c.KeyPasscodeRequired = pwReq
	_ = pgUnmarshalJSON(sansStr, &c.SANs)
	c.KeyUsage, _ = pgUnmarshalStringSlice(kuStr)
	_ = pgUnmarshalJSON(metaStr, &c.Metadata)
	return &c, nil
}
func (s *postgresStore) UpdateACMEAccountKey(ctx context.Context, accountID uuid.UUID, newKeyID string, newKeyJWK JSON) error {
	jwk, _ := pgMarshalJSON(newKeyJWK)
	res, err := s.db.ExecContext(ctx,
		`UPDATE acme_accounts SET key_id = $1, key_jwk = $2 WHERE id = $3`,
		newKeyID, jwk, accountID.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateACMEAccountKey: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("postgres: UpdateACMEAccountKey: account %s not found", accountID)
	}
	return nil
}

func (s *postgresStore) MarkKeyIDRetired(ctx context.Context, keyID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO acme_retired_keys (key_id, retired_at) VALUES ($1, $2)
		ON CONFLICT (key_id) DO NOTHING`,
		keyID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("postgres: MarkKeyIDRetired: %w", err)
	}
	return nil
}

func (s *postgresStore) IsKeyIDRetired(ctx context.Context, keyID string) (bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT 1 FROM acme_retired_keys WHERE key_id = $1`, keyID)
	var x int
	err := row.Scan(&x)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("postgres: IsKeyIDRetired: %w", err)
	}
	return true, nil
}
func pgScanCerts(rows *sql.Rows) ([]*Certificate, error) {
	var out []*Certificate
	for rows.Next() {
		var c Certificate
		var idStr, caIDStr, provIDStr string
		var sansStr, kuStr, metaStr string
		var pwReq bool
		if err := rows.Scan(
			&idStr, &caIDStr, &c.Serial, &c.SubjectCN,
			&sansStr, &kuStr, &c.CertPEM, &c.Status,
			&c.RevokedAt, &c.RevokeReason,
			&c.NotBefore, &c.NotAfter, &c.IssuedAt,
			&provIDStr, &c.Requester, &metaStr,
			&c.KeyEncrypted, &pwReq,
		); err != nil {
			return nil, err
		}
		c.ID = uuid.MustParse(idStr)
		c.CAID = uuid.MustParse(caIDStr)
		c.ProvisionerID = uuid.MustParse(provIDStr)
		c.KeyPasscodeRequired = pwReq
		_ = pgUnmarshalJSON(sansStr, &c.SANs)
		c.KeyUsage, _ = pgUnmarshalStringSlice(kuStr)
		_ = pgUnmarshalJSON(metaStr, &c.Metadata)
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (s *postgresStore) CreateProvisioner(ctx context.Context, p *Provisioner) error {
	cfg, _ := pgMarshalJSON(p.Config)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO provisioners (id, ca_id, name, type, config, policy_id, tenant_id, status, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		p.ID.String(), p.CAID.String(), p.Name, string(p.Type),
		cfg, pgUUIDToSQL(p.PolicyID), pgUUIDNullable(p.TenantID), string(p.Status), p.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateProvisioner: %w", err)
	}
	return nil
}

func (s *postgresStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*Provisioner, error) {
	row := s.db.QueryRowContext(ctx, pgProvisionerSelectSQL+" WHERE id = $1", id.String())
	p, err := pgScanProvisioner(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetProvisioner: %w", err)
	}
	return p, nil
}

func (s *postgresStore) ListProvisionersByCA(ctx context.Context, caID uuid.UUID) ([]*Provisioner, error) {
	rows, err := s.db.QueryContext(ctx,
		pgProvisionerSelectSQL+" WHERE ca_id = $1 ORDER BY created_at ASC",
		caID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListProvisionersByCA: %w", err)
	}
	defer rows.Close()
	var out []*Provisioner
	for rows.Next() {
		var p Provisioner
		var idStr, caIDStr, cfgStr string
		var policyIDStr, tenantIDStr *string
		if err := rows.Scan(&idStr, &caIDStr, &p.Name, &p.Type, &cfgStr, &policyIDStr, &tenantIDStr, &p.Status, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.ID = uuid.MustParse(idStr)
		p.CAID = uuid.MustParse(caIDStr)
		p.PolicyID = pgSQLToUUID(policyIDStr)
		p.TenantID = pgSQLToUUIDValue(tenantIDStr)
		_ = pgUnmarshalJSON(cfgStr, &p.Config)
		out = append(out, &p)
	}
	return out, rows.Err()
}

func (s *postgresStore) UpdateProvisionerStatus(ctx context.Context, id uuid.UUID, status ProvisionerStatus) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE provisioners SET status = $1 WHERE id = $2`,
		string(status), id.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateProvisionerStatus: %w", err)
	}
	return nil
}

const pgProvisionerSelectSQL = `
	SELECT id, ca_id, name, type, config, policy_id, tenant_id, status, created_at
	FROM provisioners`

func pgScanProvisioner(row *sql.Row) (*Provisioner, error) {
	var p Provisioner
	var idStr, caIDStr, cfgStr string
	var policyIDStr, tenantIDStr *string
	err := row.Scan(&idStr, &caIDStr, &p.Name, &p.Type, &cfgStr, &policyIDStr, &tenantIDStr, &p.Status, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.CAID = uuid.MustParse(caIDStr)
	p.PolicyID = pgSQLToUUID(policyIDStr)
	p.TenantID = pgSQLToUUIDValue(tenantIDStr)
	_ = pgUnmarshalJSON(cfgStr, &p.Config)
	return &p, nil
}

func (s *postgresStore) CreatePolicy(ctx context.Context, p *Policy) error {
	ad, _ := pgMarshalStringSlice(p.AllowedDomains)
	dd, _ := pgMarshalStringSlice(p.DeniedDomains)
	ai, _ := pgMarshalStringSlice(p.AllowedIPs)
	as_, _ := pgMarshalStringSlice(p.AllowedSANs)
	ka, _ := pgMarshalStringSlice(p.KeyAlgos)
	po, _ := pgMarshalStringSlice(p.PolicyOIDs)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policies
			(id, name, scope, max_ttl_seconds, allowed_domains, denied_domains,
			 allowed_ips, allowed_sans, require_san, key_algos, policy_oids, cps_uri, ssh_policy, tenant_id, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		p.ID.String(), p.Name, string(p.Scope), p.MaxTTL,
		ad, dd, ai, as_, p.RequireSAN, ka, po, p.CPSURI, string(p.SSHPolicy), pgUUIDNullable(p.TenantID), p.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreatePolicy: %w", err)
	}
	return nil
}

func (s *postgresStore) ListPolicies(ctx context.Context) ([]*Policy, error) {
	rows, err := s.db.QueryContext(ctx, pgPolicySelectSQL+" ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("postgres: ListPolicies: %w", err)
	}
	defer rows.Close()
	var out []*Policy
	for rows.Next() {
		var p Policy
		var idStr, adStr, ddStr, aiStr, asStr, kaStr, poStr, sshStr string
		var tenantIDStr *string
		if err := rows.Scan(
			&idStr, &p.Name, &p.Scope, &p.MaxTTL,
			&adStr, &ddStr, &aiStr, &asStr, &p.RequireSAN, &kaStr, &poStr, &p.CPSURI, &sshStr, &tenantIDStr, &p.CreatedAt,
		); err != nil {
			return nil, err
		}
		p.ID = uuid.MustParse(idStr)
		p.TenantID = pgSQLToUUIDValue(tenantIDStr)
		p.AllowedDomains, _ = pgUnmarshalStringSlice(adStr)
		p.DeniedDomains, _ = pgUnmarshalStringSlice(ddStr)
		p.AllowedIPs, _ = pgUnmarshalStringSlice(aiStr)
		p.AllowedSANs, _ = pgUnmarshalStringSlice(asStr)
		p.KeyAlgos, _ = pgUnmarshalStringSlice(kaStr)
		p.PolicyOIDs, _ = pgUnmarshalStringSlice(poStr)
		if sshStr != "" {
			p.SSHPolicy = []byte(sshStr)
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}
func (s *postgresStore) GetPolicy(ctx context.Context, id uuid.UUID) (*Policy, error) {
	row := s.db.QueryRowContext(ctx, policySelectSQL+" WHERE id = ?", id.String())
	p, err := scanPolicy(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetPolicy: %w", err)
	}
	return p, nil
}

func (s *postgresStore) UpdatePolicy(ctx context.Context, p *Policy) error {
	ad, _ := pgMarshalStringSlice(p.AllowedDomains)
	dd, _ := pgMarshalStringSlice(p.DeniedDomains)
	ai, _ := pgMarshalStringSlice(p.AllowedIPs)
	as_, _ := pgMarshalStringSlice(p.AllowedSANs)
	ka, _ := pgMarshalStringSlice(p.KeyAlgos)
	po, _ := pgMarshalStringSlice(p.PolicyOIDs)
	_, err := s.db.ExecContext(ctx, `
		UPDATE policies SET
			name = $1, scope = $2, max_ttl_seconds = $3,
			allowed_domains = $4, denied_domains = $5,
			allowed_ips = $6, allowed_sans = $7,
			require_san = $8, key_algos = $9, policy_oids = $10, cps_uri = $11, ssh_policy = $12
		WHERE id = $13`,
		p.Name, string(p.Scope), p.MaxTTL,
		ad, dd, ai, as_, p.RequireSAN, ka, po, p.CPSURI, string(p.SSHPolicy), p.ID.String(),
	)
	if err != nil {
		return fmt.Errorf("postgres: UpdatePolicy: %w", err)
	}
	return nil
}

const pgPolicySelectSQL = `
	SELECT id, name, scope, max_ttl_seconds,
	       allowed_domains, denied_domains, allowed_ips, allowed_sans,
	       require_san, key_algos, policy_oids, cps_uri, ssh_policy, tenant_id, created_at
	FROM policies`

func pgScanPolicy(row *sql.Row) (*Policy, error) {
	var p Policy
	var idStr, adStr, ddStr, aiStr, asStr, kaStr, poStr, sshStr string
	var tenantIDStr *string
	err := row.Scan(
		&idStr, &p.Name, &p.Scope, &p.MaxTTL,
		&adStr, &ddStr, &aiStr, &asStr, &p.RequireSAN, &kaStr, &poStr, &p.CPSURI, &sshStr, &tenantIDStr, &p.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.TenantID = pgSQLToUUIDValue(tenantIDStr)
	p.AllowedDomains, _ = pgUnmarshalStringSlice(adStr)
	p.DeniedDomains, _ = pgUnmarshalStringSlice(ddStr)
	p.AllowedIPs, _ = pgUnmarshalStringSlice(aiStr)
	p.AllowedSANs, _ = pgUnmarshalStringSlice(asStr)
	p.KeyAlgos, _ = pgUnmarshalStringSlice(kaStr)
	p.PolicyOIDs, _ = pgUnmarshalStringSlice(poStr)
	if sshStr != "" {
		p.SSHPolicy = []byte(sshStr)
	}
	return &p, nil
}

func (s *postgresStore) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id = $1`, id.String())
	if err != nil {
		return fmt.Errorf("postgres: DeletePolicy: %w", err)
	}
	return nil
}

// ---- certificate profiles ----

func pgWriteProfileArgs(p *Profile) ([]interface{}, []string) {
	aka, _ := pgMarshalStringSlice(p.AllowedKeyAlgos)
	return []interface{}{
			p.ID.String(), p.Name, aka, p.MinTTLSeconds, p.MaxTTLSeconds,
			p.RequireSAN, p.AllowWildcard, pgUUIDNullable(p.TenantID), p.CreatedAt.UTC(),
		}, []string{"id", "name", "allowed_key_algos", "min_ttl_seconds",
			"max_ttl_seconds", "require_san", "allow_wildcard", "tenant_id", "created_at"}
}

func (s *postgresStore) CreateProfile(ctx context.Context, p *Profile) error {
	args, cols := pgWriteProfileArgs(p)
	ph := ""
	for i := range cols {
		if i > 0 {
			ph += ","
		}
		ph += fmt.Sprintf("$%d", i+1)
	}
	_, err := s.db.ExecContext(ctx, "INSERT INTO profiles ("+strings.Join(cols, ",")+") VALUES ("+ph+")", args...)
	if err != nil {
		return fmt.Errorf("postgres: CreateProfile: %w", err)
	}
	return nil
}

func (s *postgresStore) GetProfile(ctx context.Context, id uuid.UUID) (*Profile, error) {
	return pgGetProfile(ctx, s.db, pgProfileSelectSQL+" WHERE id = $1", id.String())
}

func (s *postgresStore) GetProfileByName(ctx context.Context, name string) (*Profile, error) {
	return pgGetProfile(ctx, s.db, pgProfileSelectSQL+" WHERE name = $1", name)
}

func (s *postgresStore) ListProfiles(ctx context.Context) ([]*Profile, error) {
	rows, err := s.db.QueryContext(ctx, pgProfileSelectSQL+" ORDER BY name ASC")
	if err != nil {
		return nil, fmt.Errorf("postgres: ListProfiles: %w", err)
	}
	defer rows.Close()
	var out []*Profile
	for rows.Next() {
		p, err := pgScanProfile(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *postgresStore) UpdateProfile(ctx context.Context, p *Profile) error {
	aka, _ := pgMarshalStringSlice(p.AllowedKeyAlgos)
	_, err := s.db.ExecContext(ctx, `
		UPDATE profiles SET
			name = $2, allowed_key_algos = $3, min_ttl_seconds = $4,
			max_ttl_seconds = $5, require_san = $6, allow_wildcard = $7
		WHERE id = $1`, p.ID.String(), p.Name, aka,
		p.MinTTLSeconds, p.MaxTTLSeconds, p.RequireSAN, p.AllowWildcard)
	if err != nil {
		return fmt.Errorf("postgres: UpdateProfile: %w", err)
	}
	return nil
}

func (s *postgresStore) DeleteProfile(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM profiles WHERE id = $1`, id.String())
	if err != nil {
		return fmt.Errorf("postgres: DeleteProfile: %w", err)
	}
	return nil
}

const pgProfileSelectSQL = `
	SELECT id, name, allowed_key_algos, min_ttl_seconds, max_ttl_seconds,
	       require_san, allow_wildcard, tenant_id, created_at
	FROM profiles`

func pgGetProfile(ctx context.Context, db *sql.DB, query string, arg interface{}) (*Profile, error) {
	return pgScanProfile(func(dest ...interface{}) error { return db.QueryRowContext(ctx, query, arg).Scan(dest...) })
}

func pgScanProfile(scan func(...interface{}) error) (*Profile, error) {
	var p Profile
	var idStr, akaStr string
	var tenantIDStr *string
	err := scan(&idStr, &p.Name, &akaStr, &p.MinTTLSeconds, &p.MaxTTLSeconds, &p.RequireSAN, &p.AllowWildcard, &tenantIDStr, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.TenantID = pgSQLToUUIDValue(tenantIDStr)
	p.AllowedKeyAlgos, _ = pgUnmarshalStringSlice(akaStr)
	return &p, nil
}

// ---- CSR auto-approval rules ----

func pgCSRApprovalArgs(r *CSRAutoApproveRule) []interface{} {
	cn, _ := pgMarshalStringSlice(r.AllowedCommonNames)
	dns, _ := pgMarshalStringSlice(r.AllowedDNS)
	return []interface{}{
		r.ID.String(), r.ProvisionerID.String(), r.Name, cn, dns,
		r.MaxTTLSeconds, r.Enabled, r.CreatedAt.UTC(),
	}
}

func (s *postgresStore) CreateCSRAutoApproveRule(ctx context.Context, r *CSRAutoApproveRule) error {
	args := pgCSRApprovalArgs(r)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO csr_approval_rules
			(id, provisioner_id, name, allowed_common_names, allowed_dns, max_ttl_seconds, enabled, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, args...)
	if err != nil {
		return fmt.Errorf("postgres: CreateCSRAutoApproveRule: %w", err)
	}
	return nil
}

func (s *postgresStore) ListCSRAutoApproveRules(ctx context.Context, provisionerID uuid.UUID) ([]*CSRAutoApproveRule, error) {
	q := pgCSRApprovalSelectSQL
	args := []interface{}{}
	if provisionerID != uuid.Nil {
		q += " WHERE provisioner_id = $1"
		args = append(args, provisionerID.String())
	}
	q += " ORDER BY created_at ASC"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: ListCSRAutoApproveRules: %w", err)
	}
	defer rows.Close()
	var out []*CSRAutoApproveRule
	for rows.Next() {
		r, err := pgScanCSRApproval(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *postgresStore) UpdateCSRAutoApproveRule(ctx context.Context, r *CSRAutoApproveRule) error {
	cn, _ := pgMarshalStringSlice(r.AllowedCommonNames)
	dns, _ := pgMarshalStringSlice(r.AllowedDNS)
	_, err := s.db.ExecContext(ctx, `
		UPDATE csr_approval_rules SET
			provisioner_id = $2, name = $3, allowed_common_names = $4, allowed_dns = $5,
			max_ttl_seconds = $6, enabled = $7
		WHERE id = $1`, r.ID.String(), r.ProvisionerID.String(), r.Name, cn, dns, r.MaxTTLSeconds, r.Enabled)
	if err != nil {
		return fmt.Errorf("postgres: UpdateCSRAutoApproveRule: %w", err)
	}
	return nil
}

func (s *postgresStore) DeleteCSRAutoApproveRule(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM csr_approval_rules WHERE id = $1`, id.String())
	if err != nil {
		return fmt.Errorf("postgres: DeleteCSRAutoApproveRule: %w", err)
	}
	return nil
}

const pgCSRApprovalSelectSQL = `
	SELECT id, provisioner_id, name, allowed_common_names, allowed_dns, max_ttl_seconds, enabled, created_at
	FROM csr_approval_rules`

func pgScanCSRApproval(scan func(...interface{}) error) (*CSRAutoApproveRule, error) {
	var r CSRAutoApproveRule
	var idStr, provStr, cnStr, dnsStr string
	var enabled bool
	err := scan(&idStr, &provStr, &r.Name, &cnStr, &dnsStr, &r.MaxTTLSeconds, &enabled, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	r.ID = uuid.MustParse(idStr)
	r.ProvisionerID = uuid.MustParse(provStr)
	r.AllowedCommonNames, _ = pgUnmarshalStringSlice(cnStr)
	r.AllowedDNS, _ = pgUnmarshalStringSlice(dnsStr)
	r.Enabled = enabled
	return &r, nil
}

func (s *postgresStore) CreateACMEAccount(ctx context.Context, a *ACMEAccount) error {
	jwk, _ := pgMarshalJSON(a.KeyJWK)
	contact, _ := pgMarshalStringSlice(a.Contact)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO acme_accounts
			(id, provisioner_id, key_id, key_jwk, eab_id, status, contact, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		a.ID.String(), a.ProvisionerID.String(), a.KeyID,
		jwk, pgUUIDToSQL(a.EABID), string(a.Status), contact, a.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateACMEAccount: %w", err)
	}
	return nil
}

func (s *postgresStore) GetACMEAccountByKeyID(ctx context.Context, keyID string) (*ACMEAccount, error) {
	row := s.db.QueryRowContext(ctx, pgACMEAccountSelectSQL+" WHERE key_id = $1", keyID)
	a, err := pgScanACMEAccount(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetACMEAccountByKeyID: %w", err)
	}
	return a, nil
}

func (s *postgresStore) GetACMEAccount(ctx context.Context, id uuid.UUID) (*ACMEAccount, error) {
	row := s.db.QueryRowContext(ctx, pgACMEAccountSelectSQL+" WHERE id = $1", id.String())
	a, err := pgScanACMEAccount(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetACMEAccount: %w", err)
	}
	return a, nil
}

const pgACMEAuthorizationSelect = `
	SELECT id, order_id, account_id, identifier_type, identifier_value, status, expires_at, created_at
	FROM acme_authorizations`

func pgScanACMEAuthorization(row *sql.Row) (*ACMEAuthorization, error) {
	var a ACMEAuthorization
	var idStr string
	var orderIDStr, accountIDStr *string
	err := row.Scan(&idStr, &orderIDStr, &accountIDStr, &a.IdentifierType, &a.IdentifierValue, &a.Status, &a.ExpiresAt, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.ID = uuid.MustParse(idStr)
	a.OrderID = pgSQLToUUIDValue(orderIDStr)
	a.AccountID = pgSQLToUUIDValue(accountIDStr)
	return &a, nil
}

func pgScanACMEAuthorizationRows(rows *sql.Rows) (*ACMEAuthorization, error) {
	var a ACMEAuthorization
	var idStr string
	var orderIDStr, accountIDStr *string
	if err := rows.Scan(&idStr, &orderIDStr, &accountIDStr, &a.IdentifierType, &a.IdentifierValue, &a.Status, &a.ExpiresAt, &a.CreatedAt); err != nil {
		return nil, err
	}
	a.ID = uuid.MustParse(idStr)
	a.OrderID = pgSQLToUUIDValue(orderIDStr)
	a.AccountID = pgSQLToUUIDValue(accountIDStr)
	return &a, nil
}

func (s *postgresStore) GetACMEAuthorization(ctx context.Context, id uuid.UUID) (*ACMEAuthorization, error) {
	row := s.db.QueryRowContext(ctx, pgACMEAuthorizationSelect+" WHERE id = $1", id.String())
	a, err := pgScanACMEAuthorization(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetACMEAuthorization: %w", err)
	}
	return a, nil
}

func (s *postgresStore) UpdateACMEAuthorizationStatus(ctx context.Context, id uuid.UUID, status ACMEAuthorizationStatus) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_authorizations SET status = $1 WHERE id = $2`,
		string(status), id.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateACMEAuthorizationStatus: %w", err)
	}
	return nil
}

func (s *postgresStore) ListAuthorizationsByOrder(ctx context.Context, orderID uuid.UUID) ([]*ACMEAuthorization, error) {
	rows, err := s.db.QueryContext(ctx,
		pgACMEAuthorizationSelect+" WHERE order_id = $1", orderID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListAuthorizationsByOrder: %w", err)
	}
	defer rows.Close()
	var out []*ACMEAuthorization
	for rows.Next() {
		a, err := pgScanACMEAuthorizationRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetACMEAuthorizationByIdentifier returns the most recent standalone
// (order_id IS NULL) authorization for the given account + identifier.
func (s *postgresStore) GetACMEAuthorizationByIdentifier(ctx context.Context, accountID uuid.UUID, identifierType, identifierValue string) (*ACMEAuthorization, error) {
	row := s.db.QueryRowContext(ctx,
		pgACMEAuthorizationSelect+`
		 WHERE order_id IS NULL AND account_id = $1 AND identifier_type = $2 AND identifier_value = $3
		 ORDER BY created_at DESC LIMIT 1`,
		accountID.String(), identifierType, identifierValue)
	a, err := pgScanACMEAuthorization(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetACMEAuthorizationByIdentifier: %w", err)
	}
	return a, nil
}

// ListAuthorizationsByAccount returns standalone pre-authorizations for an
// account, newest first.
func (s *postgresStore) ListAuthorizationsByAccount(ctx context.Context, accountID uuid.UUID) ([]*ACMEAuthorization, error) {
	rows, err := s.db.QueryContext(ctx,
		pgACMEAuthorizationSelect+`
		 WHERE order_id IS NULL AND account_id = $1
		 ORDER BY created_at DESC`,
		accountID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListAuthorizationsByAccount: %w", err)
	}
	defer rows.Close()
	var out []*ACMEAuthorization
	for rows.Next() {
		a, err := pgScanACMEAuthorizationRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *postgresStore) UpdateACMEAccountStatus(ctx context.Context, id uuid.UUID, status ACMEAccountStatus) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_accounts SET status = $1 WHERE id = $2`,
		string(status), id.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateACMEAccountStatus: %w", err)
	}
	return nil
}

func (s *postgresStore) UpdateACMEAccountContact(ctx context.Context, id uuid.UUID, contact []string) error {
	c, _ := pgMarshalStringSlice(contact)
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_accounts SET contact = $1 WHERE id = $2`, c, id.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateACMEAccountContact: %w", err)
	}
	return nil
}

const pgACMEAccountSelectSQL = `
	SELECT id, provisioner_id, key_id, key_jwk, eab_id, status, contact, created_at
	FROM acme_accounts`

func pgScanACMEAccount(row *sql.Row) (*ACMEAccount, error) {
	var a ACMEAccount
	var idStr, provIDStr, jwkStr, contactStr string
	var eabIDStr *string
	err := row.Scan(
		&idStr, &provIDStr, &a.KeyID, &jwkStr,
		&eabIDStr, &a.Status, &contactStr, &a.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.ID = uuid.MustParse(idStr)
	a.ProvisionerID = uuid.MustParse(provIDStr)
	a.EABID = pgSQLToUUID(eabIDStr)
	_ = pgUnmarshalJSON(jwkStr, &a.KeyJWK)
	a.Contact, _ = pgUnmarshalStringSlice(contactStr)
	return &a, nil
}

func (s *postgresStore) CreateEABCredential(ctx context.Context, e *EABCredential) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO eab_credentials
			(id, provisioner_id, hmac_key, key_id, used, created_at, expires_at)
		VALUES ($1,$2,$3,$4,FALSE,$5,$6)`,
		e.ID.String(), e.ProvisionerID.String(),
		e.HMACKey, e.KeyID, e.CreatedAt.UTC(), e.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateEABCredential: %w", err)
	}
	return nil
}

func (s *postgresStore) GetEABCredential(ctx context.Context, keyID string) (*EABCredential, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, provisioner_id, hmac_key, key_id, used, used_at, created_at, expires_at
		FROM eab_credentials WHERE key_id = $1`, keyID)
	var e EABCredential
	var idStr, provIDStr string
	err := row.Scan(
		&idStr, &provIDStr, &e.HMACKey, &e.KeyID,
		&e.Used, &e.UsedAt, &e.CreatedAt, &e.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: GetEABCredential: %w", err)
	}
	e.ID = uuid.MustParse(idStr)
	e.ProvisionerID = uuid.MustParse(provIDStr)
	return &e, nil
}

func (s *postgresStore) MarkEABUsed(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE eab_credentials SET used = TRUE, used_at = $1 WHERE id = $2`,
		time.Now().UTC(), id.String())
	if err != nil {
		return fmt.Errorf("postgres: MarkEABUsed: %w", err)
	}
	return nil
}

func (s *postgresStore) CreateACMEOrder(ctx context.Context, o *ACMEOrder) error {
	ids, _ := pgMarshalJSON(o.Identifiers)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO acme_orders
			(id, account_id, status, identifiers, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		o.ID.String(), o.AccountID.String(),
		string(o.Status), ids, o.ExpiresAt.UTC(), o.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateACMEOrder: %w", err)
	}
	return nil
}

func (s *postgresStore) GetACMEOrder(ctx context.Context, id uuid.UUID) (*ACMEOrder, error) {
	row := s.db.QueryRowContext(ctx, pgOrderSelectSQL+" WHERE id = $1", id.String())
	o, err := pgScanOrder(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetACMEOrder: %w", err)
	}
	return o, nil
}

func (s *postgresStore) ListACMEOrdersByAccount(ctx context.Context, accountID uuid.UUID) ([]*ACMEOrder, error) {
	rows, err := s.db.QueryContext(ctx,
		pgOrderSelectSQL+" WHERE account_id = $1 ORDER BY created_at DESC",
		accountID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListACMEOrdersByAccount: %w", err)
	}
	defer rows.Close()
	var out []*ACMEOrder
	for rows.Next() {
		var o ACMEOrder
		var idStr, accIDStr, idsStr string
		var certIDStr *string
		if err := rows.Scan(
			&idStr, &accIDStr, &o.Status, &idsStr,
			&certIDStr, &o.ExpiresAt, &o.CreatedAt,
		); err != nil {
			return nil, err
		}
		o.ID = uuid.MustParse(idStr)
		o.AccountID = uuid.MustParse(accIDStr)
		o.CertificateID = pgSQLToUUID(certIDStr)
		_ = pgUnmarshalJSON(idsStr, &o.Identifiers)
		out = append(out, &o)
	}
	return out, rows.Err()
}
func (s *postgresStore) ListRevokedSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*SSHCertificate, error) {
	rows, err := s.db.QueryContext(ctx,
		pgSSHCertSelectSQL+" WHERE ca_id = $1 AND status = 'revoked' ORDER BY revoked_at DESC", caID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListRevokedSSHCertificatesByCA: %w", err)
	}
	defer rows.Close()
	var out []*SSHCertificate
	for rows.Next() {
		var c SSHCertificate
		var idStr, caIDStr, provIDStr, principalsStr string
		var serial int64
		if err := rows.Scan(
			&idStr, &caIDStr, &serial, &c.CertType, &c.KeyID, &principalsStr,
			&c.PublicKey, &c.CertData, &c.ValidAfter, &c.ValidBefore, &c.Status,
			&c.RevokedAt, &provIDStr, &c.Requester, &c.CreatedAt,
		); err != nil {
			return nil, err
		}
		c.ID = uuid.MustParse(idStr)
		c.CAID = uuid.MustParse(caIDStr)
		c.ProvisionerID = uuid.MustParse(provIDStr)
		c.Serial = uint64(serial)
		c.Principals, _ = pgUnmarshalStringSlice(principalsStr)
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (s *postgresStore) UpsertSSHKRL(ctx context.Context, k *SSHKRLCache) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ssh_krl_cache (id, ca_id, krl_data, krl_version, this_update, next_update)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT(ca_id) DO UPDATE SET
			krl_data    = EXCLUDED.krl_data,
			krl_version = EXCLUDED.krl_version,
			this_update = EXCLUDED.this_update,
			next_update = EXCLUDED.next_update`,
		k.ID.String(), k.CAID.String(), k.KRLData, int64(k.KRLVersion),
		k.ThisUpdate.UTC(), k.NextUpdate.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: UpsertSSHKRL: %w", err)
	}
	return nil
}

func (s *postgresStore) GetSSHKRL(ctx context.Context, caID uuid.UUID) (*SSHKRLCache, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ca_id, krl_data, krl_version, this_update, next_update
		FROM ssh_krl_cache WHERE ca_id = $1`, caID.String())
	var k SSHKRLCache
	var idStr, caIDStr string
	var version int64
	err := row.Scan(&idStr, &caIDStr, &k.KRLData, &version, &k.ThisUpdate, &k.NextUpdate)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: GetSSHKRL: %w", err)
	}
	k.ID = uuid.MustParse(idStr)
	k.CAID = uuid.MustParse(caIDStr)
	k.KRLVersion = uint64(version)
	return &k, nil
}
func (s *postgresStore) UpdateACMEOrderStatus(ctx context.Context, id uuid.UUID, status ACMEOrderStatus) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_orders SET status = $1 WHERE id = $2`,
		string(status), id.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateACMEOrderStatus: %w", err)
	}
	return nil
}

func (s *postgresStore) FinalizeACMEOrder(ctx context.Context, orderID uuid.UUID, certID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_orders SET status = 'valid', certificate_id = $1 WHERE id = $2`,
		certID.String(), orderID.String())
	if err != nil {
		return fmt.Errorf("postgres: FinalizeACMEOrder: %w", err)
	}
	return nil
}

const pgOrderSelectSQL = `
	SELECT id, account_id, status, identifiers, certificate_id, expires_at, created_at
	FROM acme_orders`

func pgScanOrder(row *sql.Row) (*ACMEOrder, error) {
	var o ACMEOrder
	var idStr, accIDStr, idsStr string
	var certIDStr *string
	err := row.Scan(
		&idStr, &accIDStr, &o.Status, &idsStr,
		&certIDStr, &o.ExpiresAt, &o.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	o.ID = uuid.MustParse(idStr)
	o.AccountID = uuid.MustParse(accIDStr)
	o.CertificateID = pgSQLToUUID(certIDStr)
	_ = pgUnmarshalJSON(idsStr, &o.Identifiers)
	return &o, nil
}

func (s *postgresStore) CreateACMEChallenge(ctx context.Context, c *ACMEChallenge) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO acme_challenges (id, order_id, authorization_id, type, token, status)
        VALUES ($1,$2,$3,$4,$5,$6)`,
		c.ID.String(), pgUUIDNullable(c.OrderID), pgUUIDToSQL(c.AuthorizationID),
		string(c.Type), c.Token, string(c.Status),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateACMEChallenge: %w", err)
	}
	return nil
}

func (s *postgresStore) GetACMEChallenge(ctx context.Context, id uuid.UUID) (*ACMEChallenge, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, order_id, authorization_id, type, token, status, validated_at
		FROM acme_challenges WHERE id = $1`, id.String())
	c, err := pgScanChallenge(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetACMEChallenge: %w", err)
	}
	return c, nil
}

func pgScanChallengeRows(rows *sql.Rows) (*ACMEChallenge, error) {
	var c ACMEChallenge
	var idStr string
	var orderIDStr, authIDStr *string
	if err := rows.Scan(&idStr, &orderIDStr, &authIDStr, &c.Type, &c.Token, &c.Status, &c.ValidatedAt); err != nil {
		return nil, err
	}
	c.ID = uuid.MustParse(idStr)
	c.OrderID = pgSQLToUUIDValue(orderIDStr)
	c.AuthorizationID = pgSQLToUUID(authIDStr)
	return &c, nil
}

func pgScanChallenge(row *sql.Row) (*ACMEChallenge, error) {
	var c ACMEChallenge
	var idStr string
	var orderIDStr, authIDStr *string
	err := row.Scan(&idStr, &orderIDStr, &authIDStr, &c.Type, &c.Token, &c.Status, &c.ValidatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.ID = uuid.MustParse(idStr)
	c.OrderID = pgSQLToUUIDValue(orderIDStr)
	c.AuthorizationID = pgSQLToUUID(authIDStr)
	return &c, nil
}

func (s *postgresStore) ListChallengesByOrder(ctx context.Context, orderID uuid.UUID) ([]*ACMEChallenge, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, order_id, authorization_id, type, token, status, validated_at
        FROM acme_challenges WHERE order_id = $1`, orderID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListChallengesByOrder: %w", err)
	}
	defer rows.Close()
	var out []*ACMEChallenge
	for rows.Next() {
		c, err := pgScanChallengeRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *postgresStore) CreateACMEAuthorization(ctx context.Context, a *ACMEAuthorization) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO acme_authorizations
            (id, order_id, account_id, identifier_type, identifier_value, status, expires_at, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		a.ID.String(), pgUUIDNullable(a.OrderID), pgUUIDNullable(a.AccountID),
		a.IdentifierType, a.IdentifierValue,
		string(a.Status), a.ExpiresAt.UTC(), a.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateACMEAuthorization: %w", err)
	}
	return nil
}

func (s *postgresStore) UpdateChallengeStatus(ctx context.Context, id uuid.UUID, status ACMEChallengeStatus, validatedAt *time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_challenges SET status = $1, validated_at = $2 WHERE id = $3`,
		string(status), validatedAt, id.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateChallengeStatus: %w", err)
	}
	return nil
}

// ListChallengesByAuthorization returns all challenges belonging to a given authorization.
func (s *sqliteStore) ListChallengesByAuthorization(ctx context.Context, authID uuid.UUID) ([]*ACMEChallenge, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, order_id, authorization_id, type, token, status, validated_at
        FROM acme_challenges WHERE authorization_id = ?`, authID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListChallengesByAuthorization: %w", err)
	}
	defer rows.Close()
	var out []*ACMEChallenge
	for rows.Next() {
		var c ACMEChallenge
		var idStr, orderIDStr string
		var authIDStr *string
		if err := rows.Scan(&idStr, &orderIDStr, &authIDStr, &c.Type, &c.Token, &c.Status, &c.ValidatedAt); err != nil {
			return nil, err
		}
		c.ID = uuid.MustParse(idStr)
		c.OrderID = uuid.MustParse(orderIDStr)
		c.AuthorizationID = sqlToUUID(authIDStr)
		out = append(out, &c)
	}
	return out, rows.Err()
}

// WriteAuditLog appends an entry and extends the tamper-evident hash chain
// (see internal/audit). SELECT ... FOR UPDATE on the singleton chain-state
// row serializes concurrent writers so the chain never forks.
func (s *postgresStore) WriteAuditLog(ctx context.Context, entry *AuditLog) error {
	payload, _ := pgMarshalJSON(entry.Payload)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("postgres: WriteAuditLog: begin: %w", err)
	}
	defer tx.Rollback()

	var prevHash string
	if err := tx.QueryRowContext(ctx, `SELECT last_hash FROM audit_chain_state WHERE id = 1 FOR UPDATE`).Scan(&prevHash); err != nil {
		return fmt.Errorf("postgres: WriteAuditLog: read chain state: %w", err)
	}

	var caIDStr, certIDStr string
	if entry.CAID != nil {
		caIDStr = entry.CAID.String()
	}
	if entry.CertID != nil {
		certIDStr = entry.CertID.String()
	}
	entryHash := audit.ComputeHash(prevHash, audit.Entry{
		ID: entry.ID.String(), EventType: entry.EventType, Actor: entry.Actor,
		CAID: caIDStr, CertID: certIDStr,
		Payload: payload, IPAddress: entry.IPAddress, CreatedAt: entry.CreatedAt,
	})

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_log
			(id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at, prev_hash, entry_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		entry.ID.String(), entry.EventType, entry.Actor,
		pgUUIDToSQL(entry.CAID), pgUUIDToSQL(entry.CertID),
		payload, entry.IPAddress, entry.CreatedAt.UTC(), prevHash, entryHash,
	); err != nil {
		return fmt.Errorf("postgres: WriteAuditLog: insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE audit_chain_state SET last_hash = $1 WHERE id = 1`, entryHash); err != nil {
		return fmt.Errorf("postgres: WriteAuditLog: update chain state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("postgres: WriteAuditLog: commit: %w", err)
	}
	entry.PrevHash = prevHash
	entry.EntryHash = entryHash
	return nil
}

func (s *postgresStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]*AuditLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at, prev_hash, entry_hash
		FROM audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		return nil, fmt.Errorf("postgres: ListAuditLogs: %w", err)
	}
	defer rows.Close()
	return pgScanAuditLogs(rows)
}

func (s *postgresStore) ListAuditLogsByCA(ctx context.Context, caID uuid.UUID, limit, offset int) ([]*AuditLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at, prev_hash, entry_hash
		FROM audit_log WHERE ca_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		caID.String(), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("postgres: ListAuditLogsByCA: %w", err)
	}
	defer rows.Close()
	return pgScanAuditLogs(rows)
}

// ListAuditLogsChronological returns every audit log entry in insertion
// order (oldest first), for hash-chain verification. Ordered by the seq
// BIGSERIAL column since created_at alone can tie within the same instant.
func (s *postgresStore) ListAuditLogsChronological(ctx context.Context) ([]*AuditLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at, prev_hash, entry_hash
		FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: ListAuditLogsChronological: %w", err)
	}
	defer rows.Close()
	return pgScanAuditLogs(rows)
}

// TryAcquireLeadership implements ha.LeadershipStore. The UPDATE's WHERE
// clause only matches when no one currently holds an unexpired lease, or
// when nodeID already holds it (renewal) — Postgres's row lock during the
// UPDATE serializes concurrent callers, so exactly one wins a contested
// campaign.
func (s *postgresStore) TryAcquireLeadership(ctx context.Context, nodeID string, lease time.Duration) (bool, error) {
	now := time.Now().UTC()
	newExpiry := now.Add(lease)
	res, err := s.db.ExecContext(ctx, `
		UPDATE ha_leader_lock
		SET holder_id = $1, expires_at = $2
		WHERE id = 1 AND (holder_id = $1 OR expires_at < $3)`,
		nodeID, newExpiry, now,
	)
	if err != nil {
		return false, fmt.Errorf("postgres: TryAcquireLeadership: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("postgres: TryAcquireLeadership: rows affected: %w", err)
	}
	return n == 1, nil
}

// CurrentLeader implements ha.LeadershipStore.
func (s *postgresStore) CurrentLeader(ctx context.Context) (string, time.Time, error) {
	var holder string
	var expires time.Time
	err := s.db.QueryRowContext(ctx, `SELECT holder_id, expires_at FROM ha_leader_lock WHERE id = 1`).Scan(&holder, &expires)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("postgres: CurrentLeader: %w", err)
	}
	return holder, expires, nil
}

func pgScanAuditLogs(rows *sql.Rows) ([]*AuditLog, error) {
	var out []*AuditLog
	for rows.Next() {
		var l AuditLog
		var idStr, payloadStr string
		var caIDStr, certIDStr *string
		if err := rows.Scan(
			&idStr, &l.EventType, &l.Actor,
			&caIDStr, &certIDStr,
			&payloadStr, &l.IPAddress, &l.CreatedAt,
			&l.PrevHash, &l.EntryHash,
		); err != nil {
			return nil, err
		}
		l.ID = uuid.MustParse(idStr)
		l.CAID = pgSQLToUUID(caIDStr)
		l.CertID = pgSQLToUUID(certIDStr)
		_ = pgUnmarshalJSON(payloadStr, &l.Payload)
		out = append(out, &l)
	}
	return out, rows.Err()
}

func (s *postgresStore) UpsertCRL(ctx context.Context, crl *CRLCache) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO crl_cache (id, ca_id, crl_pem, crl_number, this_update, next_update)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT(ca_id) DO UPDATE SET
			crl_pem     = EXCLUDED.crl_pem,
			crl_number  = EXCLUDED.crl_number,
			this_update = EXCLUDED.this_update,
			next_update = EXCLUDED.next_update`,
		crl.ID.String(), crl.CAID.String(), crl.CRLPEM, crl.CRLNumber,
		crl.ThisUpdate.UTC(), crl.NextUpdate.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: UpsertCRL: %w", err)
	}
	return nil
}

func (s *postgresStore) GetCRL(ctx context.Context, caID uuid.UUID) (*CRLCache, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ca_id, crl_pem, crl_number, this_update, next_update
		FROM crl_cache WHERE ca_id = $1`, caID.String())
	var c CRLCache
	var idStr, caIDStr string
	err := row.Scan(&idStr, &caIDStr, &c.CRLPEM, &c.CRLNumber, &c.ThisUpdate, &c.NextUpdate)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: GetCRL: %w", err)
	}
	c.ID = uuid.MustParse(idStr)
	c.CAID = uuid.MustParse(caIDStr)
	return &c, nil
}

func (s *postgresStore) NextCRLNumber(ctx context.Context, caID uuid.UUID) (int64, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO crl_number_counters (ca_id, next_number) VALUES ($1, 1)
		ON CONFLICT(ca_id) DO UPDATE SET next_number = crl_number_counters.next_number + 1
		RETURNING next_number - 1`, caID.String())
	var n int64
	if err := row.Scan(&n); err != nil {
		return 0, fmt.Errorf("postgres: NextCRLNumber: %w", err)
	}
	if n == 0 {
		n = 1 // first call: row was just inserted at 1, "returned - 1" logic below handles subsequent calls
	}
	return n, nil
}

func (s *postgresStore) ListRevokedByCASince(ctx context.Context, caID uuid.UUID, since time.Time) ([]*Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		pgCertSelectSQL+" WHERE c.ca_id = $1 AND c.status = 'revoked' AND c.revoked_at > $2 ORDER BY c.revoked_at DESC",
		caID.String(), since.UTC())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListRevokedByCASince: %w", err)
	}
	defer rows.Close()
	return pgScanCerts(rows)
}

func (s *postgresStore) UpsertDeltaCRL(ctx context.Context, d *DeltaCRLCache) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO crl_delta_cache (id, ca_id, crl_pem, crl_number, base_crl_number, this_update, next_update)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT(ca_id) DO UPDATE SET
			crl_pem         = EXCLUDED.crl_pem,
			crl_number      = EXCLUDED.crl_number,
			base_crl_number = EXCLUDED.base_crl_number,
			this_update     = EXCLUDED.this_update,
			next_update     = EXCLUDED.next_update`,
		d.ID.String(), d.CAID.String(), d.CRLPEM, d.CRLNumber, d.BaseCRLNumber,
		d.ThisUpdate.UTC(), d.NextUpdate.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: UpsertDeltaCRL: %w", err)
	}
	return nil
}

func (s *postgresStore) GetDeltaCRL(ctx context.Context, caID uuid.UUID) (*DeltaCRLCache, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ca_id, crl_pem, crl_number, base_crl_number, this_update, next_update
		FROM crl_delta_cache WHERE ca_id = $1`, caID.String())
	var d DeltaCRLCache
	var idStr, caIDStr string
	err := row.Scan(&idStr, &caIDStr, &d.CRLPEM, &d.CRLNumber, &d.BaseCRLNumber, &d.ThisUpdate, &d.NextUpdate)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: GetDeltaCRL: %w", err)
	}
	d.ID = uuid.MustParse(idStr)
	d.CAID = uuid.MustParse(caIDStr)
	return &d, nil
}

func (s *postgresStore) CreateAPIKey(ctx context.Context, k *APIKey) error {
	scopes, _ := pgMarshalStringSlice(k.Scopes)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_keys
			(id, name, key_hash, scopes, ca_id, tenant_id, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		k.ID.String(), k.Name, k.KeyHash, scopes,
		pgUUIDToSQL(k.CAID), pgUUIDToSQL(k.TenantID), k.ExpiresAt, k.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateAPIKey: %w", err)
	}
	return nil
}

func (s *postgresStore) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, key_hash, scopes, ca_id, tenant_id, expires_at, last_used, created_at
		FROM api_keys WHERE key_hash = $1`, hash)
	return pgScanAPIKey(row)
}

func (s *postgresStore) ListAPIKeys(ctx context.Context) ([]*APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, key_hash, scopes, ca_id, tenant_id, expires_at, last_used, created_at
		FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: ListAPIKeys: %w", err)
	}
	defer rows.Close()
	var out []*APIKey
	for rows.Next() {
		var k APIKey
		var idStr, scopesStr string
		var caIDStr, tenantIDStr *string
		if err := rows.Scan(
			&idStr, &k.Name, &k.KeyHash, &scopesStr,
			&caIDStr, &tenantIDStr, &k.ExpiresAt, &k.LastUsed, &k.CreatedAt,
		); err != nil {
			return nil, err
		}
		k.ID = uuid.MustParse(idStr)
		k.CAID = pgSQLToUUID(caIDStr)
		k.TenantID = pgSQLToUUID(tenantIDStr)
		k.Scopes, _ = pgUnmarshalStringSlice(scopesStr)
		out = append(out, &k)
	}
	return out, rows.Err()
}

func (s *postgresStore) DeleteAPIKey(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = $1`, id.String())
	if err != nil {
		return fmt.Errorf("postgres: DeleteAPIKey: %w", err)
	}
	return nil
}

func (s *postgresStore) UpdateAPIKeyHash(ctx context.Context, id uuid.UUID, newHash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET key_hash = $1 WHERE id = $2`, newHash, id.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateAPIKeyHash: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("postgres: UpdateAPIKeyHash: API key %s not found", id)
	}
	return nil
}

func (s *postgresStore) TouchAPIKey(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET last_used = $1 WHERE id = $2`,
		time.Now().UTC(), id.String())
	if err != nil {
		return fmt.Errorf("postgres: TouchAPIKey: %w", err)
	}
	return nil
}

func (s *postgresStore) GetSetupState(ctx context.Context) (SetupState, error) {
	row := s.db.QueryRowContext(ctx, `SELECT state FROM setup_state WHERE id = 1`)
	var state string
	err := row.Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return StateUninitialized, nil
	}
	if err != nil {
		return StateUninitialized, fmt.Errorf("postgres: GetSetupState: %w", err)
	}
	return SetupState(state), nil
}

func (s *postgresStore) SetSetupState(ctx context.Context, state SetupState) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO setup_state (id, state, updated_at)
		VALUES (1, $1, $2)
		ON CONFLICT(id) DO UPDATE SET
			state      = EXCLUDED.state,
			updated_at = EXCLUDED.updated_at`,
		string(state), time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: SetSetupState: %w", err)
	}
	return nil
}

func (s *postgresStore) GetAPIKeyByName(ctx context.Context, name string) (*APIKey, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, key_hash, scopes, ca_id, tenant_id, expires_at, last_used, created_at
		FROM api_keys WHERE name = $1`, name)
	return pgScanAPIKey(row)
}

func pgScanAPIKey(row *sql.Row) (*APIKey, error) {
	var k APIKey
	var idStr, scopesStr string
	var caIDStr, tenantIDStr *string
	err := row.Scan(
		&idStr, &k.Name, &k.KeyHash, &scopesStr,
		&caIDStr, &tenantIDStr, &k.ExpiresAt, &k.LastUsed, &k.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: scanAPIKey: %w", err)
	}
	k.ID = uuid.MustParse(idStr)
	k.CAID = pgSQLToUUID(caIDStr)
	k.TenantID = pgSQLToUUID(tenantIDStr)
	k.Scopes, _ = pgUnmarshalStringSlice(scopesStr)
	return &k, nil
}

// ---- tenants ----

const pgTenantSelectSQL = `SELECT id, name, status, created_at FROM tenants`

func (s *postgresStore) CreateTenant(ctx context.Context, t *Tenant) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tenants (id, name, status, created_at)
		VALUES ($1, $2, $3, $4)`, t.ID.String(), t.Name, string(t.Status), t.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("postgres: CreateTenant: %w", err)
	}
	return nil
}

func (s *postgresStore) GetTenant(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx, pgTenantSelectSQL+" WHERE id = $1", id.String())
	return pgScanTenant(row)
}

func (s *postgresStore) GetTenantByName(ctx context.Context, name string) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx, pgTenantSelectSQL+" WHERE name = $1", name)
	return pgScanTenant(row)
}

func (s *postgresStore) ListTenants(ctx context.Context) ([]*Tenant, error) {
	rows, err := s.db.QueryContext(ctx, pgTenantSelectSQL+" ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("postgres: ListTenants: %w", err)
	}
	defer rows.Close()
	var out []*Tenant
	for rows.Next() {
		t, err := pgScanTenantRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *postgresStore) UpdateTenantStatus(ctx context.Context, id uuid.UUID, status TenantStatus) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tenants SET status = $1 WHERE id = $2`, string(status), id.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateTenantStatus: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("postgres: UpdateTenantStatus: tenant %s not found", id)
	}
	return nil
}

func pgScanTenant(row *sql.Row) (*Tenant, error) {
	t, err := scanTenantFields(func(dest ...interface{}) error { return row.Scan(dest...) })
	if err != nil {
		return nil, err
	}
	return t, nil
}

func pgScanTenantRows(rows *sql.Rows) (*Tenant, error) {
	return scanTenantFields(rows.Scan)
}

func (s *postgresStore) CreateSSHCA(ctx context.Context, ca *SSHCertificateAuthority) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ssh_certificate_authorities
			(id, name, key_algo, public_key, key_enc, status, logical_ca_id, parent_id, tenant_id, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		ca.ID.String(), ca.Name, string(ca.KeyAlgo), ca.PublicKey,
		ca.KeyEnc, string(ca.Status), pgUUIDToSQL(ca.LogicalCAID), pgUUIDToSQL(ca.ParentID), pgUUIDNullable(ca.TenantID),
		ca.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateSSHCA: %w", err)
	}
	return nil
}

const pgSSHCASelectSQL = `
	SELECT id, name, key_algo, public_key, key_enc, status, logical_ca_id, parent_id, tenant_id, created_at
	FROM ssh_certificate_authorities`

func pgScanSSHCA(row *sql.Row) (*SSHCertificateAuthority, error) {
	var ca SSHCertificateAuthority
	var idStr string
	var logicalID, parentID, tenantID *string
	err := row.Scan(&idStr, &ca.Name, &ca.KeyAlgo, &ca.PublicKey, &ca.KeyEnc, &ca.Status, &logicalID, &parentID, &tenantID, &ca.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ca.ID = uuid.MustParse(idStr)
	ca.TenantID = pgSQLToUUIDValue(tenantID)
	ca.LogicalCAID = pgSQLToUUID(logicalID)
	ca.ParentID = pgSQLToUUID(parentID)
	return &ca, nil
}

func (s *postgresStore) GetSSHCA(ctx context.Context, id uuid.UUID) (*SSHCertificateAuthority, error) {
	row := s.db.QueryRowContext(ctx, pgSSHCASelectSQL+" WHERE id = $1", id.String())
	ca, err := pgScanSSHCA(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetSSHCA: %w", err)
	}
	return ca, nil
}

func (s *postgresStore) GetSSHCAByName(ctx context.Context, name string) (*SSHCertificateAuthority, error) {
	row := s.db.QueryRowContext(ctx, pgSSHCASelectSQL+" WHERE name = $1", name)
	ca, err := pgScanSSHCA(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetSSHCAByName: %w", err)
	}
	return ca, nil
}

func (s *postgresStore) ListSSHCAs(ctx context.Context) ([]*SSHCertificateAuthority, error) {
	rows, err := s.db.QueryContext(ctx, pgSSHCASelectSQL+" ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("postgres: ListSSHCAs: %w", err)
	}
	defer rows.Close()
	var out []*SSHCertificateAuthority
	for rows.Next() {
		var ca SSHCertificateAuthority
		var idStr string
		var logicalID, parentID, tenantID *string
		if err := rows.Scan(&idStr, &ca.Name, &ca.KeyAlgo, &ca.PublicKey, &ca.KeyEnc, &ca.Status, &logicalID, &parentID, &tenantID, &ca.CreatedAt); err != nil {
			return nil, err
		}
		ca.ID = uuid.MustParse(idStr)
		ca.TenantID = pgSQLToUUIDValue(tenantID)
		ca.LogicalCAID = pgSQLToUUID(logicalID)
		ca.ParentID = pgSQLToUUID(parentID)
		out = append(out, &ca)
	}
	return out, rows.Err()
}

func (s *postgresStore) UpdateSSHCAStatus(ctx context.Context, id uuid.UUID, status CAStatus) error {
	_, err := s.db.ExecContext(ctx, `UPDATE ssh_certificate_authorities SET status = $1 WHERE id = $2`, string(status), id.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateSSHCAStatus: %w", err)
	}
	return nil
}

func (s *postgresStore) CreateSSHCertificate(ctx context.Context, cert *SSHCertificate) error {
	principals, err := pgMarshalStringSlice(cert.Principals)
	if err != nil {
		return fmt.Errorf("postgres: CreateSSHCertificate: marshal principals: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO ssh_certificates
			(id, ca_id, serial, cert_type, key_id, principals, public_key, cert_data,
			 valid_after, valid_before, status, provisioner_id, requester, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		cert.ID.String(), cert.CAID.String(), int64(cert.Serial), string(cert.CertType),
		cert.KeyID, principals, cert.PublicKey, cert.CertData,
		cert.ValidAfter.UTC(), cert.ValidBefore.UTC(), string(cert.Status),
		cert.ProvisionerID.String(), cert.Requester, cert.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateSSHCertificate: %w", err)
	}
	return nil
}

const pgSSHCertSelectSQL = `
	SELECT id, ca_id, serial, cert_type, key_id, principals, public_key, cert_data,
	       valid_after, valid_before, status, revoked_at, provisioner_id, requester, created_at
	FROM ssh_certificates`

func pgScanSSHCert(row *sql.Row) (*SSHCertificate, error) {
	var c SSHCertificate
	var idStr, caIDStr, provIDStr, principalsStr string
	var serial int64
	err := row.Scan(
		&idStr, &caIDStr, &serial, &c.CertType, &c.KeyID, &principalsStr,
		&c.PublicKey, &c.CertData, &c.ValidAfter, &c.ValidBefore, &c.Status,
		&c.RevokedAt, &provIDStr, &c.Requester, &c.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.ID = uuid.MustParse(idStr)
	c.CAID = uuid.MustParse(caIDStr)
	c.ProvisionerID = uuid.MustParse(provIDStr)
	c.Serial = uint64(serial)
	c.Principals, _ = pgUnmarshalStringSlice(principalsStr)
	return &c, nil
}

func (s *postgresStore) GetSSHCertificate(ctx context.Context, id uuid.UUID) (*SSHCertificate, error) {
	row := s.db.QueryRowContext(ctx, pgSSHCertSelectSQL+" WHERE id = $1", id.String())
	c, err := pgScanSSHCert(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetSSHCertificate: %w", err)
	}
	return c, nil
}

func (s *postgresStore) GetSSHCertificateBySerial(ctx context.Context, caID uuid.UUID, serial uint64) (*SSHCertificate, error) {
	row := s.db.QueryRowContext(ctx, pgSSHCertSelectSQL+" WHERE ca_id = $1 AND serial = $2", caID.String(), int64(serial))
	c, err := pgScanSSHCert(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetSSHCertificateBySerial: %w", err)
	}
	return c, nil
}

func (s *postgresStore) ListSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*SSHCertificate, error) {
	rows, err := s.db.QueryContext(ctx,
		pgSSHCertSelectSQL+" WHERE ca_id = $1 ORDER BY created_at DESC", caID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListSSHCertificatesByCA: %w", err)
	}
	defer rows.Close()
	var out []*SSHCertificate
	for rows.Next() {
		var c SSHCertificate
		var idStr, caIDStr, provIDStr, principalsStr string
		var serial int64
		if err := rows.Scan(
			&idStr, &caIDStr, &serial, &c.CertType, &c.KeyID, &principalsStr,
			&c.PublicKey, &c.CertData, &c.ValidAfter, &c.ValidBefore, &c.Status,
			&c.RevokedAt, &provIDStr, &c.Requester, &c.CreatedAt,
		); err != nil {
			return nil, err
		}
		c.ID = uuid.MustParse(idStr)
		c.CAID = uuid.MustParse(caIDStr)
		c.ProvisionerID = uuid.MustParse(provIDStr)
		c.Serial = uint64(serial)
		c.Principals, _ = pgUnmarshalStringSlice(principalsStr)
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (s *postgresStore) RevokeSSHCertificate(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE ssh_certificates SET status = 'revoked', revoked_at = $1
		WHERE id = $2 AND status = 'active'`, time.Now().UTC(), id.String())
	if err != nil {
		return fmt.Errorf("postgres: RevokeSSHCertificate: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("postgres: RevokeSSHCertificate: certificate %s not found or already revoked", id)
	}
	return nil
}

// MigrateNonces runs the nonce schema migration for Postgres.
func (s *postgresStore) MigrateNonces(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, postgresNonceSchema)
	return err
}

// CreateNonce inserts a nonce, ignoring conflicts on the primary key.
func (s *postgresStore) CreateNonce(ctx context.Context, nonce string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO acme_nonces (nonce, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		nonce, expiresAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateNonce: %w", err)
	}
	return nil
}

// ConsumeNonce atomically validates and deletes a nonce using
// DELETE…RETURNING, which is atomic in Postgres without an explicit
// transaction. It returns false for unknown or expired nonces.
func (s *postgresStore) ConsumeNonce(ctx context.Context, nonce string) (bool, error) {
	// DELETE the row and return expires_at in one round trip.
	row := s.db.QueryRowContext(ctx,
		`DELETE FROM acme_nonces WHERE nonce = $1 RETURNING expires_at`, nonce)
	var expiresAt time.Time
	if err := row.Scan(&expiresAt); errors.Is(err, sql.ErrNoRows) {
		return false, nil // unknown nonce
	} else if err != nil {
		return false, fmt.Errorf("postgres: ConsumeNonce: %w", err)
	}
	// Check expiry after deleting — the nonce is consumed either way.
	if time.Now().UTC().After(expiresAt.UTC()) {
		return false, nil
	}
	return true, nil
}
func (s *postgresStore) GetRateLimitConfig(ctx context.Context, name string) (*RateLimitConfig, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT name, scope, algorithm, window_seconds, max_requests, enabled, updated_at
		FROM rate_limit_configs WHERE name = $1`, name)
	c, err := pgScanRateLimitConfig(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetRateLimitConfig: %w", err)
	}
	return c, nil
}

func (s *postgresStore) ListRateLimitConfigs(ctx context.Context) ([]*RateLimitConfig, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, scope, algorithm, window_seconds, max_requests, enabled, updated_at
		FROM rate_limit_configs ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: ListRateLimitConfigs: %w", err)
	}
	defer rows.Close()
	var out []*RateLimitConfig
	for rows.Next() {
		var c RateLimitConfig
		if err := rows.Scan(&c.Name, &c.Scope, &c.Algorithm, &c.WindowSeconds, &c.MaxRequests, &c.Enabled, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (s *postgresStore) UpsertRateLimitConfigIfAbsent(ctx context.Context, cfg *RateLimitConfig) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO rate_limit_configs
			(name, scope, algorithm, window_seconds, max_requests, enabled, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (name) DO NOTHING`,
		cfg.Name, cfg.Scope, cfg.Algorithm, cfg.WindowSeconds, cfg.MaxRequests, cfg.Enabled, cfg.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: UpsertRateLimitConfigIfAbsent: %w", err)
	}
	return nil
}

func (s *postgresStore) UpdateRateLimitConfig(ctx context.Context, cfg *RateLimitConfig) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE rate_limit_configs SET
			scope = $1, algorithm = $2, window_seconds = $3, max_requests = $4, enabled = $5, updated_at = $6
		WHERE name = $7`,
		cfg.Scope, cfg.Algorithm, cfg.WindowSeconds, cfg.MaxRequests, cfg.Enabled, cfg.UpdatedAt.UTC(),
		cfg.Name,
	)
	if err != nil {
		return fmt.Errorf("postgres: UpdateRateLimitConfig: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("postgres: UpdateRateLimitConfig: limiter %q not found", cfg.Name)
	}
	return nil
}

func pgScanRateLimitConfig(row *sql.Row) (*RateLimitConfig, error) {
	var c RateLimitConfig
	err := row.Scan(&c.Name, &c.Scope, &c.Algorithm, &c.WindowSeconds, &c.MaxRequests, &c.Enabled, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *postgresStore) IncrementRateLimitCounter(ctx context.Context, limiterName, bucketKey string, windowStart time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO rate_limit_counters (limiter_name, bucket_key, window_start, count)
		VALUES ($1,$2,$3,1)
		ON CONFLICT (limiter_name, bucket_key, window_start) DO UPDATE SET
			count = rate_limit_counters.count + 1`,
		limiterName, bucketKey, windowStart.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: IncrementRateLimitCounter: %w", err)
	}
	return nil
}

func (s *postgresStore) PruneExpiredRateLimitCounters(ctx context.Context, olderThan time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM rate_limit_counters WHERE window_start < $1`, olderThan.UTC())
	if err != nil {
		return fmt.Errorf("postgres: PruneExpiredRateLimitCounters: %w", err)
	}
	return nil
}

// PruneExpiredNonces deletes all nonces past their expiry.
func (s *postgresStore) PruneExpiredNonces(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM acme_nonces WHERE expires_at < NOW()`)
	if err != nil {
		return fmt.Errorf("postgres: PruneExpiredNonces: %w", err)
	}
	return nil
}
