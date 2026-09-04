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
	_ "github.com/mattn/go-sqlite3"
)

// sqliteStore is the SQLite implementation of Store.
const sqliteNonceSchema = `
CREATE TABLE IF NOT EXISTS acme_nonces (
	nonce      TEXT     NOT NULL PRIMARY KEY,
	expires_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonces_expires_at ON acme_nonces(expires_at);
`

type sqliteStore struct {
	db *sql.DB
}

var _ TenantStore = (*sqliteStore)(nil)

func newSQLiteStore(dsn string) (*sqliteStore, error) {
	fullDSN := fmt.Sprintf(
		"%s?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000&_synchronous=NORMAL",
		dsn,
	)

	db, err := sql.Open("sqlite3", fullDSN)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %q: %w", dsn, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &sqliteStore{db: db}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}

	if err := s.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate: %w", err)
	}

	return s, nil
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}

func (s *sqliteStore) Migrate(ctx context.Context) error {
	// Create all tables
	if _, err := s.db.ExecContext(ctx, sqliteSchema); err != nil {
		return err
	}

	// Add authorization_id column to acme_challenges if it doesn't exist
	var exists bool
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info(acme_challenges)")
	if err != nil {
		return fmt.Errorf("sqlite: query table_info: %w", err)
	}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("sqlite: scan table_info: %w", err)
		}
		if name == "authorization_id" {
			exists = true
			break
		}
	}
	rows.Close()

	if !exists {
		if _, err := s.db.ExecContext(ctx, "ALTER TABLE acme_challenges ADD COLUMN authorization_id TEXT REFERENCES acme_authorizations(id) ON DELETE CASCADE"); err != nil {
			return fmt.Errorf("sqlite: add authorization_id column: %w", err)
		}
	}

	// Add name_constraints column to certificate_authorities if it doesn't exist.
	if err := addColumnIfAbsentSQLite(ctx, s.db, "certificate_authorities", "name_constraints",
		"ALTER TABLE certificate_authorities ADD COLUMN name_constraints TEXT"); err != nil {
		return err
	}

	// Add policy_oids / cps_uri columns to policies if they don't exist.
	if err := addColumnIfAbsentSQLite(ctx, s.db, "policies", "policy_oids",
		"ALTER TABLE policies ADD COLUMN policy_oids TEXT DEFAULT '[]'"); err != nil {
		return err
	}
	if err := addColumnIfAbsentSQLite(ctx, s.db, "policies", "cps_uri",
		"ALTER TABLE policies ADD COLUMN cps_uri TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := addColumnIfAbsentSQLite(ctx, s.db, "crl_cache", "crl_number",
		"ALTER TABLE crl_cache ADD COLUMN crl_number INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// Add logical_ca_id for the provisioner->logical-CA indirection, then
	// backfill existing rows so a pre-existing CA's logical id is itself.
	if err := addColumnIfAbsentSQLite(ctx, s.db, "certificate_authorities", "logical_ca_id",
		"ALTER TABLE certificate_authorities ADD COLUMN logical_ca_id TEXT"); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE certificate_authorities SET logical_ca_id = id WHERE logical_ca_id IS NULL`); err != nil {
		return fmt.Errorf("sqlite: backfill logical_ca_id: %w", err)
	}

	// Widen the certificate_authorities.status CHECK to accept 'superseded' for
	// databases created before re-key support. SQLite cannot ALTER a CHECK, so
	// we rebuild the table (the standard 12-step approach) and copy rows over.
	if err := rebuildCAStatusConstraintSQLite(ctx, s.db); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, sqliteNonceSchema); err != nil {
		return err
	}
	if err := addColumnIfAbsentSQLite(ctx, s.db, "api_keys", "tenant_id",
		"ALTER TABLE api_keys ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL"); err != nil {
		return err
	}
	for _, t := range []string{"certificate_authorities", "provisioners", "profiles", "policies", "ssh_certificate_authorities"} {
		if err := addColumnIfAbsentSQLite(ctx, s.db, t, "tenant_id",
			"ALTER TABLE "+t+" ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL"); err != nil {
			return err
		}
	}
	if err := seedDefaultTenantSQLite(ctx, s.db); err != nil {
		return err
	}
	if err := backfillTenantSQLite(ctx, s.db); err != nil {
		return err
	}
	return nil
}

// backfillTenantSQLite points pre-existing single-tenant rows at the default
// tenant so isolation has a watermark to enforce against.
func backfillTenantSQLite(ctx context.Context, db *sql.DB) error {
	for _, t := range []string{"certificate_authorities", "provisioners", "profiles", "policies", "ssh_certificate_authorities"} {
		if _, err := db.ExecContext(ctx, `UPDATE `+t+` SET tenant_id = ? WHERE tenant_id IS NULL`, DefaultTenantID.String()); err != nil {
			return fmt.Errorf("sqlite: backfill %s tenant_id: %w", t, err)
		}
	}
	return nil
}

// seedDefaultTenantSQLite inserts the fixed default tenant if no tenant
// exists yet, so every deployment has a deterministic anchor row for its
// pre-existing single-tenant data.
func seedDefaultTenantSQLite(ctx context.Context, db *sql.DB) error {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&count); err != nil {
		return fmt.Errorf("sqlite: seed default tenant count: %w", err)
	}
	if count > 0 {
		return nil
	}
	_, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, status, created_at) VALUES (?, 'default', 'active', ?)`,
		DefaultTenantID.String(), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sqlite: seed default tenant: %w", err)
	}
	return nil
}

// sqliteCASchema is the certificate_authorities CREATE used when rebuilding the
// table to widen the status CHECK to include 'superseded'.
const sqliteCASchema = `CREATE TABLE IF NOT EXISTS certificate_authorities (
	id               TEXT    NOT NULL PRIMARY KEY,
	logical_ca_id    TEXT,
	parent_id        TEXT    REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
	name             TEXT    NOT NULL UNIQUE,
	type             TEXT    NOT NULL CHECK(type IN ('root','intermediate')),
	status           TEXT    NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired','superseded')),
	cert_pem         TEXT    NOT NULL,
	key_enc          BLOB    NOT NULL,
	key_algo         TEXT    NOT NULL,
	name_constraints TEXT,
	not_before       DATETIME NOT NULL,
	not_after        DATETIME NOT NULL,
	created_at       DATETIME NOT NULL
)`

// rebuildCAStatusConstraintSQLite recreates certificate_authorities with a
// CHECK that permits 'superseded'. It inspects the table's current SQL; if it
// already allows superseded, it is a no-op.
func rebuildCAStatusConstraintSQLite(ctx context.Context, db *sql.DB) error {
	var current string
	row := db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='certificate_authorities'")
	if err := row.Scan(&current); err != nil {
		return fmt.Errorf("sqlite: read certificate_authorities schema: %w", err)
	}
	if strings.Contains(current, "superseded") {
		return nil
	}

	_, err := db.ExecContext(ctx, `
		BEGIN;
		DROP TABLE IF EXISTS certificate_authorities_old;
		ALTER TABLE certificate_authorities RENAME TO certificate_authorities_old;
		`+sqliteCASchema+`;
		INSERT INTO certificate_authorities
			(id, logical_ca_id, parent_id, name, type, status, cert_pem, key_enc, key_algo, name_constraints, not_before, not_after, created_at)
			SELECT id, logical_ca_id, parent_id, name, type, status, cert_pem, key_enc, key_algo, name_constraints, not_before, not_after, created_at
			FROM certificate_authorities_old;
		DROP TABLE certificate_authorities_old;
		COMMIT;
	`)
	if err != nil {
		return fmt.Errorf("sqlite: rebuild certificate_authorities constraint: %w", err)
	}
	return nil
}

// addColumnIfAbsentSQLite checks PRAGMA table_info(table) for columnName and,
// if missing, runs alterSQL. Shared helper for the ADD COLUMN migration
// idiom used throughout Migrate().
func addColumnIfAbsentSQLite(ctx context.Context, db *sql.DB, table, columnName, alterSQL string) error {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return fmt.Errorf("sqlite: query table_info(%s): %w", table, err)
	}
	var exists bool
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("sqlite: scan table_info(%s): %w", table, err)
		}
		if name == columnName {
			exists = true
			break
		}
	}
	err = rows.Close()
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if _, err := db.ExecContext(ctx, alterSQL); err != nil {
		return fmt.Errorf("sqlite: add column %s.%s: %w", table, columnName, err)
	}
	return nil
}

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS certificate_authorities (
	id               TEXT    NOT NULL PRIMARY KEY,
	logical_ca_id    TEXT,
	parent_id        TEXT    REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
	name             TEXT    NOT NULL UNIQUE,
	type             TEXT    NOT NULL CHECK(type IN ('root','intermediate')),
	status           TEXT    NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired','superseded')),
	cert_pem         TEXT    NOT NULL,
	key_enc          BLOB    NOT NULL,
	key_algo         TEXT    NOT NULL,
	name_constraints TEXT,
	not_before       DATETIME NOT NULL,
	not_after        DATETIME NOT NULL,
	created_at       DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS ca_cross_certs (
	id           TEXT    NOT NULL PRIMARY KEY,
	target_ca_id TEXT    NOT NULL REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	signing_ca_id TEXT   NOT NULL REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	cert_pem     TEXT    NOT NULL,
	serial       TEXT    NOT NULL,
	not_before   DATETIME NOT NULL,
	not_after    DATETIME NOT NULL,
	created_at   DATETIME NOT NULL,
	UNIQUE(target_ca_id, signing_ca_id)
);

CREATE TABLE IF NOT EXISTS tenants (
	id         TEXT    NOT NULL PRIMARY KEY,
	name       TEXT    NOT NULL UNIQUE,
	status     TEXT    NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
	id              TEXT    NOT NULL PRIMARY KEY,
	name            TEXT    NOT NULL,
	scope           TEXT    NOT NULL CHECK(scope IN ('ca','provisioner')),
	max_ttl_seconds INTEGER NOT NULL DEFAULT 86400,
	allowed_domains TEXT    NOT NULL DEFAULT '[]',
	denied_domains  TEXT    NOT NULL DEFAULT '[]',
	allowed_ips     TEXT    NOT NULL DEFAULT '[]',
	allowed_sans    TEXT    NOT NULL DEFAULT '[]',
	require_san     INTEGER NOT NULL DEFAULT 0,
	key_algos       TEXT    NOT NULL DEFAULT '[]',
	policy_oids     TEXT    NOT NULL DEFAULT '[]',
	cps_uri         TEXT    NOT NULL DEFAULT '',
	ssh_policy      TEXT    NOT NULL DEFAULT '',
	created_at      DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
	id                 TEXT    NOT NULL PRIMARY KEY,
	name               TEXT    NOT NULL UNIQUE,
	allowed_key_algos  TEXT    NOT NULL DEFAULT '[]',
	min_ttl_seconds    INTEGER NOT NULL DEFAULT 0,
	max_ttl_seconds    INTEGER NOT NULL DEFAULT 0,
	require_san        INTEGER NOT NULL DEFAULT 0,
	allow_wildcard     INTEGER NOT NULL DEFAULT 0,
	created_at         DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS csr_approval_rules (
	id                 TEXT    NOT NULL PRIMARY KEY,
	provisioner_id     TEXT    NOT NULL,
	name               TEXT    NOT NULL,
	allowed_common_names TEXT NOT NULL DEFAULT '[]',
	allowed_dns        TEXT    NOT NULL DEFAULT '[]',
	max_ttl_seconds    INTEGER NOT NULL DEFAULT 0,
	enabled            INTEGER NOT NULL DEFAULT 1,
	created_at         DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_csr_approval_prov ON csr_approval_rules(provisioner_id);

CREATE TABLE IF NOT EXISTS provisioners (
	id         TEXT NOT NULL PRIMARY KEY,
	ca_id      TEXT NOT NULL REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
	name       TEXT NOT NULL,
	type       TEXT NOT NULL CHECK(type IN ('acme','apikey','mtls')),
	config     TEXT NOT NULL DEFAULT '{}',
	policy_id  TEXT REFERENCES policies(id) ON DELETE SET NULL,
	status     TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS setup_state (
    id         INTEGER PRIMARY KEY CHECK(id = 1),
    state      TEXT    NOT NULL DEFAULT 'uninitialized',
    updated_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS ssh_krl_cache (
	id          TEXT    NOT NULL PRIMARY KEY,
	ca_id       TEXT    NOT NULL UNIQUE REFERENCES ssh_certificate_authorities(id) ON DELETE CASCADE,
	krl_data    BLOB    NOT NULL,
	krl_version INTEGER NOT NULL,
	this_update DATETIME NOT NULL,
	next_update DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
	id             TEXT    NOT NULL PRIMARY KEY,
	ca_id          TEXT    NOT NULL REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
	serial         TEXT    NOT NULL UNIQUE,
	subject_cn     TEXT    NOT NULL,
	sans           TEXT    NOT NULL DEFAULT '{}',
	key_usage      TEXT    NOT NULL DEFAULT '[]',
	cert_pem       TEXT    NOT NULL,
	status         TEXT    NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired')),
	revoked_at     DATETIME,
	revoke_reason  INTEGER,
	not_before     DATETIME NOT NULL,
	not_after      DATETIME NOT NULL,
	issued_at      DATETIME NOT NULL,
	provisioner_id TEXT    NOT NULL REFERENCES provisioners(id) ON DELETE RESTRICT,
	requester      TEXT    NOT NULL DEFAULT '',
	metadata       TEXT    NOT NULL DEFAULT '{}',
	key_encrypted  BLOB,
	key_pw_required INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_certs_ca_id    ON certificates(ca_id);
CREATE INDEX IF NOT EXISTS idx_certs_serial   ON certificates(serial);
CREATE INDEX IF NOT EXISTS idx_certs_status   ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certs_not_after ON certificates(not_after);

CREATE TABLE IF NOT EXISTS eab_credentials (
	id             TEXT    NOT NULL PRIMARY KEY,
	provisioner_id TEXT    NOT NULL REFERENCES provisioners(id) ON DELETE RESTRICT,
	hmac_key       BLOB    NOT NULL,
	key_id         TEXT    NOT NULL UNIQUE,
	used           INTEGER NOT NULL DEFAULT 0,
	used_at        DATETIME,
	created_at     DATETIME NOT NULL,
	expires_at     DATETIME
);

CREATE TABLE IF NOT EXISTS acme_accounts (
	id             TEXT NOT NULL PRIMARY KEY,
	provisioner_id TEXT NOT NULL REFERENCES provisioners(id) ON DELETE RESTRICT,
	key_id         TEXT NOT NULL UNIQUE,
	key_jwk        TEXT NOT NULL DEFAULT '{}',
	eab_id         TEXT REFERENCES eab_credentials(id) ON DELETE SET NULL,
	status         TEXT NOT NULL DEFAULT 'valid' CHECK(status IN ('valid','deactivated','revoked')),
	contact        TEXT NOT NULL DEFAULT '[]',
	created_at     DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_orders (
	id             TEXT NOT NULL PRIMARY KEY,
	account_id     TEXT NOT NULL REFERENCES acme_accounts(id) ON DELETE RESTRICT,
	status         TEXT NOT NULL DEFAULT 'pending'
	                   CHECK(status IN ('pending','ready','processing','valid','invalid')),
	identifiers    TEXT NOT NULL DEFAULT '[]',
	certificate_id TEXT REFERENCES certificates(id) ON DELETE SET NULL,
	expires_at     DATETIME NOT NULL,
	created_at     DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_account_id ON acme_orders(account_id);

CREATE TABLE IF NOT EXISTS acme_challenges (
	id           TEXT NOT NULL PRIMARY KEY,
	order_id     TEXT REFERENCES acme_orders(id) ON DELETE CASCADE,
	type         TEXT NOT NULL CHECK(type IN ('http-01','dns-01','tls-alpn-01')),
	token        TEXT NOT NULL,
	status       TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','valid','invalid')),
	validated_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_challenges_order_id ON acme_challenges(order_id);

CREATE TABLE IF NOT EXISTS audit_log (
	id         TEXT    NOT NULL PRIMARY KEY,
	event_type TEXT    NOT NULL,
	actor      TEXT    NOT NULL,
	ca_id      TEXT    REFERENCES certificate_authorities(id) ON DELETE SET NULL,
	cert_id    TEXT    REFERENCES certificates(id) ON DELETE SET NULL,
	payload    TEXT    NOT NULL DEFAULT '{}',
	ip_address TEXT    NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL,
	prev_hash  TEXT    NOT NULL DEFAULT '',
	entry_hash TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ca_id      ON audit_log(ca_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at);

-- audit_chain_state is a singleton row tracking the tail hash of the audit
-- log's tamper-evident chain (see internal/audit), so WriteAuditLog can
-- extend it without re-scanning the whole table.
CREATE TABLE IF NOT EXISTS audit_chain_state (
	id        INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
	last_hash TEXT    NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO audit_chain_state (id, last_hash) VALUES (1, '');

CREATE TABLE IF NOT EXISTS crl_cache (
	id          TEXT    NOT NULL PRIMARY KEY,
	ca_id       TEXT    NOT NULL UNIQUE REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	crl_pem     TEXT    NOT NULL,
	this_update DATETIME NOT NULL,
	next_update DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS crl_delta_cache (
	id              TEXT    NOT NULL PRIMARY KEY,
	ca_id           TEXT    NOT NULL UNIQUE REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	crl_pem         TEXT    NOT NULL,
	crl_number      INTEGER NOT NULL,
	base_crl_number INTEGER NOT NULL,
	this_update     DATETIME NOT NULL,
	next_update     DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS crl_number_counters (
	ca_id       TEXT    NOT NULL PRIMARY KEY,
	next_number INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS api_keys (
	id         TEXT    NOT NULL PRIMARY KEY,
	name       TEXT    NOT NULL,
	key_hash   TEXT    NOT NULL UNIQUE,
	scopes     TEXT    NOT NULL DEFAULT '[]',
	ca_id      TEXT    REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	tenant_id  TEXT    REFERENCES tenants(id) ON DELETE SET NULL,
	expires_at DATETIME,
	last_used  DATETIME,
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_certificate_authorities (
	id            TEXT    NOT NULL PRIMARY KEY,
	name          TEXT    NOT NULL UNIQUE,
	key_algo      TEXT    NOT NULL,
	public_key    TEXT    NOT NULL,
	key_enc       BLOB    NOT NULL,
	status        TEXT    NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired','superseded')),
	logical_ca_id TEXT,
	parent_id     TEXT,
	created_at    DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_authorizations (
    id               TEXT    NOT NULL PRIMARY KEY,
    order_id         TEXT    REFERENCES acme_orders(id) ON DELETE CASCADE,
    account_id       TEXT    REFERENCES acme_accounts(id) ON DELETE CASCADE,
    identifier_type  TEXT    NOT NULL CHECK(identifier_type IN ('dns')),
    identifier_value TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','valid','invalid')),
    expires_at       DATETIME NOT NULL,
    created_at       DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_authz_account_identifier
    ON acme_authorizations(account_id, identifier_type, identifier_value);
CREATE TABLE IF NOT EXISTS ssh_certificates (
	id             TEXT    NOT NULL PRIMARY KEY,
	ca_id          TEXT    NOT NULL REFERENCES ssh_certificate_authorities(id) ON DELETE RESTRICT,
	serial         INTEGER NOT NULL,
	cert_type      TEXT    NOT NULL CHECK(cert_type IN ('user','host')),
	key_id         TEXT    NOT NULL DEFAULT '',
	principals     TEXT    NOT NULL DEFAULT '[]',
	public_key     TEXT    NOT NULL,
	cert_data      TEXT    NOT NULL,
	valid_after    DATETIME NOT NULL,
	valid_before   DATETIME NOT NULL,
	status         TEXT    NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired')),
	revoked_at     DATETIME,
	provisioner_id TEXT    NOT NULL REFERENCES provisioners(id) ON DELETE RESTRICT,
	requester      TEXT    NOT NULL DEFAULT '',
	created_at     DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limit_configs (
    name           TEXT NOT NULL PRIMARY KEY,
    scope          TEXT NOT NULL,
    algorithm      TEXT NOT NULL DEFAULT 'fixed_window',
    window_seconds INTEGER NOT NULL,
    max_requests   INTEGER NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    updated_at     DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_retired_keys (
    key_id     TEXT NOT NULL PRIMARY KEY,
    retired_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limit_counters (
    limiter_name TEXT NOT NULL,
    bucket_key   TEXT NOT NULL,
    window_start DATETIME NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (limiter_name, bucket_key, window_start)
);
CREATE INDEX IF NOT EXISTS idx_rl_counters_window_start ON rate_limit_counters(window_start);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_certs_ca_serial ON ssh_certificates(ca_id, serial);

`

func marshalJSON(v interface{}) (string, error) {
	if v == nil {
		return "{}", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func marshalStringSlice(v []string) (string, error) {
	if v == nil {
		return "[]", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalJSON(s string, dst interface{}) error {
	if s == "" || s == "null" {
		return nil
	}
	return json.Unmarshal([]byte(s), dst)
}

func unmarshalStringSlice(s string) ([]string, error) {
	if s == "" || s == "null" || s == "[]" {
		return []string{}, nil
	}
	var out []string
	err := json.Unmarshal([]byte(s), &out)
	return out, err
}

// uuidToSQL converts a UUID pointer to a value SQLite can store (string or nil).
func uuidToSQL(id *uuid.UUID) interface{} {
	if id == nil {
		return nil
	}
	return id.String()
}

// sqlToUUID parses a nullable string column back to a *uuid.UUID.
func sqlToUUID(s *string) *uuid.UUID {
	if s == nil {
		return nil
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		return nil
	}
	return &id
}

// uuidNullable converts a UUID to a nullable SQL value, treating uuid.Nil as NULL.
func uuidNullable(id uuid.UUID) interface{} {
	if id == uuid.Nil {
		return nil
	}
	return id.String()
}

// sqlToUUIDValue parses a nullable string column back to a uuid.UUID,
// returning uuid.Nil for NULL or invalid values.
func sqlToUUIDValue(s *string) uuid.UUID {
	if s == nil {
		return uuid.Nil
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// marshalNameConstraints returns the JSON-encoded NameConstraints, or a
// SQL NULL-equivalent empty string when nc is nil.
func marshalNameConstraints(nc *NameConstraints) (interface{}, error) {
	if nc == nil {
		return nil, nil
	}
	b, err := json.Marshal(nc)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func unmarshalNameConstraints(s *string) (*NameConstraints, error) {
	if s == nil || *s == "" || *s == "null" {
		return nil, nil
	}
	var nc NameConstraints
	if err := json.Unmarshal([]byte(*s), &nc); err != nil {
		return nil, err
	}
	return &nc, nil
}
func (s *sqliteStore) CreateCA(ctx context.Context, ca *CertificateAuthority) error {
	ncStr, err := marshalNameConstraints(ca.NameConstraints)
	if err != nil {
		return fmt.Errorf("sqlite: CreateCA: marshal name_constraints: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO certificate_authorities
			(id, logical_ca_id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
			 name_constraints, tenant_id, not_before, not_after, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ca.ID.String(),
		uuidToSQL(ca.LogicalCAID),
		uuidToSQL(ca.ParentID),
		ca.Name,
		string(ca.Type),
		string(ca.Status),
		ca.CertPEM,
		ca.KeyEnc,
		ca.KeyAlgo,
		ncStr,
		uuidNullable(ca.TenantID),
		ca.NotBefore.UTC(),
		ca.NotAfter.UTC(),
		ca.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateCA: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetCA(ctx context.Context, id uuid.UUID) (*CertificateAuthority, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, logical_ca_id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
		       name_constraints, tenant_id, not_before, not_after, created_at
		FROM certificate_authorities WHERE id = ?`, id.String())
	ca, err := scanCA(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetCA: %w", err)
	}
	return ca, nil
}

func (s *sqliteStore) GetCAByName(ctx context.Context, name string) (*CertificateAuthority, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, logical_ca_id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
		       name_constraints, tenant_id, not_before, not_after, created_at
		FROM certificate_authorities WHERE name = ?`, name)
	ca, err := scanCA(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetCAByName: %w", err)
	}
	return ca, nil
}

func (s *sqliteStore) ListCAs(ctx context.Context) ([]*CertificateAuthority, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, logical_ca_id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
		       name_constraints, tenant_id, not_before, not_after, created_at
		FROM certificate_authorities ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListCAs: %w", err)
	}
	defer rows.Close()
	return scanCAs(rows)
}

func (s *sqliteStore) ListChildCAs(ctx context.Context, parentID uuid.UUID) ([]*CertificateAuthority, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, logical_ca_id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
		       name_constraints, tenant_id, not_before, not_after, created_at
		FROM certificate_authorities WHERE parent_id = ? ORDER BY created_at ASC`,
		parentID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListChildCAs: %w", err)
	}
	defer rows.Close()
	return scanCAs(rows)
}

func (s *sqliteStore) UpdateCAStatus(ctx context.Context, id uuid.UUID, status CAStatus) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE certificate_authorities SET status = ? WHERE id = ?`,
		string(status), id.String())
	if err != nil {
		return fmt.Errorf("sqlite: UpdateCAStatus: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: UpdateCAStatus: CA %s not found", id)
	}
	return nil
}

func (s *sqliteStore) CreateCrossCert(ctx context.Context, cc *CrossCert) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ca_cross_certs
			(id, target_ca_id, signing_ca_id, cert_pem, serial, not_before, not_after, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(target_ca_id, signing_ca_id) DO UPDATE SET
			cert_pem = excluded.cert_pem,
			serial = excluded.serial,
			not_before = excluded.not_before,
			not_after = excluded.not_after,
			created_at = excluded.created_at`,
		cc.ID.String(), cc.TargetCAID.String(), cc.SigningCAID.String(), cc.CertPEM, cc.Serial,
		cc.NotBefore.UTC(), cc.NotAfter.UTC(), cc.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("sqlite: CreateCrossCert: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetCrossCert(ctx context.Context, targetCAID, signingCAID uuid.UUID) (*CrossCert, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, target_ca_id, signing_ca_id, cert_pem, serial, not_before, not_after, created_at
		FROM ca_cross_certs WHERE target_ca_id = ? AND signing_ca_id = ?`,
		targetCAID.String(), signingCAID.String())
	return scanCrossCert(row)
}

func (s *sqliteStore) ListCrossCertsByTarget(ctx context.Context, targetCAID uuid.UUID) ([]*CrossCert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_ca_id, signing_ca_id, cert_pem, serial, not_before, not_after, created_at
		FROM ca_cross_certs WHERE target_ca_id = ? ORDER BY created_at ASC`, targetCAID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListCrossCertsByTarget: %w", err)
	}
	defer rows.Close()
	var out []*CrossCert
	for rows.Next() {
		cc, err := scanCrossCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cc)
	}
	return out, rows.Err()
}

type crossCertScanner interface {
	Scan(dest ...interface{}) error
}

func scanCrossCert(row crossCertScanner) (*CrossCert, error) {
	var cc CrossCert
	var idStr, targetStr, signStr string
	err := row.Scan(&idStr, &targetStr, &signStr, &cc.CertPEM, &cc.Serial, &cc.NotBefore, &cc.NotAfter, &cc.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: scanCrossCert: %w", err)
	}
	cc.ID = uuid.MustParse(idStr)
	cc.TargetCAID = uuid.MustParse(targetStr)
	cc.SigningCAID = uuid.MustParse(signStr)
	return &cc, nil
}

func scanCA(row *sql.Row) (*CertificateAuthority, error) {
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
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ca.ID = uuid.MustParse(idStr)
	ca.TenantID = sqlToUUIDValue(tenantIDStr)
	ca.LogicalCAID = sqlToUUID(logicalCAIDStr)
	ca.ParentID = sqlToUUID(parentIDStr)
	ca.NameConstraints, err = unmarshalNameConstraints(ncStr)
	if err != nil {
		return nil, fmt.Errorf("scanCA: unmarshal name_constraints: %w", err)
	}
	return &ca, nil
}

func scanCAs(rows *sql.Rows) ([]*CertificateAuthority, error) {
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
		ca.TenantID = sqlToUUIDValue(tenantIDStr)
		ca.LogicalCAID = sqlToUUID(logicalCAIDStr)
		ca.ParentID = sqlToUUID(parentIDStr)
		nc, err := unmarshalNameConstraints(ncStr)
		if err != nil {
			return nil, fmt.Errorf("scanCAs: unmarshal name_constraints: %w", err)
		}
		ca.NameConstraints = nc
		out = append(out, &ca)
	}
	return out, rows.Err()
}

// ListChallengesByAuthorization returns all challenges belonging to a given authorization.
func (s *postgresStore) ListChallengesByAuthorization(ctx context.Context, authID uuid.UUID) ([]*ACMEChallenge, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, order_id, authorization_id, type, token, status, validated_at
        FROM acme_challenges WHERE authorization_id = $1`, authID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListChallengesByAuthorization: %w", err)
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
		c.AuthorizationID = pgSQLToUUID(authIDStr)
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (s *sqliteStore) CreateCertificate(ctx context.Context, cert *Certificate) error {
	sans, err := marshalJSON(cert.SANs)
	if err != nil {
		return fmt.Errorf("sqlite: CreateCertificate: marshal sans: %w", err)
	}
	ku, err := marshalStringSlice(cert.KeyUsage)
	if err != nil {
		return fmt.Errorf("sqlite: CreateCertificate: marshal key_usage: %w", err)
	}
	meta, err := marshalJSON(cert.Metadata)
	if err != nil {
		return fmt.Errorf("sqlite: CreateCertificate: marshal metadata: %w", err)
	}
	pwReq := 0
	if cert.KeyPasscodeRequired {
		pwReq = 1
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO certificates
			(id, ca_id, serial, subject_cn, sans, key_usage, cert_pem, status,
			 not_before, not_after, issued_at, provisioner_id, requester, metadata,
			 key_encrypted, key_pw_required)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cert.ID.String(),
		cert.CAID.String(),
		cert.Serial,
		cert.SubjectCN,
		sans,
		ku,
		cert.CertPEM,
		string(cert.Status),
		cert.NotBefore.UTC(),
		cert.NotAfter.UTC(),
		cert.IssuedAt.UTC(),
		cert.ProvisionerID.String(),
		cert.Requester,
		meta,
		cert.KeyEncrypted,
		pwReq,
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateCertificate: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetCertificate(ctx context.Context, id uuid.UUID) (*Certificate, error) {
	row := s.db.QueryRowContext(ctx, certSelectSQL+" WHERE c.id = ?", id.String())
	cert, err := scanCert(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetCertificate: %w", err)
	}
	return cert, nil
}

func (s *sqliteStore) GetCertificateBySerial(ctx context.Context, serial string) (*Certificate, error) {
	row := s.db.QueryRowContext(ctx, certSelectSQL+" WHERE c.serial = ?", serial)
	cert, err := scanCert(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetCertificateBySerial: %w", err)
	}
	return cert, nil
}

func (s *sqliteStore) ListCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		certSelectSQL+" WHERE c.ca_id = ? ORDER BY c.issued_at DESC",
		caID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListCertificatesByCA: %w", err)
	}
	defer rows.Close()
	return scanCerts(rows)
}

// ListAllCertificates returns every certificate across all CAs, newest first.
func (s *sqliteStore) ListAllCertificates(ctx context.Context, limit, offset int) ([]*Certificate, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx,
		certSelectSQL+" ORDER BY c.issued_at DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListAllCertificates: %w", err)
	}
	defer rows.Close()
	return scanCerts(rows)
}

func (s *sqliteStore) ListRevokedByCA(ctx context.Context, caID uuid.UUID) ([]*Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		certSelectSQL+" WHERE c.ca_id = ? AND c.status = 'revoked' ORDER BY c.revoked_at DESC",
		caID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListRevokedByCA: %w", err)
	}
	defer rows.Close()
	return scanCerts(rows)
}

func (s *sqliteStore) RevokeCertificate(ctx context.Context, id uuid.UUID, reason int) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE certificates
		SET status = 'revoked', revoked_at = ?, revoke_reason = ?
		WHERE id = ? AND status = 'active'`,
		now, reason, id.String())
	if err != nil {
		return fmt.Errorf("sqlite: RevokeCertificate: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: RevokeCertificate: certificate %s not found or already revoked", id)
	}
	return nil
}

const certSelectSQL = `
	SELECT c.id, c.ca_id, c.serial, c.subject_cn, c.sans, c.key_usage, c.cert_pem,
	       c.status, c.revoked_at, c.revoke_reason,
	       c.not_before, c.not_after, c.issued_at,
	       c.provisioner_id, c.requester, c.metadata,
	       c.key_encrypted, c.key_pw_required
	FROM certificates c`

func scanCert(row *sql.Row) (*Certificate, error) {
	var c Certificate
	var idStr, caIDStr, provIDStr string
	var sansStr, kuStr, metaStr string
	var pwReq int
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
	c.KeyPasscodeRequired = pwReq == 1
	_ = unmarshalJSON(sansStr, &c.SANs)
	c.KeyUsage, _ = unmarshalStringSlice(kuStr)
	_ = unmarshalJSON(metaStr, &c.Metadata)
	return &c, nil
}

func scanCerts(rows *sql.Rows) ([]*Certificate, error) {
	var out []*Certificate
	for rows.Next() {
		var c Certificate
		var idStr, caIDStr, provIDStr string
		var sansStr, kuStr, metaStr string
		var pwReq int
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
		c.KeyPasscodeRequired = pwReq == 1
		_ = unmarshalJSON(sansStr, &c.SANs)
		c.KeyUsage, _ = unmarshalStringSlice(kuStr)
		_ = unmarshalJSON(metaStr, &c.Metadata)
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (s *sqliteStore) CreateProvisioner(ctx context.Context, p *Provisioner) error {
	cfg, err := marshalJSON(p.Config)
	if err != nil {
		return fmt.Errorf("sqlite: CreateProvisioner: marshal config: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO provisioners (id, ca_id, name, type, config, policy_id, tenant_id, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID.String(),
		p.CAID.String(),
		p.Name,
		string(p.Type),
		cfg,
		uuidToSQL(p.PolicyID),
		uuidNullable(p.TenantID),
		string(p.Status),
		p.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateProvisioner: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*Provisioner, error) {
	row := s.db.QueryRowContext(ctx, provisionerSelectSQL+" WHERE id = ?", id.String())
	p, err := scanProvisioner(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetProvisioner: %w", err)
	}
	return p, nil
}

func (s *sqliteStore) ListProvisionersByCA(ctx context.Context, caID uuid.UUID) ([]*Provisioner, error) {
	rows, err := s.db.QueryContext(ctx,
		provisionerSelectSQL+" WHERE ca_id = ? ORDER BY created_at ASC",
		caID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListProvisionersByCA: %w", err)
	}
	defer rows.Close()
	var out []*Provisioner
	for rows.Next() {
		p, err := scanProvisionerRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateProvisionerStatus(ctx context.Context, id uuid.UUID, status ProvisionerStatus) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE provisioners SET status = ? WHERE id = ?`,
		string(status), id.String())
	if err != nil {
		return fmt.Errorf("sqlite: UpdateProvisionerStatus: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: UpdateProvisionerStatus: provisioner %s not found", id)
	}
	return nil
}

const provisionerSelectSQL = `
	SELECT id, ca_id, name, type, config, policy_id, tenant_id, status, created_at
	FROM provisioners`

func scanProvisioner(row *sql.Row) (*Provisioner, error) {
	var p Provisioner
	var idStr, caIDStr, cfgStr string
	var policyIDStr, tenantIDStr *string
	err := row.Scan(&idStr, &caIDStr, &p.Name, &p.Type, &cfgStr, &policyIDStr, &tenantIDStr, &p.Status, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.CAID = uuid.MustParse(caIDStr)
	p.PolicyID = sqlToUUID(policyIDStr)
	p.TenantID = sqlToUUIDValue(tenantIDStr)
	_ = unmarshalJSON(cfgStr, &p.Config)
	return &p, nil
}

func scanProvisionerRows(rows *sql.Rows) (*Provisioner, error) {
	var p Provisioner
	var idStr, caIDStr, cfgStr string
	var policyIDStr, tenantIDStr *string
	if err := rows.Scan(&idStr, &caIDStr, &p.Name, &p.Type, &cfgStr, &policyIDStr, &tenantIDStr, &p.Status, &p.CreatedAt); err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.CAID = uuid.MustParse(caIDStr)
	p.PolicyID = sqlToUUID(policyIDStr)
	p.TenantID = sqlToUUIDValue(tenantIDStr)
	_ = unmarshalJSON(cfgStr, &p.Config)
	return &p, nil
}

func (s *sqliteStore) CreatePolicy(ctx context.Context, p *Policy) error {
	ad, _ := marshalStringSlice(p.AllowedDomains)
	dd, _ := marshalStringSlice(p.DeniedDomains)
	ai, _ := marshalStringSlice(p.AllowedIPs)
	as_, _ := marshalStringSlice(p.AllowedSANs)
	ka, _ := marshalStringSlice(p.KeyAlgos)
	po, _ := marshalStringSlice(p.PolicyOIDs)
	requireSAN := 0
	if p.RequireSAN {
		requireSAN = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policies
			(id, name, scope, max_ttl_seconds, allowed_domains, denied_domains,
			 allowed_ips, allowed_sans, require_san, key_algos, policy_oids, cps_uri, ssh_policy, tenant_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID.String(), p.Name, string(p.Scope), p.MaxTTL,
		ad, dd, ai, as_, requireSAN, ka, po, p.CPSURI, string(p.SSHPolicy), uuidNullable(p.TenantID), p.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreatePolicy: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetPolicy(ctx context.Context, id uuid.UUID) (*Policy, error) {
	row := s.db.QueryRowContext(ctx, policySelectSQL+" WHERE id = ?", id.String())
	p, err := scanPolicy(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetPolicy: %w", err)
	}
	return p, nil
}

func (s *sqliteStore) ListPolicies(ctx context.Context) ([]*Policy, error) {
	rows, err := s.db.QueryContext(ctx, policySelectSQL+" ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListPolicies: %w", err)
	}
	defer rows.Close()
	var out []*Policy
	for rows.Next() {
		p, err := scanPolicyRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdatePolicy(ctx context.Context, p *Policy) error {
	ad, _ := marshalStringSlice(p.AllowedDomains)
	dd, _ := marshalStringSlice(p.DeniedDomains)
	ai, _ := marshalStringSlice(p.AllowedIPs)
	as_, _ := marshalStringSlice(p.AllowedSANs)
	ka, _ := marshalStringSlice(p.KeyAlgos)
	po, _ := marshalStringSlice(p.PolicyOIDs)
	requireSAN := 0
	if p.RequireSAN {
		requireSAN = 1
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE policies SET
			name = ?, scope = ?, max_ttl_seconds = ?,
			allowed_domains = ?, denied_domains = ?,
			allowed_ips = ?, allowed_sans = ?,
			require_san = ?, key_algos = ?, policy_oids = ?, cps_uri = ?, ssh_policy = ?
		WHERE id = ?`,
		p.Name, string(p.Scope), p.MaxTTL,
		ad, dd, ai, as_, requireSAN, ka, po, p.CPSURI, string(p.SSHPolicy),
		p.ID.String(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: UpdatePolicy: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: UpdatePolicy: policy %s not found", p.ID)
	}
	return nil
}

const policySelectSQL = `
	SELECT id, name, scope, max_ttl_seconds,
	       allowed_domains, denied_domains, allowed_ips, allowed_sans,
	       require_san, key_algos, policy_oids, cps_uri, ssh_policy, tenant_id, created_at
	FROM policies`

func scanPolicy(row *sql.Row) (*Policy, error) {
	return scanPolicyFields(func(dest ...interface{}) error { return row.Scan(dest...) })
}

func scanPolicyFields(scan func(...interface{}) error) (*Policy, error) {
	var p Policy
	var idStr, adStr, ddStr, aiStr, asStr, kaStr, poStr, sshStr string
	var tenantIDStr *string
	var requireSAN int
	err := scan(
		&idStr, &p.Name, &p.Scope, &p.MaxTTL,
		&adStr, &ddStr, &aiStr, &asStr, &requireSAN, &kaStr, &poStr, &p.CPSURI, &sshStr, &tenantIDStr, &p.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.TenantID = sqlToUUIDValue(tenantIDStr)
	p.RequireSAN = requireSAN == 1
	p.AllowedDomains, _ = unmarshalStringSlice(adStr)
	p.DeniedDomains, _ = unmarshalStringSlice(ddStr)
	p.AllowedIPs, _ = unmarshalStringSlice(aiStr)
	p.AllowedSANs, _ = unmarshalStringSlice(asStr)
	p.KeyAlgos, _ = unmarshalStringSlice(kaStr)
	p.PolicyOIDs, _ = unmarshalStringSlice(poStr)
	if sshStr != "" {
		p.SSHPolicy = []byte(sshStr)
	}
	return &p, nil
}

func scanPolicyRows(rows *sql.Rows) (*Policy, error) {
	return scanPolicyFields(rows.Scan)
}

func (s *sqliteStore) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id = ?`, id.String())
	if err != nil {
		return fmt.Errorf("sqlite: DeletePolicy: %w", err)
	}
	return nil
}

// ---- certificate profiles ----

func writeProfileArgs(p *Profile) []interface{} {
	aka, _ := marshalStringSlice(p.AllowedKeyAlgos)
	rs, aw := 0, 0
	if p.RequireSAN {
		rs = 1
	}
	if p.AllowWildcard {
		aw = 1
	}
	return []interface{}{
		p.ID.String(), p.Name, aka, p.MinTTLSeconds, p.MaxTTLSeconds,
		rs, aw, p.CreatedAt.UTC(),
	}
}

func (s *sqliteStore) CreateProfile(ctx context.Context, p *Profile) error {
	args := writeProfileArgs(p)
	args = append(args, uuidNullable(p.TenantID), p.CreatedAt.UTC())
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO profiles
			(id, name, allowed_key_algos, min_ttl_seconds, max_ttl_seconds,
			 require_san, allow_wildcard, tenant_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...)
	if err != nil {
		return fmt.Errorf("sqlite: CreateProfile: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetProfile(ctx context.Context, id uuid.UUID) (*Profile, error) {
	row := s.db.QueryRowContext(ctx, profileSelectSQL+" WHERE id = ?", id.String())
	return scanProfileRow(row)
}

func (s *sqliteStore) GetProfileByName(ctx context.Context, name string) (*Profile, error) {
	row := s.db.QueryRowContext(ctx, profileSelectSQL+" WHERE name = ?", name)
	return scanProfileRow(row)
}

func (s *sqliteStore) ListProfiles(ctx context.Context) ([]*Profile, error) {
	rows, err := s.db.QueryContext(ctx, profileSelectSQL+" ORDER BY name ASC")
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListProfiles: %w", err)
	}
	defer rows.Close()
	var out []*Profile
	for rows.Next() {
		p, err := scanProfileRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateProfile(ctx context.Context, p *Profile) error {
	args := writeProfileArgs(p)
	res, err := s.db.ExecContext(ctx, `
		UPDATE profiles SET
			name = ?, allowed_key_algos = ?, min_ttl_seconds = ?,
			max_ttl_seconds = ?, require_san = ?, allow_wildcard = ?
		WHERE id = ?`, args[1], args[2], args[3], args[4], args[5], args[6], args[0])
	if err != nil {
		return fmt.Errorf("sqlite: UpdateProfile: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: UpdateProfile: profile %s not found", p.ID)
	}
	return nil
}

func (s *sqliteStore) DeleteProfile(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM profiles WHERE id = ?`, id.String())
	if err != nil {
		return fmt.Errorf("sqlite: DeleteProfile: %w", err)
	}
	return nil
}

// ---- CSR auto-approval rules ----

func sqliteCSRArgs(r *CSRAutoApproveRule) []interface{} {
	en := 0
	if r.Enabled {
		en = 1
	}
	return []interface{}{
		r.ID.String(), r.ProvisionerID.String(), r.Name,
		marshalStringSliceOr(r.AllowedCommonNames), marshalStringSliceOr(r.AllowedDNS),
		r.MaxTTLSeconds, en, r.CreatedAt.UTC(),
	}
}

func (s *sqliteStore) CreateCSRAutoApproveRule(ctx context.Context, r *CSRAutoApproveRule) error {
	args := sqliteCSRArgs(r)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO csr_approval_rules
			(id, provisioner_id, name, allowed_common_names, allowed_dns, max_ttl_seconds, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, args...)
	if err != nil {
		return fmt.Errorf("sqlite: CreateCSRAutoApproveRule: %w", err)
	}
	return nil
}

func (s *sqliteStore) ListCSRAutoApproveRules(ctx context.Context, provisionerID uuid.UUID) ([]*CSRAutoApproveRule, error) {
	q := csrApprovalSelectSQL
	var args []interface{}
	if provisionerID != uuid.Nil {
		q += " WHERE provisioner_id = ?"
		args = append(args, provisionerID.String())
	}
	q += " ORDER BY created_at ASC"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListCSRAutoApproveRules: %w", err)
	}
	defer rows.Close()
	var out []*CSRAutoApproveRule
	for rows.Next() {
		r, err := s.sqliteScanCSRApproval(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateCSRAutoApproveRule(ctx context.Context, r *CSRAutoApproveRule) error {
	args := sqliteCSRArgs(r)
	res, err := s.db.ExecContext(ctx, `
		UPDATE csr_approval_rules SET
			provisioner_id = ?, name = ?, allowed_common_names = ?, allowed_dns = ?,
			max_ttl_seconds = ?, enabled = ?
		WHERE id = ?`, args[1], args[2], args[3], args[4], args[5], args[6], args[0])
	if err != nil {
		return fmt.Errorf("sqlite: UpdateCSRAutoApproveRule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: UpdateCSRAutoApproveRule: rule %s not found", r.ID)
	}
	return nil
}

func (s *sqliteStore) DeleteCSRAutoApproveRule(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM csr_approval_rules WHERE id = ?`, id.String())
	if err != nil {
		return fmt.Errorf("sqlite: DeleteCSRAutoApproveRule: %w", err)
	}
	return nil
}

func (s *sqliteStore) sqliteScanCSRApproval(scan func(...interface{}) error) (*CSRAutoApproveRule, error) {
	return scanCSRApproval(scan)
}

const profileSelectSQL = `
	SELECT id, name, allowed_key_algos, min_ttl_seconds, max_ttl_seconds,
	       require_san, allow_wildcard, tenant_id, created_at
	FROM profiles`

func scanProfileRow(row *sql.Row) (*Profile, error) {
	p, err := scanProfileFields(func(dest ...interface{}) error { return row.Scan(dest...) })
	if err != nil {
		return nil, err
	}
	return p, nil
}

func scanProfileRows(rows *sql.Rows) (*Profile, error) {
	return scanProfileFields(rows.Scan)
}

func scanProfileFields(scan func(...interface{}) error) (*Profile, error) {
	var p Profile
	var idStr, akaStr string
	var tenantIDStr *string
	var rs, aw int
	err := scan(&idStr, &p.Name, &akaStr, &p.MinTTLSeconds, &p.MaxTTLSeconds, &rs, &aw, &tenantIDStr, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.TenantID = sqlToUUIDValue(tenantIDStr)
	p.AllowedKeyAlgos, _ = unmarshalStringSlice(akaStr)
	p.RequireSAN = rs == 1
	p.AllowWildcard = aw == 1
	return &p, nil
}

const csrApprovalSelectSQL = `
	SELECT id, provisioner_id, name, allowed_common_names, allowed_dns, max_ttl_seconds, enabled, created_at
	FROM csr_approval_rules`

func scanCSRApproval(scan func(...interface{}) error) (*CSRAutoApproveRule, error) {
	var r CSRAutoApproveRule
	var idStr, provStr, cnStr, dnsStr string
	var enabled int
	err := scan(&idStr, &provStr, &r.Name, &cnStr, &dnsStr, &r.MaxTTLSeconds, &enabled, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	r.ID = uuid.MustParse(idStr)
	r.ProvisionerID = uuid.MustParse(provStr)
	r.AllowedCommonNames, _ = unmarshalStringSlice(cnStr)
	r.AllowedDNS, _ = unmarshalStringSlice(dnsStr)
	r.Enabled = enabled == 1
	return &r, nil
}

func marshalStringSliceOr(s []string) interface{} {
	b, _ := marshalStringSlice(s)
	return b
}

func (s *sqliteStore) CreateACMEAccount(ctx context.Context, a *ACMEAccount) error {
	jwk, _ := marshalJSON(a.KeyJWK)
	contact, _ := marshalStringSlice(a.Contact)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO acme_accounts
			(id, provisioner_id, key_id, key_jwk, eab_id, status, contact, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID.String(), a.ProvisionerID.String(), a.KeyID,
		jwk, uuidToSQL(a.EABID), string(a.Status), contact, a.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateACMEAccount: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetACMEAccountByKeyID(ctx context.Context, keyID string) (*ACMEAccount, error) {
	row := s.db.QueryRowContext(ctx,
		acmeAccountSelectSQL+" WHERE key_id = ?", keyID)
	a, err := scanACMEAccount(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetACMEAccountByKeyID: %w", err)
	}
	return a, nil
}

func (s *sqliteStore) GetACMEAccount(ctx context.Context, id uuid.UUID) (*ACMEAccount, error) {
	row := s.db.QueryRowContext(ctx,
		acmeAccountSelectSQL+" WHERE id = ?", id.String())
	a, err := scanACMEAccount(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetACMEAccount: %w", err)
	}
	return a, nil
}

func (s *sqliteStore) UpdateACMEAccountStatus(ctx context.Context, id uuid.UUID, status ACMEAccountStatus) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_accounts SET status = ? WHERE id = ?`,
		string(status), id.String())
	if err != nil {
		return fmt.Errorf("sqlite: UpdateACMEAccountStatus: %w", err)
	}
	return nil
}

func (s *sqliteStore) UpdateACMEAccountContact(ctx context.Context, id uuid.UUID, contact []string) error {
	c, _ := marshalStringSlice(contact)
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_accounts SET contact = ? WHERE id = ?`, c, id.String())
	if err != nil {
		return fmt.Errorf("sqlite: UpdateACMEAccountContact: %w", err)
	}
	return nil
}

const acmeAccountSelectSQL = `
	SELECT id, provisioner_id, key_id, key_jwk, eab_id, status, contact, created_at
	FROM acme_accounts`

func scanACMEAccount(row *sql.Row) (*ACMEAccount, error) {
	var a ACMEAccount
	var idStr, provIDStr, jwkStr, contactStr string
	var eabIDStr *string
	err := row.Scan(
		&idStr, &provIDStr, &a.KeyID, &jwkStr,
		&eabIDStr, &a.Status, &contactStr, &a.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.ID = uuid.MustParse(idStr)
	a.ProvisionerID = uuid.MustParse(provIDStr)
	a.EABID = sqlToUUID(eabIDStr)
	_ = unmarshalJSON(jwkStr, &a.KeyJWK)
	a.Contact, _ = unmarshalStringSlice(contactStr)
	return &a, nil
}

func (s *sqliteStore) CreateEABCredential(ctx context.Context, e *EABCredential) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO eab_credentials
			(id, provisioner_id, hmac_key, key_id, used, created_at, expires_at)
		VALUES (?, ?, ?, ?, 0, ?, ?)`,
		e.ID.String(), e.ProvisionerID.String(),
		e.HMACKey, e.KeyID, e.CreatedAt.UTC(), e.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateEABCredential: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetEABCredential(ctx context.Context, keyID string) (*EABCredential, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, provisioner_id, hmac_key, key_id, used, used_at, created_at, expires_at
		FROM eab_credentials WHERE key_id = ?`, keyID)
	var e EABCredential
	var idStr, provIDStr string
	var usedInt int
	err := row.Scan(
		&idStr, &provIDStr, &e.HMACKey, &e.KeyID,
		&usedInt, &e.UsedAt, &e.CreatedAt, &e.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetEABCredential: %w", err)
	}
	e.ID = uuid.MustParse(idStr)
	e.ProvisionerID = uuid.MustParse(provIDStr)
	e.Used = usedInt == 1
	return &e, nil
}

func (s *sqliteStore) MarkEABUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE eab_credentials SET used = 1, used_at = ? WHERE id = ?`,
		now, id.String())
	if err != nil {
		return fmt.Errorf("sqlite: MarkEABUsed: %w", err)
	}
	return nil
}

func (s *sqliteStore) CreateACMEOrder(ctx context.Context, o *ACMEOrder) error {
	ids, _ := marshalJSON(o.Identifiers)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO acme_orders
			(id, account_id, status, identifiers, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		o.ID.String(), o.AccountID.String(),
		string(o.Status), ids, o.ExpiresAt.UTC(), o.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateACMEOrder: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetACMEOrder(ctx context.Context, id uuid.UUID) (*ACMEOrder, error) {
	row := s.db.QueryRowContext(ctx, acmeOrderSelectSQL+" WHERE id = ?", id.String())
	o, err := scanACMEOrder(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetACMEOrder: %w", err)
	}
	return o, nil
}

func (s *sqliteStore) ListACMEOrdersByAccount(ctx context.Context, accountID uuid.UUID) ([]*ACMEOrder, error) {
	rows, err := s.db.QueryContext(ctx,
		acmeOrderSelectSQL+" WHERE account_id = ? ORDER BY created_at DESC",
		accountID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListACMEOrdersByAccount: %w", err)
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
		o.CertificateID = sqlToUUID(certIDStr)
		_ = unmarshalJSON(idsStr, &o.Identifiers)
		out = append(out, &o)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateACMEOrderStatus(ctx context.Context, id uuid.UUID, status ACMEOrderStatus) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_orders SET status = ? WHERE id = ?`,
		string(status), id.String())
	if err != nil {
		return fmt.Errorf("sqlite: UpdateACMEOrderStatus: %w", err)
	}
	return nil
}

func (s *sqliteStore) FinalizeACMEOrder(ctx context.Context, orderID uuid.UUID, certID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_orders SET status = 'valid', certificate_id = ? WHERE id = ?`,
		certID.String(), orderID.String())
	if err != nil {
		return fmt.Errorf("sqlite: FinalizeACMEOrder: %w", err)
	}
	return nil
}

const acmeOrderSelectSQL = `
	SELECT id, account_id, status, identifiers, certificate_id, expires_at, created_at
	FROM acme_orders`

func scanACMEOrder(row *sql.Row) (*ACMEOrder, error) {
	var o ACMEOrder
	var idStr, accIDStr, idsStr string
	var certIDStr *string
	err := row.Scan(
		&idStr, &accIDStr, &o.Status, &idsStr,
		&certIDStr, &o.ExpiresAt, &o.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	o.ID = uuid.MustParse(idStr)
	o.AccountID = uuid.MustParse(accIDStr)
	o.CertificateID = sqlToUUID(certIDStr)
	_ = unmarshalJSON(idsStr, &o.Identifiers)
	return &o, nil
}

func (s *sqliteStore) CreateACMEChallenge(ctx context.Context, c *ACMEChallenge) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO acme_challenges (id, order_id, authorization_id, type, token, status)
        VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID.String(), uuidNullable(c.OrderID), uuidToSQL(c.AuthorizationID),
		string(c.Type), c.Token, string(c.Status),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateACMEChallenge: %w", err)
	}
	return nil
}

func (s *sqliteStore) CreateACMEAuthorization(ctx context.Context, a *ACMEAuthorization) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO acme_authorizations
            (id, order_id, account_id, identifier_type, identifier_value, status, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID.String(), uuidNullable(a.OrderID), uuidNullable(a.AccountID),
		a.IdentifierType, a.IdentifierValue,
		string(a.Status), a.ExpiresAt.UTC(), a.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateACMEAuthorization: %w", err)
	}
	return nil
}

const sqliteACMEAuthorizationSelect = `
	SELECT id, order_id, account_id, identifier_type, identifier_value, status, expires_at, created_at
	FROM acme_authorizations`

func sqliteScanACMEAuthorization(row *sql.Row) (*ACMEAuthorization, error) {
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
	a.OrderID = sqlToUUIDValue(orderIDStr)
	a.AccountID = sqlToUUIDValue(accountIDStr)
	return &a, nil
}

func sqliteScanACMEAuthorizationRows(rows *sql.Rows) (*ACMEAuthorization, error) {
	var a ACMEAuthorization
	var idStr string
	var orderIDStr, accountIDStr *string
	if err := rows.Scan(&idStr, &orderIDStr, &accountIDStr, &a.IdentifierType, &a.IdentifierValue, &a.Status, &a.ExpiresAt, &a.CreatedAt); err != nil {
		return nil, err
	}
	a.ID = uuid.MustParse(idStr)
	a.OrderID = sqlToUUIDValue(orderIDStr)
	a.AccountID = sqlToUUIDValue(accountIDStr)
	return &a, nil
}

func (s *sqliteStore) GetACMEAuthorization(ctx context.Context, id uuid.UUID) (*ACMEAuthorization, error) {
	row := s.db.QueryRowContext(ctx, sqliteACMEAuthorizationSelect+" WHERE id = ?", id.String())
	a, err := sqliteScanACMEAuthorization(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetACMEAuthorization: %w", err)
	}
	return a, nil
}

func (s *sqliteStore) UpdateACMEAuthorizationStatus(ctx context.Context, id uuid.UUID, status ACMEAuthorizationStatus) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_authorizations SET status = ? WHERE id = ?`,
		string(status), id.String())
	if err != nil {
		return fmt.Errorf("sqlite: UpdateACMEAuthorizationStatus: %w", err)
	}
	return nil
}

func (s *sqliteStore) ListAuthorizationsByOrder(ctx context.Context, orderID uuid.UUID) ([]*ACMEAuthorization, error) {
	rows, err := s.db.QueryContext(ctx,
		sqliteACMEAuthorizationSelect+" WHERE order_id = ?", orderID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListAuthorizationsByOrder: %w", err)
	}
	defer rows.Close()
	var out []*ACMEAuthorization
	for rows.Next() {
		a, err := sqliteScanACMEAuthorizationRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetACMEAuthorizationByIdentifier returns the most recent standalone
// (order_id IS NULL) authorization for the given account + identifier.
func (s *sqliteStore) GetACMEAuthorizationByIdentifier(ctx context.Context, accountID uuid.UUID, identifierType, identifierValue string) (*ACMEAuthorization, error) {
	row := s.db.QueryRowContext(ctx,
		sqliteACMEAuthorizationSelect+`
		 WHERE order_id IS NULL AND account_id = ? AND identifier_type = ? AND identifier_value = ?
		 ORDER BY created_at DESC LIMIT 1`,
		accountID.String(), identifierType, identifierValue)
	a, err := sqliteScanACMEAuthorization(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetACMEAuthorizationByIdentifier: %w", err)
	}
	return a, nil
}

// ListAuthorizationsByAccount returns standalone pre-authorizations for an
// account, newest first.
func (s *sqliteStore) ListAuthorizationsByAccount(ctx context.Context, accountID uuid.UUID) ([]*ACMEAuthorization, error) {
	rows, err := s.db.QueryContext(ctx,
		sqliteACMEAuthorizationSelect+`
		 WHERE order_id IS NULL AND account_id = ?
		 ORDER BY created_at DESC`,
		accountID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListAuthorizationsByAccount: %w", err)
	}
	defer rows.Close()
	var out []*ACMEAuthorization
	for rows.Next() {
		a, err := sqliteScanACMEAuthorizationRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *sqliteStore) GetACMEChallenge(ctx context.Context, id uuid.UUID) (*ACMEChallenge, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, order_id, authorization_id, type, token, status, validated_at FROM acme_challenges WHERE id = ?`, id.String())
	c, err := scanChallenge(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetACMEChallenge: %w", err)
	}
	return c, nil
}

func scanChallenge(row *sql.Row) (*ACMEChallenge, error) {
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
	c.OrderID = sqlToUUIDValue(orderIDStr)
	c.AuthorizationID = sqlToUUID(authIDStr)
	return &c, nil
}

func scanChallengeRows(rows *sql.Rows) (*ACMEChallenge, error) {
	var c ACMEChallenge
	var idStr string
	var orderIDStr, authIDStr *string
	if err := rows.Scan(&idStr, &orderIDStr, &authIDStr, &c.Type, &c.Token, &c.Status, &c.ValidatedAt); err != nil {
		return nil, err
	}
	c.ID = uuid.MustParse(idStr)
	c.OrderID = sqlToUUIDValue(orderIDStr)
	c.AuthorizationID = sqlToUUID(authIDStr)
	return &c, nil
}

func (s *sqliteStore) ListChallengesByOrder(ctx context.Context, orderID uuid.UUID) ([]*ACMEChallenge, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, order_id, authorization_id, type, token, status, validated_at FROM acme_challenges WHERE order_id = ?`, orderID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListChallengesByOrder: %w", err)
	}
	defer rows.Close()
	var out []*ACMEChallenge
	for rows.Next() {
		c, err := scanChallengeRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *sqliteStore) UpdateChallengeStatus(ctx context.Context, id uuid.UUID, status ACMEChallengeStatus, validatedAt *time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_challenges SET status = ?, validated_at = ? WHERE id = ?`,
		string(status), validatedAt, id.String())
	if err != nil {
		return fmt.Errorf("sqlite: UpdateChallengeStatus: %w", err)
	}
	return nil
}

// WriteAuditLog appends an entry and extends the tamper-evident hash chain
// (see internal/audit). The single sqlite connection (MaxOpenConns(1)) means
// this transaction already serializes concurrent callers, so no explicit
// row lock is needed beyond BEGIN/COMMIT.
func (s *sqliteStore) WriteAuditLog(ctx context.Context, entry *AuditLog) error {
	payload, _ := marshalJSON(entry.Payload)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: WriteAuditLog: begin: %w", err)
	}
	defer tx.Rollback()

	var prevHash string
	if err := tx.QueryRowContext(ctx, `SELECT last_hash FROM audit_chain_state WHERE id = 1`).Scan(&prevHash); err != nil {
		return fmt.Errorf("sqlite: WriteAuditLog: read chain state: %w", err)
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID.String(), entry.EventType, entry.Actor,
		uuidToSQL(entry.CAID), uuidToSQL(entry.CertID),
		payload, entry.IPAddress, entry.CreatedAt.UTC(), prevHash, entryHash,
	); err != nil {
		return fmt.Errorf("sqlite: WriteAuditLog: insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE audit_chain_state SET last_hash = ? WHERE id = 1`, entryHash); err != nil {
		return fmt.Errorf("sqlite: WriteAuditLog: update chain state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: WriteAuditLog: commit: %w", err)
	}
	entry.PrevHash = prevHash
	entry.EntryHash = entryHash
	return nil
}

// ListAuditLogsChronological returns every audit log entry in insertion
// order (oldest first), for hash-chain verification. sqlite's implicit rowid
// reflects insertion order since WriteAuditLog serializes through the single
// connection.
func (s *sqliteStore) ListAuditLogsChronological(ctx context.Context) ([]*AuditLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at, prev_hash, entry_hash
		FROM audit_log ORDER BY rowid ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListAuditLogsChronological: %w", err)
	}
	defer rows.Close()
	return scanAuditLogs(rows)
}

func (s *sqliteStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]*AuditLog, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at, prev_hash, entry_hash
		 FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListAuditLogs: %w", err)
	}
	defer rows.Close()
	return scanAuditLogs(rows)
}

func (s *sqliteStore) ListAuditLogsByCA(ctx context.Context, caID uuid.UUID, limit, offset int) ([]*AuditLog, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at, prev_hash, entry_hash
		 FROM audit_log WHERE ca_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		caID.String(), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListAuditLogsByCA: %w", err)
	}
	defer rows.Close()
	return scanAuditLogs(rows)
}

func scanAuditLogs(rows *sql.Rows) ([]*AuditLog, error) {
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
		l.CAID = sqlToUUID(caIDStr)
		l.CertID = sqlToUUID(certIDStr)
		_ = unmarshalJSON(payloadStr, &l.Payload)
		out = append(out, &l)
	}
	return out, rows.Err()
}
func (s *sqliteStore) UpsertCRL(ctx context.Context, crl *CRLCache) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO crl_cache (id, ca_id, crl_pem, crl_number, this_update, next_update)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(ca_id) DO UPDATE SET
			crl_pem     = excluded.crl_pem,
			crl_number  = excluded.crl_number,
			this_update = excluded.this_update,
			next_update = excluded.next_update`,
		crl.ID.String(), crl.CAID.String(), crl.CRLPEM, crl.CRLNumber,
		crl.ThisUpdate.UTC(), crl.NextUpdate.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: UpsertCRL: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetCRL(ctx context.Context, caID uuid.UUID) (*CRLCache, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ca_id, crl_pem, crl_number, this_update, next_update
		FROM crl_cache WHERE ca_id = ?`, caID.String())
	var c CRLCache
	var idStr, caIDStr string
	err := row.Scan(&idStr, &caIDStr, &c.CRLPEM, &c.CRLNumber, &c.ThisUpdate, &c.NextUpdate)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetCRL: %w", err)
	}
	c.ID = uuid.MustParse(idStr)
	c.CAID = uuid.MustParse(caIDStr)
	return &c, nil
}

// NextCRLNumber atomically increments and returns the per-CA counter.
func (s *sqliteStore) NextCRLNumber(ctx context.Context, caID uuid.UUID) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("sqlite: NextCRLNumber: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO crl_number_counters (ca_id, next_number) VALUES (?, 1)
		ON CONFLICT(ca_id) DO NOTHING`, caID.String())
	if err != nil {
		return 0, fmt.Errorf("sqlite: NextCRLNumber: seed: %w", err)
	}

	var n int64
	row := tx.QueryRowContext(ctx, `SELECT next_number FROM crl_number_counters WHERE ca_id = ?`, caID.String())
	if err := row.Scan(&n); err != nil {
		return 0, fmt.Errorf("sqlite: NextCRLNumber: read: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE crl_number_counters SET next_number = next_number + 1 WHERE ca_id = ?`, caID.String()); err != nil {
		return 0, fmt.Errorf("sqlite: NextCRLNumber: increment: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("sqlite: NextCRLNumber: commit: %w", err)
	}
	return n, nil
}

func (s *sqliteStore) ListRevokedByCASince(ctx context.Context, caID uuid.UUID, since time.Time) ([]*Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		certSelectSQL+" WHERE c.ca_id = ? AND c.status = 'revoked' AND c.revoked_at > ? ORDER BY c.revoked_at DESC",
		caID.String(), since.UTC())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListRevokedByCASince: %w", err)
	}
	defer rows.Close()
	return scanCerts(rows)
}

func (s *sqliteStore) UpsertDeltaCRL(ctx context.Context, d *DeltaCRLCache) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO crl_delta_cache (id, ca_id, crl_pem, crl_number, base_crl_number, this_update, next_update)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ca_id) DO UPDATE SET
			crl_pem         = excluded.crl_pem,
			crl_number      = excluded.crl_number,
			base_crl_number = excluded.base_crl_number,
			this_update     = excluded.this_update,
			next_update     = excluded.next_update`,
		d.ID.String(), d.CAID.String(), d.CRLPEM, d.CRLNumber, d.BaseCRLNumber,
		d.ThisUpdate.UTC(), d.NextUpdate.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: UpsertDeltaCRL: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetDeltaCRL(ctx context.Context, caID uuid.UUID) (*DeltaCRLCache, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ca_id, crl_pem, crl_number, base_crl_number, this_update, next_update
		FROM crl_delta_cache WHERE ca_id = ?`, caID.String())
	var d DeltaCRLCache
	var idStr, caIDStr string
	err := row.Scan(&idStr, &caIDStr, &d.CRLPEM, &d.CRLNumber, &d.BaseCRLNumber, &d.ThisUpdate, &d.NextUpdate)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetDeltaCRL: %w", err)
	}
	d.ID = uuid.MustParse(idStr)
	d.CAID = uuid.MustParse(caIDStr)
	return &d, nil
}

func (s *sqliteStore) CreateAPIKey(ctx context.Context, k *APIKey) error {
	scopes, _ := marshalStringSlice(k.Scopes)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_keys
			(id, name, key_hash, scopes, ca_id, tenant_id, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID.String(), k.Name, k.KeyHash, scopes,
		uuidToSQL(k.CAID), uuidToSQL(k.TenantID), k.ExpiresAt, k.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateAPIKey: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, key_hash, scopes, ca_id, tenant_id, expires_at, last_used, created_at
		FROM api_keys WHERE key_hash = ?`, hash)
	return scanAPIKey(row)
}

func (s *sqliteStore) ListAPIKeys(ctx context.Context) ([]*APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, key_hash, scopes, ca_id, tenant_id, expires_at, last_used, created_at
		FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListAPIKeys: %w", err)
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
		k.CAID = sqlToUUID(caIDStr)
		k.TenantID = sqlToUUID(tenantIDStr)
		k.Scopes, _ = unmarshalStringSlice(scopesStr)
		out = append(out, &k)
	}
	return out, rows.Err()
}

func (s *sqliteStore) DeleteAPIKey(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ?`, id.String())
	if err != nil {
		return fmt.Errorf("sqlite: DeleteAPIKey: %w", err)
	}
	return nil
}

func (s *sqliteStore) UpdateAPIKeyHash(ctx context.Context, id uuid.UUID, newHash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET key_hash = ? WHERE id = ?`, newHash, id.String())
	if err != nil {
		return fmt.Errorf("sqlite: UpdateAPIKeyHash: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: UpdateAPIKeyHash: API key %s not found", id)
	}
	return nil
}

func (s *sqliteStore) TouchAPIKey(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET last_used = ? WHERE id = ?`,
		time.Now().UTC(), id.String())
	if err != nil {
		return fmt.Errorf("sqlite: TouchAPIKey: %w", err)
	}
	return nil
}

func scanAPIKey(row *sql.Row) (*APIKey, error) {
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
		return nil, fmt.Errorf("sqlite: scanAPIKey: %w", err)
	}
	k.ID = uuid.MustParse(idStr)
	k.CAID = sqlToUUID(caIDStr)
	k.TenantID = sqlToUUID(tenantIDStr)
	k.Scopes, _ = unmarshalStringSlice(scopesStr)
	return &k, nil
}
func (s *sqliteStore) GetSetupState(ctx context.Context) (SetupState, error) {
	row := s.db.QueryRowContext(ctx, `SELECT state FROM setup_state WHERE id = 1`)
	var state string
	err := row.Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return StateUninitialized, nil
	}
	if err != nil {
		return StateUninitialized, fmt.Errorf("sqlite: GetSetupState: %w", err)
	}
	return SetupState(state), nil
}

func (s *sqliteStore) SetSetupState(ctx context.Context, state SetupState) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO setup_state (id, state, updated_at)
		VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			state      = excluded.state,
			updated_at = excluded.updated_at`,
		string(state), time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: SetSetupState: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetAPIKeyByName(ctx context.Context, name string) (*APIKey, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, key_hash, scopes, ca_id, tenant_id, expires_at, last_used, created_at
		FROM api_keys WHERE name = ?`, name)
	return scanAPIKey(row)
}

// ---- tenants ----

const tenantSelectSQL = `SELECT id, name, status, created_at FROM tenants`

func (s *sqliteStore) CreateTenant(ctx context.Context, t *Tenant) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tenants (id, name, status, created_at)
		VALUES (?, ?, ?, ?)`, t.ID.String(), t.Name, string(t.Status), t.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("sqlite: CreateTenant: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetTenant(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx, tenantSelectSQL+" WHERE id = ?", id.String())
	return sqliteScanTenant(row)
}

func (s *sqliteStore) GetTenantByName(ctx context.Context, name string) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx, tenantSelectSQL+" WHERE name = ?", name)
	return sqliteScanTenant(row)
}

func (s *sqliteStore) ListTenants(ctx context.Context) ([]*Tenant, error) {
	rows, err := s.db.QueryContext(ctx, tenantSelectSQL+" ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListTenants: %w", err)
	}
	defer rows.Close()
	var out []*Tenant
	for rows.Next() {
		t, err := sqliteScanTenantRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateTenantStatus(ctx context.Context, id uuid.UUID, status TenantStatus) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tenants SET status = ? WHERE id = ?`, string(status), id.String())
	if err != nil {
		return fmt.Errorf("sqlite: UpdateTenantStatus: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: UpdateTenantStatus: tenant %s not found", id)
	}
	return nil
}

func sqliteScanTenant(row *sql.Row) (*Tenant, error) {
	t, err := scanTenantFields(func(dest ...interface{}) error { return row.Scan(dest...) })
	if err != nil {
		return nil, err
	}
	return t, nil
}

func sqliteScanTenantRows(rows *sql.Rows) (*Tenant, error) {
	return scanTenantFields(rows.Scan)
}

func scanTenantFields(scan func(...interface{}) error) (*Tenant, error) {
	var t Tenant
	var idStr string
	err := scan(&idStr, &t.Name, &t.Status, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: scanTenantFields: %w", err)
	}
	t.ID = uuid.MustParse(idStr)
	return &t, nil
}

func (s *sqliteStore) CreateSSHCA(ctx context.Context, ca *SSHCertificateAuthority) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ssh_certificate_authorities
			(id, name, key_algo, public_key, key_enc, status, logical_ca_id, parent_id, tenant_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ca.ID.String(), ca.Name, string(ca.KeyAlgo), ca.PublicKey,
		ca.KeyEnc, string(ca.Status), uuidToSQL(ca.LogicalCAID), uuidToSQL(ca.ParentID), uuidNullable(ca.TenantID),
		ca.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateSSHCA: %w", err)
	}
	return nil
}

const sqliteSSHCASelectSQL = `
	SELECT id, name, key_algo, public_key, key_enc, status, logical_ca_id, parent_id, tenant_id, created_at
	FROM ssh_certificate_authorities`

func sqliteScanSSHCA(row *sql.Row) (*SSHCertificateAuthority, error) {
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
	ca.TenantID = sqlToUUIDValue(tenantID)
	ca.LogicalCAID = sqlToUUID(logicalID)
	ca.ParentID = sqlToUUID(parentID)
	return &ca, nil
}

func (s *sqliteStore) GetSSHCA(ctx context.Context, id uuid.UUID) (*SSHCertificateAuthority, error) {
	row := s.db.QueryRowContext(ctx, sqliteSSHCASelectSQL+" WHERE id = ?", id.String())
	ca, err := sqliteScanSSHCA(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetSSHCA: %w", err)
	}
	return ca, nil
}

func (s *sqliteStore) GetSSHCAByName(ctx context.Context, name string) (*SSHCertificateAuthority, error) {
	row := s.db.QueryRowContext(ctx, sqliteSSHCASelectSQL+" WHERE name = ?", name)
	ca, err := sqliteScanSSHCA(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetSSHCAByName: %w", err)
	}
	return ca, nil
}

func (s *sqliteStore) ListSSHCAs(ctx context.Context) ([]*SSHCertificateAuthority, error) {
	rows, err := s.db.QueryContext(ctx, sqliteSSHCASelectSQL+" ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListSSHCAs: %w", err)
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
		ca.TenantID = sqlToUUIDValue(tenantID)
		ca.LogicalCAID = sqlToUUID(logicalID)
		ca.ParentID = sqlToUUID(parentID)
		out = append(out, &ca)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateSSHCAStatus(ctx context.Context, id uuid.UUID, status CAStatus) error {
	res, err := s.db.ExecContext(ctx, `UPDATE ssh_certificate_authorities SET status = ? WHERE id = ?`, string(status), id.String())
	if err != nil {
		return fmt.Errorf("sqlite: UpdateSSHCAStatus: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: UpdateSSHCAStatus: SSH CA %s not found", id)
	}
	return nil
}

func (s *sqliteStore) CreateSSHCertificate(ctx context.Context, cert *SSHCertificate) error {
	principals, err := marshalStringSlice(cert.Principals)
	if err != nil {
		return fmt.Errorf("sqlite: CreateSSHCertificate: marshal principals: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO ssh_certificates
			(id, ca_id, serial, cert_type, key_id, principals, public_key, cert_data,
			 valid_after, valid_before, status, provisioner_id, requester, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cert.ID.String(), cert.CAID.String(), int64(cert.Serial), string(cert.CertType),
		cert.KeyID, principals, cert.PublicKey, cert.CertData,
		cert.ValidAfter.UTC(), cert.ValidBefore.UTC(), string(cert.Status),
		cert.ProvisionerID.String(), cert.Requester, cert.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateSSHCertificate: %w", err)
	}
	return nil
}

const sqliteSSHCertSelectSQL = `
	SELECT id, ca_id, serial, cert_type, key_id, principals, public_key, cert_data,
	       valid_after, valid_before, status, revoked_at, provisioner_id, requester, created_at
	FROM ssh_certificates`

func sqliteScanSSHCert(row *sql.Row) (*SSHCertificate, error) {
	var c SSHCertificate
	var idStr, caIDStr, provIDStr, principalsStr string
	// The sqlite driver returns INTEGER as int64. The SSH serial is a uint64
	// that we store via an int64 cast, so on read we must flow it through an
	// int64 intermediate and reinterpret the bits — otherwise a serial with the
	// high bit set (negative as int64) fails to scan into a uint64.
	var serialInt int64
	err := row.Scan(
		&idStr, &caIDStr, &serialInt, &c.CertType, &c.KeyID, &principalsStr,
		&c.PublicKey, &c.CertData, &c.ValidAfter, &c.ValidBefore, &c.Status,
		&c.RevokedAt, &provIDStr, &c.Requester, &c.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Serial = uint64(serialInt)
	c.ID = uuid.MustParse(idStr)
	c.CAID = uuid.MustParse(caIDStr)
	c.ProvisionerID = uuid.MustParse(provIDStr)
	c.Principals, _ = unmarshalStringSlice(principalsStr)
	return &c, nil
}

func (s *sqliteStore) GetSSHCertificate(ctx context.Context, id uuid.UUID) (*SSHCertificate, error) {
	row := s.db.QueryRowContext(ctx, sqliteSSHCertSelectSQL+" WHERE id = ?", id.String())
	c, err := sqliteScanSSHCert(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetSSHCertificate: %w", err)
	}
	return c, nil
}

func (s *sqliteStore) GetSSHCertificateBySerial(ctx context.Context, caID uuid.UUID, serial uint64) (*SSHCertificate, error) {
	row := s.db.QueryRowContext(ctx, sqliteSSHCertSelectSQL+" WHERE ca_id = ? AND serial = ?", caID.String(), int64(serial))
	c, err := sqliteScanSSHCert(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetSSHCertificateBySerial: %w", err)
	}
	return c, nil
}

func (s *sqliteStore) ListSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*SSHCertificate, error) {
	rows, err := s.db.QueryContext(ctx,
		sqliteSSHCertSelectSQL+" WHERE ca_id = ? ORDER BY created_at DESC", caID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListSSHCertificatesByCA: %w", err)
	}
	defer rows.Close()
	return scanSSHCertList(rows)
}

func (s *sqliteStore) RevokeSSHCertificate(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE ssh_certificates SET status = 'revoked', revoked_at = ?
		WHERE id = ? AND status = 'active'`, now, id.String())
	if err != nil {
		return fmt.Errorf("sqlite: RevokeSSHCertificate: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: RevokeSSHCertificate: certificate %s not found or already revoked", id)
	}
	return nil
}
func (s *sqliteStore) MigrateNonces(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sqliteNonceSchema)
	return err
}
func (s *sqliteStore) CreateNonce(ctx context.Context, nonce string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO acme_nonces (nonce, expires_at) VALUES (?, ?)`,
		nonce, expiresAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateNonce: %w", err)
	}
	return nil
}

func (s *sqliteStore) ConsumeNonce(ctx context.Context, nonce string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("sqlite: ConsumeNonce: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var expiresAt time.Time
	row := tx.QueryRowContext(ctx,
		`SELECT expires_at FROM acme_nonces WHERE nonce = ?`, nonce)
	if err := row.Scan(&expiresAt); errors.Is(err, sql.ErrNoRows) {
		return false, nil // unknown nonce
	} else if err != nil {
		return false, fmt.Errorf("sqlite: ConsumeNonce: lookup: %w", err)
	}

	if time.Now().UTC().After(expiresAt.UTC()) {
		// Expired — delete it and report invalid.
		_, _ = tx.ExecContext(ctx, `DELETE FROM acme_nonces WHERE nonce = ?`, nonce)
		_ = tx.Commit()
		return false, nil
	}

	// Valid — delete it (single-use).
	if _, err := tx.ExecContext(ctx, `DELETE FROM acme_nonces WHERE nonce = ?`, nonce); err != nil {
		return false, fmt.Errorf("sqlite: ConsumeNonce: delete: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("sqlite: ConsumeNonce: commit: %w", err)
	}
	return true, nil
}
func (s *sqliteStore) GetRateLimitConfig(ctx context.Context, name string) (*RateLimitConfig, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT name, scope, algorithm, window_seconds, max_requests, enabled, updated_at
		FROM rate_limit_configs WHERE name = ?`, name)
	c, err := scanRateLimitConfig(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetRateLimitConfig: %w", err)
	}
	return c, nil
}

func (s *sqliteStore) ListRateLimitConfigs(ctx context.Context) ([]*RateLimitConfig, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, scope, algorithm, window_seconds, max_requests, enabled, updated_at
		FROM rate_limit_configs ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListRateLimitConfigs: %w", err)
	}
	defer rows.Close()
	var out []*RateLimitConfig
	for rows.Next() {
		var c RateLimitConfig
		var enabledInt int
		if err := rows.Scan(&c.Name, &c.Scope, &c.Algorithm, &c.WindowSeconds, &c.MaxRequests, &enabledInt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Enabled = enabledInt == 1
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpsertRateLimitConfigIfAbsent(ctx context.Context, cfg *RateLimitConfig) error {
	enabled := 0
	if cfg.Enabled {
		enabled = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO rate_limit_configs
			(name, scope, algorithm, window_seconds, max_requests, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO NOTHING`,
		cfg.Name, cfg.Scope, cfg.Algorithm, cfg.WindowSeconds, cfg.MaxRequests, enabled, cfg.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: UpsertRateLimitConfigIfAbsent: %w", err)
	}
	return nil
}

func (s *sqliteStore) UpdateRateLimitConfig(ctx context.Context, cfg *RateLimitConfig) error {
	enabled := 0
	if cfg.Enabled {
		enabled = 1
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE rate_limit_configs SET
			scope = ?, algorithm = ?, window_seconds = ?, max_requests = ?, enabled = ?, updated_at = ?
		WHERE name = ?`,
		cfg.Scope, cfg.Algorithm, cfg.WindowSeconds, cfg.MaxRequests, enabled, cfg.UpdatedAt.UTC(),
		cfg.Name,
	)
	if err != nil {
		return fmt.Errorf("sqlite: UpdateRateLimitConfig: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: UpdateRateLimitConfig: limiter %q not found", cfg.Name)
	}
	return nil
}

func scanRateLimitConfig(row *sql.Row) (*RateLimitConfig, error) {
	var c RateLimitConfig
	var enabledInt int
	err := row.Scan(&c.Name, &c.Scope, &c.Algorithm, &c.WindowSeconds, &c.MaxRequests, &enabledInt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Enabled = enabledInt == 1
	return &c, nil
}

func (s *sqliteStore) IncrementRateLimitCounter(ctx context.Context, limiterName, bucketKey string, windowStart time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO rate_limit_counters (limiter_name, bucket_key, window_start, count)
		VALUES (?, ?, ?, 1)
		ON CONFLICT(limiter_name, bucket_key, window_start) DO UPDATE SET
			count = count + 1`,
		limiterName, bucketKey, windowStart.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: IncrementRateLimitCounter: %w", err)
	}
	return nil
}
func (s *sqliteStore) UpdateACMEAccountKey(ctx context.Context, accountID uuid.UUID, newKeyID string, newKeyJWK JSON) error {
	jwk, _ := marshalJSON(newKeyJWK)
	res, err := s.db.ExecContext(ctx,
		`UPDATE acme_accounts SET key_id = ?, key_jwk = ? WHERE id = ?`,
		newKeyID, jwk, accountID.String())
	if err != nil {
		return fmt.Errorf("sqlite: UpdateACMEAccountKey: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: UpdateACMEAccountKey: account %s not found", accountID)
	}
	return nil
}

func (s *sqliteStore) MarkKeyIDRetired(ctx context.Context, keyID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO acme_retired_keys (key_id, retired_at) VALUES (?, ?)
		ON CONFLICT(key_id) DO NOTHING`,
		keyID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sqlite: MarkKeyIDRetired: %w", err)
	}
	return nil
}

// ListRevokedSSHCertificatesByCA returns only revoked SSH certs for caID.
func (s *sqliteStore) ListRevokedSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*SSHCertificate, error) {
	rows, err := s.db.QueryContext(ctx,
		sqliteSSHCertSelectSQL+" WHERE ca_id = ? AND status = 'revoked' ORDER BY revoked_at DESC", caID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListRevokedSSHCertificatesByCA: %w", err)
	}
	defer rows.Close()
	return scanSSHCertList(rows)
}

// scanSSHCertList scans all rows from a query into SSHCertificates, handling
// the sqlite int64->uint64 serial conversion (see sqliteScanSSHCert). Shared by
// ListSSHCertificatesByCA and ListRevokedSSHCertificatesByCA.
func scanSSHCertList(rows *sql.Rows) ([]*SSHCertificate, error) {
	var out []*SSHCertificate
	for rows.Next() {
		var c SSHCertificate
		var idStr, caIDStr, provIDStr, principalsStr string
		var serialInt int64
		if err := rows.Scan(
			&idStr, &caIDStr, &serialInt, &c.CertType, &c.KeyID, &principalsStr,
			&c.PublicKey, &c.CertData, &c.ValidAfter, &c.ValidBefore, &c.Status,
			&c.RevokedAt, &provIDStr, &c.Requester, &c.CreatedAt,
		); err != nil {
			return nil, err
		}
		c.Serial = uint64(serialInt)
		c.ID = uuid.MustParse(idStr)
		c.CAID = uuid.MustParse(caIDStr)
		c.ProvisionerID = uuid.MustParse(provIDStr)
		c.Principals, _ = unmarshalStringSlice(principalsStr)
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpsertSSHKRL(ctx context.Context, k *SSHKRLCache) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ssh_krl_cache (id, ca_id, krl_data, krl_version, this_update, next_update)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(ca_id) DO UPDATE SET
			krl_data    = excluded.krl_data,
			krl_version = excluded.krl_version,
			this_update = excluded.this_update,
			next_update = excluded.next_update`,
		k.ID.String(), k.CAID.String(), k.KRLData, int64(k.KRLVersion),
		k.ThisUpdate.UTC(), k.NextUpdate.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: UpsertSSHKRL: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetSSHKRL(ctx context.Context, caID uuid.UUID) (*SSHKRLCache, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ca_id, krl_data, krl_version, this_update, next_update
		FROM ssh_krl_cache WHERE ca_id = ?`, caID.String())
	var k SSHKRLCache
	var idStr, caIDStr string
	var version int64
	err := row.Scan(&idStr, &caIDStr, &k.KRLData, &version, &k.ThisUpdate, &k.NextUpdate)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetSSHKRL: %w", err)
	}
	k.ID = uuid.MustParse(idStr)
	k.CAID = uuid.MustParse(caIDStr)
	k.KRLVersion = uint64(version)
	return &k, nil
}
func (s *sqliteStore) IsKeyIDRetired(ctx context.Context, keyID string) (bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT 1 FROM acme_retired_keys WHERE key_id = ?`, keyID)
	var x int
	err := row.Scan(&x)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sqlite: IsKeyIDRetired: %w", err)
	}
	return true, nil
}

func (s *sqliteStore) PruneExpiredRateLimitCounters(ctx context.Context, olderThan time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM rate_limit_counters WHERE window_start < ?`, olderThan.UTC())
	if err != nil {
		return fmt.Errorf("sqlite: PruneExpiredRateLimitCounters: %w", err)
	}
	return nil
}
func (s *sqliteStore) PruneExpiredNonces(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM acme_nonces WHERE expires_at < ?`, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sqlite: PruneExpiredNonces: %w", err)
	}
	return nil
}
