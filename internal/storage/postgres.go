package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// postgresStore is the Postgres implementation of Store.
type postgresStore struct {
	db *sql.DB
}

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
	_, err := s.db.ExecContext(ctx, postgresNonceSchema)
	return err
}

const postgresSchema = `
CREATE TABLE IF NOT EXISTS certificate_authorities (
	id         TEXT        NOT NULL PRIMARY KEY,
	parent_id  TEXT        REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
	name       TEXT        NOT NULL UNIQUE,
	type       TEXT        NOT NULL CHECK(type IN ('root','intermediate')),
	status     TEXT        NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired')),
	cert_pem   TEXT        NOT NULL,
	key_enc    BYTEA       NOT NULL,
	key_algo   TEXT        NOT NULL,
	not_before TIMESTAMPTZ NOT NULL,
	not_after  TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL
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
	created_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_authorizations (
    id               TEXT        NOT NULL PRIMARY KEY,
    order_id         TEXT        NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
    identifier_type  TEXT        NOT NULL CHECK(identifier_type IN ('dns')),
    identifier_value TEXT        NOT NULL,
    status           TEXT        NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','valid','invalid')),
    expires_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL
);

ALTER TABLE acme_challenges ADD COLUMN IF NOT EXISTS authorization_id TEXT REFERENCES acme_authorizations(id) ON DELETE CASCADE;

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
	metadata       TEXT        NOT NULL DEFAULT '{}'
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
	order_id     TEXT        NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
	type         TEXT        NOT NULL CHECK(type IN ('http-01','dns-01','tls-alpn-01')),
	token        TEXT        NOT NULL,
	status       TEXT        NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','valid','invalid')),
	validated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pg_challenges_order_id ON acme_challenges(order_id);

CREATE TABLE IF NOT EXISTS audit_log (
	id         TEXT        NOT NULL PRIMARY KEY,
	event_type TEXT        NOT NULL,
	actor      TEXT        NOT NULL,
	ca_id      TEXT        REFERENCES certificate_authorities(id) ON DELETE SET NULL,
	cert_id    TEXT        REFERENCES certificates(id) ON DELETE SET NULL,
	payload    TEXT        NOT NULL DEFAULT '{}',
	ip_address TEXT        NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_audit_ca_id      ON audit_log(ca_id);
CREATE INDEX IF NOT EXISTS idx_pg_audit_created_at ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS crl_cache (
	id          TEXT        NOT NULL PRIMARY KEY,
	ca_id       TEXT        NOT NULL UNIQUE REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	crl_pem     TEXT        NOT NULL,
	this_update TIMESTAMPTZ NOT NULL,
	next_update TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
	id         TEXT        NOT NULL PRIMARY KEY,
	name       TEXT        NOT NULL,
	key_hash   TEXT        NOT NULL UNIQUE,
	scopes     TEXT        NOT NULL DEFAULT '[]',
	ca_id      TEXT        REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	expires_at TIMESTAMPTZ,
	last_used  TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS setup_state (
    id         INTEGER     NOT NULL PRIMARY KEY CHECK(id = 1),
    state      TEXT        NOT NULL DEFAULT 'uninitialized',
    updated_at TIMESTAMPTZ NOT NULL
);
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

func pgUUIDToSQL(id *uuid.UUID) interface{} {
	if id == nil {
		return nil
	}
	return id.String()
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
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO certificate_authorities
			(id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
			 not_before, not_after, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		ca.ID.String(), pgUUIDToSQL(ca.ParentID), ca.Name,
		string(ca.Type), string(ca.Status), ca.CertPEM, ca.KeyEnc, ca.KeyAlgo,
		ca.NotBefore.UTC(), ca.NotAfter.UTC(), ca.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateCA: %w", err)
	}
	return nil
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

const pgCASelectSQL = `
	SELECT id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
	       not_before, not_after, created_at
	FROM certificate_authorities`

func pgScanCA(row *sql.Row) (*CertificateAuthority, error) {
	var ca CertificateAuthority
	var idStr string
	var parentIDStr *string
	err := row.Scan(
		&idStr, &parentIDStr, &ca.Name, &ca.Type, &ca.Status,
		&ca.CertPEM, &ca.KeyEnc, &ca.KeyAlgo,
		&ca.NotBefore, &ca.NotAfter, &ca.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ca.ID = uuid.MustParse(idStr)
	ca.ParentID = pgSQLToUUID(parentIDStr)
	return &ca, nil
}

func pgScanCAs(rows *sql.Rows) ([]*CertificateAuthority, error) {
	var out []*CertificateAuthority
	for rows.Next() {
		var ca CertificateAuthority
		var idStr string
		var parentIDStr *string
		if err := rows.Scan(
			&idStr, &parentIDStr, &ca.Name, &ca.Type, &ca.Status,
			&ca.CertPEM, &ca.KeyEnc, &ca.KeyAlgo,
			&ca.NotBefore, &ca.NotAfter, &ca.CreatedAt,
		); err != nil {
			return nil, err
		}
		ca.ID = uuid.MustParse(idStr)
		ca.ParentID = pgSQLToUUID(parentIDStr)
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
			 not_before, not_after, issued_at, provisioner_id, requester, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		cert.ID.String(), cert.CAID.String(), cert.Serial, cert.SubjectCN,
		sans, ku, cert.CertPEM, string(cert.Status),
		cert.NotBefore.UTC(), cert.NotAfter.UTC(), cert.IssuedAt.UTC(),
		cert.ProvisionerID.String(), cert.Requester, meta,
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
	       c.provisioner_id, c.requester, c.metadata
	FROM certificates c`

func pgScanCert(row *sql.Row) (*Certificate, error) {
	var c Certificate
	var idStr, caIDStr, provIDStr string
	var sansStr, kuStr, metaStr string
	err := row.Scan(
		&idStr, &caIDStr, &c.Serial, &c.SubjectCN,
		&sansStr, &kuStr, &c.CertPEM, &c.Status,
		&c.RevokedAt, &c.RevokeReason,
		&c.NotBefore, &c.NotAfter, &c.IssuedAt,
		&provIDStr, &c.Requester, &metaStr,
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
	_ = pgUnmarshalJSON(sansStr, &c.SANs)
	c.KeyUsage, _ = pgUnmarshalStringSlice(kuStr)
	_ = pgUnmarshalJSON(metaStr, &c.Metadata)
	return &c, nil
}

func pgScanCerts(rows *sql.Rows) ([]*Certificate, error) {
	var out []*Certificate
	for rows.Next() {
		var c Certificate
		var idStr, caIDStr, provIDStr string
		var sansStr, kuStr, metaStr string
		if err := rows.Scan(
			&idStr, &caIDStr, &c.Serial, &c.SubjectCN,
			&sansStr, &kuStr, &c.CertPEM, &c.Status,
			&c.RevokedAt, &c.RevokeReason,
			&c.NotBefore, &c.NotAfter, &c.IssuedAt,
			&provIDStr, &c.Requester, &metaStr,
		); err != nil {
			return nil, err
		}
		c.ID = uuid.MustParse(idStr)
		c.CAID = uuid.MustParse(caIDStr)
		c.ProvisionerID = uuid.MustParse(provIDStr)
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
		INSERT INTO provisioners (id, ca_id, name, type, config, policy_id, status, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		p.ID.String(), p.CAID.String(), p.Name, string(p.Type),
		cfg, pgUUIDToSQL(p.PolicyID), string(p.Status), p.CreatedAt.UTC(),
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
		var policyIDStr *string
		if err := rows.Scan(&idStr, &caIDStr, &p.Name, &p.Type, &cfgStr, &policyIDStr, &p.Status, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.ID = uuid.MustParse(idStr)
		p.CAID = uuid.MustParse(caIDStr)
		p.PolicyID = pgSQLToUUID(policyIDStr)
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
	SELECT id, ca_id, name, type, config, policy_id, status, created_at
	FROM provisioners`

func pgScanProvisioner(row *sql.Row) (*Provisioner, error) {
	var p Provisioner
	var idStr, caIDStr, cfgStr string
	var policyIDStr *string
	err := row.Scan(&idStr, &caIDStr, &p.Name, &p.Type, &cfgStr, &policyIDStr, &p.Status, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.CAID = uuid.MustParse(caIDStr)
	p.PolicyID = pgSQLToUUID(policyIDStr)
	_ = pgUnmarshalJSON(cfgStr, &p.Config)
	return &p, nil
}

func (s *postgresStore) CreatePolicy(ctx context.Context, p *Policy) error {
	ad, _ := pgMarshalStringSlice(p.AllowedDomains)
	dd, _ := pgMarshalStringSlice(p.DeniedDomains)
	ai, _ := pgMarshalStringSlice(p.AllowedIPs)
	as_, _ := pgMarshalStringSlice(p.AllowedSANs)
	ka, _ := pgMarshalStringSlice(p.KeyAlgos)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policies
			(id, name, scope, max_ttl_seconds, allowed_domains, denied_domains,
			 allowed_ips, allowed_sans, require_san, key_algos, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		p.ID.String(), p.Name, string(p.Scope), p.MaxTTL,
		ad, dd, ai, as_, p.RequireSAN, ka, p.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreatePolicy: %w", err)
	}
	return nil
}

func (s *postgresStore) GetPolicy(ctx context.Context, id uuid.UUID) (*Policy, error) {
	row := s.db.QueryRowContext(ctx, pgPolicySelectSQL+" WHERE id = $1", id.String())
	p, err := pgScanPolicy(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetPolicy: %w", err)
	}
	return p, nil
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
		var idStr, adStr, ddStr, aiStr, asStr, kaStr string
		if err := rows.Scan(
			&idStr, &p.Name, &p.Scope, &p.MaxTTL,
			&adStr, &ddStr, &aiStr, &asStr, &p.RequireSAN, &kaStr, &p.CreatedAt,
		); err != nil {
			return nil, err
		}
		p.ID = uuid.MustParse(idStr)
		p.AllowedDomains, _ = pgUnmarshalStringSlice(adStr)
		p.DeniedDomains, _ = pgUnmarshalStringSlice(ddStr)
		p.AllowedIPs, _ = pgUnmarshalStringSlice(aiStr)
		p.AllowedSANs, _ = pgUnmarshalStringSlice(asStr)
		p.KeyAlgos, _ = pgUnmarshalStringSlice(kaStr)
		out = append(out, &p)
	}
	return out, rows.Err()
}

func (s *postgresStore) UpdatePolicy(ctx context.Context, p *Policy) error {
	ad, _ := pgMarshalStringSlice(p.AllowedDomains)
	dd, _ := pgMarshalStringSlice(p.DeniedDomains)
	ai, _ := pgMarshalStringSlice(p.AllowedIPs)
	as_, _ := pgMarshalStringSlice(p.AllowedSANs)
	ka, _ := pgMarshalStringSlice(p.KeyAlgos)
	_, err := s.db.ExecContext(ctx, `
		UPDATE policies SET
			name = $1, scope = $2, max_ttl_seconds = $3,
			allowed_domains = $4, denied_domains = $5,
			allowed_ips = $6, allowed_sans = $7,
			require_san = $8, key_algos = $9
		WHERE id = $10`,
		p.Name, string(p.Scope), p.MaxTTL,
		ad, dd, ai, as_, p.RequireSAN, ka, p.ID.String(),
	)
	if err != nil {
		return fmt.Errorf("postgres: UpdatePolicy: %w", err)
	}
	return nil
}

func (s *postgresStore) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id = $1`, id.String())
	if err != nil {
		return fmt.Errorf("postgres: DeletePolicy: %w", err)
	}
	return nil
}

const pgPolicySelectSQL = `
	SELECT id, name, scope, max_ttl_seconds,
	       allowed_domains, denied_domains, allowed_ips, allowed_sans,
	       require_san, key_algos, created_at
	FROM policies`

func pgScanPolicy(row *sql.Row) (*Policy, error) {
	var p Policy
	var idStr, adStr, ddStr, aiStr, asStr, kaStr string
	err := row.Scan(
		&idStr, &p.Name, &p.Scope, &p.MaxTTL,
		&adStr, &ddStr, &aiStr, &asStr, &p.RequireSAN, &kaStr, &p.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.AllowedDomains, _ = pgUnmarshalStringSlice(adStr)
	p.DeniedDomains, _ = pgUnmarshalStringSlice(ddStr)
	p.AllowedIPs, _ = pgUnmarshalStringSlice(aiStr)
	p.AllowedSANs, _ = pgUnmarshalStringSlice(asStr)
	p.KeyAlgos, _ = pgUnmarshalStringSlice(kaStr)
	return &p, nil
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
		c.ID.String(), c.OrderID.String(), pgUUIDToSQL(c.AuthorizationID),
		string(c.Type), c.Token, string(c.Status),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateACMEChallenge: %w", err)
	}
	return nil
}

func (s *postgresStore) GetACMEChallenge(ctx context.Context, id uuid.UUID) (*ACMEChallenge, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, order_id, type, token, status, validated_at
		FROM acme_challenges WHERE id = $1`, id.String())
	c, err := pgScanChallenge(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetACMEChallenge: %w", err)
	}
	return c, nil
}
func (s *postgresStore) CreateACMEAuthorization(ctx context.Context, a *ACMEAuthorization) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO acme_authorizations
            (id, order_id, identifier_type, identifier_value, status, expires_at, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		a.ID.String(), a.OrderID.String(),
		a.IdentifierType, a.IdentifierValue,
		string(a.Status), a.ExpiresAt.UTC(), a.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateACMEAuthorization: %w", err)
	}
	return nil
}

func (s *postgresStore) GetACMEAuthorization(ctx context.Context, id uuid.UUID) (*ACMEAuthorization, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, order_id, identifier_type, identifier_value, status, expires_at, created_at
        FROM acme_authorizations WHERE id = $1`, id.String())
	var a ACMEAuthorization
	var idStr, orderIDStr string
	err := row.Scan(&idStr, &orderIDStr, &a.IdentifierType, &a.IdentifierValue, &a.Status, &a.ExpiresAt, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: GetACMEAuthorization: %w", err)
	}
	a.ID = uuid.MustParse(idStr)
	a.OrderID = uuid.MustParse(orderIDStr)
	return &a, nil
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
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, order_id, identifier_type, identifier_value, status, expires_at, created_at
        FROM acme_authorizations WHERE order_id = $1`, orderID.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: ListAuthorizationsByOrder: %w", err)
	}
	defer rows.Close()
	var out []*ACMEAuthorization
	for rows.Next() {
		var a ACMEAuthorization
		var idStr, orderIDStr string
		if err := rows.Scan(&idStr, &orderIDStr, &a.IdentifierType, &a.IdentifierValue, &a.Status, &a.ExpiresAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.ID = uuid.MustParse(idStr)
		a.OrderID = uuid.MustParse(orderIDStr)
		out = append(out, &a)
	}
	return out, rows.Err()
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

func (s *postgresStore) UpdateChallengeStatus(ctx context.Context, id uuid.UUID, status ACMEChallengeStatus, validatedAt *time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_challenges SET status = $1, validated_at = $2 WHERE id = $3`,
		string(status), validatedAt, id.String())
	if err != nil {
		return fmt.Errorf("postgres: UpdateChallengeStatus: %w", err)
	}
	return nil
}
func pgScanChallengeRows(rows *sql.Rows) (*ACMEChallenge, error) {
	var c ACMEChallenge
	var idStr, orderIDStr string
	var authIDStr *string
	if err := rows.Scan(&idStr, &orderIDStr, &authIDStr, &c.Type, &c.Token, &c.Status, &c.ValidatedAt); err != nil {
		return nil, err
	}
	c.ID = uuid.MustParse(idStr)
	c.OrderID = uuid.MustParse(orderIDStr)
	c.AuthorizationID = pgSQLToUUID(authIDStr)
	return &c, nil
}
func pgScanChallenge(row *sql.Row) (*ACMEChallenge, error) {
	var c ACMEChallenge
	var idStr, orderIDStr string
	var authIDStr *string
	err := row.Scan(&idStr, &orderIDStr, &authIDStr, &c.Type, &c.Token, &c.Status, &c.ValidatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.ID = uuid.MustParse(idStr)
	c.OrderID = uuid.MustParse(orderIDStr)
	c.AuthorizationID = pgSQLToUUID(authIDStr)
	return &c, nil
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
func (s *postgresStore) WriteAuditLog(ctx context.Context, entry *AuditLog) error {
	payload, _ := pgMarshalJSON(entry.Payload)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log
			(id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		entry.ID.String(), entry.EventType, entry.Actor,
		pgUUIDToSQL(entry.CAID), pgUUIDToSQL(entry.CertID),
		payload, entry.IPAddress, entry.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: WriteAuditLog: %w", err)
	}
	return nil
}

func (s *postgresStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]*AuditLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at
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
		SELECT id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at
		FROM audit_log WHERE ca_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		caID.String(), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("postgres: ListAuditLogsByCA: %w", err)
	}
	defer rows.Close()
	return pgScanAuditLogs(rows)
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
		INSERT INTO crl_cache (id, ca_id, crl_pem, this_update, next_update)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT(ca_id) DO UPDATE SET
			crl_pem     = EXCLUDED.crl_pem,
			this_update = EXCLUDED.this_update,
			next_update = EXCLUDED.next_update`,
		crl.ID.String(), crl.CAID.String(), crl.CRLPEM,
		crl.ThisUpdate.UTC(), crl.NextUpdate.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: UpsertCRL: %w", err)
	}
	return nil
}

func (s *postgresStore) GetCRL(ctx context.Context, caID uuid.UUID) (*CRLCache, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ca_id, crl_pem, this_update, next_update
		FROM crl_cache WHERE ca_id = $1`, caID.String())
	var c CRLCache
	var idStr, caIDStr string
	err := row.Scan(&idStr, &caIDStr, &c.CRLPEM, &c.ThisUpdate, &c.NextUpdate)
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

func (s *postgresStore) CreateAPIKey(ctx context.Context, k *APIKey) error {
	scopes, _ := pgMarshalStringSlice(k.Scopes)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_keys
			(id, name, key_hash, scopes, ca_id, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		k.ID.String(), k.Name, k.KeyHash, scopes,
		pgUUIDToSQL(k.CAID), k.ExpiresAt, k.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: CreateAPIKey: %w", err)
	}
	return nil
}

func (s *postgresStore) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, key_hash, scopes, ca_id, expires_at, last_used, created_at
		FROM api_keys WHERE key_hash = $1`, hash)
	return pgScanAPIKey(row)
}

func (s *postgresStore) ListAPIKeys(ctx context.Context) ([]*APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, key_hash, scopes, ca_id, expires_at, last_used, created_at
		FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: ListAPIKeys: %w", err)
	}
	defer rows.Close()
	var out []*APIKey
	for rows.Next() {
		var k APIKey
		var idStr, scopesStr string
		var caIDStr *string
		if err := rows.Scan(
			&idStr, &k.Name, &k.KeyHash, &scopesStr,
			&caIDStr, &k.ExpiresAt, &k.LastUsed, &k.CreatedAt,
		); err != nil {
			return nil, err
		}
		k.ID = uuid.MustParse(idStr)
		k.CAID = pgSQLToUUID(caIDStr)
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
		SELECT id, name, key_hash, scopes, ca_id, expires_at, last_used, created_at
		FROM api_keys WHERE name = $1`, name)
	return pgScanAPIKey(row)
}

func pgScanAPIKey(row *sql.Row) (*APIKey, error) {
	var k APIKey
	var idStr, scopesStr string
	var caIDStr *string
	err := row.Scan(
		&idStr, &k.Name, &k.KeyHash, &scopesStr,
		&caIDStr, &k.ExpiresAt, &k.LastUsed, &k.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: scanAPIKey: %w", err)
	}
	k.ID = uuid.MustParse(idStr)
	k.CAID = pgSQLToUUID(caIDStr)
	k.Scopes, _ = pgUnmarshalStringSlice(scopesStr)
	return &k, nil
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

// PruneExpiredNonces deletes all nonces past their expiry.
func (s *postgresStore) PruneExpiredNonces(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM acme_nonces WHERE expires_at < NOW()`)
	if err != nil {
		return fmt.Errorf("postgres: PruneExpiredNonces: %w", err)
	}
	return nil
}
