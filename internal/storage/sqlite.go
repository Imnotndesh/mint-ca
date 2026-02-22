package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// sqliteStore is the SQLite implementation of Store.
type sqliteStore struct {
	db *sql.DB
}

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
	_, err := s.db.ExecContext(ctx, sqliteSchema)
	return err
}

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS certificate_authorities (
	id         TEXT    NOT NULL PRIMARY KEY,
	parent_id  TEXT    REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
	name       TEXT    NOT NULL UNIQUE,
	type       TEXT    NOT NULL CHECK(type IN ('root','intermediate')),
	status     TEXT    NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired')),
	cert_pem   TEXT    NOT NULL,
	key_enc    BLOB    NOT NULL,
	key_algo   TEXT    NOT NULL,
	not_before DATETIME NOT NULL,
	not_after  DATETIME NOT NULL,
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
	created_at      DATETIME NOT NULL
);

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
	metadata       TEXT    NOT NULL DEFAULT '{}'
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
	order_id     TEXT NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
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
	created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ca_id      ON audit_log(ca_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS crl_cache (
	id          TEXT    NOT NULL PRIMARY KEY,
	ca_id       TEXT    NOT NULL UNIQUE REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	crl_pem     TEXT    NOT NULL,
	this_update DATETIME NOT NULL,
	next_update DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
	id         TEXT    NOT NULL PRIMARY KEY,
	name       TEXT    NOT NULL,
	key_hash   TEXT    NOT NULL UNIQUE,
	scopes     TEXT    NOT NULL DEFAULT '[]',
	ca_id      TEXT    REFERENCES certificate_authorities(id) ON DELETE CASCADE,
	expires_at DATETIME,
	last_used  DATETIME,
	created_at DATETIME NOT NULL
);
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

func (s *sqliteStore) CreateCA(ctx context.Context, ca *CertificateAuthority) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO certificate_authorities
			(id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
			 not_before, not_after, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ca.ID.String(),
		uuidToSQL(ca.ParentID),
		ca.Name,
		string(ca.Type),
		string(ca.Status),
		ca.CertPEM,
		ca.KeyEnc,
		ca.KeyAlgo,
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
		SELECT id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
		       not_before, not_after, created_at
		FROM certificate_authorities WHERE id = ?`, id.String())
	ca, err := scanCA(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetCA: %w", err)
	}
	return ca, nil
}

func (s *sqliteStore) GetCAByName(ctx context.Context, name string) (*CertificateAuthority, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
		       not_before, not_after, created_at
		FROM certificate_authorities WHERE name = ?`, name)
	ca, err := scanCA(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetCAByName: %w", err)
	}
	return ca, nil
}

func (s *sqliteStore) ListCAs(ctx context.Context) ([]*CertificateAuthority, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
		       not_before, not_after, created_at
		FROM certificate_authorities ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListCAs: %w", err)
	}
	defer rows.Close()
	return scanCAs(rows)
}

func (s *sqliteStore) ListChildCAs(ctx context.Context, parentID uuid.UUID) ([]*CertificateAuthority, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, parent_id, name, type, status, cert_pem, key_enc, key_algo,
		       not_before, not_after, created_at
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

func scanCA(row *sql.Row) (*CertificateAuthority, error) {
	var ca CertificateAuthority
	var idStr string
	var parentIDStr *string
	err := row.Scan(
		&idStr, &parentIDStr, &ca.Name, &ca.Type, &ca.Status,
		&ca.CertPEM, &ca.KeyEnc, &ca.KeyAlgo,
		&ca.NotBefore, &ca.NotAfter, &ca.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ca.ID = uuid.MustParse(idStr)
	ca.ParentID = sqlToUUID(parentIDStr)
	return &ca, nil
}

func scanCAs(rows *sql.Rows) ([]*CertificateAuthority, error) {
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
		ca.ParentID = sqlToUUID(parentIDStr)
		out = append(out, &ca)
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
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO certificates
			(id, ca_id, serial, subject_cn, sans, key_usage, cert_pem, status,
			 not_before, not_after, issued_at, provisioner_id, requester, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
	       c.provisioner_id, c.requester, c.metadata
	FROM certificates c`

func scanCert(row *sql.Row) (*Certificate, error) {
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
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.ID = uuid.MustParse(idStr)
	c.CAID = uuid.MustParse(caIDStr)
	c.ProvisionerID = uuid.MustParse(provIDStr)
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
		INSERT INTO provisioners (id, ca_id, name, type, config, policy_id, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID.String(),
		p.CAID.String(),
		p.Name,
		string(p.Type),
		cfg,
		uuidToSQL(p.PolicyID),
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
	SELECT id, ca_id, name, type, config, policy_id, status, created_at
	FROM provisioners`

func scanProvisioner(row *sql.Row) (*Provisioner, error) {
	var p Provisioner
	var idStr, caIDStr, cfgStr string
	var policyIDStr *string
	err := row.Scan(&idStr, &caIDStr, &p.Name, &p.Type, &cfgStr, &policyIDStr, &p.Status, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.CAID = uuid.MustParse(caIDStr)
	p.PolicyID = sqlToUUID(policyIDStr)
	_ = unmarshalJSON(cfgStr, &p.Config)
	return &p, nil
}

func scanProvisionerRows(rows *sql.Rows) (*Provisioner, error) {
	var p Provisioner
	var idStr, caIDStr, cfgStr string
	var policyIDStr *string
	if err := rows.Scan(&idStr, &caIDStr, &p.Name, &p.Type, &cfgStr, &policyIDStr, &p.Status, &p.CreatedAt); err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.CAID = uuid.MustParse(caIDStr)
	p.PolicyID = sqlToUUID(policyIDStr)
	_ = unmarshalJSON(cfgStr, &p.Config)
	return &p, nil
}

func (s *sqliteStore) CreatePolicy(ctx context.Context, p *Policy) error {
	ad, _ := marshalStringSlice(p.AllowedDomains)
	dd, _ := marshalStringSlice(p.DeniedDomains)
	ai, _ := marshalStringSlice(p.AllowedIPs)
	as_, _ := marshalStringSlice(p.AllowedSANs)
	ka, _ := marshalStringSlice(p.KeyAlgos)
	requireSAN := 0
	if p.RequireSAN {
		requireSAN = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policies
			(id, name, scope, max_ttl_seconds, allowed_domains, denied_domains,
			 allowed_ips, allowed_sans, require_san, key_algos, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID.String(), p.Name, string(p.Scope), p.MaxTTL,
		ad, dd, ai, as_, requireSAN, ka, p.CreatedAt.UTC(),
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
	requireSAN := 0
	if p.RequireSAN {
		requireSAN = 1
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE policies SET
			name = ?, scope = ?, max_ttl_seconds = ?,
			allowed_domains = ?, denied_domains = ?,
			allowed_ips = ?, allowed_sans = ?,
			require_san = ?, key_algos = ?
		WHERE id = ?`,
		p.Name, string(p.Scope), p.MaxTTL,
		ad, dd, ai, as_, requireSAN, ka,
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

func (s *sqliteStore) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id = ?`, id.String())
	if err != nil {
		return fmt.Errorf("sqlite: DeletePolicy: %w", err)
	}
	return nil
}

const policySelectSQL = `
	SELECT id, name, scope, max_ttl_seconds,
	       allowed_domains, denied_domains, allowed_ips, allowed_sans,
	       require_san, key_algos, created_at
	FROM policies`

func scanPolicy(row *sql.Row) (*Policy, error) {
	var p Policy
	var idStr, adStr, ddStr, aiStr, asStr, kaStr string
	var requireSAN int
	err := row.Scan(
		&idStr, &p.Name, &p.Scope, &p.MaxTTL,
		&adStr, &ddStr, &aiStr, &asStr, &requireSAN, &kaStr, &p.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.RequireSAN = requireSAN == 1
	p.AllowedDomains, _ = unmarshalStringSlice(adStr)
	p.DeniedDomains, _ = unmarshalStringSlice(ddStr)
	p.AllowedIPs, _ = unmarshalStringSlice(aiStr)
	p.AllowedSANs, _ = unmarshalStringSlice(asStr)
	p.KeyAlgos, _ = unmarshalStringSlice(kaStr)
	return &p, nil
}

func scanPolicyRows(rows *sql.Rows) (*Policy, error) {
	var p Policy
	var idStr, adStr, ddStr, aiStr, asStr, kaStr string
	var requireSAN int
	if err := rows.Scan(
		&idStr, &p.Name, &p.Scope, &p.MaxTTL,
		&adStr, &ddStr, &aiStr, &asStr, &requireSAN, &kaStr, &p.CreatedAt,
	); err != nil {
		return nil, err
	}
	p.ID = uuid.MustParse(idStr)
	p.RequireSAN = requireSAN == 1
	p.AllowedDomains, _ = unmarshalStringSlice(adStr)
	p.DeniedDomains, _ = unmarshalStringSlice(ddStr)
	p.AllowedIPs, _ = unmarshalStringSlice(aiStr)
	p.AllowedSANs, _ = unmarshalStringSlice(asStr)
	p.KeyAlgos, _ = unmarshalStringSlice(kaStr)
	return &p, nil
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
		INSERT INTO acme_challenges (id, order_id, type, token, status)
		VALUES (?, ?, ?, ?, ?)`,
		c.ID.String(), c.OrderID.String(),
		string(c.Type), c.Token, string(c.Status),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateACMEChallenge: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetACMEChallenge(ctx context.Context, id uuid.UUID) (*ACMEChallenge, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, order_id, type, token, status, validated_at
		 FROM acme_challenges WHERE id = ?`, id.String())
	c, err := scanChallenge(row)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetACMEChallenge: %w", err)
	}
	return c, nil
}

func (s *sqliteStore) ListChallengesByOrder(ctx context.Context, orderID uuid.UUID) ([]*ACMEChallenge, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, order_id, type, token, status, validated_at
		 FROM acme_challenges WHERE order_id = ?`, orderID.String())
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListChallengesByOrder: %w", err)
	}
	defer rows.Close()
	var out []*ACMEChallenge
	for rows.Next() {
		var c ACMEChallenge
		var idStr, orderIDStr string
		if err := rows.Scan(
			&idStr, &orderIDStr, &c.Type, &c.Token, &c.Status, &c.ValidatedAt,
		); err != nil {
			return nil, err
		}
		c.ID = uuid.MustParse(idStr)
		c.OrderID = uuid.MustParse(orderIDStr)
		out = append(out, &c)
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

func scanChallenge(row *sql.Row) (*ACMEChallenge, error) {
	var c ACMEChallenge
	var idStr, orderIDStr string
	err := row.Scan(&idStr, &orderIDStr, &c.Type, &c.Token, &c.Status, &c.ValidatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.ID = uuid.MustParse(idStr)
	c.OrderID = uuid.MustParse(orderIDStr)
	return &c, nil
}
func (s *sqliteStore) WriteAuditLog(ctx context.Context, entry *AuditLog) error {
	payload, _ := marshalJSON(entry.Payload)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log
			(id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID.String(), entry.EventType, entry.Actor,
		uuidToSQL(entry.CAID), uuidToSQL(entry.CertID),
		payload, entry.IPAddress, entry.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: WriteAuditLog: %w", err)
	}
	return nil
}

func (s *sqliteStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]*AuditLog, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at
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
		`SELECT id, event_type, actor, ca_id, cert_id, payload, ip_address, created_at
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
		INSERT INTO crl_cache (id, ca_id, crl_pem, this_update, next_update)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(ca_id) DO UPDATE SET
			crl_pem     = excluded.crl_pem,
			this_update = excluded.this_update,
			next_update = excluded.next_update`,
		crl.ID.String(), crl.CAID.String(), crl.CRLPEM,
		crl.ThisUpdate.UTC(), crl.NextUpdate.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: UpsertCRL: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetCRL(ctx context.Context, caID uuid.UUID) (*CRLCache, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ca_id, crl_pem, this_update, next_update
		FROM crl_cache WHERE ca_id = ?`, caID.String())
	var c CRLCache
	var idStr, caIDStr string
	err := row.Scan(&idStr, &caIDStr, &c.CRLPEM, &c.ThisUpdate, &c.NextUpdate)
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

func (s *sqliteStore) CreateAPIKey(ctx context.Context, k *APIKey) error {
	scopes, _ := marshalStringSlice(k.Scopes)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_keys
			(id, name, key_hash, scopes, ca_id, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		k.ID.String(), k.Name, k.KeyHash, scopes,
		uuidToSQL(k.CAID), k.ExpiresAt, k.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateAPIKey: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, key_hash, scopes, ca_id, expires_at, last_used, created_at
		FROM api_keys WHERE key_hash = ?`, hash)
	return scanAPIKey(row)
}

func (s *sqliteStore) ListAPIKeys(ctx context.Context) ([]*APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, key_hash, scopes, ca_id, expires_at, last_used, created_at
		FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListAPIKeys: %w", err)
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
		k.CAID = sqlToUUID(caIDStr)
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
	var caIDStr *string
	err := row.Scan(
		&idStr, &k.Name, &k.KeyHash, &scopesStr,
		&caIDStr, &k.ExpiresAt, &k.LastUsed, &k.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: scanAPIKey: %w", err)
	}
	k.ID = uuid.MustParse(idStr)
	k.CAID = sqlToUUID(caIDStr)
	k.Scopes, _ = unmarshalStringSlice(scopesStr)
	return &k, nil
}
func (s *sqliteStore) GetSetupState(ctx context.Context) (SetupState, error) {
	row := s.db.QueryRowContext(ctx, `SELECT state FROM setup_state WHERE id = 1`)
	var state string
	err := row.Scan(&state)
	if err == sql.ErrNoRows {
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
		SELECT id, name, key_hash, scopes, ca_id, expires_at, last_used, created_at
		FROM api_keys WHERE name = ?`, name)
	return scanAPIKey(row)
}
