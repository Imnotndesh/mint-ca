package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// sqlitePasskeySchema creates the passkey credential table (SQLite). Kept in
// its own constant (like sqliteNonceSchema) so the main schema blob stays put.
const sqlitePasskeySchema = `
CREATE TABLE IF NOT EXISTS passkey_credentials (
	id              BLOB     NOT NULL PRIMARY KEY,
	user_handle     TEXT     NOT NULL,
	name            TEXT     NOT NULL DEFAULT '',
	credential_json BLOB     NOT NULL,
	sign_count      INTEGER  NOT NULL DEFAULT 0,
	created_at      DATETIME NOT NULL,
	last_used       DATETIME
);
CREATE INDEX IF NOT EXISTS idx_passkey_user ON passkey_credentials(user_handle);
`

// PasskeyCredential is a registered WebAuthn credential (a passkey).
type PasskeyCredential struct {
	// ID is the raw credential id from the authenticator.
	ID             []byte     `json:"id"`
	UserHandle     string     `json:"user_handle"`
	Name           string     `json:"name"`
	CredentialJSON []byte     `json:"-"`
	SignCount      uint32     `json:"sign_count"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsed       *time.Time `json:"last_used,omitempty"`
}

func (s *sqliteStore) CreatePasskeyCredential(ctx context.Context, c *PasskeyCredential) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO passkey_credentials (id, user_handle, name, credential_json, sign_count, created_at, last_used)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserHandle, c.Name, c.CredentialJSON, c.SignCount, c.CreatedAt.UTC(), c.LastUsed)
	if err != nil {
		return fmt.Errorf("sqlite: CreatePasskeyCredential: %w", err)
	}
	return nil
}

func scanPasskeyCredential(scan func(...any) error) (*PasskeyCredential, error) {
	var c PasskeyCredential
	var lastUsed sql.NullTime
	if err := scan(&c.ID, &c.UserHandle, &c.Name, &c.CredentialJSON, &c.SignCount, &c.CreatedAt, &lastUsed); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if lastUsed.Valid {
		c.LastUsed = &lastUsed.Time
	}
	return &c, nil
}

func (s *sqliteStore) GetPasskeyCredential(ctx context.Context, id []byte) (*PasskeyCredential, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_handle, name, credential_json, sign_count, created_at, last_used
		FROM passkey_credentials WHERE id = ?`, id)
	c, err := scanPasskeyCredential(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetPasskeyCredential: %w", err)
	}
	return c, nil
}

func (s *sqliteStore) ListPasskeyCredentials(ctx context.Context) ([]*PasskeyCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_handle, name, credential_json, sign_count, created_at, last_used
		FROM passkey_credentials ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListPasskeyCredentials: %w", err)
	}
	defer rows.Close()
	var out []*PasskeyCredential
	for rows.Next() {
		c, err := scanPasskeyCredential(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdatePasskeyCredential(ctx context.Context, c *PasskeyCredential) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE passkey_credentials SET credential_json = ?, sign_count = ?, last_used = ? WHERE id = ?`,
		c.CredentialJSON, c.SignCount, c.LastUsed, c.ID)
	if err != nil {
		return fmt.Errorf("sqlite: UpdatePasskeyCredential: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite: UpdatePasskeyCredential: credential not found")
	}
	return nil
}

func (s *sqliteStore) DeletePasskeyCredential(ctx context.Context, id []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM passkey_credentials WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: DeletePasskeyCredential: %w", err)
	}
	return nil
}
