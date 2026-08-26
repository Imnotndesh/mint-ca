package storage

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// TestMigrate_RekeySchemaOnOldDB re-creates a certificate_authorities table
// with the pre-rekey status CHECK (no 'superseded') and the pre-existing extra
// columns, seeds a CA, then runs Migrate() to verify the CHECK is widened and a
// 'superseded' status can be written — proving the table-rebuild migration works.
func TestMigrate_RekeySchemaOnOldDB(t *testing.T) {
	ctx := context.Background()

	// Create a DB that mimics an install created before re-key support:
	// name_constraints already present, but status CHECK lacks 'superseded'.
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	oldCACreate := `CREATE TABLE certificate_authorities (
		id TEXT NOT NULL PRIMARY KEY,
		parent_id TEXT REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
		name TEXT NOT NULL UNIQUE,
		type TEXT NOT NULL CHECK(type IN ('root','intermediate')),
		status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired')),
		cert_pem TEXT NOT NULL,
		key_enc BLOB NOT NULL,
		key_algo TEXT NOT NULL,
		name_constraints TEXT,
		not_before DATETIME NOT NULL,
		not_after DATETIME NOT NULL,
		created_at DATETIME NOT NULL
	)`
	if _, err := db.ExecContext(ctx, oldCACreate); err != nil {
		t.Fatalf("create old table: %v", err)
	}

	caID := uuid.New().String()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO certificate_authorities (id, name, type, status, cert_pem, key_enc, key_algo, not_before, not_after, created_at)
		VALUES (?, 'legacy', 'root', 'active', 'PEM', X'00', 'ecdsa-p256', ?, ?, ?)`,
		caID, time.Now().UTC(), time.Now().Add(time.Hour), time.Now().UTC()); err != nil {
		t.Fatalf("seed CA: %v", err)
	}

	// Migrate must widen the constraint AND create the new tables.
	s := &sqliteStore{db: db}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Writing superseded must now succeed.
	if _, err := db.ExecContext(ctx, `UPDATE certificate_authorities SET status='superseded' WHERE id=?`, caID); err != nil {
		t.Fatalf("write superseded status failed (CHECK not widened?): %v", err)
	}

	// ca_cross_certs table must exist.
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='ca_cross_certs'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ca_cross_certs table missing (n=%d err=%v)", n, err)
	}
}

// TestSQLiteStore_CrossCertCRUD exercises the cross-cert store methods.
func TestSQLiteStore_CrossCertCRUD(t *testing.T) {
	ctx := context.Background()
	s, err := newSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer s.Close()

	// Need two CA parents for the FK references.
	mkCA := func(name string) *CertificateAuthority {
		c := &CertificateAuthority{
			ID: uuid.New(), Name: name, Type: CATypeRoot, Status: CAStatusActive,
			CertPEM: "PEM", KeyEnc: []byte{1}, KeyAlgo: "ecdsa-p256",
			NotBefore: time.Now().UTC(), NotAfter: time.Now().Add(time.Hour), CreatedAt: time.Now().UTC(),
		}
		if err := s.CreateCA(ctx, c); err != nil {
			t.Fatalf("create CA %s: %v", name, err)
		}
		return c
	}
	target := mkCA("target")
	signer := mkCA("signer")

	cc := &CrossCert{
		ID: uuid.New(), TargetCAID: target.ID, SigningCAID: signer.ID,
		CertPEM: "CROSSPEM", Serial: "12345",
		NotBefore: time.Now().UTC(), NotAfter: time.Now().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	if err := s.CreateCrossCert(ctx, cc); err != nil {
		t.Fatalf("create cross cert: %v", err)
	}

	got, err := s.GetCrossCert(ctx, target.ID, signer.ID)
	if err != nil || got == nil || got.CertPEM != "CROSSPEM" {
		t.Fatalf("get cross cert: %v (got=%v)", err, got)
	}

	list, err := s.ListCrossCertsByTarget(ctx, target.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list cross certs: %v (len=%d)", err, len(list))
	}
}
