package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func mkCA(t *testing.T, s *sqliteStore, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	err := s.CreateCA(context.Background(), &CertificateAuthority{
		ID: id, Name: name, Type: CATypeRoot, Status: CAStatusActive,
		CertPEM: "CERT", KeyEnc: []byte("k"), KeyAlgo: "ecdsa-p256",
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create ca %s: %v", name, err)
	}
	return id
}

func TestSQLite_BackupRestoreRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mint.db")
	s, err := newSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	keep := mkCA(t, s, "keep")
	data, err := s.Backup(ctx)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty backup")
	}

	// Mutate after the snapshot: adding this CA must disappear after restore.
	extra := mkCA(t, s, "extra")

	if err := s.Restore(ctx, data); err != nil {
		t.Fatalf("restore: %v", err)
	}

	if ca, _ := s.GetCA(ctx, keep); ca == nil {
		t.Error("original CA missing after restore")
	}
	if ca, _ := s.GetCA(ctx, extra); ca != nil {
		t.Error("post-snapshot CA still present after restore")
	}
}

func TestSQLite_RestoreRejectsGarbage(t *testing.T) {
	s, err := newSQLiteStore(filepath.Join(t.TempDir(), "mint.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer s.Close()
	if err := s.Restore(context.Background(), []byte("not a sqlite database")); err == nil {
		t.Fatal("expected error restoring garbage")
	}
}
