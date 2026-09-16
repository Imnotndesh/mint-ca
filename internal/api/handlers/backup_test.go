package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type backupFakeStore struct {
	storage.Store
	restored []byte
}

func (f *backupFakeStore) Close() error { return nil }
func (f *backupFakeStore) Backup(ctx context.Context) ([]byte, error) {
	return []byte("BACKUPBYTES"), nil
}
func (f *backupFakeStore) Restore(ctx context.Context, data []byte) error {
	f.restored = data
	return nil
}

func TestBackup_OperatorOnlyAndDownload(t *testing.T) {
	store := &backupFakeStore{}
	h := NewBackupHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	// tenant-scoped is denied
	tenant := uuid.New()
	if rec := doScopeRequest(r, http.MethodGet, "/api/v1/admin/backup", "", &tenant); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant backup = %d, want 403", rec.Code)
	}
	// platform admin downloads
	rec := doScopeRequest(r, http.MethodGet, "/api/v1/admin/backup", "", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "BACKUPBYTES" {
		t.Fatalf("platform backup = %d body=%q", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("missing attachment header: %q", cd)
	}

	// restore rejects empty body, then accepts bytes
	if rec := doScopeRequest(r, http.MethodPost, "/api/v1/admin/restore", "", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty restore = %d, want 400", rec.Code)
	}
	if rec := doScopeRequest(r, http.MethodPost, "/api/v1/admin/restore", "RESTOREME", nil); rec.Code != http.StatusOK {
		t.Fatalf("restore = %d", rec.Code)
	}
	if string(store.restored) != "RESTOREME" {
		t.Fatalf("store got %q", store.restored)
	}
}
