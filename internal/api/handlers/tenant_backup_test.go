package handlers

import (
	"context"
	"net/http"
	"testing"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// tenantBackupFake embeds the tenant CRUD fake and adds backup methods.
type tenantBackupFake struct {
	*tenantFakeStore
	restored []byte
}

func (f *tenantBackupFake) TenantExport(ctx context.Context, tenantID string) ([]byte, error) {
	return []byte("EXPORTED"), nil
}
func (f *tenantBackupFake) TenantRestore(ctx context.Context, data []byte) (*storage.Tenant, error) {
	f.restored = data
	return &storage.Tenant{ID: uuid.New(), Name: "restored", Status: storage.TenantStatusActive}, nil
}

func newTenantBackupFake() *tenantBackupFake {
	return &tenantBackupFake{tenantFakeStore: &tenantFakeStore{tenants: map[uuid.UUID]*storage.Tenant{}, byName: map[string]*storage.Tenant{}}}
}

func TestTenantExportRestore_Handlers(t *testing.T) {
	store := newTenantBackupFake()
	h := NewTenantHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	tenantA, tenantB := uuid.New(), uuid.New()

	// A tenant may export its own data.
	if rec := doScopeRequest(r, http.MethodGet, "/api/v1/tenants/"+tenantA.String()+"/export", "", &tenantA); rec.Code != http.StatusOK || rec.Body.String() != "EXPORTED" {
		t.Fatalf("self export = %d body=%q", rec.Code, rec.Body.String())
	}
	// A tenant may not export another tenant's data (404, existence-hiding).
	if rec := doScopeRequest(r, http.MethodGet, "/api/v1/tenants/"+tenantB.String()+"/export", "", &tenantA); rec.Code != http.StatusNotFound {
		t.Fatalf("cross export = %d, want 404", rec.Code)
	}
	// Platform admin may export any tenant.
	if rec := doScopeRequest(r, http.MethodGet, "/api/v1/tenants/"+tenantB.String()+"/export", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("platform export = %d", rec.Code)
	}

	// Restore is platform-admin only.
	if rec := doScopeRequest(r, http.MethodPost, "/api/v1/tenants/restore", "BLOB", &tenantA); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant restore = %d, want 403", rec.Code)
	}
	if rec := doScopeRequest(r, http.MethodPost, "/api/v1/tenants/restore", "BLOB", nil); rec.Code != http.StatusCreated {
		t.Fatalf("platform restore = %d body=%s", rec.Code, rec.Body.String())
	}
	if string(store.restored) != "BLOB" {
		t.Fatalf("store got %q", store.restored)
	}
}
