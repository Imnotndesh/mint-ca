package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	apimiddleware "mint-ca/internal/api/middleware"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// tenantFakeStore is a minimal in-memory tenant store for the tenant handler.
type tenantFakeStore struct {
	storage.Store
	mu      sync.Mutex
	tenants map[uuid.UUID]*storage.Tenant
	byName  map[string]*storage.Tenant
}

func (f *tenantFakeStore) CreateTenant(ctx context.Context, t *storage.Tenant) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants[t.ID] = t
	f.byName[t.Name] = t
	return nil
}
func (f *tenantFakeStore) GetTenant(ctx context.Context, id uuid.UUID) (*storage.Tenant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tenants[id], nil
}
func (f *tenantFakeStore) GetTenantByName(ctx context.Context, name string) (*storage.Tenant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byName[name], nil
}
func (f *tenantFakeStore) ListTenants(ctx context.Context) ([]*storage.Tenant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*storage.Tenant{}
	for _, t := range f.tenants {
		out = append(out, t)
	}
	return out, nil
}
func (f *tenantFakeStore) UpdateTenantStatus(ctx context.Context, id uuid.UUID, status storage.TenantStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tenants[id]
	if !ok {
		return context.Canceled
	}
	t.Status = status
	return nil
}

// doTenantRequest issues a request against the tenant handler with an injected
// caller. callerTenantID nil => platform admin.
func doTenantRequest(r chi.Router, method, path, body string, callerTenantID *uuid.UUID) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	caller := &storage.APIKey{Name: "caller", TenantID: callerTenantID}
	req = req.WithContext(context.WithValue(req.Context(), apimiddleware.APIKeyKey, caller))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestTenantHandler_CreateRequiresPlatformAdmin(t *testing.T) {
	store := &tenantFakeStore{tenants: map[uuid.UUID]*storage.Tenant{}, byName: map[string]*storage.Tenant{}}
	h := NewTenantHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	// A tenant-scoped caller cannot create tenants.
	tenantID := uuid.New()
	rec := doTenantRequest(r, http.MethodPost, "/api/v1/tenants/", `{"name":"acme"}`, &tenantID)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenantscoped create = %d, want 403", rec.Code)
	}
	// A platform admin can.
	rec = doTenantRequest(r, http.MethodPost, "/api/v1/tenants/", `{"name":"acme"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("platform create = %d: %s", rec.Code, rec.Body.String())
	}
	// Duplicate name is rejected.
	rec = doTenantRequest(r, http.MethodPost, "/api/v1/tenants/", `{"name":"acme"}`, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create = %d, want 409", rec.Code)
	}
}

func TestTenantHandler_ListAndGet(t *testing.T) {
	store := &tenantFakeStore{tenants: map[uuid.UUID]*storage.Tenant{}, byName: map[string]*storage.Tenant{}}
	acme := &storage.Tenant{ID: uuid.New(), Name: "acme", Status: storage.TenantStatusActive, CreatedAt: time.Now().UTC()}
	store.tenants[acme.ID] = acme
	store.byName[acme.Name] = acme

	h := NewTenantHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	// List is platform-admin-only.
	rec := doTenantRequest(r, http.MethodGet, "/api/v1/tenants", "", &acme.ID)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenantscoped list = %d, want 403", rec.Code)
	}
	rec = doTenantRequest(r, http.MethodGet, "/api/v1/tenants", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("platform list = %d", rec.Code)
	}

	// A tenant-scoped caller may only read its own tenant.
	rec = doTenantRequest(r, http.MethodGet, "/api/v1/tenants/"+acme.ID.String(), "", &acme.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("self get = %d, want 200", rec.Code)
	}
	other := uuid.New()
	rec = doTenantRequest(r, http.MethodGet, "/api/v1/tenants/"+acme.ID.String(), "", &other)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get = %d, want 404", rec.Code)
	}
}

func TestTenantHandler_SuspendActivate(t *testing.T) {
	store := &tenantFakeStore{tenants: map[uuid.UUID]*storage.Tenant{}, byName: map[string]*storage.Tenant{}}
	acme := &storage.Tenant{ID: uuid.New(), Name: "acme", Status: storage.TenantStatusActive, CreatedAt: time.Now().UTC()}
	store.tenants[acme.ID] = acme
	store.byName[acme.Name] = acme

	h := NewTenantHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	// Tenant-scoped key cannot suspend anyone (including its own).
	rec := doTenantRequest(r, http.MethodPut, "/api/v1/tenants/"+acme.ID.String()+"/suspend", "", &acme.ID)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenantscoped suspend = %d, want 403", rec.Code)
	}
	// Platform admin can.
	rec = doTenantRequest(r, http.MethodPut, "/api/v1/tenants/"+acme.ID.String()+"/suspend", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("platform suspend = %d: %s", rec.Code, rec.Body.String())
	}
	store.mu.Lock()
	status := store.tenants[acme.ID].Status
	store.mu.Unlock()
	if status != storage.TenantStatusSuspended {
		t.Fatalf("expected tenant suspended, got %s", status)
	}
	rec = doTenantRequest(r, http.MethodPut, "/api/v1/tenants/"+acme.ID.String()+"/activate", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("platform activate = %d", rec.Code)
	}
}
