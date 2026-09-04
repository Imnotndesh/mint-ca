package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func keyHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type authFakeStore struct {
	storage.Store
	keyByHash  map[string]*storage.APIKey
	tenantByID map[uuid.UUID]*storage.Tenant
}

func (f *authFakeStore) Close() error { return nil }

func (f *authFakeStore) TouchAPIKey(ctx context.Context, id uuid.UUID) error { return nil }

func (f *authFakeStore) GetAPIKeyByHash(ctx context.Context, hash string) (*storage.APIKey, error) {
	return f.keyByHash[hash], nil
}

func (f *authFakeStore) GetTenant(ctx context.Context, id uuid.UUID) (*storage.Tenant, error) {
	return f.tenantByID[id], nil
}

func (f *authFakeStore) CreateTenant(ctx context.Context, t *storage.Tenant) error { return nil }
func (f *authFakeStore) GetTenantByName(ctx context.Context, name string) (*storage.Tenant, error) {
	return nil, nil
}
func (f *authFakeStore) ListTenants(ctx context.Context) ([]*storage.Tenant, error) { return nil, nil }
func (f *authFakeStore) UpdateTenantStatus(ctx context.Context, id uuid.UUID, status storage.TenantStatus) error {
	return nil
}

type authRecorder struct {
	status    int
	gotTenant *uuid.UUID
	body      string
}

func doAuth(bearer string, store storage.Store) (*authRecorder, error) {
	rec := &authRecorder{}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.status = http.StatusOK
		if tid, ok := TenantIDFromContext(r.Context()); ok {
			rec.gotTenant = tid
		}
		w.WriteHeader(http.StatusOK)
	})
	h := Auth(store)(inner)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	ww := httptest.NewRecorder()
	h.ServeHTTP(ww, req)
	rec.status = ww.Code
	rec.body = ww.Body.String()
	return rec, nil
}

func TestTenantIDFromContext_PlatAdminAndTenantScoped(t *testing.T) {
	store := &authFakeStore{
		keyByHash:  map[string]*storage.APIKey{},
		tenantByID: map[uuid.UUID]*storage.Tenant{},
	}
	platformTok := "platform-token-admin"
	store.keyByHash[keyHash(platformTok)] = &storage.APIKey{ID: uuid.New(), Name: "admin"} // nil tenant

	active := &storage.Tenant{ID: uuid.New(), Name: "acme", Status: storage.TenantStatusActive}
	tenantTok := "tenant-token-bot"
	store.keyByHash[keyHash(tenantTok)] = &storage.APIKey{ID: uuid.New(), Name: "acme-bot", TenantID: &active.ID}
	store.tenantByID[active.ID] = active

	// Platform-admin passes with nil tenant.
	rec, err := doAuth(platformTok, store)
	if err != nil {
		t.Fatal(err)
	}
	if rec.status != http.StatusOK {
		t.Fatalf("platform admin status = %d body=%s", rec.status, rec.body)
	}
	if rec.gotTenant != nil {
		t.Errorf("platform admin tenant should be nil, got %v", *rec.gotTenant)
	}

	// Active tenant-scoped key passes with its tenant.
	rec, err = doAuth(tenantTok, store)
	if err != nil {
		t.Fatal(err)
	}
	if rec.status != http.StatusOK {
		t.Fatalf("active tenant key status = %d", rec.status)
	}
	if rec.gotTenant == nil || *rec.gotTenant != active.ID {
		t.Errorf("tenant-scoped key tenant = %v, want %s", rec.gotTenant, active.ID)
	}
}

func TestAuth_SuspendedTenantLockedOut(t *testing.T) {
	store := &authFakeStore{
		keyByHash:  map[string]*storage.APIKey{},
		tenantByID: map[uuid.UUID]*storage.Tenant{},
	}
	suspended := &storage.Tenant{ID: uuid.New(), Name: "bad-tenant", Status: storage.TenantStatusSuspended}
	tok := "suspended-token-bot"
	store.keyByHash[keyHash(tok)] = &storage.APIKey{ID: uuid.New(), Name: "bad-bot", TenantID: &suspended.ID}
	store.tenantByID[suspended.ID] = suspended

	rec, _ := doAuth(tok, store)
	if rec.status != http.StatusForbidden {
		t.Fatalf("expected 403 for suspended tenant key, got %d", rec.status)
	}
}

func TestAuth_InvalidKeyUnauthorized(t *testing.T) {
	store := &authFakeStore{keyByHash: map[string]*storage.APIKey{}, tenantByID: map[uuid.UUID]*storage.Tenant{}}
	rec, _ := doAuth("unknown-key-token", store)
	if rec.status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown key, got %d", rec.status)
	}
}
