package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"mint-ca/internal/config"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// scepTenantFakeStore exposes only GetCA/GetProvisioner for the SCEP cross-check test.
type scepTenantFakeStore struct {
	storage.Store
	cas  map[uuid.UUID]*storage.CertificateAuthority
	prov map[uuid.UUID]*storage.Provisioner
}

func (f *scepTenantFakeStore) Close() error { return nil }
func (f *scepTenantFakeStore) GetCA(ctx context.Context, id uuid.UUID) (*storage.CertificateAuthority, error) {
	return f.cas[id], nil
}
func (f *scepTenantFakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	return f.prov[id], nil
}

// TestPhase4_SCEP_RequiresSameTenant ensures the public SCEP endpoint refuses a
// CA whose tenant differs from the configured SCEP provisioner's tenant.
func TestPhase4_SCEP_RequiresSameTenant(t *testing.T) {
	store := &scepTenantFakeStore{
		cas:  map[uuid.UUID]*storage.CertificateAuthority{},
		prov: map[uuid.UUID]*storage.Provisioner{},
	}
	tenantB := uuid.New()
	caB := &storage.CertificateAuthority{ID: uuid.New(), Name: "caB", TenantID: tenantB}
	provA := &storage.Provisioner{ID: uuid.New(), CAID: uuid.New(), Name: "scep-prov", TenantID: uuid.New()}
	store.cas[caB.ID] = caB
	store.prov[provA.ID] = provA

	h := NewSCEPHandler(nil, store, config.SCEPConfig{Enabled: true, ProvisionerID: provA.ID.String(), DefaultTTLSeconds: 86400})
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	// Cross-tenant CA/provisioner => refused (403), before any crypto.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/pki/"+caB.ID.String()+"/scep/?operation=PKCSReq", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant scep = %d, want 403", rec.Code)
	}
}
