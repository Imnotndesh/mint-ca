package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internalacme "mint-ca/internal/acme"
	"mint-ca/internal/config"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// renewalFakeStore covers only what getRenewalInfo + the cert-download path need.
type renewalFakeStore struct {
	storage.Store // embedded nil: any unoverridden method panics
	certs         map[uuid.UUID]*storage.Certificate
	provs         map[uuid.UUID]*storage.Provisioner
}

func (f *renewalFakeStore) Close() error { return nil }
func (f *renewalFakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	return f.provs[id], nil
}
func (f *renewalFakeStore) GetCertificate(ctx context.Context, id uuid.UUID) (*storage.Certificate, error) {
	return f.certs[id], nil
}
// Nonce support so acmeWriteJSON's IssueNonce works.
func (f *renewalFakeStore) CreateNonce(ctx context.Context, nonce string, expiresAt time.Time) error { return nil }
func (f *renewalFakeStore) ConsumeNonce(ctx context.Context, nonce string) (bool, error) { return true, nil }
func (f *renewalFakeStore) PruneExpiredNonces(ctx context.Context) error { return nil }

// TestHandler_RenewalInfo_GET returns the renewalWindow JSON.
func TestHandler_RenewalInfo_GET(t *testing.T) {
	store := &renewalFakeStore{
		certs: map[uuid.UUID]*storage.Certificate{},
		provs: map[uuid.UUID]*storage.Provisioner{},
	}
	provID := uuid.New()
	store.provs[provID] = &storage.Provisioner{ID: provID, Status: storage.ProvisionerStatusActive, Type: storage.ProvisionerTypeACME}

	certID := uuid.New()
	now := time.Now().UTC()
	store.certs[certID] = &storage.Certificate{
		ID: certID, CAID: uuid.New(), Serial: "1", CertPEM: "PEM",
		Status: storage.CertStatusActive,
		NotBefore: now.Add(-10 * 24 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), IssuedAt: now,
	}

	svc := internalacme.NewService(store, nil, internalacme.NewNonceManager(store, 0), nil, "https://ca.test")
	h := NewACMEHandler(store, nil, svc, config.ACMEConfig{}, nil)

	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/acme/"+provID.String()+"/renewal-info/"+certID.String(), nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		RenewalWindow struct {
			Start string `json:"start"`
			End   string `json:"end"`
		} `json:"renewalWindow"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.RenewalWindow.Start == "" || body.RenewalWindow.End == "" {
		t.Fatalf("missing renewalWindow start/end: %s", rec.Body.String())
	}
}

// TestService_RenewalInfoURLShape verifies the discovery URL embeds the
// provisioner and certificate IDs (the URL the Link: rel=renewalInfo prefix).
func TestService_RenewalInfoURLShape(t *testing.T) {
	svc := internalacme.NewService(&renewalFakeStore{certs: map[uuid.UUID]*storage.Certificate{}, provs: map[uuid.UUID]*storage.Provisioner{}}, nil, internalacme.NewNonceManager(nil, 0), nil, "https://ca.test")
	provID := uuid.New()
	certID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	got := svc.RenewalInfoURL(provID, certID)
	want := "https://ca.test/acme/" + provID.String() + "/renewal-info/" + certID.String()
	if got != want {
		t.Errorf("RenewalInfoURL: got %q want %q", got, want)
	}
}
