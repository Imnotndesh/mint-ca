package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mint-ca/internal/config"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type renewalStatusFakeStore struct {
	storage.Store
	cas   []*storage.CertificateAuthority
	certs map[uuid.UUID][]*storage.Certificate
}

func (f *renewalStatusFakeStore) ListCAs(ctx context.Context) ([]*storage.CertificateAuthority, error) {
	return f.cas, nil
}
func (f *renewalStatusFakeStore) ListCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	return f.certs[caID], nil
}

func newRenewalTestStore() (*renewalStatusFakeStore, uuid.UUID) {
	caID := uuid.New()
	now := time.Now().UTC()
	store := &renewalStatusFakeStore{
		cas: []*storage.CertificateAuthority{{ID: caID, Status: storage.CAStatusActive}},
		certs: map[uuid.UUID][]*storage.Certificate{
			caID: {
				{ID: uuid.New(), CAID: caID, SubjectCN: "expiring.example.com", Status: storage.CertStatusActive, NotAfter: now.Add(24 * time.Hour)},
				{ID: uuid.New(), CAID: caID, SubjectCN: "due.example.com", Status: storage.CertStatusActive, NotAfter: now.Add(5 * 24 * time.Hour)},
				{ID: uuid.New(), CAID: caID, SubjectCN: "valid.example.com", Status: storage.CertStatusActive, NotAfter: now.Add(30 * 24 * time.Hour)},
				{ID: uuid.New(), CAID: caID, SubjectCN: "expired.example.com", Status: storage.CertStatusExpired, NotAfter: now.Add(-time.Hour)},
				{ID: uuid.New(), CAID: caID, SubjectCN: "revoked.example.com", Status: storage.CertStatusRevoked, NotAfter: now.Add(time.Hour)},
			},
		},
	}
	return store, caID
}

func testRenewalConfig() config.RenewalConfig {
	return config.RenewalConfig{LeadSeconds: int64((7 * 24 * time.Hour).Seconds()), ExpiringSeconds: int64((48 * time.Hour).Seconds())}
}

func TestRenewalHandler_Status_Summary(t *testing.T) {
	store, _ := newRenewalTestStore()
	h := NewRenewalHandler(store, testRenewalConfig())
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/renewal/status", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp renewalStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Summary.Due != 1 || resp.Summary.ExpiringSoon != 1 || resp.Summary.Expired != 1 || resp.Summary.Revoked != 1 {
		t.Errorf("unexpected summary: %+v", resp.Summary)
	}
	if len(resp.Certificates) != 4 {
		t.Errorf("expected 4 actionable certs (valid excluded), got %d", len(resp.Certificates))
	}
}

func TestRenewalHandler_Status_FilterByCA(t *testing.T) {
	store, caID := newRenewalTestStore()
	otherCA := uuid.New()
	store.cas = append(store.cas, &storage.CertificateAuthority{ID: otherCA, Status: storage.CAStatusActive})
	store.certs[otherCA] = []*storage.Certificate{
		{ID: uuid.New(), CAID: otherCA, SubjectCN: "other.example.com", Status: storage.CertStatusRevoked, NotAfter: time.Now().UTC().Add(time.Hour)},
	}

	h := NewRenewalHandler(store, testRenewalConfig())
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/renewal/status?ca_id="+caID.String(), nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp renewalStatusResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	for _, c := range resp.Certificates {
		if c.CAID != caID.String() {
			t.Errorf("expected only certs for filtered CA, got cert for %s", c.CAID)
		}
	}
}

func TestRenewalHandler_Status_InvalidCAID(t *testing.T) {
	store, _ := newRenewalTestStore()
	h := NewRenewalHandler(store, testRenewalConfig())
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/renewal/status?ca_id=not-a-uuid", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
