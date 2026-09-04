package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mint-ca/internal/config"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type metricsRenewalFakeStore struct {
	storage.Store
	cas   []*storage.CertificateAuthority
	certs map[uuid.UUID][]*storage.Certificate
}

func (f *metricsRenewalFakeStore) ListCAs(ctx context.Context) ([]*storage.CertificateAuthority, error) {
	return f.cas, nil
}
func (f *metricsRenewalFakeStore) ListCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	return f.certs[caID], nil
}
func (f *metricsRenewalFakeStore) ListSSHCAs(ctx context.Context) ([]*storage.SSHCertificateAuthority, error) {
	return nil, nil
}
func (f *metricsRenewalFakeStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]*storage.AuditLog, error) {
	return nil, nil
}

func TestMetricsHandler_RenewalGauges(t *testing.T) {
	caID := uuid.New()
	now := time.Now().UTC()
	store := &metricsRenewalFakeStore{
		cas: []*storage.CertificateAuthority{{ID: caID}},
		certs: map[uuid.UUID][]*storage.Certificate{
			caID: {
				{ID: uuid.New(), CAID: caID, Status: storage.CertStatusActive, NotAfter: now.Add(24 * time.Hour)},     // expiring_soon
				{ID: uuid.New(), CAID: caID, Status: storage.CertStatusActive, NotAfter: now.Add(5 * 24 * time.Hour)}, // due
				{ID: uuid.New(), CAID: caID, Status: storage.CertStatusExpired, NotAfter: now.Add(-time.Hour)},        // expired
			},
		},
	}
	cfg := config.RenewalConfig{LeadSeconds: int64((7 * 24 * time.Hour).Seconds()), ExpiringSeconds: int64((48 * time.Hour).Seconds())}
	h := NewMetricsHandler(store, cfg)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "mintca_certs_due_total 1\n") {
		t.Errorf("expected due=1, body:\n%s", body)
	}
	if !strings.Contains(body, "mintca_certs_expiring_soon_total 1\n") {
		t.Errorf("expected expiring_soon=1, body:\n%s", body)
	}
	if !strings.Contains(body, "mintca_certs_expired_total 1\n") {
		t.Errorf("expected expired=1, body:\n%s", body)
	}
}
