package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// approvalFakeStore is a minimal CSR-approval store.
type approvalFakeStore struct {
	storage.Store
	mu    sync.Mutex
	rules map[uuid.UUID]*storage.CSRAutoApproveRule
}

func newApprovalFakeStore() *approvalFakeStore {
	return &approvalFakeStore{rules: map[uuid.UUID]*storage.CSRAutoApproveRule{}}
}
func (f *approvalFakeStore) Close() error { return nil }
func (f *approvalFakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	return &storage.Provisioner{ID: id, Name: "any", Type: storage.ProvisionerTypeAPIKey, Status: storage.ProvisionerStatusActive}, nil
}
func (f *approvalFakeStore) CreateCSRAutoApproveRule(ctx context.Context, r *storage.CSRAutoApproveRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[r.ID] = r
	return nil
}
func (f *approvalFakeStore) ListCSRAutoApproveRules(ctx context.Context, p uuid.UUID) ([]*storage.CSRAutoApproveRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*storage.CSRAutoApproveRule{}
	for _, r := range f.rules {
		if p == uuid.Nil || r.ProvisionerID == p {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *approvalFakeStore) UpdateCSRAutoApproveRule(ctx context.Context, r *storage.CSRAutoApproveRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[r.ID] = r
	return nil
}
func (f *approvalFakeStore) DeleteCSRAutoApproveRule(ctx context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rules, id)
	return nil
}

func TestApprovalRules_CRUDAndEnforcement(t *testing.T) {
	store := newApprovalFakeStore()
	h := NewApprovalHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	provID := uuid.New()
	// Create a rule allowing *.internal.example DNS SANs.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/approval/csr-rules/", strings.NewReader(
		`{"provisioner_id":"`+provID.String()+`","name":"internal-fleet","allowed_dns":["\\.internal\\.example$"],"max_ttl_seconds":3600}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d: %s", rec.Code, rec.Body.String())
	}

	// List filtered by provisioner.
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/approval/csr-rules/?provisioner_id="+provID.String(), nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "internal-fleet") {
		t.Fatalf("list: %d: %s", rec.Code, rec.Body.String())
	}

	// Enforcement: a CSR with a matching DNS SAN is approved; one with a
	// non-matching DNS SAN is denied.
	ch := &CertHandler{store: store}
	if err := ch.enforceCSRAutoApproval(context.Background(), provID, genApprovalCSR(t, "svc.internal.example"), 3600); err != nil {
		t.Errorf("matching CSR should be approved: %v", err)
	}
	if err := ch.enforceCSRAutoApproval(context.Background(), provID, genApprovalCSR(t, "svc.evil.com"), 3600); err == nil {
		t.Error("non-matching CSR should be denied")
	}
}

func genApprovalCSR(t *testing.T, hostname string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
