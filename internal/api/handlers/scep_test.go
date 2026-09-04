package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"mint-ca/internal/ca"
	"mint-ca/internal/config"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// scepFakeStore is a CA-issuance fake covering what the SCEP handler and
// engine need, plus CSR auto-approval rules for the reject/deny test.
type scepFakeStore struct {
	storage.Store
	mu    sync.Mutex
	cas   map[uuid.UUID]*storage.CertificateAuthority
	certs []*storage.Certificate
	rules map[uuid.UUID][]*storage.CSRAutoApproveRule
}

func (f *scepFakeStore) Close() error { return nil }
func (f *scepFakeStore) GetCA(ctx context.Context, id uuid.UUID) (*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cas[id], nil
}
func (f *scepFakeStore) GetCAByName(ctx context.Context, name string) (*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cas {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, nil
}
func (f *scepFakeStore) CreateCA(ctx context.Context, ca *storage.CertificateAuthority) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cas[ca.ID] = ca
	return nil
}
func (f *scepFakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	return &storage.Provisioner{ID: id, Name: "scep", Status: storage.ProvisionerStatusActive}, nil
}
func (f *scepFakeStore) CreateCertificate(ctx context.Context, cert *storage.Certificate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certs = append(f.certs, cert)
	return nil
}

// ---- CSR auto-approval rules, for the reject/deny consistency test ----

func (f *scepFakeStore) CreateCSRAutoApproveRule(ctx context.Context, r *storage.CSRAutoApproveRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rules == nil {
		f.rules = map[uuid.UUID][]*storage.CSRAutoApproveRule{}
	}
	f.rules[r.ProvisionerID] = append(f.rules[r.ProvisionerID], r)
	return nil
}
func (f *scepFakeStore) ListCSRAutoApproveRules(ctx context.Context, provisionerID uuid.UUID) ([]*storage.CSRAutoApproveRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rules[provisionerID], nil
}
func (f *scepFakeStore) UpdateCSRAutoApproveRule(ctx context.Context, r *storage.CSRAutoApproveRule) error {
	return nil
}
func (f *scepFakeStore) DeleteCSRAutoApproveRule(ctx context.Context, id uuid.UUID) error {
	return nil
}

func setupSCEPHandler(t *testing.T) (*scepFakeStore, chi.Router, uuid.UUID, uuid.UUID) {
	t.Helper()
	store := &scepFakeStore{cas: map[uuid.UUID]*storage.CertificateAuthority{}}
	ks, err := mintcrypto.NewKeystore(make([]byte, 32))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(store, ks, "https://ca.test")
	root, err := engine.CreateRootCA(context.Background(), ca.CreateRootCARequest{
		Name: "scep-root", CommonName: "SCEP Root", KeyAlgo: ca.KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	provID := uuid.New()
	cfg := config.SCEPConfig{Enabled: true, ProvisionerID: provID.String(), DefaultTTLSeconds: 3600}
	h := NewSCEPHandler(engine, store, cfg)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	return store, r, root.ID, provID
}

func scepCSRDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return der
}

func TestSCEP_GetCACaps(t *testing.T) {
	_, r, caID, _ := setupSCEPHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/pki/"+caID.String()+"/scep?operation=GetCACaps", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "SHA-256") {
		t.Errorf("expected capabilities to list SHA-256, got %q", rec.Body.String())
	}
}

func TestSCEP_GetCACert(t *testing.T) {
	_, r, caID, _ := setupSCEPHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/pki/"+caID.String()+"/scep?operation=GetCACert", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/x-x509-ca-cert" {
		t.Errorf("unexpected content-type: %s", rec.Header().Get("Content-Type"))
	}
	if _, err := x509.ParseCertificate(rec.Body.Bytes()); err != nil {
		t.Errorf("expected a DER certificate, got parse error: %v", err)
	}
}

func TestSCEP_GetNextCACert_NotImplemented(t *testing.T) {
	_, r, caID, _ := setupSCEPHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/pki/"+caID.String()+"/scep?operation=GetNextCACert", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSCEP_PKCSReq_HappyPath(t *testing.T) {
	store, r, caID, provID := setupSCEPHandler(t)

	csrDER := scepCSRDER(t, "device1.example.com")
	req := httptest.NewRequest(http.MethodPost, "/pki/"+caID.String()+"/scep?operation=PKCSReq", strings.NewReader(string(csrDER)))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/x-x509-user-cert" {
		t.Errorf("unexpected content-type: %s", rec.Header().Get("Content-Type"))
	}
	cert, err := x509.ParseCertificate(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("expected a DER certificate, got parse error: %v", err)
	}
	if cert.Subject.CommonName != "device1.example.com" {
		t.Errorf("unexpected CN: %s", cert.Subject.CommonName)
	}

	store.mu.Lock()
	issued := len(store.certs)
	store.mu.Unlock()
	if issued != 1 {
		t.Errorf("expected 1 cert persisted, got %d", issued)
	}
	_ = provID
}

func TestSCEP_PKCSReq_RejectedByCSRApprovalRules(t *testing.T) {
	store, r, caID, provID := setupSCEPHandler(t)

	// A rule exists for this provisioner allowing only *.allowed.example.
	rule := &storage.CSRAutoApproveRule{
		ID: uuid.New(), ProvisionerID: provID, Name: "scep-fleet",
		AllowedCommonNames: []string{`^dev-.*\.allowed\.example$`},
		Enabled:            true,
	}
	if err := store.CreateCSRAutoApproveRule(context.Background(), rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}

	csrDER := scepCSRDER(t, "not-allowed.example.com")
	req := httptest.NewRequest(http.MethodPost, "/pki/"+caID.String()+"/scep?operation=PKCSReq", strings.NewReader(string(csrDER)))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a CSR violating approval rules, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSCEP_Disabled_RoutesNotRegistered(t *testing.T) {
	store := &scepFakeStore{cas: map[uuid.UUID]*storage.CertificateAuthority{}}
	ks, _ := mintcrypto.NewKeystore(make([]byte, 32))
	engine := ca.NewEngine(store, ks, "https://ca.test")
	h := NewSCEPHandler(engine, store, config.SCEPConfig{Enabled: false})
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/pki/"+uuid.New().String()+"/scep?operation=GetCACaps", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when SCEP is disabled, got %d", rec.Code)
	}
}
