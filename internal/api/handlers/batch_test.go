package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"mint-ca/internal/ca"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/policy"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// batchFakeStore is a CA-issuance fake: GetCA + CreateCertificate, plus an
// embedded nil store to satisfy the interface.
type batchFakeStore struct {
	storage.Store
	mu    sync.Mutex
	cas   map[uuid.UUID]*storage.CertificateAuthority
	certs []*storage.Certificate
}

func (f *batchFakeStore) Close() error { return nil }
func (f *batchFakeStore) GetCA(ctx context.Context, id uuid.UUID) (*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cas[id], nil
}
func (f *batchFakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	return &storage.Provisioner{ID: id, Name: "batch", Status: storage.ProvisionerStatusActive}, nil
}
func (f *batchFakeStore) GetCAByName(ctx context.Context, name string) (*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cas {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, nil
}
func (f *batchFakeStore) CreateCA(ctx context.Context, ca *storage.CertificateAuthority) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cas[ca.ID] = ca
	return nil
}
func (f *batchFakeStore) CreateCertificate(ctx context.Context, cert *storage.Certificate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certs = append(f.certs, cert)
	return nil
}

func setupBatchHandler(t *testing.T) (*batchFakeStore, chi.Router, uuid.UUID) {
	t.Helper()
	store := &batchFakeStore{cas: map[uuid.UUID]*storage.CertificateAuthority{}}
	ks, err := mintcrypto.NewKeystore(make([]byte, 32))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(store, ks, "https://ca.test")
	root, err := engine.CreateRootCA(context.Background(), ca.CreateRootCARequest{
		Name: "root", CommonName: "Batch Root", KeyAlgo: ca.KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	h := NewCertHandler(engine, policy.NewEngine(store), store, nil)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	return store, r, root.ID
}

// genCSR builds a PEM CSR for the given CN, returning PEM.
func genCSR(t *testing.T, cn string) string {
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
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestBatchSignCSR_HappyPathAndPartialFailure(t *testing.T) {
	store, r, caID := setupBatchHandler(t)
	provID := uuid.New()

	validCSR := genCSR(t, "node-a.example.com")
	badCSR := "-----BEGIN CERTIFICATE REQUEST-----\nAAAB\n-----END CERTIFICATE REQUEST-----"

	body := `{"ca_id":"` + caID.String() + `","provisioner_id":"` + provID.String() + `","items":[` +
		`{"csr_pem":` + mustQuote(validCSR) + `,"ttl_seconds":3600},` +
		`{"csr_pem":` + mustQuote(badCSR) + `,"ttl_seconds":3600},` +
		`{"csr_pem":` + mustQuote(genCSR(t, "node-c.example.com")) + `,"ttl_seconds":7200}` +
		`]}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/batch/sign", strings.NewReader(body))
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("batch: %d: %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, `"issued": 2`) {
		t.Errorf("expected issued=2 in %s", out)
	}
	if !strings.Contains(out, `"failed": 1`) {
		t.Errorf("expected failed=1 in %s", out)
	}
	// One result carries an error (the malformed CSR).
	if !strings.Contains(out, `"error"`) {
		t.Errorf("expected at least one error result: %s", out)
	}

	store.mu.Lock()
	stored := len(store.certs)
	store.mu.Unlock()
	if stored != 2 {
		t.Errorf("expected 2 certs persisted, got %d", stored)
	}
}

func mustQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
