package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mint-ca/internal/ca"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// enrollFakeStore is a minimal CA-issuance store for the enrollment handler.
type enrollFakeStore struct {
	storage.Store
	cas          map[uuid.UUID]*storage.CertificateAuthority
	provisioners map[uuid.UUID]*storage.Provisioner
}

func (f *enrollFakeStore) Close() error { return nil }
func (f *enrollFakeStore) GetCA(ctx context.Context, id uuid.UUID) (*storage.CertificateAuthority, error) {
	return f.cas[id], nil
}
func (f *enrollFakeStore) GetCAByName(ctx context.Context, name string) (*storage.CertificateAuthority, error) {
	for _, c := range f.cas {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, nil
}
func (f *enrollFakeStore) CreateCA(ctx context.Context, ca *storage.CertificateAuthority) error {
	f.cas[ca.ID] = ca
	return nil
}
func (f *enrollFakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	return f.provisioners[id], nil
}
func (f *enrollFakeStore) CreateCertificate(ctx context.Context, cert *storage.Certificate) error {
	return nil
}
func (f *enrollFakeStore) CreateProvisioner(ctx context.Context, p *storage.Provisioner) error {
	f.provisioners[p.ID] = p
	return nil
}

// signerFor returns a crypto signer for the fake store's CA so IssueCert works.
func TestEnroll_IssuesLeafForAuthenticatedDevice(t *testing.T) {
	ctx := context.Background()
	store := &enrollFakeStore{
		cas:          map[uuid.UUID]*storage.CertificateAuthority{},
		provisioners: map[uuid.UUID]*storage.Provisioner{},
	}
	ks, _ := mintcrypto.NewKeystore(make([]byte, 32))
	engine := ca.NewEngine(store, ks, "https://ca.test")
	root, err := engine.CreateRootCA(ctx, ca.CreateRootCARequest{
		Name: "root", CommonName: "Enroll Root", KeyAlgo: ca.KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	provID := uuid.New()
	store.provisioners[provID] = &storage.Provisioner{ID: provID, Name: "enroll", Status: storage.ProvisionerStatusActive}

	// Build a fake device client certificate chained (self-signed here) to act
	// as the authenticated peer.
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "device-42"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	devDER, _ := x509.CreateCertificate(rand.Reader, deviceTmpl, deviceTmpl, &deviceKey.PublicKey, deviceKey)
	devCert, _ := x509.ParseCertificate(devDER)

	h := NewEnrollHandler(engine, store, root.ID, provID)
	h.StoreKey = true
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/enroll", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{devCert}}
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll: %d: %s", rec.Code, rec.Body.String())
	}
	// Response must include a cert PEM and an escrowed key PEM (fields present).
	var out struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(out.CertPEM, "BEGIN CERTIFICATE") {
		t.Error("expected cert PEM in response")
	}
	if !strings.Contains(out.KeyPEM, "PRIVATE KEY") {
		t.Error("expected escrowed key PEM in response")
	}
}
