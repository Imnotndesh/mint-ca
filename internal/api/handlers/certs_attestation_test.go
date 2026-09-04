package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mint-ca/internal/attestation"
	"mint-ca/internal/attestation/tpm2"
	"mint-ca/internal/ca"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/policy"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func setupAttestationHandler(t *testing.T, reg *attestation.Registry) (*eventsFakeStore, chi.Router, uuid.UUID) {
	t.Helper()
	base := &batchFakeStore{cas: map[uuid.UUID]*storage.CertificateAuthority{}}
	store := &eventsFakeStore{batchFakeStore: base}
	ks, err := mintcrypto.NewKeystore(make([]byte, 32))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(store, ks, "https://ca.test")
	root, err := engine.CreateRootCA(context.Background(), ca.CreateRootCARequest{
		Name: "root", CommonName: "Attest Root", KeyAlgo: ca.KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	store.rootID = root.ID
	h := NewCertHandler(engine, policy.NewEngine(store), store, nil, reg)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	return store, r, root.ID
}

func genEKAndCSR(t *testing.T, cn string) (csrPEM string, csrDER []byte, ekPEM []byte, ekKey *ecdsa.PrivateKey) {
	t.Helper()
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("csr key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, tmpl, csrKey)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	ekKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ek key: %v", err)
	}
	ekTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test EK"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, ekTmpl, ekTmpl, &ekKey.PublicKey, ekKey)
	if err != nil {
		t.Fatalf("create ek cert: %v", err)
	}
	ekPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return
}

func signCSRAttestationBody(t *testing.T, caID, provID uuid.UUID, csrPEM string, att map[string]any) []byte {
	t.Helper()
	body := map[string]any{
		"ca_id":          caID.String(),
		"provisioner_id": provID.String(),
		"csr_pem":        csrPEM,
		"ttl_seconds":    3600,
	}
	if att != nil {
		body["attestation"] = att
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return b
}

func TestSignCSR_WithValidTPMAttestation_Succeeds(t *testing.T) {
	reg := attestation.NewRegistry()
	reg.Register(tpm2.New(nil))
	_, r, caID := setupAttestationHandler(t, reg)
	provID := uuid.New()

	csrPEM, csrDER, ekPEM, ekKey := genEKAndCSR(t, "device.example.com")
	digest := sha256.Sum256(csrDER)
	sig, err := ecdsa.SignASN1(rand.Reader, ekKey, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	attData, _ := json.Marshal(map[string]string{
		"ek_cert_pem":   string(ekPEM),
		"signature_b64": base64.StdEncoding.EncodeToString(sig),
	})

	body := signCSRAttestationBody(t, caID, provID, csrPEM, map[string]any{
		"format":   "tpm2",
		"data_b64": base64.StdEncoding.EncodeToString(attData),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/sign", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestSignCSR_WithInvalidTPMAttestation_Rejected(t *testing.T) {
	reg := attestation.NewRegistry()
	reg.Register(tpm2.New(nil))
	_, r, caID := setupAttestationHandler(t, reg)
	provID := uuid.New()

	csrPEM, _, ekPEM, _ := genEKAndCSR(t, "device.example.com")
	// Sign garbage instead of the CSR digest, so verification fails.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	badSig, _ := ecdsa.SignASN1(rand.Reader, otherKey, sha256Sum32(t, []byte("garbage")))
	attData, _ := json.Marshal(map[string]string{
		"ek_cert_pem":   string(ekPEM),
		"signature_b64": base64.StdEncoding.EncodeToString(badSig),
	})

	body := signCSRAttestationBody(t, caID, provID, csrPEM, map[string]any{
		"format":   "tpm2",
		"data_b64": base64.StdEncoding.EncodeToString(attData),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/sign", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s, want 403", rec.Code, rec.Body.String())
	}
}

func TestSignCSR_UnregisteredAttestationFormat_Rejected(t *testing.T) {
	reg := attestation.NewRegistry() // nothing registered
	_, r, caID := setupAttestationHandler(t, reg)
	provID := uuid.New()

	csrPEM, _, _, _ := genEKAndCSR(t, "device.example.com")
	body := signCSRAttestationBody(t, caID, provID, csrPEM, map[string]any{
		"format":   "tpm2",
		"data_b64": base64.StdEncoding.EncodeToString([]byte("{}")),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/sign", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s, want 403", rec.Code, rec.Body.String())
	}
}

func TestSignCSR_NoAttestationRequested_SkipsGate(t *testing.T) {
	reg := attestation.NewRegistry() // nothing registered, but not requested either
	_, r, caID := setupAttestationHandler(t, reg)
	provID := uuid.New()

	csrPEM, _, _, _ := genEKAndCSR(t, "device.example.com")
	body := signCSRAttestationBody(t, caID, provID, csrPEM, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/sign", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func sha256Sum32(t *testing.T, b []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(b)
	return sum[:]
}
