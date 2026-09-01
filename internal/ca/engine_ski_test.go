package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	mintcrypto "mint-ca/internal/crypto"

	"github.com/google/uuid"
)

func setupSKITestEngine(t *testing.T) *Engine {
	t.Helper()
	store := newCAFakeStore()
	masterKey := make([]byte, 32)
	ks, err := mintcrypto.NewKeystore(masterKey)
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	return NewEngine(store, ks, "https://ca.test")
}

func parseCertFromPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestRootCA_HasSelfReferentialSKIAndAKI(t *testing.T) {
	ctx := context.Background()
	engine := setupSKITestEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root", CommonName: "Test Root", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	cert := parseCertFromPEM(t, []byte(root.CertPEM))

	if len(cert.SubjectKeyId) == 0 {
		t.Error("expected root CA to have a non-empty SubjectKeyId")
	}
	if len(cert.AuthorityKeyId) == 0 {
		t.Error("expected root CA to have a non-empty AuthorityKeyId")
	}
	if !bytes.Equal(cert.SubjectKeyId, cert.AuthorityKeyId) {
		t.Errorf("expected root CA AKI == SKI (self-signed); SKI=%x AKI=%x",
			cert.SubjectKeyId, cert.AuthorityKeyId)
	}
}

func TestIntermediateCA_AKIMatchesParentSKI(t *testing.T) {
	ctx := context.Background()
	engine := setupSKITestEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root2", CommonName: "Test Root 2", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	inter, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "inter", CommonName: "Test Intermediate",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 0,
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}

	rootCert := parseCertFromPEM(t, []byte(root.CertPEM))
	interCert := parseCertFromPEM(t, []byte(inter.CertPEM))

	if len(interCert.SubjectKeyId) == 0 {
		t.Error("expected intermediate to have a non-empty SubjectKeyId")
	}
	if !bytes.Equal(interCert.AuthorityKeyId, rootCert.SubjectKeyId) {
		t.Errorf("intermediate AKI (%x) does not match root SKI (%x)",
			interCert.AuthorityKeyId, rootCert.SubjectKeyId)
	}
	if bytes.Equal(interCert.SubjectKeyId, rootCert.SubjectKeyId) {
		t.Error("intermediate SKI should not equal root SKI (different keys)")
	}
}

func TestIssueCert_AKIMatchesIssuerSKI(t *testing.T) {
	ctx := context.Background()
	engine := setupSKITestEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root3", CommonName: "Test Root 3", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	issued, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: root.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "leaf.example.com", KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	rootCert := parseCertFromPEM(t, []byte(root.CertPEM))
	leafCert := parseCertFromPEM(t, issued.CertPEM)

	if len(leafCert.SubjectKeyId) == 0 {
		t.Error("expected leaf cert to have a non-empty SubjectKeyId")
	}
	if !bytes.Equal(leafCert.AuthorityKeyId, rootCert.SubjectKeyId) {
		t.Errorf("leaf AKI (%x) does not match issuer SKI (%x)",
			leafCert.AuthorityKeyId, rootCert.SubjectKeyId)
	}
}

func TestEnsureSKI_FallsBackForCertWithoutSKI(t *testing.T) {
	ctx := context.Background()
	engine := setupSKITestEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root4", CommonName: "Test Root 4", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	cert := parseCertFromPEM(t, []byte(root.CertPEM))

	cert.SubjectKeyId = nil

	aki, err := ensureSKI(cert)
	if err != nil {
		t.Fatalf("ensureSKI: %v", err)
	}
	if len(aki) == 0 {
		t.Error("expected ensureSKI to compute a non-empty fallback SKI")
	}

	aki2, err := subjectKeyID(cert.PublicKey)
	if err != nil {
		t.Fatalf("subjectKeyID: %v", err)
	}
	if !bytes.Equal(aki, aki2) {
		t.Error("ensureSKI fallback is not deterministic against subjectKeyID")
	}
}
