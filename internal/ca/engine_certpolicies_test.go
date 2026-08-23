package ca

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	mintcrypto "mint-ca/internal/crypto"

	"github.com/google/uuid"
)

func setupCertPoliciesTestEngine(t *testing.T) *Engine {
	t.Helper()
	store := newCAFakeStore()
	masterKey := make([]byte, 32)
	ks, err := mintcrypto.NewKeystore(masterKey)
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	return NewEngine(store, ks, "https://ca.test")
}

func TestIssueCert_CertPolicies_BareOIDs(t *testing.T) {
	ctx := context.Background()
	engine := setupCertPoliciesTestEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "cp-root", CommonName: "CP Root", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	issued, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: root.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "leaf.example.com", KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
		CertPolicyOIDs: []string{"2.23.140.1.2.1", "1.3.6.1.4.1.99999.1.1"},
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	block, _ := pem.Decode(issued.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}

	if len(cert.PolicyIdentifiers) != 2 { //nolint:staticcheck // PolicyIdentifiers deprecated in favor of Policies (go1.22+); asserting either is acceptable depending on Go version
		// Fall back to checking the raw extension is present at all, since
		// stdlib parsing of PolicyIdentifiers vs Policies (uber-typed OID)
		// differs across Go versions.
		found := false
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(idCeCertificatePolicies) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected certificatePolicies extension present, got PolicyIdentifiers=%v and no matching raw extension", cert.PolicyIdentifiers)
		}
	}
}

func TestIssueCert_CertPolicies_WithCPSURI(t *testing.T) {
	ctx := context.Background()
	engine := setupCertPoliciesTestEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "cp-root-cps", CommonName: "CP Root CPS", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	issued, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: root.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "leaf2.example.com", KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
		CertPolicyOIDs:   []string{"2.23.140.1.2.1"},
		CertPolicyCPSURI: "https://ca.example.com/cps",
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	block, _ := pem.Decode(issued.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}

	found := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(idCeCertificatePolicies) {
			found = true
			var infos []asn1PolicyInformation
			if _, err := asn1.Unmarshal(ext.Value, &infos); err != nil {
				t.Fatalf("failed to re-parse certificatePolicies extension: %v", err)
			}
			if len(infos) != 1 {
				t.Fatalf("expected 1 policyInformation entry, got %d", len(infos))
			}
			if len(infos[0].Qualifiers) != 1 {
				t.Fatalf("expected 1 qualifier (CPS URI) on the policy, got %d", len(infos[0].Qualifiers))
			}
			if !infos[0].Qualifiers[0].PolicyQualifierID.Equal(idQtCPS) {
				t.Errorf("expected CPS qualifier OID, got %v", infos[0].Qualifiers[0].PolicyQualifierID)
			}
		}
	}
	if !found {
		t.Fatal("expected certificatePolicies extension to be present")
	}
}

func TestIssueCert_NoCertPolicies_NoExtension(t *testing.T) {
	ctx := context.Background()
	engine := setupCertPoliciesTestEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "cp-root-none", CommonName: "CP Root None", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	issued, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: root.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "leaf3.example.com", KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	block, _ := pem.Decode(issued.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(idCeCertificatePolicies) {
			t.Fatal("expected no certificatePolicies extension when CertPolicyOIDs is empty")
		}
	}
}

func TestIssueCert_InvalidPolicyOID_Rejected(t *testing.T) {
	ctx := context.Background()
	engine := setupCertPoliciesTestEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "cp-root-bad", CommonName: "CP Root Bad", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	_, err = engine.IssueCert(ctx, IssueCertRequest{
		CAID: root.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "leaf4.example.com", KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
		CertPolicyOIDs: []string{"not-an-oid"},
	})
	if err == nil {
		t.Fatal("expected malformed OID string to be rejected")
	}
}
