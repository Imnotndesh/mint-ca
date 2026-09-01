package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"

	"crypto/x509/pkix"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func setupNameConstraintsTestEngine(t *testing.T) *Engine {
	t.Helper()
	store := newCAFakeStore()
	masterKey := make([]byte, 32)
	ks, err := mintcrypto.NewKeystore(masterKey)
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	return NewEngine(store, ks, "https://ca.test")
}

func mustParseCert(t *testing.T, certPEM []byte) *x509.Certificate {
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

func TestCreateIntermediateCA_NameConstraints_RoundTrip(t *testing.T) {
	ctx := context.Background()
	engine := setupNameConstraintsTestEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "nc-root", CommonName: "NC Root", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	nc := &storage.NameConstraints{
		PermittedDNSDomains: []string{"example.com", "example.org"},
		ExcludedDNSDomains:  []string{"internal.example.com"},
		PermittedIPRanges:   []string{"10.0.0.0/8"},
		ExcludedIPRanges:    []string{"10.99.0.0/16"},
	}

	inter, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "nc-inter", CommonName: "NC Intermediate",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 0,
		NameConstraints: nc,
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}

	// Storage round-trip: the record returned (and, by extension, what a
	// GET /api/v1/ca/{id} would surface) must carry the same constraints.
	if inter.NameConstraints == nil {
		t.Fatal("expected NameConstraints to be persisted on the CA record")
	}
	if strings.Join(inter.NameConstraints.PermittedDNSDomains, ",") != "example.com,example.org" {
		t.Errorf("permitted DNS domains not round-tripped: got %v", inter.NameConstraints.PermittedDNSDomains)
	}

	// DER round-trip: parse the intermediate's own cert back out and check
	// the stdlib x509 fields, not just our storage struct.
	cert := mustParseCert(t, []byte(inter.CertPEM))
	if len(cert.PermittedDNSDomains) != 2 {
		t.Fatalf("expected 2 permitted DNS domains in DER, got %d: %v", len(cert.PermittedDNSDomains), cert.PermittedDNSDomains)
	}
	if len(cert.ExcludedDNSDomains) != 1 || cert.ExcludedDNSDomains[0] != "internal.example.com" {
		t.Errorf("expected excluded DNS domain internal.example.com in DER, got %v", cert.ExcludedDNSDomains)
	}
	if len(cert.PermittedIPRanges) != 1 {
		t.Fatalf("expected 1 permitted IP range in DER, got %d", len(cert.PermittedIPRanges))
	}
	if !cert.PermittedDNSDomainsCritical {
		t.Error("expected PermittedDNSDomainsCritical == true (RFC 5280 recommendation / CA/B baseline requirement)")
	}
}

func TestCreateIntermediateCA_NameConstraints_RejectsWildcard(t *testing.T) {
	ctx := context.Background()
	engine := setupNameConstraintsTestEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "nc-root-wc", CommonName: "NC Root WC", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	_, err = engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "nc-inter-wc", CommonName: "NC Intermediate WC",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 0,
		NameConstraints: &storage.NameConstraints{
			PermittedDNSDomains: []string{"*.example.com"},
		},
	})
	if err == nil {
		t.Fatal("expected wildcard DNS constraint to be rejected — RFC 5280 forbids '*' in name constraints")
	}
}

func TestCreateIntermediateCA_NameConstraints_RejectsBadCIDR(t *testing.T) {
	ctx := context.Background()
	engine := setupNameConstraintsTestEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "nc-root-cidr", CommonName: "NC Root CIDR", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	_, err = engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "nc-inter-cidr", CommonName: "NC Intermediate CIDR",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 0,
		NameConstraints: &storage.NameConstraints{
			PermittedIPRanges: []string{"not-a-cidr"},
		},
	})
	if err == nil {
		t.Fatal("expected invalid CIDR to be rejected")
	}
}

func TestIssueCert_CompliantWithNameConstraints_Succeeds(t *testing.T) {
	ctx := context.Background()
	engine := setupNameConstraintsTestEngine(t)

	root, _ := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "nc-root-ok", CommonName: "NC Root OK", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	inter, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "nc-inter-ok", CommonName: "NC Intermediate OK",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 0,
		NameConstraints: &storage.NameConstraints{
			PermittedDNSDomains: []string{"example.com"},
		},
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}

	issued, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: inter.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "host.example.com",
		SANsDNS:    []string{"host.example.com", "api.example.com"},
		KeyAlgo:    KeyAlgoECDSAP256, TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("expected compliant leaf to be issued, got error: %v", err)
	}
	if issued == nil {
		t.Fatal("expected non-nil issued certificate")
	}
}

func TestIssueCert_ViolatesNameConstraints_RejectedAtIssuance(t *testing.T) {
	ctx := context.Background()
	engine := setupNameConstraintsTestEngine(t)

	root, _ := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "nc-root-bad", CommonName: "NC Root Bad", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	inter, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "nc-inter-bad", CommonName: "NC Intermediate Bad",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 0,
		NameConstraints: &storage.NameConstraints{
			PermittedDNSDomains: []string{"example.com"},
		},
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}

	_, err = engine.IssueCert(ctx, IssueCertRequest{
		CAID: inter.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "evil.attacker.net",
		SANsDNS:    []string{"evil.attacker.net"},
		KeyAlgo:    KeyAlgoECDSAP256, TTLSeconds: 3600,
	})
	if err == nil {
		t.Fatal("expected issuance to be rejected — SAN violates ancestor CA's permitted DNS domains")
	}
	if !strings.Contains(err.Error(), "name constraints") {
		t.Errorf("expected error to mention 'name constraints', got: %v", err)
	}
}

func TestIssueCert_ExcludedDNSDomain_RejectedEvenIfNoPermittedList(t *testing.T) {
	ctx := context.Background()
	engine := setupNameConstraintsTestEngine(t)

	root, _ := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "nc-root-excl", CommonName: "NC Root Excl", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	inter, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "nc-inter-excl", CommonName: "NC Intermediate Excl",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 0,
		NameConstraints: &storage.NameConstraints{
			ExcludedDNSDomains: []string{"blocked.example.com"},
		},
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}

	// No PermittedDNSDomains set — everything except the excluded subtree
	// should be allowed.
	if _, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: inter.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "fine.other.com", SANsDNS: []string{"fine.other.com"},
		KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
	}); err != nil {
		t.Errorf("expected unrelated domain to succeed with only an exclusion list set, got: %v", err)
	}

	if _, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: inter.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "sub.blocked.example.com", SANsDNS: []string{"sub.blocked.example.com"},
		KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
	}); err == nil {
		t.Fatal("expected subdomain of an excluded domain to be rejected")
	}
}

func TestIssueCert_NameConstraints_WalksMultipleAncestors(t *testing.T) {
	ctx := context.Background()
	engine := setupNameConstraintsTestEngine(t)

	root, _ := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "nc-root-chain", CommonName: "NC Root Chain", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})

	// First-level intermediate constrains to example.com.
	interA, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "nc-inter-chain-a", CommonName: "NC Intermediate Chain A",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 1,
		NameConstraints: &storage.NameConstraints{
			PermittedDNSDomains: []string{"example.com"},
		},
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA (A): %v", err)
	}

	// Second-level intermediate (grandchild of root) has NO constraints of
	// its own — but must still inherit and enforce interA's constraint.
	interB, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: interA.ID, Name: "nc-inter-chain-b", CommonName: "NC Intermediate Chain B",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 900, MaxPathLen: 0,
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA (B): %v", err)
	}

	// Leaf under interB, violating grandparent interA's constraint — must
	// be rejected even though interB itself declared no constraints.
	_, err = engine.IssueCert(ctx, IssueCertRequest{
		CAID: interB.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "host.notallowed.net", SANsDNS: []string{"host.notallowed.net"},
		KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
	})
	if err == nil {
		t.Fatal("expected grandparent's name constraints to be enforced on a leaf issued via an unconstrained intermediate")
	}

	// Compliant leaf under interB should still succeed.
	if _, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: interB.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "host.example.com", SANsDNS: []string{"host.example.com"},
		KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
	}); err != nil {
		t.Errorf("expected compliant leaf through the chain to succeed, got: %v", err)
	}
}

func TestSignCSR_ViolatesNameConstraints_RejectedAtIssuance(t *testing.T) {
	ctx := context.Background()
	engine := setupNameConstraintsTestEngine(t)

	root, _ := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "nc-root-csr", CommonName: "NC Root CSR", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	inter, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "nc-inter-csr", CommonName: "NC Intermediate CSR",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 0,
		NameConstraints: &storage.NameConstraints{
			PermittedDNSDomains: []string{"example.com"},
		},
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}

	csrPEM := generateTestCSR(t, []string{"malicious.evil.net"})

	_, err = engine.SignCSR(ctx, SignCSRRequest{
		CAID: inter.ID, ProvisionerID: uuid.New(), Requester: "test",
		CSRPEM: csrPEM, TTLSeconds: 3600,
	})
	if err == nil {
		t.Fatal("expected SignCSR to reject a CSR whose SANs violate ancestor name constraints — a CSR submitter must not be able to bypass constraints")
	}
}

func TestIssueCert_IPNameConstraints(t *testing.T) {
	ctx := context.Background()
	engine := setupNameConstraintsTestEngine(t)

	root, _ := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "nc-root-ip", CommonName: "NC Root IP", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	inter, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "nc-inter-ip", CommonName: "NC Intermediate IP",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 0,
		NameConstraints: &storage.NameConstraints{
			PermittedIPRanges: []string{"10.0.0.0/8"},
		},
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}

	if _, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: inter.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "10.1.2.3", SANsIP: []net.IP{net.ParseIP("10.1.2.3")},
		KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
	}); err != nil {
		t.Errorf("expected IP within permitted range to succeed, got: %v", err)
	}

	if _, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: inter.ID, ProvisionerID: uuid.New(), Requester: "test",
		CommonName: "192.168.1.1", SANsIP: []net.IP{net.ParseIP("192.168.1.1")},
		KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
	}); err == nil {
		t.Fatal("expected IP outside permitted range to be rejected")
	}
}
func generateTestCSR(t *testing.T, dnsNames []string) []byte {
	t.Helper()
	priv, _, err := generateKey(KeyAlgoECDSAP256)
	if err != nil {
		t.Fatalf("generate CSR key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject:  pkixNameFor(dnsNames[0]),
		DNSNames: dnsNames,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func pkixNameFor(cn string) pkix.Name {
	return pkix.Name{CommonName: cn}
}
