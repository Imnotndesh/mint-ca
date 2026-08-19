package sshca

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"golang.org/x/crypto/ssh"
)

func setupTestEngine(t *testing.T) *Engine {
	t.Helper()
	store := newFakeStore()
	masterKey := make([]byte, 32)
	ks, err := mintcrypto.NewKeystore(masterKey)
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	return NewEngine(store, ks)
}

func TestCreateCA_Ed25519(t *testing.T) {
	ctx := context.Background()
	engine := setupTestEngine(t)

	ca, err := engine.CreateCA(ctx, CreateCARequest{Name: "test-ed25519", KeyAlgo: KeyAlgoEd25519})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	if ca.KeyAlgo != storage.SSHKeyAlgoEd25519 {
		t.Errorf("expected key algo %q, got %q", storage.SSHKeyAlgoEd25519, ca.KeyAlgo)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey)); err != nil {
		t.Errorf("stored public key is not a valid authorized_keys line: %v", err)
	}
}

func TestCreateCA_ECDSAP256(t *testing.T) {
	ctx := context.Background()
	engine := setupTestEngine(t)

	ca, err := engine.CreateCA(ctx, CreateCARequest{Name: "test-ecdsa", KeyAlgo: KeyAlgoECDSAP256})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	if ca.KeyAlgo != storage.SSHKeyAlgoECDSAP256 {
		t.Errorf("expected key algo %q, got %q", storage.SSHKeyAlgoECDSAP256, ca.KeyAlgo)
	}
}

func TestCreateCA_DuplicateNameRejected(t *testing.T) {
	ctx := context.Background()
	engine := setupTestEngine(t)

	if _, err := engine.CreateCA(ctx, CreateCARequest{Name: "dup", KeyAlgo: KeyAlgoEd25519}); err != nil {
		t.Fatalf("first CreateCA: %v", err)
	}
	if _, err := engine.CreateCA(ctx, CreateCARequest{Name: "dup", KeyAlgo: KeyAlgoEd25519}); err == nil {
		t.Fatal("expected duplicate name to be rejected")
	}
}

func TestIssueCert_UserCert_VerifiesAgainstCA(t *testing.T) {
	ctx := context.Background()
	engine := setupTestEngine(t)

	ca, err := engine.CreateCA(ctx, CreateCARequest{Name: "user-test", KeyAlgo: KeyAlgoEd25519})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	clientAuthorizedKey := generateTestClientKey(t)

	issued, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID:           ca.ID,
		Requester:      "test",
		CertType:       storage.SSHCertTypeUser,
		PublicKeyInput: clientAuthorizedKey,
		KeyID:          "alice",
		Principals:     []string{"alice", "ops"},
		TTLSeconds:     3600,
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
	if err != nil {
		t.Fatalf("parse CA public key: %v", err)
	}

	certPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(issued.CertData))
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	cert, ok := certPub.(*ssh.Certificate)
	if !ok {
		t.Fatal("issued cert is not an *ssh.Certificate")
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("expected UserCert, got %v", cert.CertType)
	}
	if cert.KeyId != "alice" {
		t.Errorf("expected KeyId alice, got %q", cert.KeyId)
	}
	if len(cert.ValidPrincipals) != 2 {
		t.Errorf("expected 2 principals, got %d", len(cert.ValidPrincipals))
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caPub.Marshal())
		},
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Errorf("CheckCert failed: %v", err)
	}
}

func TestIssueCert_HostCert_TypeAndPrincipals(t *testing.T) {
	ctx := context.Background()
	engine := setupTestEngine(t)

	ca, err := engine.CreateCA(ctx, CreateCARequest{Name: "host-test", KeyAlgo: KeyAlgoEd25519})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	clientAuthorizedKey := generateTestClientKey(t)

	issued, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID:           ca.ID,
		CertType:       storage.SSHCertTypeHost,
		PublicKeyInput: clientAuthorizedKey,
		KeyID:          "web01.internal",
		Principals:     []string{"web01.internal", "web01"},
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	certPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(issued.CertData))
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	cert := certPub.(*ssh.Certificate)
	if cert.CertType != ssh.HostCert {
		t.Errorf("expected HostCert, got %v", cert.CertType)
	}
	// Host certs should carry no permit-* extensions.
	if len(cert.Permissions.Extensions) != 0 {
		t.Errorf("expected no extensions on host cert, got %v", cert.Permissions.Extensions)
	}
}

func TestParsePublicKeyInput_AutoDetectsBothFormats(t *testing.T) {
	authorizedLine := generateTestClientKey(t)

	// authorized_keys line format
	if _, err := parsePublicKeyInput(authorizedLine); err != nil {
		t.Errorf("authorized_keys format failed to parse: %v", err)
	}

	// raw base64 wire format: strip "ssh-ed25519 " prefix and trailing comment
	fields := strings.Fields(authorizedLine)
	if len(fields) < 2 {
		t.Fatalf("unexpected authorized_keys line shape: %q", authorizedLine)
	}
	if _, err := parsePublicKeyInput(fields[1]); err != nil {
		t.Errorf("raw base64 wire format failed to parse: %v", err)
	}
}

// generateTestClientKey creates a throwaway ed25519 SSH keypair and returns
// its public key as an authorized_keys line, for use as request input.
func generateTestClientKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test client key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("wrap test client signer: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}
