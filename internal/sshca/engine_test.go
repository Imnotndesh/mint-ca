package sshca

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

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

func TestIssueCert_TTL_SetsValidBefore(t *testing.T) {
	ctx := context.Background()
	engine := setupTestEngine(t)

	ca, err := engine.CreateCA(ctx, CreateCARequest{Name: "ttl-test", KeyAlgo: KeyAlgoEd25519})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	clientAuthorizedKey := generateTestClientKey(t)
	const ttl = int64(120) // 2 minutes

	issued, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID:           ca.ID,
		CertType:       storage.SSHCertTypeUser,
		PublicKeyInput: clientAuthorizedKey,
		Principals:     []string{"alice"},
		TTLSeconds:     ttl,
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// The engine applies a 1-minute clock-skew buffer before validAfter, so
	// the full window is ttl plus that buffer.
	expected := time.Duration(ttl+60) * time.Second
	if got := issued.Record.ValidBefore.Sub(issued.Record.ValidAfter); got != expected {
		t.Errorf("expected ValidBefore-ValidAfter %s, got %s", expected, got)
	}

	// The signed certificate must encode the same window in OpenSSH uint32 ticks.
	certPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(issued.CertData))
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	cert := certPub.(*ssh.Certificate)
	if int64(cert.ValidBefore-cert.ValidAfter) != ttl+60 {
		t.Errorf("expected cert validity %ds, got %d", ttl+60, cert.ValidBefore-cert.ValidAfter)
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

// TestIssueCert_CriticalOptionsAndExtensions verifies operator-supplied
// critical options (e.g. force-command, source-address) and custom extensions
// (e.g. permit-open) are embedded in the signed user certificate, merged over
// the built-in default permit-* set (which must still be present).
func TestIssueCert_CriticalOptionsAndExtensions(t *testing.T) {
	ctx := context.Background()
	engine := setupTestEngine(t)

	ca, err := engine.CreateCA(ctx, CreateCARequest{Name: "critical-test", KeyAlgo: KeyAlgoEd25519})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	issued, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID:           ca.ID,
		Requester:      "test",
		CertType:       storage.SSHCertTypeUser,
		PublicKeyInput: generateTestClientKey(t),
		KeyID:          "bob",
		Principals:     []string{"bob"},
		TTLSeconds:     3600,
		CriticalOptions: map[string]string{
			"force-command":  "/usr/local/bin/gateway",
			"source-address": "203.0.113.0/24",
		},
		Extensions: map[string]string{
			"permit-open": "host:22",
		},
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	certPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(issued.CertData))
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	cert, ok := certPub.(*ssh.Certificate)
	if !ok {
		t.Fatal("issued cert is not an *ssh.Certificate")
	}

	// Critical options present.
	if cert.Permissions.CriticalOptions["force-command"] != "/usr/local/bin/gateway" {
		t.Errorf("force-command critical option missing, got %v", cert.Permissions.CriticalOptions)
	}
	if cert.Permissions.CriticalOptions["source-address"] != "203.0.113.0/24" {
		t.Errorf("source-address critical option missing, got %v", cert.Permissions.CriticalOptions)
	}

	// Custom extension present.
	if cert.Permissions.Extensions["permit-open"] != "host:22" {
		t.Errorf("permit-open extension missing, got %v", cert.Permissions.Extensions)
	}
	// Default permit-* set must be retained (merge-over semantics).
	if _, ok := cert.Permissions.Extensions["permit-X11-forwarding"]; !ok {
		t.Errorf("default permit-X11-forwarding dropped after merge, got %v", cert.Permissions.Extensions)
	}
}

// TestIssueCert_HostCert_CriticalOptionsCarried verifies critical options and
// extensions are also embedded on host certs when supplied (OpenSSH ignores
// critical options there, but we carry them through faithfully).
func TestIssueCert_HostCert_CriticalOptionsCarried(t *testing.T) {
	ctx := context.Background()
	engine := setupTestEngine(t)

	ca, err := engine.CreateCA(ctx, CreateCARequest{Name: "host-critical-test", KeyAlgo: KeyAlgoEd25519})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	issued, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID:           ca.ID,
		Requester:      "test",
		CertType:       storage.SSHCertTypeHost,
		PublicKeyInput: generateTestClientKey(t),
		KeyID:          "web1",
		Principals:     []string{"web1"},
		TTLSeconds:     3600,
		CriticalOptions: map[string]string{"force-command": "/bin/true"},
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	certPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(issued.CertData))
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	cert, ok := certPub.(*ssh.Certificate)
	if !ok {
		t.Fatal("issued cert is not an *ssh.Certificate")
	}
	if cert.Permissions.CriticalOptions["force-command"] != "/bin/true" {
		t.Errorf("host cert force-command missing, got %v", cert.Permissions.CriticalOptions)
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
