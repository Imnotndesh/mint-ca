package ca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// setupEscrowEngine creates a root + issues a leaf, requesting key escrow,
// and returns the engine and the leaf's cert ID.
func setupEscrowEngine(t *testing.T, storeKey bool, passcode string) (*Engine, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	engine, _ := newEd25519Engine(t)
	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root", CommonName: "Escrow Root", KeyAlgo: KeyAlgoEd25519, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	leaf, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: root.ID, ProvisionerID: uuid.New(), Requester: "t",
		CommonName: "leaf.escrow.test", SANsDNS: []string{"leaf.escrow.test"},
		KeyAlgo: KeyAlgoEd25519, TTLSeconds: 3600,
		StoreKey: storeKey, KeyPasscode: passcode,
	})
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	return engine, leaf.Record.ID
}

func TestEscrow_NotStoredByDefault(t *testing.T) {
	ctx := context.Background()
	engine, id := setupEscrowEngine(t, false, "")
	key, err := engine.RetrieveKey(ctx, id, "")
	if err != nil {
		t.Fatalf("RetrieveKey: %v", err)
	}
	if key != nil {
		t.Error("expected no key when escrow disabled")
	}
}

func TestEscrow_RetrievalWithoutPasscode(t *testing.T) {
	ctx := context.Background()
	engine, id := setupEscrowEngine(t, true, "")
	key, err := engine.RetrieveKey(ctx, id, "")
	if err != nil {
		t.Fatalf("RetrieveKey: %v", err)
	}
	if !strings.Contains(string(key), "PRIVATE KEY") {
		t.Error("expected a private key PEM")
	}
	block, _ := pem.Decode(key)
	if block == nil {
		t.Fatal("retrieved key is not valid PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		if _, err2 := x509.ParseECPrivateKey(block.Bytes); err2 != nil {
			t.Errorf("retrieved key is not a parseable private key: %v", err)
		}
	}
}

func TestEscrow_PasscodeRequired(t *testing.T) {
	ctx := context.Background()
	engine, id := setupEscrowEngine(t, true, "s3cret")
	// Wrong / missing passcode must fail.
	if _, err := engine.RetrieveKey(ctx, id, ""); err == nil {
		t.Error("expected error without passcode")
	}
	if _, err := engine.RetrieveKey(ctx, id, "wrong"); err == nil {
		t.Error("expected error with wrong passcode")
	}
	// Correct passcode succeeds, and the retrieved key is a valid EC key.
	key, err := engine.RetrieveKey(ctx, id, "s3cret")
	if err != nil {
		t.Fatalf("retrieve with correct passcode: %v", err)
	}
	if !strings.Contains(string(key), "PRIVATE KEY") {
		t.Error("expected private key PEM")
	}
}
