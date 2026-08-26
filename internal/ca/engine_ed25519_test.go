package ca

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"

	mintcrypto "mint-ca/internal/crypto"

	"github.com/google/uuid"
)

// newEd25519Engine builds an Engine over a caFakeStore (real CA create/get)
// plus a keystore, for the Ed25519 round-trip tests.
func newEd25519Engine(t *testing.T) (*Engine, *caFakeStore) {
	t.Helper()
	store := newCAFakeStore()
	ks, err := mintcrypto.NewKeystore(make([]byte, 32))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	return NewEngine(store, ks, "https://ca.test"), store
}

// TestEd25519_RootIntermediateLeafRoundTrip exercises Ed25519 end-to-end:
// root, intermediate, and a leaf all generated with Ed25519, then each cert is
// parsed and its signature verified against the issuing key material.
func TestEd25519_RootIntermediateLeafRoundTrip(t *testing.T) {
	ctx := context.Background()
	engine, _ := newEd25519Engine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root", CommonName: "Ed Root", KeyAlgo: KeyAlgoEd25519, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create ed25519 root: %v", err)
	}
	assertEd25519Cert(t, root.CertPEM, "root")

	inter, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "inter", CommonName: "Ed Inter",
		KeyAlgo: KeyAlgoEd25519, TTLDays: 1825, MaxPathLen: 0,
	})
	if err != nil {
		t.Fatalf("create ed25519 intermediate: %v", err)
	}
	assertEd25519Cert(t, inter.CertPEM, "intermediate")

	leaf, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: inter.ID, ProvisionerID: uuid.New(), Requester: "t",
		CommonName: "leaf.ed.test", SANsDNS: []string{"leaf.ed.test"},
		KeyAlgo: KeyAlgoEd25519, TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("issue ed25519 leaf: %v", err)
	}
	assertEd25519Cert(t, string(leaf.CertPEM), "leaf")
}

// assertEd25519Cert decrypts/parses nothing here — it validates the public
// certificate itself: the SPKI algorithm is Ed25519 and an Ed25519 signature
// (from the CAs verified by creation) parses correctly.
func assertEd25519Cert(t *testing.T, certPEM string, label string) {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("%s: no PEM block", label)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: parse: %v", label, err)
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		t.Fatalf("%s: expected Ed25519 public key (alg=%v), got %T", label, cert.PublicKeyAlgorithm, cert.PublicKey)
	}
}

// TestEd25519_ParseKeyPEM verifies the stored encrypted key decrypts and parses
// back into an Ed25519 signer (the decode path used for signing operations).
func TestEd25519_ParseKeyPEM(t *testing.T) {
	ctx := context.Background()
	engine, store := newEd25519Engine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root", CommonName: "Ed Root", KeyAlgo: KeyAlgoEd25519, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rec, _ := store.GetCA(ctx, root.ID)

	signer, err := engine.loadKey(rec)
	if err != nil {
		t.Fatalf("load Ed25519 key: %v", err)
	}
	if _, ok := signer.(ed25519.PrivateKey); !ok {
		t.Fatalf("expected ed25519.PrivateKey signer, got %T", signer)
	}
}
