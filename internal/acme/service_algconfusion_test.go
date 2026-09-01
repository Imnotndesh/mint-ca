package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func TestNewAccount_RejectsAlgorithmKeyTypeMismatch(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	rootCA := &storage.CertificateAuthority{ID: uuid.New(), Name: "root"}
	_ = store.CreateCA(ctx, rootCA)
	prov := &storage.Provisioner{
		ID: uuid.New(), CAID: rootCA.ID, Name: "acme-test",
		Type: storage.ProvisionerTypeACME, Config: storage.JSON{},
		Status: storage.ProvisionerStatusActive,
	}
	_ = store.CreateProvisioner(ctx, prov)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(priv.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(priv.Y.Bytes())
	jwk, _ := json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y})

	protectedObj := map[string]interface{}{"alg": "RS256", "nonce": "n1", "url": "https://ca.test/x", "jwk": json.RawMessage(jwk)}
	protectedBytes, _ := json.Marshal(protectedObj)
	protected := base64.RawURLEncoding.EncodeToString(protectedBytes)

	jws := &RawJWS{Protected: protected, Payload: "", Signature: "AA"}
	hdr, err := jws.ParseProtected()
	if err != nil {
		t.Fatalf("parse protected: %v", err)
	}

	svc := NewService(store, nil, NewNonceManager(store, 0), nil, nil, "https://ca.test")
	_, _, prob := svc.AuthenticateJWK(jws, hdr)
	if prob == nil {
		t.Fatal("expected algorithm/key-type mismatch to be rejected")
	}
	if prob.Type != ErrBadSignatureAlg {
		t.Errorf("expected badSignatureAlgorithm, got %s", prob.Type)
	}
}
