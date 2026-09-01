package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestAlgorithmMatchesKey_ECValid(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := AlgorithmMatchesKey("ES256", &priv.PublicKey); err != nil {
		t.Errorf("expected ES256 valid for EC key, got %v", err)
	}
}

func TestAlgorithmMatchesKey_ECWrongAlg(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := AlgorithmMatchesKey("RS256", &priv.PublicKey); err == nil {
		t.Error("expected RS256 to be rejected for an EC key")
	}
}

func TestAlgorithmMatchesKey_RSAValid(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := AlgorithmMatchesKey("RS256", &priv.PublicKey); err != nil {
		t.Errorf("expected RS256 valid for RSA key, got %v", err)
	}
	if err := AlgorithmMatchesKey("PS256", &priv.PublicKey); err != nil {
		t.Errorf("expected PS256 valid for RSA key, got %v", err)
	}
}

func TestAlgorithmMatchesKey_RSAWrongAlg(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := AlgorithmMatchesKey("ES384", &priv.PublicKey); err == nil {
		t.Error("expected ES384 to be rejected for an RSA key")
	}
}
