package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func genSelfSignedForP12(t *testing.T, cn string) (certPEM, keyPEM []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func TestExportP12_RoundTrip(t *testing.T) {
	leafPEM, keyPEM, _, _ := genSelfSignedForP12(t, "leaf.example.com")
	rootPEM, _, _, _ := genSelfSignedForP12(t, "Test Root")
	chainPEM := append(append([]byte{}, leafPEM...), rootPEM...)

	data, err := exportP12(leafPEM, chainPEM, keyPEM, "testpass")
	if err != nil {
		t.Fatalf("exportP12: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty p12 data")
	}

	_, cert, caCerts, err := pkcs12.DecodeChain(data, "testpass")
	if err != nil {
		t.Fatalf("decode p12: %v", err)
	}
	if cert.Subject.CommonName != "leaf.example.com" {
		t.Errorf("leaf CN = %q", cert.Subject.CommonName)
	}
	if len(caCerts) != 1 || caCerts[0].Subject.CommonName != "Test Root" {
		t.Errorf("unexpected caCerts: %+v", caCerts)
	}
}

func TestExportP12_NoKey_Errors(t *testing.T) {
	leafPEM, _, _, _ := genSelfSignedForP12(t, "leaf.example.com")
	if _, err := exportP12(leafPEM, leafPEM, nil, "testpass"); err == nil {
		t.Fatal("expected error when key is missing")
	}
}

func TestExportP12_WrongPassword_Fails(t *testing.T) {
	leafPEM, keyPEM, _, _ := genSelfSignedForP12(t, "leaf.example.com")
	data, err := exportP12(leafPEM, leafPEM, keyPEM, "testpass")
	if err != nil {
		t.Fatalf("exportP12: %v", err)
	}
	if _, _, _, err := pkcs12.DecodeChain(data, "wrong"); err == nil {
		t.Fatal("expected decode failure with wrong password")
	}
}
