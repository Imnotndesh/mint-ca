package tpm2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"mint-ca/internal/attestation"
)

func genEK(t *testing.T) (certPEM []byte, key *ecdsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test EK"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
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
	return
}

func mkStatement(t *testing.T, ekPEM []byte, key *ecdsa.PrivateKey, csrDER []byte) attestation.Statement {
	t.Helper()
	digest := sha256.Sum256(csrDER)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	data, _ := json.Marshal(statement{
		EKCertPEM:    string(ekPEM),
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
	})
	return attestation.Statement{Format: Format, Data: data}
}

func TestVerify_ValidSignature_Succeeds(t *testing.T) {
	ekPEM, key, cert := genEK(t)
	csrDER := []byte("pretend-csr-bytes")
	stmt := mkStatement(t, ekPEM, key, csrDER)

	v := New(nil)
	res, err := v.Verify(context.Background(), csrDER, stmt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Verified {
		t.Error("expected Verified=true")
	}
	if res.KeyID != cert.SerialNumber.String() {
		t.Errorf("KeyID = %q, want %q", res.KeyID, cert.SerialNumber.String())
	}
}

func TestVerify_WrongCSR_Fails(t *testing.T) {
	ekPEM, key, _ := genEK(t)
	stmt := mkStatement(t, ekPEM, key, []byte("csr-a"))

	v := New(nil)
	_, err := v.Verify(context.Background(), []byte("csr-b"), stmt)
	if err == nil {
		t.Fatal("expected verification to fail for a mismatched CSR")
	}
}

func TestVerify_UntrustedRoot_Fails(t *testing.T) {
	ekPEM, key, _ := genEK(t)
	csrDER := []byte("pretend-csr-bytes")
	stmt := mkStatement(t, ekPEM, key, csrDER)

	// A non-nil, empty pool means "only these roots are trusted" — the
	// self-signed test EK cert won't chain to anything in it.
	v := New(x509.NewCertPool())
	_, err := v.Verify(context.Background(), csrDER, stmt)
	if err == nil {
		t.Fatal("expected an untrusted EK certificate to be rejected")
	}
}

func TestVerify_MalformedStatement_Fails(t *testing.T) {
	v := New(nil)
	_, err := v.Verify(context.Background(), []byte("csr"), attestation.Statement{Format: Format, Data: []byte("not json")})
	if err == nil {
		t.Fatal("expected an error for malformed statement data")
	}
}
