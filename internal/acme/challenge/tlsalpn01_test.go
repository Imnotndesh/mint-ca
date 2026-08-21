package challenge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

type certOpts struct {
	domain        string
	digest        []byte
	extraSAN      string
	nonCritical   bool
	notSelfSigned bool
}

func buildTestCert(t *testing.T, opts certOpts) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var extra []pkix.Extension
	if opts.digest != nil {
		val, err := asn1.Marshal(opts.digest)
		if err != nil {
			t.Fatalf("marshal digest: %v", err)
		}
		extra = append(extra, pkix.Extension{
			Id:       idPeACMEIdentifier,
			Critical: !opts.nonCritical,
			Value:    val,
		})
	}

	dnsNames := []string{opts.domain}
	if opts.extraSAN != "" {
		dnsNames = append(dnsNames, opts.extraSAN)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: opts.domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              dnsNames,
		ExtraExtensions:       extra,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	signerTemplate := template
	signerKey := priv
	if opts.notSelfSigned {
		otherPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signerTemplate = &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "some-other-issuer"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}
		signerKey = otherPriv
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerTemplate, &priv.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func startACMETLSListener(t *testing.T, cert tls.Certificate, negotiateALPN bool) (net.Listener, string) {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if negotiateALPN {
		cfg.NextProtos = []string{acmeTLS1Protocol}
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(50 * time.Millisecond)
			}(conn)
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return ln, port
}

func portToInt(t *testing.T, port string) int {
	t.Helper()
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return n
}

// newTestValidator builds a validator for domain's cert.
func newTestValidator(t *testing.T, port string) *TLSALPN01Validator {
	t.Helper()
	v := NewTLSALPN01Validator(portToInt(t, port))
	v.dialAddr = "127.0.0.1:" + port
	return v
}

func TestTLSALPN01_Success(t *testing.T) {
	domain := "example.com"
	keyAuth := "test-token.test-thumbprint"
	digest := sha256.Sum256([]byte(keyAuth))

	cert := buildTestCert(t, certOpts{domain: domain, digest: digest[:]})
	ln, port := startACMETLSListener(t, cert, true)
	defer func(ln net.Listener) {
		err := ln.Close()
		if err != nil {
			return
		}
	}(ln)

	v := newTestValidator(t, port)
	if err := v.Validate(context.Background(), domain, keyAuth); err != nil {
		t.Errorf("expected success, got: %v", err)
	}
}

func TestTLSALPN01_WildcardRejected(t *testing.T) {
	v := NewTLSALPN01Validator(443)
	if err := v.Validate(context.Background(), "*.example.com", "irrelevant"); err == nil {
		t.Fatal("expected wildcard identifier to be rejected")
	}
}

func TestTLSALPN01_ALPNNotNegotiated_Fails(t *testing.T) {
	domain := "example.com"
	keyAuth := "test-token.test-thumbprint"
	digest := sha256.Sum256([]byte(keyAuth))

	cert := buildTestCert(t, certOpts{domain: domain, digest: digest[:]})
	ln, port := startACMETLSListener(t, cert, false)
	defer ln.Close()

	v := newTestValidator(t, port)
	if err := v.Validate(context.Background(), domain, keyAuth); err == nil {
		t.Fatal("expected failure when ALPN protocol is not negotiated")
	}
}

func TestTLSALPN01_DigestMismatch_Fails(t *testing.T) {
	domain := "example.com"
	wrongDigest := sha256.Sum256([]byte("wrong-key-auth"))

	cert := buildTestCert(t, certOpts{domain: domain, digest: wrongDigest[:]})
	ln, port := startACMETLSListener(t, cert, true)
	defer ln.Close()

	v := newTestValidator(t, port)
	if err := v.Validate(context.Background(), domain, "correct-key-auth"); err == nil {
		t.Fatal("expected digest mismatch to fail validation")
	}
}

func TestTLSALPN01_MissingExtension_Fails(t *testing.T) {
	domain := "example.com"
	cert := buildTestCert(t, certOpts{domain: domain, digest: nil})
	ln, port := startACMETLSListener(t, cert, true)
	defer ln.Close()

	v := newTestValidator(t, port)
	if err := v.Validate(context.Background(), domain, "any-key-auth"); err == nil {
		t.Fatal("expected missing acmeIdentifier extension to fail validation")
	}
}

func TestTLSALPN01_NonCriticalExtension_Fails(t *testing.T) {
	domain := "example.com"
	keyAuth := "test-token.test-thumbprint"
	digest := sha256.Sum256([]byte(keyAuth))

	cert := buildTestCert(t, certOpts{domain: domain, digest: digest[:], nonCritical: true})
	ln, port := startACMETLSListener(t, cert, true)
	defer ln.Close()

	v := newTestValidator(t, port)
	if err := v.Validate(context.Background(), domain, keyAuth); err == nil {
		t.Fatal("expected non-critical acmeIdentifier extension to fail validation")
	}
}

func TestTLSALPN01_NotSelfSigned_Fails(t *testing.T) {
	domain := "example.com"
	keyAuth := "test-token.test-thumbprint"
	digest := sha256.Sum256([]byte(keyAuth))

	cert := buildTestCert(t, certOpts{domain: domain, digest: digest[:], notSelfSigned: true})
	ln, port := startACMETLSListener(t, cert, true)
	defer ln.Close()

	v := newTestValidator(t, port)
	if err := v.Validate(context.Background(), domain, keyAuth); err == nil {
		t.Fatal("expected non-self-signed certificate to fail validation")
	}
}

func TestTLSALPN01_ExtraSAN_Fails(t *testing.T) {
	domain := "example.com"
	keyAuth := "test-token.test-thumbprint"
	digest := sha256.Sum256([]byte(keyAuth))

	cert := buildTestCert(t, certOpts{domain: domain, digest: digest[:], extraSAN: "other.example.com"})
	ln, port := startACMETLSListener(t, cert, true)
	defer ln.Close()

	v := newTestValidator(t, port)
	if err := v.Validate(context.Background(), domain, keyAuth); err == nil {
		t.Fatal("expected certificate with more than one SAN to fail validation")
	}
}
