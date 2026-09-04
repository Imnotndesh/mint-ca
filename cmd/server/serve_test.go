package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// freeAddr returns an available 127.0.0.1 TCP address and releases it so a
// listener can reuse the exact port across the setup->ready swap.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func getBody(t *testing.T, base string, tlsOn bool) string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	if tlsOn {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	resp, err := client.Get(base)
	if err != nil {
		t.Fatalf("GET %s: %v", base, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// TestServeListener_InProcessSwap verifies that a plain-HTTP listener can be
// stopped and the same addr re-served over TLS within one process (the model
// behind setup->ready without a container restart).
func TestServeListener_InProcessSwap(t *testing.T) {
	addr := freeAddr(t)
	certFile, keyFile := writeSelfSignedCert(t)

	setupHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("setup"))
	})
	readyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ready"))
	})

	// Phase 1: plain HTTP setup.
	stopSetup, _, err := serveListener(addr, setupHandler, false, certFile, keyFile, 5e9, 5e9, 5e9)
	if err != nil {
		t.Fatalf("serve plain: %v", err)
	}
	if got := getBody(t, "http://"+addr, false); got != "setup" {
		t.Fatalf("plain body = %q, want setup", got)
	}
	stopSetup()

	// Phase 2: same addr served over TLS (ready) — still in-process.
	stopReady, _, err := serveListener(addr, readyHandler, true, certFile, keyFile, 5e9, 5e9, 5e9)
	if err != nil {
		t.Fatalf("serve tls: %v", err)
	}
	if got := getBody(t, "https://"+addr, true); got != "ready" {
		t.Fatalf("tls body = %q, want ready", got)
	}
	stopReady()
}
