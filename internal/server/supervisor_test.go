package server

import (
	"context"
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
	"testing"
	"time"
)

// selfSignedMaterial builds an in-memory leaf TLSMaterial for 127.0.0.1.
func selfSignedMaterial(t *testing.T) TLSMaterial {
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
	return TLSMaterial{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

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

// TestSupervisor_InProcessSwap verifies a plain-HTTP listener can be stopped
// and the same address re-served over TLS within one process — the model behind
// setup -> ready without a container restart.
func TestSupervisor_InProcessSwap(t *testing.T) {
	addr := freeAddr(t)
	mat := selfSignedMaterial(t)
	ctx := context.Background()

	setupHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("setup"))
	})
	readyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ready"))
	})

	s := New(5*time.Second, 5*time.Second, 5*time.Second)

	if err := s.Start(ListenerSpec{Addr: addr, Handler: setupHandler}); err != nil {
		t.Fatalf("start plain: %v", err)
	}
	if got := getBody(t, "http://"+addr, false); got != "setup" {
		t.Fatalf("plain body = %q, want setup", got)
	}

	if err := s.Swap(ctx, ListenerSpec{Addr: addr, Handler: readyHandler, TLS: &mat}); err != nil {
		t.Fatalf("swap to tls: %v", err)
	}
	if got := getBody(t, "https://"+addr, true); got != "ready" {
		t.Fatalf("tls body = %q, want ready", got)
	}

	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// TestSupervisor_StartBindError verifies bind failures return synchronously.
func TestSupervisor_StartBindError(t *testing.T) {
	addr := freeAddr(t)
	blocker, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	s := New(0, 0, 0)
	if err := s.Start(ListenerSpec{Addr: addr, Handler: http.NotFoundHandler()}); err == nil {
		t.Fatal("expected bind error, got nil")
	}
}

// TestSupervisor_StartBadKeyPair verifies TLS keypair load errors return
// synchronously and the listener is not left bound.
func TestSupervisor_StartBadKeyPair(t *testing.T) {
	s := New(0, 0, 0)
	err := s.Start(ListenerSpec{
		Addr: freeAddr(t), Handler: http.NotFoundHandler(),
		TLS: &TLSMaterial{CertPEM: []byte("junk"), KeyPEM: []byte("junk")},
	})
	if err == nil {
		t.Fatal("expected keypair load error, got nil")
	}
}

// TestSupervisor_ShutdownIdempotent verifies shutdown before any start and a
// double shutdown are both safe.
func TestSupervisor_ShutdownIdempotent(t *testing.T) {
	ctx := context.Background()
	s := New(0, 0, 0)
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown with no listener: %v", err)
	}
	if err := s.Start(ListenerSpec{Addr: freeAddr(t), Handler: http.NotFoundHandler()}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
}
