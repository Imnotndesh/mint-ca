package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/config"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/ha"
	"mint-ca/internal/notify"
	"mint-ca/internal/policy"
	"mint-ca/internal/setup"
	"mint-ca/internal/sshca"
	"mint-ca/internal/sshca/krl"
	"mint-ca/internal/storage"
)

// TestAutoModeSetupReadySwap is the regression test for the reported pain
// point: a fresh instance with TLS intended (auto mode) and no cert on disk
// must boot to HTTP setup and then transition the same process to HTTPS using
// the cert minted during setup — no container restart.
func TestAutoModeSetupReadySwap(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "mint-ca.db")
	bootstrap := "test-bootstrap-key"
	addr := reserveAddr(t)

	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}

	t.Setenv("MINT_MASTER_KEY", hex.EncodeToString(master))
	t.Setenv("MINT_DB_DRIVER", "sqlite")
	t.Setenv("MINT_DB_DSN", dbPath)
	t.Setenv("MINT_LISTEN_ADDR", addr)
	t.Setenv("MINT_BOOTSTRAP_KEY", bootstrap)
	t.Setenv("MINT_TLS_DISABLED", "")
	os.Unsetenv("MINT_TLS_CERT")
	os.Unsetenv("MINT_TLS_KEY")
	t.Setenv("MINT_LOG_LEVEL", "error")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Server.TLSMode() != config.TLSAutoMode {
		t.Fatalf("expected auto TLS mode, got %s", cfg.Server.TLSMode())
	}

	store, err := storage.New()
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	defer store.Close()
	if err := setup.SeedRateLimitConfigs(context.Background(), store, cfg.RateLimit); err != nil {
		t.Fatal(err)
	}
	rlEngine, err := setup.LoadRateLimitEngine(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := mintcrypto.NewKeystore(cfg.Crypto.MasterKey)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Zero()

	buildDeps := func() (*ca.Engine, *policy.Engine, *sshca.Engine, *revocation.CRLManager, *revocation.OCSPResponder, *krl.Manager) {
		caEngine := ca.NewEngine(store, ks, cfg.ACME.BaseURL)
		policyEngine := policy.NewEngine(store)
		sshcaEngine := sshca.NewEngine(store, ks, policyEngine)
		crlManager := revocation.NewCRLManager(store, ks, cfg.ACME.BaseURL, false)
		ocspResponder := revocation.NewOCSPResponder(store, ks)
		sshKRLManager := krl.NewManager(store)
		return caEngine, policyEngine, sshcaEngine, crlManager, ocspResponder, sshKRLManager
	}
	caEngine, policyEngine, sshcaEngine, crlManager, ocspResponder, sshKRLManager := buildDeps()
	notifyMgr := notify.NewManager(store, ks)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runServer(ctx, cfg, store, rlEngine, caEngine, policyEngine,
			sshcaEngine, crlManager, ocspResponder, sshKRLManager,
			ha.NewElector(nil, "node", 0, 0), notifyMgr)
	}()

	base := "http://" + addr
	// 1. The fresh instance boots to HTTP setup on the same port.
	waitFor(t, 10*time.Second, func() bool {
		return getStatus(base+"/setup/state", false) == http.StatusOK
	})
	body := getBody(t, base+"/setup/state", false)
	var st struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("parse setup state: %v (body=%q)", err, body)
	}
	if st.State != "setup" {
		t.Fatalf("state = %q, want setup", st.State)
	}

	// 1b. The transition endpoint reports "setup" while in setup mode.
	if status, configured := transitionStatus(t, base+"/setup/transition", false); status != "setup" || configured {
		t.Fatalf("transition before swap = status %q configured %v, want setup/false", status, configured)
	}

	// 2. Complete setup over HTTP using the known bootstrap key.
	if err := postTo(base+"/setup/root-ca", bootstrap, map[string]interface{}{
		"common_name": "Transition Root", "key_algo": "ecdsa-p256", "ttl_days": 3650,
	}); err != nil {
		t.Fatalf("root-ca: %v", err)
	}
	if err := postTo(base+"/setup/api-key", bootstrap, map[string]interface{}{
		"name": "transition-admin", "terms_accepted": true,
	}); err != nil {
		t.Fatalf("api-key: %v", err)
	}

	// 3. The same process/port now serves HTTPS with the minted cert.
	waitFor(t, 10*time.Second, func() bool {
		return getStatus("https://"+addr+"/healthz", true) == http.StatusOK
	})
	// 3b. The transition endpoint (now over HTTPS) reports ready.
	waitFor(t, 10*time.Second, func() bool {
		status, configured := transitionStatus(t, "https://"+addr+"/setup/transition", true)
		return status == "ready" && configured
	})
	if got := getBody(t, "https://"+addr+"/healthz", true); got == "" {
		t.Fatal("expected a response over HTTPS")
	}
	// Plain HTTP to the now-TLS port should fail (TLS handshake on plain socket).
	if getStatus(base+"/healthz", false) == http.StatusOK {
		t.Fatal("plain HTTP should not still serve after the swap to HTTPS")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runServer returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runServer did not shut down after cancel")
	}
}

func reserveAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func postTo(url, token string, body interface{}) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		rb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s: %d %s", url, resp.StatusCode, rb)
	}
	return nil
}

func tlsClient() *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

func getStatus(url string, tlsOn bool) int {
	c := http.DefaultClient
	if tlsOn {
		c = tlsClient()
	}
	resp, err := c.Get(url)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func getBody(t *testing.T, url string, tlsOn bool) string {
	t.Helper()
	c := http.DefaultClient
	if tlsOn {
		c = tlsClient()
	}
	resp, err := c.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func transitionStatus(t *testing.T, url string, tlsOn bool) (string, bool) {
	t.Helper()
	b := getBody(t, url, tlsOn)
	var tr struct {
		Status     string `json:"status"`
		Configured bool   `json:"configured"`
	}
	if err := json.Unmarshal([]byte(b), &tr); err != nil {
		t.Fatalf("parse transition: %v (body=%q)", err, b)
	}
	return tr.Status, tr.Configured
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}
