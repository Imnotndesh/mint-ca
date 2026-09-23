package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setBaseEnv(t *testing.T, dbDSN string) {
	t.Helper()
	t.Setenv("MINT_MASTER_KEY", strings.Repeat("ab", 32))
	t.Setenv("MINT_DB_DRIVER", "sqlite")
	t.Setenv("MINT_DB_DSN", dbDSN)
}

// TestTLSModeDerivation verifies the three TLS modes are derived from the env.
func TestTLSModeDerivation(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "db.sqlite")

	t.Run("disabled", func(t *testing.T) {
		setBaseEnv(t, dsn)
		t.Setenv("MINT_TLS_DISABLED", "true")
		os.Unsetenv("MINT_TLS_CERT")
		os.Unsetenv("MINT_TLS_KEY")
		c, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := c.Server.TLSMode(); got != TLSDisabledMode {
			t.Fatalf("mode = %q, want disabled", got)
		}
	})

	t.Run("auto", func(t *testing.T) {
		setBaseEnv(t, dsn)
		os.Unsetenv("MINT_TLS_DISABLED")
		os.Unsetenv("MINT_TLS_CERT")
		os.Unsetenv("MINT_TLS_KEY")
		c, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := c.Server.TLSMode(); got != TLSAutoMode {
			t.Fatalf("mode = %q, want auto", got)
		}
	})

	t.Run("provided", func(t *testing.T) {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "server.crt")
		keyFile := filepath.Join(dir, "server.key")
		if err := os.WriteFile(certFile, []byte("cert"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, []byte("key"), 0600); err != nil {
			t.Fatal(err)
		}
		setBaseEnv(t, dsn)
		os.Unsetenv("MINT_TLS_DISABLED")
		t.Setenv("MINT_TLS_CERT", certFile)
		t.Setenv("MINT_TLS_KEY", keyFile)
		c, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := c.Server.TLSMode(); got != TLSProvidedMode {
			t.Fatalf("mode = %q, want provided", got)
		}
	})
}

// TestLoadAutoWithoutCert verifies the reported pain point: auto mode must load
// with no cert files present at boot.
func TestLoadAutoWithoutCert(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "db.sqlite")
	setBaseEnv(t, dsn)
	os.Unsetenv("MINT_TLS_DISABLED")
	os.Unsetenv("MINT_TLS_CERT")
	os.Unsetenv("MINT_TLS_KEY")
	if _, err := Load(); err != nil {
		t.Fatalf("auto mode should load without cert material: %v", err)
	}
}

// TestLoadProvidedRequiresFiles verifies provided mode still fails fast when
// the operator-supplied files are missing.
func TestLoadProvidedRequiresFiles(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "db.sqlite")
	setBaseEnv(t, dsn)
	os.Unsetenv("MINT_TLS_DISABLED")
	t.Setenv("MINT_TLS_CERT", filepath.Join(t.TempDir(), "missing.crt"))
	t.Setenv("MINT_TLS_KEY", filepath.Join(t.TempDir(), "missing.key"))
	if _, err := Load(); err == nil {
		t.Fatal("expected error when provided cert files are missing")
	}
}

// TestLoadProvidedHalfSet verifies providing only one of cert/key is rejected.
func TestLoadProvidedHalfSet(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "db.sqlite")
	setBaseEnv(t, dsn)
	os.Unsetenv("MINT_TLS_DISABLED")
	os.Unsetenv("MINT_TLS_CERT")
	t.Setenv("MINT_TLS_KEY", filepath.Join(t.TempDir(), "k.key"))
	if _, err := Load(); err == nil {
		t.Fatal("expected error when only one of cert/key is set")
	}
}

// TestAutoTLSDefaultsNextToSQLite verifies auto-mode certs resolve under the
// sqlite data directory.
func TestAutoTLSDefaultsNextToSQLite(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "db.sqlite")
	setBaseEnv(t, dsn)
	os.Unsetenv("MINT_TLS_DISABLED")
	os.Unsetenv("MINT_TLS_CERT")
	os.Unsetenv("MINT_TLS_KEY")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := c.ResolvedTLSCertFile(); got != filepath.Join(dir, "server.crt") {
		t.Fatalf("resolved cert = %q, want %q", got, filepath.Join(dir, "server.crt"))
	}
	if got := c.ResolvedTLSKeyFile(); got != filepath.Join(dir, "server.key") {
		t.Fatalf("resolved key = %q, want %q", got, filepath.Join(dir, "server.key"))
	}
}
