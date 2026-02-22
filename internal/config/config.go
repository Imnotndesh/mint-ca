package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration for mint-ca resolved from environment
// variables. It is constructed once at startup by Load() and then passed by
// value or pointer to the components that need it.
//
// No package other than this one calls os.Getenv. If you need a value from the
// environment, add it here.
type Config struct {
	Server  ServerConfig
	Storage StorageConfig
	Crypto  CryptoConfig
	ACME    ACMEConfig
	CRL     CRLConfig
	Log     LogConfig
}

// ServerConfig controls the HTTP/TLS listener.
type ServerConfig struct {
	// ListenAddr is the address and port to bind on.
	// Default: ":8443"
	// Env: MINT_LISTEN_ADDR
	ListenAddr string

	// TLSCertFile and TLSKeyFile are paths to the PEM-encoded server TLS
	// certificate and private key. Required unless TLSDisabled is true.
	// Env: MINT_TLS_CERT, MINT_TLS_KEY
	TLSCertFile string
	TLSKeyFile  string

	// TLSDisabled runs the server over plain HTTP. Only for local development.
	// Never set this in production — the API handles encrypted private key
	// material and must not be exposed unencrypted.
	// Default: false
	// Env: MINT_TLS_DISABLED
	TLSDisabled bool

	// ReadTimeout, WriteTimeout, IdleTimeout are the HTTP server timeouts.
	// Defaults: 30s, 60s, 120s
	// Env: MINT_READ_TIMEOUT_SECONDS, MINT_WRITE_TIMEOUT_SECONDS, MINT_IDLE_TIMEOUT_SECONDS
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// StorageConfig controls which database backend is used and how to connect.
type StorageConfig struct {
	// Driver is either "sqlite" (default) or "postgres".
	// Env: MINT_DB_DRIVER
	Driver string

	// DSN is the data source name.
	// For sqlite: an absolute path, e.g. /data/mint-ca.db
	// For postgres: a connection string, e.g.
	//   postgres://mintca:secret@db:5432/mintca?sslmode=require
	// Default for sqlite: /data/mint-ca.db
	// Env: MINT_DB_DSN
	DSN string
}

// CryptoConfig holds key material for the keystore.
type CryptoConfig struct {
	// MasterKey is the 32-byte AES-256 key used to encrypt CA private keys at
	// rest. It is provided as a 64-character lowercase hex string in the
	// environment and decoded to []byte here. The hex string is cleared after
	// decoding.
	//
	// Generate with: openssl rand -hex 32
	//
	// Env: MINT_MASTER_KEY (required)
	MasterKey []byte
}

// ACMEConfig controls the ACME protocol endpoint.
type ACMEConfig struct {
	// Enabled controls whether the ACME endpoints are registered on the router.
	// Default: false
	// Env: MINT_ACME_ENABLED
	Enabled bool

	// BaseURL is the public HTTPS URL at which mint-ca is reachable.
	// It is used to construct the URLs returned in the ACME directory response.
	// Must not have a trailing slash.
	// Example: https://ca.internal:8443
	// Env: MINT_ACME_BASE_URL (required when Enabled is true)
	BaseURL string

	// EABRequired controls whether every new ACME account registration must
	// include a valid External Account Binding. When true, unauthenticated
	// account creation is rejected. Strongly recommended for production.
	// Default: false
	// Env: MINT_ACME_EAB_REQUIRED
	EABRequired bool
}

// CRLConfig controls the CRL background refresh behaviour.
type CRLConfig struct {
	// RefreshInterval is how often the background goroutine regenerates CRLs
	// for all active CAs. This keeps the NextUpdate field current even when
	// no revocations occur.
	// Default: 1h
	// Env: MINT_CRL_REFRESH_INTERVAL_SECONDS
	RefreshInterval time.Duration

	// Validity is how long a freshly generated CRL is valid (the window between
	// ThisUpdate and NextUpdate). Clients should re-fetch before this expires.
	// Default: 24h
	// Env: MINT_CRL_VALIDITY_SECONDS
	Validity time.Duration
}

// LogConfig controls structured logging output.
type LogConfig struct {
	// Level is one of: debug, info, warn, error.
	// Default: info
	// Env: MINT_LOG_LEVEL
	Level string

	// JSON controls whether log output is JSON (true) or human-readable text (false).
	// Default: false
	// Env: MINT_LOG_JSON
	JSON bool
}

// Load reads all configuration from environment variables, applies defaults,
// validates every field, and returns a fully populated Config.
//
// If any required value is missing or any value is malformed, Load returns an
// error that lists every problem found — not just the first one — so the
// operator can fix everything in a single edit.
func Load() (*Config, error) {
	c := &Config{}
	var errs []string

	c.Server.ListenAddr = envOr("MINT_LISTEN_ADDR", ":8443")
	c.Server.TLSCertFile = os.Getenv("MINT_TLS_CERT")
	c.Server.TLSKeyFile = os.Getenv("MINT_TLS_KEY")
	c.Server.TLSDisabled = envBool("MINT_TLS_DISABLED")
	c.Server.ReadTimeout = envDuration("MINT_READ_TIMEOUT_SECONDS", 30*time.Second)
	c.Server.WriteTimeout = envDuration("MINT_WRITE_TIMEOUT_SECONDS", 60*time.Second)
	c.Server.IdleTimeout = envDuration("MINT_IDLE_TIMEOUT_SECONDS", 120*time.Second)

	if !c.Server.TLSDisabled {
		if c.Server.TLSCertFile == "" {
			errs = append(errs, "MINT_TLS_CERT is required when TLS is enabled (set MINT_TLS_DISABLED=true for development)")
		} else if _, err := os.Stat(c.Server.TLSCertFile); err != nil {
			errs = append(errs, fmt.Sprintf("MINT_TLS_CERT: file not found or not readable: %s", c.Server.TLSCertFile))
		}
		if c.Server.TLSKeyFile == "" {
			errs = append(errs, "MINT_TLS_KEY is required when TLS is enabled")
		} else if _, err := os.Stat(c.Server.TLSKeyFile); err != nil {
			errs = append(errs, fmt.Sprintf("MINT_TLS_KEY: file not found or not readable: %s", c.Server.TLSKeyFile))
		}
	}

	c.Storage.Driver = strings.ToLower(strings.TrimSpace(envOr("MINT_DB_DRIVER", "sqlite")))
	c.Storage.DSN = strings.TrimSpace(os.Getenv("MINT_DB_DSN"))

	switch c.Storage.Driver {
	case "sqlite":
		if c.Storage.DSN == "" {
			c.Storage.DSN = "/data/mint-ca.db"
		}
	case "postgres":
		if c.Storage.DSN == "" {
			errs = append(errs,
				"MINT_DB_DSN is required when MINT_DB_DRIVER=postgres\n"+
					"  example: postgres://mintca:secret@db:5432/mintca?sslmode=require",
			)
		}
	default:
		errs = append(errs, fmt.Sprintf(
			"MINT_DB_DRIVER: unsupported value %q — must be \"sqlite\" or \"postgres\"",
			c.Storage.Driver,
		))
	}

	masterKeyHex := strings.TrimSpace(os.Getenv("MINT_MASTER_KEY"))
	if masterKeyHex == "" {
		errs = append(errs,
			"MINT_MASTER_KEY is required\n"+
				"  generate with: openssl rand -hex 32",
		)
	} else {
		key, err := hex.DecodeString(masterKeyHex)
		if err != nil {
			errs = append(errs,
				"MINT_MASTER_KEY: not valid hexadecimal — generate with: openssl rand -hex 32",
			)
		} else if len(key) != 32 {
			errs = append(errs, fmt.Sprintf(
				"MINT_MASTER_KEY: must decode to exactly 32 bytes (got %d) — generate with: openssl rand -hex 32",
				len(key),
			))
		} else {
			c.Crypto.MasterKey = key
		}
	}

	c.ACME.Enabled = envBool("MINT_ACME_ENABLED")
	c.ACME.BaseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("MINT_ACME_BASE_URL")), "/")
	c.ACME.EABRequired = envBool("MINT_ACME_EAB_REQUIRED")

	if c.ACME.Enabled {
		if c.ACME.BaseURL == "" {
			errs = append(errs,
				"MINT_ACME_BASE_URL is required when MINT_ACME_ENABLED=true\n"+
					"  example: https://ca.internal:8443",
			)
		} else if !strings.HasPrefix(c.ACME.BaseURL, "https://") && !strings.HasPrefix(c.ACME.BaseURL, "http://") {
			errs = append(errs,
				"MINT_ACME_BASE_URL must begin with https:// (or http:// for development)",
			)
		}
	}

	c.CRL.RefreshInterval = envDuration("MINT_CRL_REFRESH_INTERVAL_SECONDS", 1*time.Hour)
	c.CRL.Validity = envDuration("MINT_CRL_VALIDITY_SECONDS", 24*time.Hour)

	if c.CRL.RefreshInterval < 1*time.Minute {
		errs = append(errs,
			"MINT_CRL_REFRESH_INTERVAL_SECONDS must be at least 60 seconds",
		)
	}
	if c.CRL.Validity < c.CRL.RefreshInterval {
		errs = append(errs,
			"MINT_CRL_VALIDITY_SECONDS must be greater than MINT_CRL_REFRESH_INTERVAL_SECONDS — "+
				"a CRL must be valid for longer than the refresh interval or clients will see expired CRLs",
		)
	}

	c.Log.Level = strings.ToLower(strings.TrimSpace(envOr("MINT_LOG_LEVEL", "info")))
	c.Log.JSON = envBool("MINT_LOG_JSON")

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
		// valid
	default:
		errs = append(errs, fmt.Sprintf(
			"MINT_LOG_LEVEL: unsupported value %q — must be one of: debug, info, warn, error",
			c.Log.Level,
		))
	}

	if len(errs) > 0 {
		return nil, formatErrors(errs)
	}

	return c, nil
}

// Redact returns a copy of the config safe for logging at startup.
// The master key is replaced with a fixed string so it never appears in logs.
func (c *Config) Redact() map[string]interface{} {
	masterKeyStatus := "not set"
	if len(c.Crypto.MasterKey) == 32 {
		masterKeyStatus = "[32 bytes, redacted]"
	}

	return map[string]interface{}{
		"server": map[string]interface{}{
			"listen_addr":   c.Server.ListenAddr,
			"tls_disabled":  c.Server.TLSDisabled,
			"tls_cert_file": c.Server.TLSCertFile,
			"tls_key_file":  c.Server.TLSKeyFile,
			"read_timeout":  c.Server.ReadTimeout.String(),
			"write_timeout": c.Server.WriteTimeout.String(),
			"idle_timeout":  c.Server.IdleTimeout.String(),
		},
		"storage": map[string]interface{}{
			"driver": c.Storage.Driver,
			"dsn":    redactDSN(c.Storage.DSN),
		},
		"crypto": map[string]interface{}{
			"master_key": masterKeyStatus,
		},
		"acme": map[string]interface{}{
			"enabled":      c.ACME.Enabled,
			"base_url":     c.ACME.BaseURL,
			"eab_required": c.ACME.EABRequired,
		},
		"crl": map[string]interface{}{
			"refresh_interval": c.CRL.RefreshInterval.String(),
			"validity":         c.CRL.Validity.String(),
		},
		"log": map[string]interface{}{
			"level": c.Log.Level,
			"json":  c.Log.JSON,
		},
	}
}

// envOr returns the value of the environment variable named key, or def if
// the variable is unset or empty.
func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// envBool returns true if the named environment variable is set to one of:
// "true", "1", "yes", "on" (case-insensitive).
func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// envDuration reads an environment variable as a number of seconds and returns
// it as a time.Duration. If the variable is unset, empty, zero, or cannot be
// parsed, def is returned. Negative values are treated as invalid and def is
// returned.
func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Second
}

// formatErrors joins all validation errors into a single descriptive error that
// lists every problem so the operator can fix them all in one go.
func formatErrors(errs []string) error {
	if len(errs) == 1 {
		return errors.New("mint-ca: configuration error:\n  • " + errs[0])
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("mint-ca: %d configuration errors:\n", len(errs)))
	for _, e := range errs {
		b.WriteString("  • ")
		// Indent continuation lines so multi-line error messages align.
		b.WriteString(strings.ReplaceAll(e, "\n", "\n    "))
		b.WriteString("\n")
	}
	return errors.New(strings.TrimRight(b.String(), "\n"))
}

// redactDSN removes the password from a postgres DSN for safe logging.
// For SQLite file paths it returns the path as-is.
func redactDSN(dsn string) string {
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		return dsn
	}
	// Parse out the password portion from postgres://user:password@host/db
	// We do a best-effort string replacement rather than full URL parsing to
	// avoid importing net/url just for logging.
	atIdx := strings.Index(dsn, "@")
	if atIdx == -1 {
		return dsn
	}
	schemeEnd := strings.Index(dsn, "://")
	if schemeEnd == -1 {
		return dsn
	}
	userInfo := dsn[schemeEnd+3 : atIdx]
	colonIdx := strings.Index(userInfo, ":")
	if colonIdx == -1 {
		// No password in the DSN.
		return dsn
	}
	user := userInfo[:colonIdx]
	return dsn[:schemeEnd+3] + user + ":***@" + dsn[atIdx+1:]
}
