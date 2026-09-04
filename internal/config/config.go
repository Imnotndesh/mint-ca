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
	Server      ServerConfig
	Storage     StorageConfig
	Crypto      CryptoConfig
	ACME        ACMEConfig
	CRL         CRLConfig
	Log         LogConfig
	RateLimit   RateLimitConfig
	MTLS        MTLSConfig
	Renewal     RenewalConfig
	SCEP        SCEPConfig
	Events      EventsConfig
	Attestation AttestationConfig
	HA          HAConfig
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

	// BootstrapKey, when set, is used as the bootstrap API key for first-boot
	// setup instead of mint-ca generating (and only printing to console) a
	// random one. This lets a CLI/CI init drive onboarding without a human on
	// the server console. Empty by default (then a random one is printed).
	// Env: MINT_BOOTSTRAP_KEY
	BootstrapKey string
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

	// CAADomain is this CA's public identity announced in its own CAA
	// issue/issuewild records (RFC 8659). Operators grant mint-ca the right
	// to issue by publishing, e.g.
	//
	//	example.com	CAA 0 issue "<CAADomain>"
	//
	// When set, mint-ca checks each requested identifier's Relevant RRset and
	// refuses issuance unless the RRset is empty or authorises this domain.
	// When empty, CAA lookup is skipped entirely (and the ACME service does
	// not restrict issuance).
	// Env: MINT_ACME_CAA_DOMAIN
	CAADomain string

	// CAADNSServer optionally overrides the resolver used for CAA lookups, in
	// host:port form (e.g. "1.1.1.1:53"). Empty means read the system
	// resolvers from /etc/resolv.conf.
	// Env: MINT_ACME_CAA_DNS_SERVER
	CAADNSServer string

	// CAABypassLabels is a comma-separated list of domain labels for which CAA
	// checking is skipped (an explicit CP/CPS exception per RFC 8659 §3). Any
	// requested identifier that is exactly, or is a subdomain of, one of these
	// labels bypasses CAA enforcement.
	// Env: MINT_ACME_CAA_BYPASS_LABELS
	CAABypassLabels string
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

	// DeltaEnabled turns on delta CRL generation/serving. Opt-in — default
	// false so existing deployments see no behavior change.
	// Default: false
	// Env: MINT_CRL_DELTA_ENABLED
	DeltaEnabled bool

	// BaseRefreshInterval is how often the full base CRL is regenerated while
	// delta CRLs are enabled. Deltas are refreshed on every revocation and on
	// the main RefreshInterval ticker; base CRLs can be rebuilt less frequently
	// to reduce churn. Ignored when DeltaEnabled is false.
	// Must be >= RefreshInterval.
	// Default: RefreshInterval
	// Env: MINT_CRL_BASE_REFRESH_INTERVAL_SECONDS
	BaseRefreshInterval time.Duration
}

// RateLimitOverride holds an optional first-boot-only override for one
// hardcoded default limiter. Zero value (both fields 0) means "no override,
// use the hardcoded default" for that field individually.
type RateLimitOverride struct {
	WindowSeconds int
	MaxRequests   int
}

// RateLimitConfig holds optional env-sourced overrides for the four
// hardcoded default limiters, applied only when seeding the DB for the
// first time (see storage.UpsertRateLimitConfigIfAbsent). If a DB row
// already exists, these are ignored entirely — the DB is authoritative
// after first boot so a future web UI's edits are never clobbered.
type RateLimitConfig struct {
	NewAccountPerIP      RateLimitOverride
	NewOrderPerAccount   RateLimitOverride
	NewAuthzPerAccount   RateLimitOverride
	APIKeyRequestsPerKey RateLimitOverride
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

// MTLSConfig controls the optional mutual-TLS device enrollment listener. When
// enabled, mint-ca runs a separate TLS listener that requires devices to present
// a client certificate chain to a trusted issuer, then issues a new leaf bound
// to the device identity.
type MTLSConfig struct {
	// Enabled turns on the MTLS enrollment listener.
	// Env: MINT_MTLS_ENABLED
	Enabled bool

	// ListenAddr is the address the enrollment listener binds (e.g. ":8444").
	// Env: MINT_MTLS_LISTEN_ADDR
	ListenAddr string

	// ClientCACertPEM is a PEM block of the CA cert (or chain) used to validate
	// device client certificates presented during enrollment.
	// Env: MINT_MTLS_CLIENT_CA
	ClientCACertPEM string

	// ServerCertFile/KeyFile are the server TLS cert/key for this listener.
	// Reuses the main server TLS files when empty.
	// Env: MINT_MTLS_CERT, MINT_MTLS_KEY
	ServerCertFile string
	ServerKeyFile  string
}

// RenewalConfig controls automatic certificate-renewal notices. A background
// worker scans for active certificates whose NotAfter is within the lead window
// and hands each to a configured deliverer (e.g. a webhook POST). The worker is
// the generic trigger; the deliverer is pluggable so future integrations
// (ACME re-issue, a management callback, a CLI) can be added without changing
// the worker.
type RenewalConfig struct {
	// Enabled turns on the renewal worker.
	// Env: MINT_RENEWAL_ENABLED
	Enabled bool

	// IntervalSeconds is how often the worker scans for certs due for renewal.
	// Env: MINT_RENEWAL_INTERVAL_SECONDS
	IntervalSeconds int64

	// LeadSeconds is how long before NotAfter a certificate is considered due
	// for renewal.
	// Env: MINT_RENEWAL_LEAD_SECONDS
	LeadSeconds int64

	// WebhookURL, when set, is POSTed a JSON payload describing each certificate
	// due for renewal, letting an external system perform the actual renewal.
	// Env: MINT_RENEWAL_WEBHOOK_URL
	WebhookURL string

	// ExpiringSeconds is a tighter window than LeadSeconds: certs whose NotAfter
	// falls within this window are classified "expiring_soon" instead of just
	// "due", so automation can distinguish urgency.
	// Env: MINT_RENEWAL_EXPIRING_SECONDS
	ExpiringSeconds int64
}

// SCEPConfig controls the public SCEP (RFC 8894-ish) enrollment endpoint at
// /pki/{caID}/scep. Pre-release, single-user posture: one provisioner handles
// every SCEP enrollment rather than per-device provisioner mapping.
//
// This implementation does not wrap requests/responses in PKCS#7 as the full
// SCEP spec requires (PKIOperation's SignedData/EnvelopedData). It accepts a
// raw PKCS#10 CSR as the POST body and returns a raw DER certificate,
// documented as a deviation in docs/Api.md. Clients or gateways that speak
// full SCEP need a PKCS#7 unwrap/wrap shim in front of this endpoint.
type SCEPConfig struct {
	// Enabled turns on the /pki/{caID}/scep routes.
	// Env: MINT_SCEP_ENABLED
	Enabled bool

	// ProvisionerID is the provisioner every SCEP enrollment is signed under.
	// Env: MINT_SCEP_PROVISIONER_ID
	ProvisionerID string

	// DefaultTTLSeconds is the leaf lifetime granted to SCEP enrollments.
	// Env: MINT_SCEP_DEFAULT_TTL_SECONDS
	DefaultTTLSeconds int64
}

// EventsConfig controls the generic action-notification webhook. When set,
// mint-ca POSTs a JSON event for each significant action (certificate issued,
// certificate revoked) so external systems (SIEM, chat, ticketing) can react
// in real time instead of polling the audit log.
type EventsConfig struct {
	// WebhookURL, when set, is POSTed a JSON payload for each event.
	// Env: MINT_EVENTS_WEBHOOK_URL
	WebhookURL string
}

// AttestationConfig controls hardware-attestation-gated issuance (see
// internal/attestation). Attestation is always opt-in per request (a
// "attestation" field on POST /api/v1/certs/sign); this config only narrows
// what the built-in TPM2 verifier accepts.
type AttestationConfig struct {
	// TPMRootsFile, when set, is a PEM bundle of trusted TPM manufacturer
	// root certificates. The tpm2 verifier only accepts EK certificates
	// chaining to one of these. When empty, any well-formed EK certificate
	// is accepted (proves possession of its key, not genuine TPM hardware —
	// fine for development, not recommended for production).
	// Env: MINT_ATTESTATION_TPM_ROOTS_FILE
	TPMRootsFile string
}

// HAConfig controls active-passive leader election for running multiple
// mint-ca processes against one shared Postgres database (see internal/ha).
// Only one node — the current leader — serves API traffic at a time;
// standbys return 503 until they win an election. Requires the postgres
// storage backend, since sqlite is inherently single-process.
type HAConfig struct {
	// Enabled turns on leader election. Requires MINT_DB_DRIVER=postgres.
	// Env: MINT_HA_ENABLED
	Enabled bool

	// NodeID identifies this process in the leader-election lock. Defaults
	// to the OS hostname if unset.
	// Env: MINT_HA_NODE_ID
	NodeID string

	// LeaseSeconds is how long a won leadership lease lasts before it can be
	// taken over, if not renewed.
	// Env: MINT_HA_LEASE_SECONDS
	LeaseSeconds int64

	// RenewSeconds is how often the leader (and every standby) attempts to
	// acquire/renew the lease. Should be well under LeaseSeconds so a
	// healthy leader doesn't lose its lease due to renewal jitter.
	// Env: MINT_HA_RENEW_SECONDS
	RenewSeconds int64
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
	c.Server.BootstrapKey = strings.TrimSpace(os.Getenv("MINT_BOOTSTRAP_KEY"))

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
	c.ACME.CAADomain = strings.TrimSpace(os.Getenv("MINT_ACME_CAA_DOMAIN"))
	c.ACME.CAADNSServer = strings.TrimSpace(os.Getenv("MINT_ACME_CAA_DNS_SERVER"))
	c.ACME.CAABypassLabels = os.Getenv("MINT_ACME_CAA_BYPASS_LABELS")

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
	c.CRL.DeltaEnabled = envBool("MINT_CRL_DELTA_ENABLED")
	c.CRL.BaseRefreshInterval = envDuration("MINT_CRL_BASE_REFRESH_INTERVAL_SECONDS", 0)
	if c.CRL.BaseRefreshInterval == 0 {
		// Default the base refresh cadence to the delta refresh cadence when
		// unset, so an operator only has to think about one number unless they
		// explicitly want a longer base lifecycle.
		c.CRL.BaseRefreshInterval = c.CRL.RefreshInterval
	}

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
	if c.CRL.DeltaEnabled && c.CRL.BaseRefreshInterval < c.CRL.RefreshInterval {
		errs = append(errs,
			"MINT_CRL_BASE_REFRESH_INTERVAL_SECONDS must be at least MINT_CRL_REFRESH_INTERVAL_SECONDS when delta CRLs are enabled",
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
	c.RateLimit.NewAccountPerIP = RateLimitOverride{
		WindowSeconds: envIntOptional("MINT_RATELIMIT_NEW_ACCOUNT_WINDOW_SECONDS"),
		MaxRequests:   envIntOptional("MINT_RATELIMIT_NEW_ACCOUNT_MAX"),
	}
	c.RateLimit.NewOrderPerAccount = RateLimitOverride{
		WindowSeconds: envIntOptional("MINT_RATELIMIT_NEW_ORDER_WINDOW_SECONDS"),
		MaxRequests:   envIntOptional("MINT_RATELIMIT_NEW_ORDER_MAX"),
	}
	c.RateLimit.NewAuthzPerAccount = RateLimitOverride{
		WindowSeconds: envIntOptional("MINT_RATELIMIT_NEW_AUTHZ_WINDOW_SECONDS"),
		MaxRequests:   envIntOptional("MINT_RATELIMIT_NEW_AUTHZ_MAX"),
	}
	c.RateLimit.APIKeyRequestsPerKey = RateLimitOverride{
		WindowSeconds: envIntOptional("MINT_RATELIMIT_APIKEY_WINDOW_SECONDS"),
		MaxRequests:   envIntOptional("MINT_RATELIMIT_APIKEY_MAX"),
	}

	c.MTLS.Enabled = envBool("MINT_MTLS_ENABLED")
	c.MTLS.ListenAddr = strings.TrimSpace(os.Getenv("MINT_MTLS_LISTEN_ADDR"))
	c.MTLS.ClientCACertPEM = strings.TrimSpace(os.Getenv("MINT_MTLS_CLIENT_CA"))
	c.MTLS.ServerCertFile = strings.TrimSpace(os.Getenv("MINT_MTLS_CERT"))
	c.MTLS.ServerKeyFile = strings.TrimSpace(os.Getenv("MINT_MTLS_KEY"))

	if c.MTLS.Enabled {
		if c.MTLS.ListenAddr == "" {
			errs = append(errs, "MINT_MTLS_LISTEN_ADDR is required when MINT_MTLS_ENABLED=true")
		}
		if c.MTLS.ClientCACertPEM == "" {
			errs = append(errs, "MINT_MTLS_CLIENT_CA is required when MINT_MTLS_ENABLED=true")
		}
	}

	c.Renewal.Enabled = envBool("MINT_RENEWAL_ENABLED")
	c.Renewal.IntervalSeconds = int64(envIntOptional("MINT_RENEWAL_INTERVAL_SECONDS"))
	if c.Renewal.IntervalSeconds == 0 {
		c.Renewal.IntervalSeconds = 3600 // 1h
	}
	c.Renewal.LeadSeconds = int64(envIntOptional("MINT_RENEWAL_LEAD_SECONDS"))
	if c.Renewal.LeadSeconds == 0 {
		c.Renewal.LeadSeconds = 7 * 24 * 3600 // 7 days
	}
	c.Renewal.WebhookURL = strings.TrimSpace(os.Getenv("MINT_RENEWAL_WEBHOOK_URL"))
	c.Renewal.ExpiringSeconds = int64(envIntOptional("MINT_RENEWAL_EXPIRING_SECONDS"))
	if c.Renewal.ExpiringSeconds == 0 {
		c.Renewal.ExpiringSeconds = 48 * 3600 // 48h
	}

	c.SCEP.Enabled = envBool("MINT_SCEP_ENABLED")
	c.SCEP.ProvisionerID = strings.TrimSpace(os.Getenv("MINT_SCEP_PROVISIONER_ID"))
	c.SCEP.DefaultTTLSeconds = int64(envIntOptional("MINT_SCEP_DEFAULT_TTL_SECONDS"))
	if c.SCEP.DefaultTTLSeconds == 0 {
		c.SCEP.DefaultTTLSeconds = 90 * 24 * 3600 // 90 days
	}

	c.Events.WebhookURL = strings.TrimSpace(os.Getenv("MINT_EVENTS_WEBHOOK_URL"))
	c.Attestation.TPMRootsFile = strings.TrimSpace(os.Getenv("MINT_ATTESTATION_TPM_ROOTS_FILE"))

	c.HA.Enabled = envBool("MINT_HA_ENABLED")
	c.HA.NodeID = strings.TrimSpace(os.Getenv("MINT_HA_NODE_ID"))
	if c.HA.NodeID == "" {
		if h, err := os.Hostname(); err == nil {
			c.HA.NodeID = h
		}
	}
	c.HA.LeaseSeconds = int64(envIntOptional("MINT_HA_LEASE_SECONDS"))
	if c.HA.LeaseSeconds == 0 {
		c.HA.LeaseSeconds = 15
	}
	c.HA.RenewSeconds = int64(envIntOptional("MINT_HA_RENEW_SECONDS"))
	if c.HA.RenewSeconds == 0 {
		c.HA.RenewSeconds = 5
	}
	if c.HA.Enabled {
		if c.Storage.Driver != "postgres" {
			errs = append(errs, "MINT_HA_ENABLED requires MINT_DB_DRIVER=postgres (sqlite is single-process)")
		}
		if c.HA.NodeID == "" {
			errs = append(errs, "MINT_HA_NODE_ID is required when MINT_HA_ENABLED=true and the hostname could not be determined")
		}
		if c.HA.RenewSeconds >= c.HA.LeaseSeconds {
			errs = append(errs, "MINT_HA_RENEW_SECONDS must be less than MINT_HA_LEASE_SECONDS")
		}
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
			"refresh_interval":      c.CRL.RefreshInterval.String(),
			"validity":              c.CRL.Validity.String(),
			"delta_enabled":         c.CRL.DeltaEnabled,
			"base_refresh_interval": c.CRL.BaseRefreshInterval.String(),
		},
		"log": map[string]interface{}{
			"level": c.Log.Level,
			"json":  c.Log.JSON,
		},
		"rate_limit": map[string]interface{}{
			"new_account_override": c.RateLimit.NewAccountPerIP.MaxRequests > 0 || c.RateLimit.NewAccountPerIP.WindowSeconds > 0,
			"new_order_override":   c.RateLimit.NewOrderPerAccount.MaxRequests > 0 || c.RateLimit.NewOrderPerAccount.WindowSeconds > 0,
			"new_authz_override":   c.RateLimit.NewAuthzPerAccount.MaxRequests > 0 || c.RateLimit.NewAuthzPerAccount.WindowSeconds > 0,
			"apikey_override":      c.RateLimit.APIKeyRequestsPerKey.MaxRequests > 0 || c.RateLimit.APIKeyRequestsPerKey.WindowSeconds > 0,
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

// envIntOptional reads an integer environment variable, returning 0 if
// unset, empty, or unparsable — 0 is treated by callers as "no override".
func envIntOptional(key string) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return n
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
