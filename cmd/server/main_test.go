package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mint-ca/internal/ratelimit"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mint-ca/internal/api"
	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/config"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/ha"
	"mint-ca/internal/policy"
	"mint-ca/internal/setup"
	"mint-ca/internal/sshca"
	"mint-ca/internal/sshca/krl"
	"mint-ca/internal/storage"

	"golang.org/x/crypto/ssh"
)

// Shared live-instance state — one struct, built once in TestMain.

type liveState struct {
	baseURL   string
	bootstrap string
	adminKey  string
	rootCAID  string
	rlEngine  *ratelimit.Engine
	extra     map[string]string
}

func (s *liveState) put(k, v string)     { s.extra[k] = v }
func (s *liveState) get(k string) string { return s.extra[k] }

var (
	shared     *liveState
	liveClient = &http.Client{Timeout: 15 * time.Second}
)

// Registry — append-only. New tests never touch the driver or TestMain.

type authMode int

const (
	authNone authMode = iota
	authBootstrap
	authAdmin
)

func resolveAuth(m authMode, ctx *liveState) string {
	switch m {
	case authBootstrap:
		return ctx.bootstrap
	case authAdmin:
		return ctx.adminKey
	default:
		return ""
	}
}

// apiCase is one HTTP-level request/assertion against the live server.
type apiCase struct {
	Name    string
	Method  string
	Path    func(ctx *liveState) string
	Auth    authMode
	Body    func(ctx *liveState) interface{}
	Want    int
	Extract func(t *testing.T, ctx *liveState, data []byte)
	Skip    func(ctx *liveState) bool
}

// scenario is for multi-step flows that don't reduce to one request.
type scenario struct {
	Name string
	Run  func(t *testing.T, ctx *liveState)
}

var apiCases []apiCase
var scenarios []scenario

func registerCase(c apiCase)      { apiCases = append(apiCases, c) }
func registerScenario(s scenario) { scenarios = append(scenarios, s) }

// TestMain — boots the real stack once, drives setup over real HTTP,
// keeps the full API alive for the whole test binary run.

func TestMain(m *testing.M) {
	code, err := runLiveStack(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "main_test: fatal:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runLiveStack(m *testing.M) (int, error) {
	tmpDir, err := os.MkdirTemp("", "mint-ca-test-*")
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(tmpDir)
	dbPath := filepath.Join(tmpDir, "mint-ca.db")

	masterKeyBytes := make([]byte, 32)
	if _, err := rand.Read(masterKeyBytes); err != nil {
		return 1, fmt.Errorf("generate master key: %w", err)
	}

	env := map[string]string{
		"MINT_MASTER_KEY":                   hex.EncodeToString(masterKeyBytes),
		"MINT_DB_DRIVER":                    "sqlite",
		"MINT_DB_DSN":                       dbPath,
		"MINT_TLS_DISABLED":                 "true",
		"MINT_ACME_ENABLED":                 "true",
		"MINT_ACME_BASE_URL":                "http://127.0.0.1:0",
		"MINT_ACME_EAB_REQUIRED":            "false",
		"MINT_LOG_LEVEL":                    "error",
		"MINT_CRL_REFRESH_INTERVAL_SECONDS": "3600",
		"MINT_CRL_VALIDITY_SECONDS":         "86400",
	}
	var keys []string
	for k, v := range env {
		if err := os.Setenv(k, v); err != nil {
			return 1, err
		}
		keys = append(keys, k)
	}
	defer func() {
		for _, k := range keys {
			_ = os.Unsetenv(k)
		}
	}()

	cfg, err := config.Load()
	if err != nil {
		return 1, fmt.Errorf("config.Load: %w", err)
	}

	store, err := storage.New()
	if err != nil {
		return 1, fmt.Errorf("storage.New: %w", err)
	}
	defer store.Close()

	if err := setup.SeedRateLimitConfigs(context.Background(), store, cfg.RateLimit); err != nil {
		return 1, fmt.Errorf("seed ratelimit: %w", err)
	}
	rlEngine, err := setup.LoadRateLimitEngine(context.Background(), store)
	if err != nil {
		return 1, fmt.Errorf("load ratelimit engine: %w", err)
	}

	ks, err := mintcrypto.NewKeystore(cfg.Crypto.MasterKey)
	if err != nil {
		return 1, fmt.Errorf("keystore: %w", err)
	}
	defer ks.Zero()

	// Reserve a fixed listener address BEFORE building engines, so the
	// ACME base URL baked into caEngine/ACME service matches exactly
	// where the full API server ends up actually listening.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 1, fmt.Errorf("reserve listener: %w", err)
	}
	baseURL := "http://" + listener.Addr().String()
	cfg.ACME.BaseURL = baseURL

	caEngine := ca.NewEngine(store, ks, cfg.ACME.BaseURL)
	policyEngine := policy.NewEngine(store)
	sshcaEngine := sshca.NewEngine(store, ks, policyEngine)
	crlManager := revocation.NewCRLManager(store, ks, baseURL, false)
	ocspResponder := revocation.NewOCSPResponder(store, ks)
	sshKRLManager := krl.NewManager(store)

	// ---- setup mode over real HTTP (separate ephemeral server; doesn't
	// need to match baseURL since /setup/* never validates a JWS URL) ----
	setupRouter := api.BuildSetupRouter(cfg, store, caEngine, func(certPEM, keyPEM []byte) error { return nil })
	setupSrv := httptest.NewServer(setupRouter)
	defer setupSrv.Close()

	bk, err := setup.GenerateBootstrapKey(context.Background(), store)
	if err != nil {
		return 1, fmt.Errorf("bootstrap key: %w", err)
	}

	if err := postJSON(setupSrv.URL+"/setup/root-ca", bk.Raw, map[string]interface{}{
		"common_name": "Test Root CA", "key_algo": "ecdsa-p256", "ttl_days": 3650,
	}, nil); err != nil {
		return 1, fmt.Errorf("setup root-ca: %w", err)
	}

	var apiKeyResp struct {
		APIKey string `json:"api_key"`
		CAID   string `json:"ca_id"`
	}
	if err := postJSON(setupSrv.URL+"/setup/api-key", bk.Raw, map[string]interface{}{
		"name":           "test-admin",
		"scopes":         []string{"*"},
		"terms_accepted": true,
	}, &apiKeyResp); err != nil {
		return 1, fmt.Errorf("setup api-key: %w", err)
	}

	// ---- full API, bound to the SAME address baked into cfg.ACME.BaseURL ----
	fullRouter := api.BuildRouter(cfg, store, caEngine, sshcaEngine, crlManager, ocspResponder, policyEngine, rlEngine, sshKRLManager, ha.NewElector(nil, "test-node", 0, 0))
	fullSrv := httptest.NewUnstartedServer(fullRouter)
	_ = fullSrv.Listener.Close()
	fullSrv.Listener = listener
	fullSrv.Start()
	defer fullSrv.Close()

	shared = &liveState{
		baseURL:   baseURL,
		bootstrap: bk.Raw,
		adminKey:  apiKeyResp.APIKey,
		rootCAID:  apiKeyResp.CAID,
		rlEngine:  rlEngine,
		extra:     make(map[string]string),
	}

	return m.Run(), nil
}

// generic HTTP helpers

func postJSON(url, bearer string, body interface{}, out interface{}) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := liveClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s: status %d: %s", url, resp.StatusCode, string(data))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func doReq(t *testing.T, method, path, bearer string, body interface{}) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, shared.baseURL+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := liveClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, data
}

func mustJSON(t *testing.T, data []byte, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("unmarshal %s: %v", string(data), err)
	}
}

func extractID(field string) func(t *testing.T, ctx *liveState, data []byte) {
	return func(t *testing.T, ctx *liveState, data []byte) {
		var r struct {
			ID string `json:"id"`
		}
		mustJSON(t, data, &r)
		if r.ID == "" {
			t.Fatalf("expected non-empty id in response: %s", data)
		}
		ctx.put(field, r.ID)
	}
}

// Driver tests — never edited when adding new coverage.

func TestAPI_Registry(t *testing.T) {
	for _, c := range apiCases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			if c.Skip != nil && c.Skip(shared) {
				t.Skip("skipped by case condition")
			}
			var body interface{}
			if c.Body != nil {
				body = c.Body(shared)
			}
			bearer := resolveAuth(c.Auth, shared)
			path := c.Path(shared)
			resp, data := doReq(t, c.Method, path, bearer, body)
			if resp.StatusCode != c.Want {
				t.Fatalf("%s %s: want %d got %d: %s", c.Method, path, c.Want, resp.StatusCode, data)
			}
			if c.Extract != nil {
				c.Extract(t, shared, data)
			}
		})
	}
}

func TestAPI_Scenarios(t *testing.T) {
	for _, s := range scenarios {
		s := s
		t.Run(s.Name, func(t *testing.T) { s.Run(t, shared) })
	}
}

// Registered cases — CRUD-shaped endpoints. Append more via init() in
// this file or any other *_test.go in package main; no harness changes.

func init() {
	registerCase(apiCase{
		Name: "Healthz", Method: http.MethodGet, Auth: authNone,
		Path: func(*liveState) string { return "/healthz" },
		Want: http.StatusOK,
	})

	registerCase(apiCase{
		Name: "ListRootCA", Method: http.MethodGet, Auth: authAdmin,
		Path: func(*liveState) string { return "/api/v1/ca" },
		Want: http.StatusOK,
	})

	registerCase(apiCase{
		Name: "CreateIntermediateCA", Method: http.MethodPost, Auth: authAdmin,
		Path: func(*liveState) string { return "/api/v1/ca/intermediate" },
		Body: func(ctx *liveState) interface{} {
			return map[string]interface{}{
				"parent_ca_id": ctx.rootCAID, "name": "test-intermediate",
				"common_name": "Test Intermediate", "key_algo": "ecdsa-p256",
				"ttl_days": 1825, "max_path_len": 0,
			}
		},
		Want:    http.StatusCreated,
		Extract: extractID("inter_ca_id"),
	})

	registerCase(apiCase{
		Name: "CreateAPIKeyProvisioner", Method: http.MethodPost, Auth: authAdmin,
		Path: func(*liveState) string { return "/api/v1/provisioners" },
		Body: func(ctx *liveState) interface{} {
			return map[string]interface{}{
				"ca_id": ctx.get("inter_ca_id"), "name": "test-provisioner",
				"type": "apikey", "config": map[string]interface{}{},
			}
		},
		Want:    http.StatusCreated,
		Extract: extractID("apikey_prov_id"),
	})

	registerCase(apiCase{
		Name: "IssueCertificate", Method: http.MethodPost, Auth: authAdmin,
		Path: func(*liveState) string { return "/api/v1/certs/issue" },
		Body: func(ctx *liveState) interface{} {
			return map[string]interface{}{
				"ca_id": ctx.get("inter_ca_id"), "provisioner_id": ctx.get("apikey_prov_id"),
				"common_name": "leaf.example.com", "sans_dns": []string{"leaf.example.com"},
				"ttl_seconds": 3600, "key_algo": "ecdsa-p256", "server_auth": true,
			}
		},
		Want: http.StatusCreated,
		Extract: func(t *testing.T, ctx *liveState, data []byte) {
			var out struct {
				Certificate struct {
					ID     string `json:"id"`
					Serial string `json:"serial"`
				} `json:"certificate"`
			}
			mustJSON(t, data, &out)
			ctx.put("cert_id", out.Certificate.ID)
		},
	})

	registerCase(apiCase{
		Name: "RevokeCertificate", Method: http.MethodPut, Auth: authAdmin,
		Path: func(ctx *liveState) string { return "/api/v1/certs/" + ctx.get("cert_id") + "/revoke" },
		Body: func(*liveState) interface{} { return map[string]interface{}{"reason": 1} },
		Want: http.StatusOK,
	})

	registerCase(apiCase{
		Name: "PublicChain", Method: http.MethodGet, Auth: authNone,
		Path: func(ctx *liveState) string { return "/pki/" + ctx.get("inter_ca_id") + "/chain" },
		Want: http.StatusOK,
	})

	registerCase(apiCase{
		Name: "PublicCRL", Method: http.MethodGet, Auth: authNone,
		Path: func(ctx *liveState) string { return "/pki/" + ctx.get("inter_ca_id") + "/crl" },
		Want: http.StatusOK,
	})

	registerCase(apiCase{
		Name: "CreatePolicy", Method: http.MethodPost, Auth: authAdmin,
		Path: func(*liveState) string { return "/api/v1/policies" },
		Body: func(*liveState) interface{} {
			return map[string]interface{}{
				"name": "test-policy", "scope": "ca", "max_ttl_seconds": 86400,
				"allowed_domains": []string{"*.example.com"}, "require_san": true,
			}
		},
		Want:    http.StatusCreated,
		Extract: extractID("policy_id"),
	})

	registerCase(apiCase{
		Name: "GetPolicy", Method: http.MethodGet, Auth: authAdmin,
		Path: func(ctx *liveState) string { return "/api/v1/policies/" + ctx.get("policy_id") },
		Want: http.StatusOK,
	})

	registerCase(apiCase{
		Name: "DeletePolicy", Method: http.MethodDelete, Auth: authAdmin,
		Path: func(ctx *liveState) string { return "/api/v1/policies/" + ctx.get("policy_id") },
		Want: http.StatusOK,
	})

	registerCase(apiCase{
		Name: "CreateSSHCA", Method: http.MethodPost, Auth: authAdmin,
		Path: func(*liveState) string { return "/api/v1/sshca/" },
		Body: func(*liveState) interface{} {
			return map[string]interface{}{"name": "test-sshca", "key_algo": "ed25519"}
		},
		Want:    http.StatusCreated,
		Extract: extractID("ssh_ca_id"),
	})

	registerCase(apiCase{
		Name: "SignSSHUserCert", Method: http.MethodPost, Auth: authAdmin,
		Path: func(ctx *liveState) string { return "/api/v1/sshca/" + ctx.get("ssh_ca_id") + "/sign/user" },
		Body: func(ctx *liveState) interface{} {
			pub, _ := genSSHAuthorizedKey(nil)
			ctx.put("ssh_pub", pub)
			return map[string]interface{}{
				"provisioner_id": ctx.get("apikey_prov_id"),
				"public_key":     pub,
				"principals":     []string{"alice"}, "key_id": "alice", "ttl_seconds": 3600,
			}
		},
		Want: http.StatusCreated,
		Extract: func(t *testing.T, ctx *liveState, data []byte) {
			var out struct {
				Certificate struct {
					ID string `json:"id"`
				} `json:"certificate"`
			}
			mustJSON(t, data, &out)
			ctx.put("ssh_cert_id", out.Certificate.ID)
		},
	})

	registerCase(apiCase{
		Name: "RevokeSSHCert", Method: http.MethodPut, Auth: authAdmin,
		Path: func(ctx *liveState) string { return "/api/v1/sshca/certs/" + ctx.get("ssh_cert_id") + "/revoke" },
		Want: http.StatusOK,
	})

	registerCase(apiCase{
		Name: "AuditLog", Method: http.MethodGet, Auth: authAdmin,
		Path: func(*liveState) string { return "/api/v1/audit?limit=5" },
		Want: http.StatusOK,
	})

	registerCase(apiCase{
		Name: "Metrics", Method: http.MethodGet, Auth: authAdmin,
		Path: func(*liveState) string { return "/metrics" },
		Want: http.StatusOK,
		Extract: func(t *testing.T, ctx *liveState, data []byte) {
			if !strings.Contains(string(data), "mintca_ca_total") {
				t.Fatalf("expected mintca metrics in output, got: %s", data)
			}
		},
	})
}

// Registered scenarios — multi-step flows. Same append-only pattern.

func init() {
	registerScenario(scenario{Name: "RateLimit_APIKey", Run: runRateLimitTrip})
	registerScenario(scenario{Name: "ACME_FullLifecycle", Run: runACMELifecycle})
}

// RateLimit_APIKey trips the 5/60s apikey limiter set via env in TestMain.
func runRateLimitTrip(t *testing.T, ctx *liveState) {
	// Dedicated key so this scenario's bucket is independent of every
	// other case's usage of ctx.adminKey.
	resp, data := doReq(t, http.MethodPost, "/api/v1/apikeys", ctx.adminKey, map[string]interface{}{
		"name": "ratelimit-test-key", "scopes": []string{"*"}, "platform_admin": true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create dedicated key: %d: %s", resp.StatusCode, data)
	}
	var nk struct {
		Key string `json:"key"`
	}
	mustJSON(t, data, &nk)

	// Temporarily tighten the limiter in-process (config lives in memory,
	// no DB/HTTP round trip needed) so we can trip it in a handful of
	// requests without affecting any other key's bucket or quota.
	const lowMax = 3
	if err := ctx.rlEngine.UpdateConfig(ratelimit.LimiterConfig{
		Name: "apikey_requests_per_key", Scope: "api_key", Algorithm: "fixed_window",
		WindowSeconds: 60, MaxRequests: lowMax, Enabled: true,
	}); err != nil {
		t.Fatalf("lower apikey limit: %v", err)
	}
	defer func() {
		_ = ctx.rlEngine.UpdateConfig(ratelimit.LimiterConfig{
			Name: "apikey_requests_per_key", Scope: "api_key", Algorithm: "fixed_window",
			WindowSeconds: 60, MaxRequests: 300, Enabled: true,
		})
	}()

	var last *http.Response
	for i := 0; i < lowMax+2; i++ {
		last, _ = doReq(t, http.MethodGet, "/api/v1/ca", nk.Key, nil)
		if last.StatusCode == http.StatusTooManyRequests {
			break
		}
	}
	if last.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected to eventually hit 429, last status %d", last.StatusCode)
	}
	if last.Header.Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429")
	}
}

// ACME_FullLifecycle: provisioner -> directory -> nonce -> new-account ->
// new-order -> authz -> trigger challenge -> (async validation not
// asserted, since it needs real DNS/HTTP reachability out of sandbox).
func runACMELifecycle(t *testing.T, ctx *liveState) {
	resp, data := doReq(t, http.MethodPost, "/api/v1/apikeys", ctx.adminKey, map[string]interface{}{
		"name": "acme-test-admin", "scopes": []string{"*"}, "platform_admin": true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create fresh admin key: %d: %s", resp.StatusCode, data)
	}
	var newKey struct {
		Key string `json:"key"`
	}
	mustJSON(t, data, &newKey)
	admin := newKey.Key

	interCAID := ctx.get("inter_ca_id")
	if interCAID == "" {
		t.Fatal("expected inter_ca_id to already be set by registry cases")
	}

	resp2, data2 := doReq(t, http.MethodPost, "/api/v1/provisioners", admin, map[string]interface{}{
		"ca_id": interCAID, "name": "acme-test-prov", "type": "acme",
		"config": map[string]interface{}{"allowed_challenge_types": []string{"http-01"}},
	})
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("create acme provisioner: %d: %s", resp2.StatusCode, data2)
	}
	var acmeProv struct {
		ID string `json:"id"`
	}
	mustJSON(t, data2, &acmeProv)

	dirResp, dirData := doReq(t, http.MethodGet, "/acme/"+acmeProv.ID+"/directory", "", nil)
	if dirResp.StatusCode != http.StatusOK {
		t.Fatalf("directory: %d: %s", dirResp.StatusCode, dirData)
	}

	nonceResp, _ := doReq(t, http.MethodHead, "/acme/"+acmeProv.ID+"/new-nonce", "", nil)
	nonce := nonceResp.Header.Get("Replay-Nonce")
	if nonce == "" {
		t.Fatal("expected Replay-Nonce header")
	}

	priv, jwk := genACMEJWK(t)

	newAcctURL := ctx.baseURL + "/acme/" + acmeProv.ID + "/new-account"
	acctResp, acctData, nonce := postACMEJWS(t, priv, jwk, "", newAcctURL, nonce,
		map[string]interface{}{"termsOfServiceAgreed": true})
	if acctResp.StatusCode != http.StatusCreated {
		t.Fatalf("new-account: %d: %s", acctResp.StatusCode, acctData)
	}
	accountURL := acctResp.Header.Get("Location")
	if accountURL == "" {
		t.Fatal("expected Location header with account URL")
	}

	newOrderURL := ctx.baseURL + "/acme/" + acmeProv.ID + "/new-order"
	orderResp, orderData, nonce := postACMEJWS(t, priv, jwk, accountURL, newOrderURL, nonce,
		map[string]interface{}{"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}}})
	if orderResp.StatusCode != http.StatusCreated {
		t.Fatalf("new-order: %d: %s", orderResp.StatusCode, orderData)
	}
	var order struct {
		Authorizations []string `json:"authorizations"`
	}
	mustJSON(t, orderData, &order)
	if len(order.Authorizations) != 1 {
		t.Fatalf("expected 1 authorization, got %d", len(order.Authorizations))
	}

	authResp, authData, nonce := postACMEJWS(t, priv, jwk, accountURL, order.Authorizations[0], nonce, nil)
	if authResp.StatusCode != http.StatusOK && authResp.StatusCode != http.StatusCreated {
		t.Fatalf("get authz: %d: %s", authResp.StatusCode, authData)
	}
	var authz struct {
		Challenges []struct {
			URL string `json:"url"`
		} `json:"challenges"`
	}
	mustJSON(t, authData, &authz)
	if len(authz.Challenges) == 0 {
		t.Fatal("expected at least one challenge")
	}

	challResp, challData, _ := postACMEJWS(t, priv, jwk, accountURL, authz.Challenges[0].URL, nonce,
		map[string]interface{}{})
	if challResp.StatusCode != http.StatusOK {
		t.Fatalf("trigger challenge: %d: %s", challResp.StatusCode, challData)
	}

	t.Logf("ACME lifecycle exercised through challenge trigger for account %s", accountURL)
}

// ACME crypto helpers — reusable by any future ACME scenario.

func genACMEJWK(t *testing.T) (*ecdsa.PrivateKey, json.RawMessage) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate acme key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(priv.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(priv.Y.Bytes())
	jwk, _ := json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y})
	return priv, jwk
}

// postACMEJWS builds and posts a JWS-wrapped ACME request, either
// jwk-authenticated (kid == "") or kid-authenticated, returning the
// response, body, and the fresh nonce for the next call.
func postACMEJWS(t *testing.T, priv *ecdsa.PrivateKey, jwk json.RawMessage, kid, url, nonce string, payload interface{}) (*http.Response, []byte, string) {
	t.Helper()

	hdr := map[string]interface{}{"alg": "ES256", "nonce": nonce, "url": url}
	if kid != "" {
		hdr["kid"] = kid
	} else {
		hdr["jwk"] = json.RawMessage(jwk)
	}
	hdrBytes, _ := json.Marshal(hdr)
	protected := base64.RawURLEncoding.EncodeToString(hdrBytes)

	var payloadB64 string
	if payload != nil {
		pb, _ := json.Marshal(payload)
		payloadB64 = base64.RawURLEncoding.EncodeToString(pb)
	}

	sig := signACMEES256(t, priv, protected, payloadB64)

	body, _ := json.Marshal(map[string]string{
		"protected": protected, "payload": payloadB64, "signature": sig,
	})
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := liveClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, data, resp.Header.Get("Replay-Nonce")
}

func signACMEES256(t *testing.T, priv *ecdsa.PrivateKey, protected, payload string) string {
	t.Helper()
	msg := []byte(protected + "." + payload)
	s := sha256.Sum256(msg)
	r, ss, err := ecdsa.Sign(rand.Reader, priv, s[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rb := make([]byte, 32)
	sb := make([]byte, 32)
	r.FillBytes(rb)
	ss.FillBytes(sb)
	return base64.RawURLEncoding.EncodeToString(append(rb, sb...))
}

// SSH key helper — reusable by any future SSH scenario/case.

// genSSHAuthorizedKey generates a throwaway ed25519 keypair and returns
// its authorized_keys line. t may be nil when called from a Body func
// (no fatal path needed there since key generation practically never
// fails); pass a *testing.T when available for clearer failure messages.
func genSSHAuthorizedKey(t *testing.T) (string, ed25519.PrivateKey) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		if t != nil {
			t.Fatalf("generate ssh key: %v", err)
		}
		panic(err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		if t != nil {
			t.Fatalf("wrap signer: %v", err)
		}
		panic(err)
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey())), priv
}
