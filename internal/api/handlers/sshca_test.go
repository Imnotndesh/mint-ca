package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/sshca"
	"mint-ca/internal/sshca/krl"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// sshFakeStore implements storage.Store for the SSH CA handler tests. Only the
// SSH methods are real; everything else panics loudly so a missing case fails
// fast instead of silently returning zero values.
type sshFakeStore struct {
	mu    sync.Mutex
	cas   map[uuid.UUID]*storage.SSHCertificateAuthority
	certs map[uuid.UUID]*storage.SSHCertificate
	krls  map[uuid.UUID]*storage.SSHKRLCache
}

func newSSHFakeStore() *sshFakeStore {
	return &sshFakeStore{
		cas:   make(map[uuid.UUID]*storage.SSHCertificateAuthority),
		certs: make(map[uuid.UUID]*storage.SSHCertificate),
	}
}

func sshNotImplemented(method string) {
	panic("handlers fakeStore: " + method + " not implemented — add it if your test needs it")
}

func (f *sshFakeStore) CreateSSHCA(ctx context.Context, ca *storage.SSHCertificateAuthority) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cas[ca.ID] = ca
	return nil
}
func (f *sshFakeStore) GetSSHCA(ctx context.Context, id uuid.UUID) (*storage.SSHCertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cas[id], nil
}
func (f *sshFakeStore) GetSSHCAByName(ctx context.Context, name string) (*storage.SSHCertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cas {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, nil
}
func (f *sshFakeStore) ListSSHCAs(ctx context.Context) ([]*storage.SSHCertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.SSHCertificateAuthority
	for _, c := range f.cas {
		out = append(out, c)
	}
	return out, nil
}
func (f *sshFakeStore) CreateSSHCertificate(ctx context.Context, cert *storage.SSHCertificate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certs[cert.ID] = cert
	return nil
}
func (f *sshFakeStore) GetSSHCertificate(ctx context.Context, id uuid.UUID) (*storage.SSHCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.certs[id], nil
}
func (f *sshFakeStore) GetSSHCertificateBySerial(ctx context.Context, caID uuid.UUID, serial uint64) (*storage.SSHCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.certs {
		if c.CAID == caID && c.Serial == serial {
			return c, nil
		}
	}
	return nil, nil
}
func (f *sshFakeStore) ListRevokedSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.SSHCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.SSHCertificate
	for _, c := range f.certs {
		if c.CAID == caID && c.Status == storage.SSHCertStatusRevoked {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *sshFakeStore) UpsertSSHKRL(ctx context.Context, k *storage.SSHKRLCache) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.krls == nil {
		f.krls = make(map[uuid.UUID]*storage.SSHKRLCache)
	}
	f.krls[k.CAID] = k
	return nil
}
func (f *sshFakeStore) GetSSHKRL(ctx context.Context, caID uuid.UUID) (*storage.SSHKRLCache, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.krls[caID], nil
}
func (f *sshFakeStore) ListSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.SSHCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.SSHCertificate
	for _, c := range f.certs {
		if c.CAID == caID {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *sshFakeStore) RevokeSSHCertificate(ctx context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.certs[id]
	if !ok {
		return sshErrNotFound
	}
	if c.Status == storage.SSHCertStatusRevoked {
		return sshErrNotFound // mirrors real store: already-revoked matches 0 rows
	}
	now := time.Now().UTC()
	c.Status = storage.SSHCertStatusRevoked
	c.RevokedAt = &now
	return nil
}

// --- unused by SSH handler tests but required to satisfy storage.Store ---

func (f *sshFakeStore) CreateCA(ctx context.Context, ca *storage.CertificateAuthority) error {
	sshNotImplemented("CreateCA")
	return nil
}
func (f *sshFakeStore) GetCA(ctx context.Context, id uuid.UUID) (*storage.CertificateAuthority, error) {
	sshNotImplemented("GetCA")
	return nil, nil
}
func (f *sshFakeStore) GetCAByName(ctx context.Context, name string) (*storage.CertificateAuthority, error) {
	sshNotImplemented("GetCAByName")
	return nil, nil
}
func (f *sshFakeStore) ListCAs(ctx context.Context) ([]*storage.CertificateAuthority, error) {
	sshNotImplemented("ListCAs")
	return nil, nil
}
func (f *sshFakeStore) ListChildCAs(ctx context.Context, parentID uuid.UUID) ([]*storage.CertificateAuthority, error) {
	sshNotImplemented("ListChildCAs")
	return nil, nil
}
func (f *sshFakeStore) UpdateCAStatus(ctx context.Context, id uuid.UUID, status storage.CAStatus) error {
	sshNotImplemented("UpdateCAStatus")
	return nil
}
func (f *sshFakeStore) CreateCrossCert(ctx context.Context, cc *storage.CrossCert) error {
	sshNotImplemented("CreateCrossCert")
	return nil
}
func (f *sshFakeStore) GetCrossCert(ctx context.Context, targetCAID, signingCAID uuid.UUID) (*storage.CrossCert, error) {
	sshNotImplemented("GetCrossCert")
	return nil, nil
}
func (f *sshFakeStore) ListCrossCertsByTarget(ctx context.Context, targetCAID uuid.UUID) ([]*storage.CrossCert, error) {
	sshNotImplemented("ListCrossCertsByTarget")
	return nil, nil
}
func (f *sshFakeStore) CreateCertificate(ctx context.Context, cert *storage.Certificate) error {
	sshNotImplemented("CreateCertificate")
	return nil
}
func (f *sshFakeStore) GetCertificate(ctx context.Context, id uuid.UUID) (*storage.Certificate, error) {
	sshNotImplemented("GetCertificate")
	return nil, nil
}
func (f *sshFakeStore) GetCertificateBySerial(ctx context.Context, serial string) (*storage.Certificate, error) {
	sshNotImplemented("GetCertificateBySerial")
	return nil, nil
}
func (f *sshFakeStore) ListCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	sshNotImplemented("ListCertificatesByCA")
	return nil, nil
}
func (f *sshFakeStore) ListRevokedByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	sshNotImplemented("ListRevokedByCA")
	return nil, nil
}
func (f *sshFakeStore) RevokeCertificate(ctx context.Context, id uuid.UUID, reason int) error {
	sshNotImplemented("RevokeCertificate")
	return nil
}
func (f *sshFakeStore) CreateProvisioner(ctx context.Context, p *storage.Provisioner) error {
	sshNotImplemented("CreateProvisioner")
	return nil
}
func (f *sshFakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	sshNotImplemented("GetProvisioner")
	return nil, nil
}
func (f *sshFakeStore) ListProvisionersByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Provisioner, error) {
	sshNotImplemented("ListProvisionersByCA")
	return nil, nil
}
func (f *sshFakeStore) UpdateProvisionerStatus(ctx context.Context, id uuid.UUID, status storage.ProvisionerStatus) error {
	sshNotImplemented("UpdateProvisionerStatus")
	return nil
}
func (f *sshFakeStore) CreatePolicy(ctx context.Context, p *storage.Policy) error {
	sshNotImplemented("CreatePolicy")
	return nil
}
func (f *sshFakeStore) GetPolicy(ctx context.Context, id uuid.UUID) (*storage.Policy, error) {
	sshNotImplemented("GetPolicy")
	return nil, nil
}
func (f *sshFakeStore) ListPolicies(ctx context.Context) ([]*storage.Policy, error) {
	sshNotImplemented("ListPolicies")
	return nil, nil
}
func (f *sshFakeStore) UpdatePolicy(ctx context.Context, p *storage.Policy) error {
	sshNotImplemented("UpdatePolicy")
	return nil
}
func (f *sshFakeStore) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	sshNotImplemented("DeletePolicy")
	return nil
}
func (f *sshFakeStore) CreateACMEAccount(ctx context.Context, a *storage.ACMEAccount) error {
	sshNotImplemented("CreateACMEAccount")
	return nil
}
func (f *sshFakeStore) GetACMEAccountByKeyID(ctx context.Context, keyID string) (*storage.ACMEAccount, error) {
	sshNotImplemented("GetACMEAccountByKeyID")
	return nil, nil
}
func (f *sshFakeStore) GetACMEAccount(ctx context.Context, id uuid.UUID) (*storage.ACMEAccount, error) {
	sshNotImplemented("GetACMEAccount")
	return nil, nil
}
func (f *sshFakeStore) UpdateACMEAccountStatus(ctx context.Context, id uuid.UUID, status storage.ACMEAccountStatus) error {
	sshNotImplemented("UpdateACMEAccountStatus")
	return nil
}
func (f *sshFakeStore) UpdateACMEAccountContact(ctx context.Context, id uuid.UUID, contact []string) error {
	sshNotImplemented("UpdateACMEAccountContact")
	return nil
}
func (f *sshFakeStore) CreateEABCredential(ctx context.Context, e *storage.EABCredential) error {
	sshNotImplemented("CreateEABCredential")
	return nil
}
func (f *sshFakeStore) GetEABCredential(ctx context.Context, keyID string) (*storage.EABCredential, error) {
	sshNotImplemented("GetEABCredential")
	return nil, nil
}
func (f *sshFakeStore) MarkEABUsed(ctx context.Context, id uuid.UUID) error {
	sshNotImplemented("MarkEABUsed")
	return nil
}
func (f *sshFakeStore) CreateACMEOrder(ctx context.Context, o *storage.ACMEOrder) error {
	sshNotImplemented("CreateACMEOrder")
	return nil
}
func (f *sshFakeStore) GetACMEOrder(ctx context.Context, id uuid.UUID) (*storage.ACMEOrder, error) {
	sshNotImplemented("GetACMEOrder")
	return nil, nil
}
func (f *sshFakeStore) ListACMEOrdersByAccount(ctx context.Context, accountID uuid.UUID) ([]*storage.ACMEOrder, error) {
	sshNotImplemented("ListACMEOrdersByAccount")
	return nil, nil
}
func (f *sshFakeStore) UpdateACMEOrderStatus(ctx context.Context, id uuid.UUID, status storage.ACMEOrderStatus) error {
	sshNotImplemented("UpdateACMEOrderStatus")
	return nil
}
func (f *sshFakeStore) FinalizeACMEOrder(ctx context.Context, orderID uuid.UUID, certID uuid.UUID) error {
	sshNotImplemented("FinalizeACMEOrder")
	return nil
}
func (f *sshFakeStore) CreateACMEChallenge(ctx context.Context, c *storage.ACMEChallenge) error {
	sshNotImplemented("CreateACMEChallenge")
	return nil
}
func (f *sshFakeStore) GetACMEChallenge(ctx context.Context, id uuid.UUID) (*storage.ACMEChallenge, error) {
	sshNotImplemented("GetACMEChallenge")
	return nil, nil
}
func (f *sshFakeStore) ListChallengesByOrder(ctx context.Context, orderID uuid.UUID) ([]*storage.ACMEChallenge, error) {
	sshNotImplemented("ListChallengesByOrder")
	return nil, nil
}
func (f *sshFakeStore) UpdateChallengeStatus(ctx context.Context, id uuid.UUID, status storage.ACMEChallengeStatus, validatedAt *time.Time) error {
	sshNotImplemented("UpdateChallengeStatus")
	return nil
}
func (f *sshFakeStore) ListChallengesByAuthorization(ctx context.Context, authID uuid.UUID) ([]*storage.ACMEChallenge, error) {
	sshNotImplemented("ListChallengesByAuthorization")
	return nil, nil
}
func (f *sshFakeStore) CreateACMEAuthorization(ctx context.Context, a *storage.ACMEAuthorization) error {
	sshNotImplemented("CreateACMEAuthorization")
	return nil
}
func (f *sshFakeStore) GetACMEAuthorization(ctx context.Context, id uuid.UUID) (*storage.ACMEAuthorization, error) {
	sshNotImplemented("GetACMEAuthorization")
	return nil, nil
}
func (f *sshFakeStore) UpdateACMEAuthorizationStatus(ctx context.Context, id uuid.UUID, status storage.ACMEAuthorizationStatus) error {
	sshNotImplemented("UpdateACMEAuthorizationStatus")
	return nil
}
func (f *sshFakeStore) ListAuthorizationsByOrder(ctx context.Context, orderID uuid.UUID) ([]*storage.ACMEAuthorization, error) {
	sshNotImplemented("ListAuthorizationsByOrder")
	return nil, nil
}
func (f *sshFakeStore) WriteAuditLog(ctx context.Context, entry *storage.AuditLog) error { return nil }
func (f *sshFakeStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]*storage.AuditLog, error) {
	sshNotImplemented("ListAuditLogs")
	return nil, nil
}
func (f *sshFakeStore) ListAuditLogsByCA(ctx context.Context, caID uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
	sshNotImplemented("ListAuditLogsByCA")
	return nil, nil
}
func (f *sshFakeStore) UpsertCRL(ctx context.Context, crl *storage.CRLCache) error {
	sshNotImplemented("UpsertCRL")
	return nil
}
func (f *sshFakeStore) GetCRL(ctx context.Context, caID uuid.UUID) (*storage.CRLCache, error) {
	sshNotImplemented("GetCRL")
	return nil, nil
}
func (f *sshFakeStore) NextCRLNumber(ctx context.Context, caID uuid.UUID) (int64, error) {
	sshNotImplemented("NextCRLNumber")
	return 0, nil
}
func (f *sshFakeStore) ListRevokedByCASince(ctx context.Context, caID uuid.UUID, since time.Time) ([]*storage.Certificate, error) {
	sshNotImplemented("ListRevokedByCASince")
	return nil, nil
}
func (f *sshFakeStore) UpsertDeltaCRL(ctx context.Context, d *storage.DeltaCRLCache) error {
	sshNotImplemented("UpsertDeltaCRL")
	return nil
}
func (f *sshFakeStore) GetDeltaCRL(ctx context.Context, caID uuid.UUID) (*storage.DeltaCRLCache, error) {
	sshNotImplemented("GetDeltaCRL")
	return nil, nil
}
func (f *sshFakeStore) CreateAPIKey(ctx context.Context, k *storage.APIKey) error {
	sshNotImplemented("CreateAPIKey")
	return nil
}
func (f *sshFakeStore) GetAPIKeyByHash(ctx context.Context, hash string) (*storage.APIKey, error) {
	sshNotImplemented("GetAPIKeyByHash")
	return nil, nil
}
func (f *sshFakeStore) ListAPIKeys(ctx context.Context) ([]*storage.APIKey, error) {
	sshNotImplemented("ListAPIKeys")
	return nil, nil
}
func (f *sshFakeStore) DeleteAPIKey(ctx context.Context, id uuid.UUID) error {
	sshNotImplemented("DeleteAPIKey")
	return nil
}
func (f *sshFakeStore) TouchAPIKey(ctx context.Context, id uuid.UUID) error {
	sshNotImplemented("TouchAPIKey")
	return nil
}
func (f *sshFakeStore) GetAPIKeyByName(ctx context.Context, name string) (*storage.APIKey, error) {
	sshNotImplemented("GetAPIKeyByName")
	return nil, nil
}
func (f *sshFakeStore) Migrate(ctx context.Context) error { return nil }
func (f *sshFakeStore) GetSetupState(ctx context.Context) (storage.SetupState, error) {
	sshNotImplemented("GetSetupState")
	return "", nil
}
func (f *sshFakeStore) SetSetupState(ctx context.Context, state storage.SetupState) error {
	sshNotImplemented("SetSetupState")
	return nil
}
func (f *sshFakeStore) Close() error { return nil }
func (f *sshFakeStore) CreateNonce(ctx context.Context, nonce string, expiresAt time.Time) error {
	sshNotImplemented("CreateNonce")
	return nil
}
func (f *sshFakeStore) ConsumeNonce(ctx context.Context, nonce string) (bool, error) {
	sshNotImplemented("ConsumeNonce")
	return false, nil
}
func (f *sshFakeStore) PruneExpiredNonces(ctx context.Context) error {
	sshNotImplemented("PruneExpiredNonces")
	return nil
}
func (f *sshFakeStore) GetACMEAuthorizationByIdentifier(ctx context.Context, accountID uuid.UUID, identifierType, identifierValue string) (*storage.ACMEAuthorization, error) {
	sshNotImplemented("GetACMEAuthorizationByIdentifier")
	return nil, nil
}
func (f *sshFakeStore) ListAuthorizationsByAccount(ctx context.Context, accountID uuid.UUID) ([]*storage.ACMEAuthorization, error) {
	sshNotImplemented("ListAuthorizationsByAccount")
	return nil, nil
}
func (f *sshFakeStore) GetRateLimitConfig(ctx context.Context, name string) (*storage.RateLimitConfig, error) {
	sshNotImplemented("GetRateLimitConfig")
	return nil, nil
}
func (f *sshFakeStore) ListRateLimitConfigs(ctx context.Context) ([]*storage.RateLimitConfig, error) {
	sshNotImplemented("ListRateLimitConfigs")
	return nil, nil
}
func (f *sshFakeStore) UpsertRateLimitConfigIfAbsent(ctx context.Context, cfg *storage.RateLimitConfig) error {
	sshNotImplemented("UpsertRateLimitConfigIfAbsent")
	return nil
}
func (f *sshFakeStore) UpdateRateLimitConfig(ctx context.Context, cfg *storage.RateLimitConfig) error {
	sshNotImplemented("UpdateRateLimitConfig")
	return nil
}
func (f *sshFakeStore) IncrementRateLimitCounter(ctx context.Context, limiterName, bucketKey string, windowStart time.Time) error {
	sshNotImplemented("IncrementRateLimitCounter")
	return nil
}
func (f *sshFakeStore) PruneExpiredRateLimitCounters(ctx context.Context, olderThan time.Time) error {
	sshNotImplemented("PruneExpiredRateLimitCounters")
	return nil
}
func (f *sshFakeStore) UpdateACMEAccountKey(ctx context.Context, accountID uuid.UUID, newKeyID string, newKeyJWK storage.JSON) error {
	sshNotImplemented("UpdateACMEAccountKey")
	return nil
}
func (f *sshFakeStore) MarkKeyIDRetired(ctx context.Context, keyID string) error {
	sshNotImplemented("MarkKeyIDRetired")
	return nil
}
func (f *sshFakeStore) IsKeyIDRetired(ctx context.Context, keyID string) (bool, error) {
	sshNotImplemented("IsKeyIDRetired")
	return false, nil
}

var sshErrNotFound = errors.New("handlers fakeStore: record not found")

// setupSSHRouter wires an SSHCAHandler plus an sshca.Engine over the fake
// store and returns a ready chi.Router with both authed and public routes.
func setupSSHRouter(t *testing.T) (*sshFakeStore, *SSHCAHandler, chi.Router) {
	t.Helper()
	store := newSSHFakeStore()
	masterKey := make([]byte, 32)
	ks, err := mintcrypto.NewKeystore(masterKey)
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := sshca.NewEngine(store, ks)
	krlMgr := krl.NewManager(store)
	h := NewSSHCAHandler(engine, store, krlMgr)

	r := chi.NewRouter()
	h.RegisterRoutes(r)
	h.RegisterPublicRoutes(r)
	return store, h, r
}

func doRequest(t *testing.T, r chi.Router, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestHandlers_SSHCA_CreateListGetPublicKey(t *testing.T) {
	_, _, r := setupSSHRouter(t)

	// Create.
	rec := doRequest(t, r, http.MethodPost, "/api/v1/sshca/",
		`{"name":"ssh-test","key_algo":"ed25519"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var ca storage.SSHCertificateAuthority
	if err := decodeTestJSON(rec.Body.String(), &ca); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if ca.ID == uuid.Nil {
		t.Fatal("expected a CA id in the response")
	}

	// List.
	rec = doRequest(t, r, http.MethodGet, "/api/v1/sshca/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), ca.Name) {
		t.Errorf("list should contain CA name %q", ca.Name)
	}

	// Get.
	rec = doRequest(t, r, http.MethodGet, "/api/v1/sshca/"+ca.ID.String(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", rec.Code)
	}

	// Public key (unauthenticated route).
	rec = doRequest(t, r, http.MethodGet, "/pki/sshca/"+ca.ID.String()+"/public-key", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("public-key: expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("public-key content-type should be text/plain, got %q", ct)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rec.Body.String())); err != nil {
		t.Errorf("public-key is not a valid authorized_keys line: %v", err)
	}
}

func TestHandlers_SSHCA_SignUserAndHost(t *testing.T) {
	_, _, r := setupSSHRouter(t)

	rec := doRequest(t, r, http.MethodPost, "/api/v1/sshca/", `{"name":"ssh-sign","key_algo":"ed25519"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var ca storage.SSHCertificateAuthority
	if err := decodeTestJSON(rec.Body.String(), &ca); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	clientPub := testClientAuthorizedKey(t)

	// sign/user.
	signBody := mustMarshal(t, struct {
		ProvisionerID string   `json:"provisioner_id"`
		PublicKey     string   `json:"public_key"`
		KeyID         string   `json:"key_id"`
		Principals    []string `json:"principals"`
		TTLSeconds    int64    `json:"ttl_seconds"`
	}{
		ProvisionerID: uuid.NewString(),
		PublicKey:     clientPub,
		KeyID:         "alice",
		Principals:    []string{"alice", "ops"},
		TTLSeconds:    3600,
	})
	rec = doRequest(t, r, http.MethodPost, "/api/v1/sshca/"+ca.ID.String()+"/sign/user", signBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("sign/user: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	userCert := signAndDecode(t, rec)
	if userCert.Certificate.CertType != storage.SSHCertTypeUser {
		t.Errorf("expected user cert type, got %q", userCert.Certificate.CertType)
	}
	if len(userCert.Certificate.Principals) != 2 {
		t.Errorf("expected 2 principals, got %d", len(userCert.Certificate.Principals))
	}
	certPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(userCert.CertData))
	if err != nil {
		t.Fatalf("parse cert_data: %v", err)
	}
	if certPub.(*ssh.Certificate).CertType != ssh.UserCert {
		t.Error("expected ssh.UserCert in signed cert")
	}

	// sign/host.
	rec = doRequest(t, r, http.MethodPost, "/api/v1/sshca/"+ca.ID.String()+"/sign/host", signBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("sign/host: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	hostCert := signAndDecode(t, rec)
	if hostCert.Certificate.CertType != storage.SSHCertTypeHost {
		t.Errorf("expected host cert type, got %q", hostCert.Certificate.CertType)
	}

	// Issued certs list by CA should contain at least the user cert.
	rec = doRequest(t, r, http.MethodGet, "/api/v1/sshca/"+ca.ID.String()+"/certs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list certs: expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), userCert.Certificate.ID.String()) {
		t.Errorf("issued cert list should contain the cert we just created")
	}
}

func TestHandlers_SSHCA_RevokeCert(t *testing.T) {
	_, _, r := setupSSHRouter(t)

	rec := doRequest(t, r, http.MethodPost, "/api/v1/sshca/", `{"name":"ssh-revoke","key_algo":"ed25519"}`)
	var ca storage.SSHCertificateAuthority
	if err := decodeTestJSON(rec.Body.String(), &ca); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	clientPub := testClientAuthorizedKey(t)
	rec = doRequest(t, r, http.MethodPost, "/api/v1/sshca/"+ca.ID.String()+"/sign/user", mustMarshal(t, struct {
		ProvisionerID string   `json:"provisioner_id"`
		PublicKey     string   `json:"public_key"`
		KeyID         string   `json:"key_id"`
		Principals    []string `json:"principals"`
	}{
		ProvisionerID: uuid.NewString(),
		PublicKey:     clientPub,
		KeyID:         "alice",
		Principals:    []string{"alice"},
	}))
	certID := signAndDecode(t, rec).Certificate.ID.String()

	rec = doRequest(t, r, http.MethodPut, "/api/v1/sshca/certs/"+certID+"/revoke", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Revoking again should 404 (not found / already revoked).
	rec = doRequest(t, r, http.MethodPut, "/api/v1/sshca/certs/"+certID+"/revoke", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("second revoke: expected 404, got %d", rec.Code)
	}
}

func decodeTestJSON(s string, v interface{}) error {
	return json.Unmarshal([]byte(s), v)
}

func mustMarshal(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	return string(b)
}

type issuedCertResponse struct {
	Certificate *storage.SSHCertificate `json:"certificate"`
	CertData    string                  `json:"cert_data"`
}

func signAndDecode(t *testing.T, rec *httptest.ResponseRecorder) issuedCertResponse {
	t.Helper()
	var out issuedCertResponse
	if err := decodeTestJSON(rec.Body.String(), &out); err != nil {
		t.Fatalf("decode issue/sign response: %v (body: %s)", err, rec.Body.String())
	}
	return out
}

// testClientAuthorizedKey creates a throwaway ed25519 SSH keypair and returns
// its public key as an authorized_keys line for use as certificate input.
func testClientAuthorizedKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test client key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("wrap test client signer: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}
