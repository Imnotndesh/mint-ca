package acme

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// fakeStore is an in-memory storage.Store covering only what ACME
// service-layer tests exercise. Unimplemented methods panic with a clear
// message so a missing case fails loudly instead of silently.
type fakeStore struct {
	mu             sync.Mutex
	cas            map[uuid.UUID]*storage.CertificateAuthority
	provisioners   map[uuid.UUID]*storage.Provisioner
	accounts       map[uuid.UUID]*storage.ACMEAccount
	orders         map[uuid.UUID]*storage.ACMEOrder
	authorizations map[uuid.UUID]*storage.ACMEAuthorization
	challenges     map[uuid.UUID]*storage.ACMEChallenge
	certsBySerial  map[string]*storage.Certificate
	retiredKeys    map[string]bool
	crls           map[uuid.UUID]*storage.CRLCache
	deltaCRLs      map[uuid.UUID]*storage.DeltaCRLCache
	crlCounter     map[uuid.UUID]int64
	nonces         map[string]time.Time
	profiles       map[uuid.UUID]*storage.Profile
}

func NewFakeStore() *fakeStore {
	return &fakeStore{
		cas:            make(map[uuid.UUID]*storage.CertificateAuthority),
		provisioners:   make(map[uuid.UUID]*storage.Provisioner),
		accounts:       make(map[uuid.UUID]*storage.ACMEAccount),
		orders:         make(map[uuid.UUID]*storage.ACMEOrder),
		authorizations: make(map[uuid.UUID]*storage.ACMEAuthorization),
		challenges:     make(map[uuid.UUID]*storage.ACMEChallenge),
		certsBySerial:  make(map[string]*storage.Certificate),
		retiredKeys:    make(map[string]bool),
		crls:           make(map[uuid.UUID]*storage.CRLCache),
		deltaCRLs:      make(map[uuid.UUID]*storage.DeltaCRLCache),
		crlCounter:     make(map[uuid.UUID]int64),
		nonces:         make(map[string]time.Time),
		profiles:       make(map[uuid.UUID]*storage.Profile),
	}
}

// ---- Profiles (not part of storage.Store; used via the acme package's
// local profileLookup interface assertion, mirroring the REST handler
// pattern) ----

func (f *fakeStore) CreateProfile(ctx context.Context, p *storage.Profile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.profiles[p.ID] = p
	return nil
}
func (f *fakeStore) GetProfile(ctx context.Context, id uuid.UUID) (*storage.Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.profiles[id], nil
}
func (f *fakeStore) GetProfileByName(ctx context.Context, name string) (*storage.Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.profiles {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, nil
}

func notImplemented(method string) {
	panic(fmt.Sprintf("fakeStore: %s not implemented in fake — add it if your test needs it", method))
}

// ---- CA ----

func (f *fakeStore) CreateCA(ctx context.Context, ca *storage.CertificateAuthority) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cas[ca.ID] = ca
	return nil
}
func (f *fakeStore) GetCA(ctx context.Context, id uuid.UUID) (*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cas[id], nil
}
func (f *fakeStore) GetCAByName(ctx context.Context, name string) (*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cas {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, nil
}
func (f *fakeStore) ListCAs(ctx context.Context) ([]*storage.CertificateAuthority, error) {
	notImplemented("ListCAs")
	return nil, nil
}
func (f *fakeStore) ListChildCAs(ctx context.Context, parentID uuid.UUID) ([]*storage.CertificateAuthority, error) {
	notImplemented("ListChildCAs")
	return nil, nil
}
func (f *fakeStore) UpdateCAStatus(ctx context.Context, id uuid.UUID, status storage.CAStatus) error {
	notImplemented("UpdateCAStatus")
	return nil
}
func (f *fakeStore) CreateCrossCert(ctx context.Context, cc *storage.CrossCert) error {
	notImplemented("CreateCrossCert")
	return nil
}
func (f *fakeStore) GetCrossCert(ctx context.Context, targetCAID, signingCAID uuid.UUID) (*storage.CrossCert, error) {
	notImplemented("GetCrossCert")
	return nil, nil
}
func (f *fakeStore) ListCrossCertsByTarget(ctx context.Context, targetCAID uuid.UUID) ([]*storage.CrossCert, error) {
	notImplemented("ListCrossCertsByTarget")
	return nil, nil
}

// ---- Certificates ----

func (f *fakeStore) CreateCertificate(ctx context.Context, cert *storage.Certificate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certsBySerial[cert.Serial] = cert
	return nil
}
func (f *fakeStore) GetCertificate(ctx context.Context, id uuid.UUID) (*storage.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.certsBySerial {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, nil
}
func (f *fakeStore) GetCertificateBySerial(ctx context.Context, serial string) (*storage.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.certsBySerial[serial], nil
}
func (f *fakeStore) ListCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	notImplemented("ListCertificatesByCA")
	return nil, nil
}
func (f *fakeStore) ListRevokedByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.Certificate
	for _, c := range f.certsBySerial {
		if c.CAID == caID && c.Status == storage.CertStatusRevoked {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *fakeStore) RevokeCertificate(ctx context.Context, id uuid.UUID, reason int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.certsBySerial {
		if c.ID == id {
			if c.Status == storage.CertStatusRevoked {
				return fmt.Errorf("already revoked")
			}
			c.Status = storage.CertStatusRevoked
			c.RevokeReason = &reason
			return nil
		}
	}
	return fmt.Errorf("certificate not found")
}

// ---- Provisioners ----

func (f *fakeStore) CreateProvisioner(ctx context.Context, p *storage.Provisioner) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.provisioners[p.ID] = p
	return nil
}
func (f *fakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.provisioners[id], nil
}
func (f *fakeStore) ListProvisionersByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Provisioner, error) {
	notImplemented("ListProvisionersByCA")
	return nil, nil
}
func (f *fakeStore) UpdateProvisionerStatus(ctx context.Context, id uuid.UUID, status storage.ProvisionerStatus) error {
	notImplemented("UpdateProvisionerStatus")
	return nil
}

// ---- Policies ----

func (f *fakeStore) CreatePolicy(ctx context.Context, p *storage.Policy) error {
	notImplemented("CreatePolicy")
	return nil
}
func (f *fakeStore) GetPolicy(ctx context.Context, id uuid.UUID) (*storage.Policy, error) {
	notImplemented("GetPolicy")
	return nil, nil
}
func (f *fakeStore) ListPolicies(ctx context.Context) ([]*storage.Policy, error) {
	notImplemented("ListPolicies")
	return nil, nil
}
func (f *fakeStore) UpdatePolicy(ctx context.Context, p *storage.Policy) error {
	notImplemented("UpdatePolicy")
	return nil
}
func (f *fakeStore) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	notImplemented("DeletePolicy")
	return nil
}

// ---- ACME accounts ----
func (f *fakeStore) UpdateACMEAccountContact(ctx context.Context, id uuid.UUID, contact []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.accounts[id]
	if !ok {
		return fmt.Errorf("account not found")
	}
	a.Contact = contact
	return nil
}
func (f *fakeStore) CreateACMEAccount(ctx context.Context, a *storage.ACMEAccount) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accounts[a.ID] = a
	return nil
}
func (f *fakeStore) GetACMEAccountByKeyID(ctx context.Context, keyID string) (*storage.ACMEAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.accounts {
		if a.KeyID == keyID {
			return a, nil
		}
	}
	return nil, nil
}
func (f *fakeStore) GetACMEAccount(ctx context.Context, id uuid.UUID) (*storage.ACMEAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accounts[id], nil
}
func (f *fakeStore) UpdateACMEAccountStatus(ctx context.Context, id uuid.UUID, status storage.ACMEAccountStatus) error {
	notImplemented("UpdateACMEAccountStatus")
	return nil
}

// ---- EAB ----

func (f *fakeStore) CreateEABCredential(ctx context.Context, e *storage.EABCredential) error {
	notImplemented("CreateEABCredential")
	return nil
}
func (f *fakeStore) GetEABCredential(ctx context.Context, keyID string) (*storage.EABCredential, error) {
	notImplemented("GetEABCredential")
	return nil, nil
}
func (f *fakeStore) MarkEABUsed(ctx context.Context, id uuid.UUID) error {
	notImplemented("MarkEABUsed")
	return nil
}

// ---- ACME orders ----

func (f *fakeStore) CreateACMEOrder(ctx context.Context, o *storage.ACMEOrder) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orders[o.ID] = o
	return nil
}
func (f *fakeStore) GetACMEOrder(ctx context.Context, id uuid.UUID) (*storage.ACMEOrder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.orders[id], nil
}
func (f *fakeStore) ListACMEOrdersByAccount(ctx context.Context, accountID uuid.UUID) ([]*storage.ACMEOrder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.ACMEOrder
	for _, o := range f.orders {
		if o.AccountID == accountID {
			out = append(out, o)
		}
	}
	return out, nil
}
func (f *fakeStore) UpdateACMEOrderStatus(ctx context.Context, id uuid.UUID, status storage.ACMEOrderStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o, ok := f.orders[id]; ok {
		o.Status = status
	}
	return nil
}
func (f *fakeStore) FinalizeACMEOrder(ctx context.Context, orderID uuid.UUID, certID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.orders[orderID]
	if !ok {
		return fmt.Errorf("order %s not found", orderID)
	}
	o.Status = storage.ACMEOrderStatusValid
	o.CertificateID = &certID
	return nil
}

// ---- ACME challenges ----

func (f *fakeStore) CreateACMEChallenge(ctx context.Context, c *storage.ACMEChallenge) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.challenges[c.ID] = c
	return nil
}
func (f *fakeStore) GetACMEChallenge(ctx context.Context, id uuid.UUID) (*storage.ACMEChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.challenges[id], nil
}
func (f *fakeStore) ListChallengesByOrder(ctx context.Context, orderID uuid.UUID) ([]*storage.ACMEChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.ACMEChallenge
	for _, c := range f.challenges {
		if c.OrderID == orderID {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *fakeStore) UpdateChallengeStatus(ctx context.Context, id uuid.UUID, status storage.ACMEChallengeStatus, validatedAt *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.challenges[id]; ok {
		c.Status = status
		c.ValidatedAt = validatedAt
	}
	return nil
}
func (f *fakeStore) ListChallengesByAuthorization(ctx context.Context, authID uuid.UUID) ([]*storage.ACMEChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.ACMEChallenge
	for _, c := range f.challenges {
		if c.AuthorizationID != nil && *c.AuthorizationID == authID {
			out = append(out, c)
		}
	}
	return out, nil
}

// ---- ACME authorizations ----

func (f *fakeStore) CreateACMEAuthorization(ctx context.Context, a *storage.ACMEAuthorization) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorizations[a.ID] = a
	return nil
}
func (f *fakeStore) GetACMEAuthorization(ctx context.Context, id uuid.UUID) (*storage.ACMEAuthorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authorizations[id], nil
}
func (f *fakeStore) UpdateACMEAuthorizationStatus(ctx context.Context, id uuid.UUID, status storage.ACMEAuthorizationStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.authorizations[id]; ok {
		a.Status = status
	}
	return nil
}
func (f *fakeStore) ListAuthorizationsByOrder(ctx context.Context, orderID uuid.UUID) ([]*storage.ACMEAuthorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.ACMEAuthorization
	for _, a := range f.authorizations {
		if a.OrderID == orderID {
			out = append(out, a)
		}
	}
	return out, nil
}

// ---- Audit ----

func (f *fakeStore) WriteAuditLog(ctx context.Context, entry *storage.AuditLog) error {
	return nil // silently accept; tests here don't assert on audit trail
}
func (f *fakeStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]*storage.AuditLog, error) {
	notImplemented("ListAuditLogs")
	return nil, nil
}
func (f *fakeStore) ListAuditLogsByCA(ctx context.Context, caID uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
	notImplemented("ListAuditLogsByCA")
	return nil, nil
}

// ---- CRL ----

func (f *fakeStore) UpsertCRL(ctx context.Context, crl *storage.CRLCache) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.crls == nil {
		f.crls = make(map[uuid.UUID]*storage.CRLCache)
	}
	f.crls[crl.CAID] = crl
	return nil
}
func (f *fakeStore) GetCRL(ctx context.Context, caID uuid.UUID) (*storage.CRLCache, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.crls[caID], nil
}
func (f *fakeStore) NextCRLNumber(ctx context.Context, caID uuid.UUID) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.crlCounter[caID]++
	return f.crlCounter[caID], nil
}
func (f *fakeStore) ListRevokedByCASince(ctx context.Context, caID uuid.UUID, since time.Time) ([]*storage.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.Certificate
	for _, c := range f.certsBySerial {
		if c.CAID == caID && c.RevokedAt != nil && c.RevokedAt.UTC().After(since) {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *fakeStore) UpsertDeltaCRL(ctx context.Context, d *storage.DeltaCRLCache) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deltaCRLs == nil {
		f.deltaCRLs = make(map[uuid.UUID]*storage.DeltaCRLCache)
	}
	f.deltaCRLs[d.CAID] = d
	return nil
}
func (f *fakeStore) GetDeltaCRL(ctx context.Context, caID uuid.UUID) (*storage.DeltaCRLCache, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deltaCRLs[caID], nil
}

// ---- API keys ----

func (f *fakeStore) CreateAPIKey(ctx context.Context, k *storage.APIKey) error {
	notImplemented("CreateAPIKey")
	return nil
}
func (f *fakeStore) GetAPIKeyByHash(ctx context.Context, hash string) (*storage.APIKey, error) {
	notImplemented("GetAPIKeyByHash")
	return nil, nil
}
func (f *fakeStore) ListAPIKeys(ctx context.Context) ([]*storage.APIKey, error) {
	notImplemented("ListAPIKeys")
	return nil, nil
}
func (f *fakeStore) DeleteAPIKey(ctx context.Context, id uuid.UUID) error {
	notImplemented("DeleteAPIKey")
	return nil
}
func (f *fakeStore) TouchAPIKey(ctx context.Context, id uuid.UUID) error {
	notImplemented("TouchAPIKey")
	return nil
}
func (f *fakeStore) GetAPIKeyByName(ctx context.Context, name string) (*storage.APIKey, error) {
	notImplemented("GetAPIKeyByName")
	return nil, nil
}

// ---- Setup / misc ----

func (f *fakeStore) Migrate(ctx context.Context) error { return nil }
func (f *fakeStore) GetSetupState(ctx context.Context) (storage.SetupState, error) {
	notImplemented("GetSetupState")
	return "", nil
}
func (f *fakeStore) SetSetupState(ctx context.Context, state storage.SetupState) error {
	notImplemented("SetSetupState")
	return nil
}
func (f *fakeStore) Close() error { return nil }

// ---- Nonces ----

func (f *fakeStore) CreateNonce(ctx context.Context, nonce string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonces[nonce] = expiresAt
	return nil
}
func (f *fakeStore) ConsumeNonce(ctx context.Context, nonce string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, ok := f.nonces[nonce]
	if !ok {
		return false, nil
	}
	delete(f.nonces, nonce)
	return time.Now().UTC().Before(exp), nil
}
func (f *fakeStore) PruneExpiredNonces(ctx context.Context) error {
	notImplemented("PruneExpiredNonces")
	return nil
}

// ---- SSH CA (not exercised by ACME tests) ----

func (f *fakeStore) CreateSSHCA(ctx context.Context, ca *storage.SSHCertificateAuthority) error {
	notImplemented("CreateSSHCA")
	return nil
}
func (f *fakeStore) GetSSHCA(ctx context.Context, id uuid.UUID) (*storage.SSHCertificateAuthority, error) {
	notImplemented("GetSSHCA")
	return nil, nil
}
func (f *fakeStore) GetSSHCAByName(ctx context.Context, name string) (*storage.SSHCertificateAuthority, error) {
	notImplemented("GetSSHCAByName")
	return nil, nil
}
func (f *fakeStore) ListSSHCAs(ctx context.Context) ([]*storage.SSHCertificateAuthority, error) {
	notImplemented("ListSSHCAs")
	return nil, nil
}
func (f *fakeStore) CreateSSHCertificate(ctx context.Context, cert *storage.SSHCertificate) error {
	notImplemented("CreateSSHCertificate")
	return nil
}
func (f *fakeStore) GetSSHCertificate(ctx context.Context, id uuid.UUID) (*storage.SSHCertificate, error) {
	notImplemented("GetSSHCertificate")
	return nil, nil
}
func (f *fakeStore) GetSSHCertificateBySerial(ctx context.Context, caID uuid.UUID, serial uint64) (*storage.SSHCertificate, error) {
	notImplemented("GetSSHCertificateBySerial")
	return nil, nil
}
func (f *fakeStore) ListSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.SSHCertificate, error) {
	notImplemented("ListSSHCertificatesByCA")
	return nil, nil
}
func (f *fakeStore) RevokeSSHCertificate(ctx context.Context, id uuid.UUID) error {
	notImplemented("RevokeSSHCertificate")
	return nil
}
func (f *fakeStore) ListRevokedSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.SSHCertificate, error) {
	notImplemented("ListRevokedSSHCertificatesByCA")
	return nil, nil
}
func (f *fakeStore) UpsertSSHKRL(ctx context.Context, k *storage.SSHKRLCache) error {
	notImplemented("UpsertSSHKRL")
	return nil
}
func (f *fakeStore) GetSSHKRL(ctx context.Context, caID uuid.UUID) (*storage.SSHKRLCache, error) {
	notImplemented("GetSSHKRL")
	return nil, nil
}

// GetACMEAuthorizationByIdentifier returns the most recent standalone
// (OrderID == uuid.Nil) authorization for the given account + identifier.
func (f *fakeStore) GetACMEAuthorizationByIdentifier(ctx context.Context, accountID uuid.UUID, identifierType, identifierValue string) (*storage.ACMEAuthorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var best *storage.ACMEAuthorization
	for _, a := range f.authorizations {
		if a.OrderID != uuid.Nil {
			continue
		}
		if a.AccountID != accountID {
			continue
		}
		if a.IdentifierType != identifierType || a.IdentifierValue != identifierValue {
			continue
		}
		if best == nil || a.CreatedAt.After(best.CreatedAt) {
			best = a
		}
	}
	return best, nil
}
func (f *fakeStore) GetRateLimitConfig(ctx context.Context, name string) (*storage.RateLimitConfig, error) {
	notImplemented("GetRateLimitConfig")
	return nil, nil
}
func (f *fakeStore) ListRateLimitConfigs(ctx context.Context) ([]*storage.RateLimitConfig, error) {
	notImplemented("ListRateLimitConfigs")
	return nil, nil
}
func (f *fakeStore) UpsertRateLimitConfigIfAbsent(ctx context.Context, cfg *storage.RateLimitConfig) error {
	notImplemented("UpsertRateLimitConfigIfAbsent")
	return nil
}
func (f *fakeStore) UpdateRateLimitConfig(ctx context.Context, cfg *storage.RateLimitConfig) error {
	notImplemented("UpdateRateLimitConfig")
	return nil
}
func (f *fakeStore) IncrementRateLimitCounter(ctx context.Context, limiterName, bucketKey string, windowStart time.Time) error {
	// Silently accept — ratelimit tests that exercise the real Engine can
	// override this via a purpose-built fake if needed; ACME service tests
	// don't touch rate limiting directly.
	return nil
}
func (f *fakeStore) PruneExpiredRateLimitCounters(ctx context.Context, olderThan time.Time) error {
	notImplemented("PruneExpiredRateLimitCounters")
	return nil
}
func (f *fakeStore) UpdateACMEAccountKey(ctx context.Context, accountID uuid.UUID, newKeyID string, newKeyJWK storage.JSON) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.accounts[accountID]
	if !ok {
		return fmt.Errorf("account not found")
	}
	a.KeyID = newKeyID
	a.KeyJWK = newKeyJWK
	return nil
}

func (f *fakeStore) MarkKeyIDRetired(ctx context.Context, keyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.retiredKeys == nil {
		f.retiredKeys = make(map[string]bool)
	}
	f.retiredKeys[keyID] = true
	return nil
}

func (f *fakeStore) IsKeyIDRetired(ctx context.Context, keyID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.retiredKeys[keyID], nil
}

// ListAuthorizationsByAccount returns standalone pre-authorizations for an
// account, newest first.
func (f *fakeStore) ListAuthorizationsByAccount(ctx context.Context, accountID uuid.UUID) ([]*storage.ACMEAuthorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.ACMEAuthorization
	for _, a := range f.authorizations {
		if a.OrderID == uuid.Nil && a.AccountID == accountID {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
