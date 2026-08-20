package ca

import (
	"context"
	"sync"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// caFakeStore is a minimal in-memory storage.Store covering only what the
// Engine touches (CreateCA, GetCA, GetCAByName, CreateCertificate).
// Every other method panics loudly so a missing case fails fast rather than
// silently returning zero values.
type caFakeStore struct {
	mu    sync.Mutex
	cas   map[uuid.UUID]*storage.CertificateAuthority
	certs map[uuid.UUID]*storage.Certificate
}

func newCAFakeStore() *caFakeStore {
	return &caFakeStore{
		cas:   make(map[uuid.UUID]*storage.CertificateAuthority),
		certs: make(map[uuid.UUID]*storage.Certificate),
	}
}

func caNotImplemented(method string) {
	panic("caFakeStore: " + method + " not implemented in fake — add it if your test needs it")
}

// ---- CA ----

func (f *caFakeStore) CreateCA(ctx context.Context, ca *storage.CertificateAuthority) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cas[ca.ID] = ca
	return nil
}
func (f *caFakeStore) GetCA(ctx context.Context, id uuid.UUID) (*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cas[id], nil
}
func (f *caFakeStore) GetCAByName(ctx context.Context, name string) (*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cas {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, nil
}
func (f *caFakeStore) ListCAs(ctx context.Context) ([]*storage.CertificateAuthority, error) {
	caNotImplemented("ListCAs")
	return nil, nil
}
func (f *caFakeStore) ListChildCAs(ctx context.Context, parentID uuid.UUID) ([]*storage.CertificateAuthority, error) {
	caNotImplemented("ListChildCAs")
	return nil, nil
}
func (f *caFakeStore) UpdateCAStatus(ctx context.Context, id uuid.UUID, status storage.CAStatus) error {
	caNotImplemented("UpdateCAStatus")
	return nil
}

// ---- Certificates ----

func (f *caFakeStore) CreateCertificate(ctx context.Context, cert *storage.Certificate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certs[cert.ID] = cert
	return nil
}
func (f *caFakeStore) GetCertificate(ctx context.Context, id uuid.UUID) (*storage.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.certs[id], nil
}
func (f *caFakeStore) GetCertificateBySerial(ctx context.Context, serial string) (*storage.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.certs {
		if c.Serial == serial {
			return c, nil
		}
	}
	return nil, nil
}
func (f *caFakeStore) ListCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	caNotImplemented("ListCertificatesByCA")
	return nil, nil
}
func (f *caFakeStore) ListRevokedByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	caNotImplemented("ListRevokedByCA")
	return nil, nil
}
func (f *caFakeStore) RevokeCertificate(ctx context.Context, id uuid.UUID, reason int) error {
	caNotImplemented("RevokeCertificate")
	return nil
}

// ---- Provisioners ----

func (f *caFakeStore) CreateProvisioner(ctx context.Context, p *storage.Provisioner) error {
	caNotImplemented("CreateProvisioner")
	return nil
}
func (f *caFakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	caNotImplemented("GetProvisioner")
	return nil, nil
}
func (f *caFakeStore) ListProvisionersByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Provisioner, error) {
	caNotImplemented("ListProvisionersByCA")
	return nil, nil
}
func (f *caFakeStore) UpdateProvisionerStatus(ctx context.Context, id uuid.UUID, status storage.ProvisionerStatus) error {
	caNotImplemented("UpdateProvisionerStatus")
	return nil
}

// ---- Policies ----

func (f *caFakeStore) CreatePolicy(ctx context.Context, p *storage.Policy) error {
	caNotImplemented("CreatePolicy")
	return nil
}
func (f *caFakeStore) GetPolicy(ctx context.Context, id uuid.UUID) (*storage.Policy, error) {
	caNotImplemented("GetPolicy")
	return nil, nil
}
func (f *caFakeStore) ListPolicies(ctx context.Context) ([]*storage.Policy, error) {
	caNotImplemented("ListPolicies")
	return nil, nil
}
func (f *caFakeStore) UpdatePolicy(ctx context.Context, p *storage.Policy) error {
	caNotImplemented("UpdatePolicy")
	return nil
}
func (f *caFakeStore) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	caNotImplemented("DeletePolicy")
	return nil
}

// ---- ACME accounts ----

func (f *caFakeStore) CreateACMEAccount(ctx context.Context, a *storage.ACMEAccount) error {
	caNotImplemented("CreateACMEAccount")
	return nil
}
func (f *caFakeStore) GetACMEAccountByKeyID(ctx context.Context, keyID string) (*storage.ACMEAccount, error) {
	caNotImplemented("GetACMEAccountByKeyID")
	return nil, nil
}
func (f *caFakeStore) GetACMEAccount(ctx context.Context, id uuid.UUID) (*storage.ACMEAccount, error) {
	caNotImplemented("GetACMEAccount")
	return nil, nil
}
func (f *caFakeStore) UpdateACMEAccountStatus(ctx context.Context, id uuid.UUID, status storage.ACMEAccountStatus) error {
	caNotImplemented("UpdateACMEAccountStatus")
	return nil
}
func (f *caFakeStore) UpdateACMEAccountContact(ctx context.Context, id uuid.UUID, contact []string) error {
	caNotImplemented("UpdateACMEAccountContact")
	return nil
}

// ---- EAB ----

func (f *caFakeStore) CreateEABCredential(ctx context.Context, e *storage.EABCredential) error {
	caNotImplemented("CreateEABCredential")
	return nil
}
func (f *caFakeStore) GetEABCredential(ctx context.Context, keyID string) (*storage.EABCredential, error) {
	caNotImplemented("GetEABCredential")
	return nil, nil
}
func (f *caFakeStore) MarkEABUsed(ctx context.Context, id uuid.UUID) error {
	caNotImplemented("MarkEABUsed")
	return nil
}

// ---- ACME orders ----

func (f *caFakeStore) CreateACMEOrder(ctx context.Context, o *storage.ACMEOrder) error {
	caNotImplemented("CreateACMEOrder")
	return nil
}
func (f *caFakeStore) GetACMEOrder(ctx context.Context, id uuid.UUID) (*storage.ACMEOrder, error) {
	caNotImplemented("GetACMEOrder")
	return nil, nil
}
func (f *caFakeStore) ListACMEOrdersByAccount(ctx context.Context, accountID uuid.UUID) ([]*storage.ACMEOrder, error) {
	caNotImplemented("ListACMEOrdersByAccount")
	return nil, nil
}
func (f *caFakeStore) UpdateACMEOrderStatus(ctx context.Context, id uuid.UUID, status storage.ACMEOrderStatus) error {
	caNotImplemented("UpdateACMEOrderStatus")
	return nil
}
func (f *caFakeStore) FinalizeACMEOrder(ctx context.Context, orderID uuid.UUID, certID uuid.UUID) error {
	caNotImplemented("FinalizeACMEOrder")
	return nil
}

// ---- ACME challenges ----

func (f *caFakeStore) CreateACMEChallenge(ctx context.Context, c *storage.ACMEChallenge) error {
	caNotImplemented("CreateACMEChallenge")
	return nil
}
func (f *caFakeStore) GetACMEChallenge(ctx context.Context, id uuid.UUID) (*storage.ACMEChallenge, error) {
	caNotImplemented("GetACMEChallenge")
	return nil, nil
}
func (f *caFakeStore) ListChallengesByOrder(ctx context.Context, orderID uuid.UUID) ([]*storage.ACMEChallenge, error) {
	caNotImplemented("ListChallengesByOrder")
	return nil, nil
}
func (f *caFakeStore) UpdateChallengeStatus(ctx context.Context, id uuid.UUID, status storage.ACMEChallengeStatus, validatedAt *time.Time) error {
	caNotImplemented("UpdateChallengeStatus")
	return nil
}
func (f *caFakeStore) ListChallengesByAuthorization(ctx context.Context, authID uuid.UUID) ([]*storage.ACMEChallenge, error) {
	caNotImplemented("ListChallengesByAuthorization")
	return nil, nil
}

// ---- ACME authorizations ----

func (f *caFakeStore) CreateACMEAuthorization(ctx context.Context, a *storage.ACMEAuthorization) error {
	caNotImplemented("CreateACMEAuthorization")
	return nil
}
func (f *caFakeStore) GetACMEAuthorization(ctx context.Context, id uuid.UUID) (*storage.ACMEAuthorization, error) {
	caNotImplemented("GetACMEAuthorization")
	return nil, nil
}
func (f *caFakeStore) UpdateACMEAuthorizationStatus(ctx context.Context, id uuid.UUID, status storage.ACMEAuthorizationStatus) error {
	caNotImplemented("UpdateACMEAuthorizationStatus")
	return nil
}
func (f *caFakeStore) ListAuthorizationsByOrder(ctx context.Context, orderID uuid.UUID) ([]*storage.ACMEAuthorization, error) {
	caNotImplemented("ListAuthorizationsByOrder")
	return nil, nil
}

// ---- Audit ----

func (f *caFakeStore) WriteAuditLog(ctx context.Context, entry *storage.AuditLog) error {
	return nil
}
func (f *caFakeStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]*storage.AuditLog, error) {
	caNotImplemented("ListAuditLogs")
	return nil, nil
}
func (f *caFakeStore) ListAuditLogsByCA(ctx context.Context, caID uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
	caNotImplemented("ListAuditLogsByCA")
	return nil, nil
}

// ---- CRL ----

func (f *caFakeStore) UpsertCRL(ctx context.Context, crl *storage.CRLCache) error {
	caNotImplemented("UpsertCRL")
	return nil
}
func (f *caFakeStore) GetCRL(ctx context.Context, caID uuid.UUID) (*storage.CRLCache, error) {
	caNotImplemented("GetCRL")
	return nil, nil
}

// ---- API keys ----

func (f *caFakeStore) CreateAPIKey(ctx context.Context, k *storage.APIKey) error {
	caNotImplemented("CreateAPIKey")
	return nil
}
func (f *caFakeStore) GetAPIKeyByHash(ctx context.Context, hash string) (*storage.APIKey, error) {
	caNotImplemented("GetAPIKeyByHash")
	return nil, nil
}
func (f *caFakeStore) ListAPIKeys(ctx context.Context) ([]*storage.APIKey, error) {
	caNotImplemented("ListAPIKeys")
	return nil, nil
}
func (f *caFakeStore) DeleteAPIKey(ctx context.Context, id uuid.UUID) error {
	caNotImplemented("DeleteAPIKey")
	return nil
}
func (f *caFakeStore) TouchAPIKey(ctx context.Context, id uuid.UUID) error {
	caNotImplemented("TouchAPIKey")
	return nil
}
func (f *caFakeStore) GetAPIKeyByName(ctx context.Context, name string) (*storage.APIKey, error) {
	caNotImplemented("GetAPIKeyByName")
	return nil, nil
}

// ---- Setup / misc ----

func (f *caFakeStore) Migrate(ctx context.Context) error { return nil }
func (f *caFakeStore) GetSetupState(ctx context.Context) (storage.SetupState, error) {
	caNotImplemented("GetSetupState")
	return "", nil
}
func (f *caFakeStore) SetSetupState(ctx context.Context, state storage.SetupState) error {
	caNotImplemented("SetSetupState")
	return nil
}
func (f *caFakeStore) Close() error { return nil }

// ---- Nonces ----

func (f *caFakeStore) CreateNonce(ctx context.Context, nonce string, expiresAt time.Time) error {
	caNotImplemented("CreateNonce")
	return nil
}
func (f *caFakeStore) ConsumeNonce(ctx context.Context, nonce string) (bool, error) {
	caNotImplemented("ConsumeNonce")
	return false, nil
}
func (f *caFakeStore) PruneExpiredNonces(ctx context.Context) error {
	caNotImplemented("PruneExpiredNonces")
	return nil
}

// ---- SSH CA (not exercised by X.509 CA engine tests) ----

func (f *caFakeStore) CreateSSHCA(ctx context.Context, ca *storage.SSHCertificateAuthority) error {
	caNotImplemented("CreateSSHCA")
	return nil
}
func (f *caFakeStore) GetSSHCA(ctx context.Context, id uuid.UUID) (*storage.SSHCertificateAuthority, error) {
	caNotImplemented("GetSSHCA")
	return nil, nil
}
func (f *caFakeStore) GetSSHCAByName(ctx context.Context, name string) (*storage.SSHCertificateAuthority, error) {
	caNotImplemented("GetSSHCAByName")
	return nil, nil
}
func (f *caFakeStore) ListSSHCAs(ctx context.Context) ([]*storage.SSHCertificateAuthority, error) {
	caNotImplemented("ListSSHCAs")
	return nil, nil
}
func (f *caFakeStore) CreateSSHCertificate(ctx context.Context, cert *storage.SSHCertificate) error {
	caNotImplemented("CreateSSHCertificate")
	return nil
}
func (f *caFakeStore) GetSSHCertificate(ctx context.Context, id uuid.UUID) (*storage.SSHCertificate, error) {
	caNotImplemented("GetSSHCertificate")
	return nil, nil
}
func (f *caFakeStore) GetSSHCertificateBySerial(ctx context.Context, caID uuid.UUID, serial uint64) (*storage.SSHCertificate, error) {
	caNotImplemented("GetSSHCertificateBySerial")
	return nil, nil
}
func (f *caFakeStore) ListSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.SSHCertificate, error) {
	caNotImplemented("ListSSHCertificatesByCA")
	return nil, nil
}
func (f *caFakeStore) RevokeSSHCertificate(ctx context.Context, id uuid.UUID) error {
	caNotImplemented("RevokeSSHCertificate")
	return nil
}
func (f *caFakeStore) GetACMEAuthorizationByIdentifier(ctx context.Context, accountID uuid.UUID, identifierType, identifierValue string) (*storage.ACMEAuthorization, error) {
	caNotImplemented("GetACMEAuthorizationByIdentifier")
	return nil, nil
}
func (f *caFakeStore) ListAuthorizationsByAccount(ctx context.Context, accountID uuid.UUID) ([]*storage.ACMEAuthorization, error) {
	caNotImplemented("ListAuthorizationsByAccount")
	return nil, nil
}
func (f *caFakeStore) GetRateLimitConfig(ctx context.Context, name string) (*storage.RateLimitConfig, error) {
	caNotImplemented("GetRateLimitConfig")
	return nil, nil
}
func (f *caFakeStore) ListRateLimitConfigs(ctx context.Context) ([]*storage.RateLimitConfig, error) {
	caNotImplemented("ListRateLimitConfigs")
	return nil, nil
}
func (f *caFakeStore) UpsertRateLimitConfigIfAbsent(ctx context.Context, cfg *storage.RateLimitConfig) error {
	caNotImplemented("UpsertRateLimitConfigIfAbsent")
	return nil
}
func (f *caFakeStore) UpdateRateLimitConfig(ctx context.Context, cfg *storage.RateLimitConfig) error {
	caNotImplemented("UpdateRateLimitConfig")
	return nil
}
func (f *caFakeStore) IncrementRateLimitCounter(ctx context.Context, limiterName, bucketKey string, windowStart time.Time) error {
	caNotImplemented("IncrementRateLimitCounter")
	return nil
}
func (f *caFakeStore) PruneExpiredRateLimitCounters(ctx context.Context, olderThan time.Time) error {
	caNotImplemented("PruneExpiredRateLimitCounters")
	return nil
}
