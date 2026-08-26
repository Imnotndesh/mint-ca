package sshca

import (
	"context"
	"fmt"
	"sync"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// fakeStore is a minimal in-memory storage.Store covering only what the
// sshca Engine touches. Everything else panics loudly so a missing case
// fails fast instead of silently returning zero values.
type fakeStore struct {
	mu    sync.Mutex
	cas   map[uuid.UUID]*storage.SSHCertificateAuthority
	certs map[uuid.UUID]*storage.SSHCertificate
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		cas:   make(map[uuid.UUID]*storage.SSHCertificateAuthority),
		certs: make(map[uuid.UUID]*storage.SSHCertificate),
	}
}

func notImplemented(method string) {
	panic("sshca fakeStore: " + method + " not implemented in fake — add it if your test needs it")
}

func (f *fakeStore) CreateSSHCA(ctx context.Context, ca *storage.SSHCertificateAuthority) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cas[ca.ID] = ca
	return nil
}
func (f *fakeStore) GetSSHCA(ctx context.Context, id uuid.UUID) (*storage.SSHCertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cas[id], nil
}
func (f *fakeStore) GetSSHCAByName(ctx context.Context, name string) (*storage.SSHCertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cas {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, nil
}
func (f *fakeStore) ListSSHCAs(ctx context.Context) ([]*storage.SSHCertificateAuthority, error) {
	notImplemented("ListSSHCAs")
	return nil, nil
}
func (f *fakeStore) CreateSSHCertificate(ctx context.Context, cert *storage.SSHCertificate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certs[cert.ID] = cert
	return nil
}
func (f *fakeStore) GetSSHCertificate(ctx context.Context, id uuid.UUID) (*storage.SSHCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.certs[id], nil
}
func (f *fakeStore) GetSSHCertificateBySerial(ctx context.Context, caID uuid.UUID, serial uint64) (*storage.SSHCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.certs {
		if c.CAID == caID && c.Serial == serial {
			return c, nil
		}
	}
	return nil, nil
}
func (f *fakeStore) ListSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.SSHCertificate, error) {
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
func (f *fakeStore) RevokeSSHCertificate(ctx context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.certs[id]
	if !ok {
		return errNotFound
	}
	now := time.Now().UTC()
	c.Status = storage.SSHCertStatusRevoked
	c.RevokedAt = &now
	return nil
}
func (f *fakeStore) ListRevokedSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.SSHCertificate, error) {
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
func (f *fakeStore) UpsertSSHKRL(ctx context.Context, k *storage.SSHKRLCache) error {
	notImplemented("UpsertSSHKRL")
	return nil
}
func (f *fakeStore) GetSSHKRL(ctx context.Context, caID uuid.UUID) (*storage.SSHKRLCache, error) {
	notImplemented("GetSSHKRL")
	return nil, nil
}

// --- everything below is unused by sshca but required to satisfy storage.Store ---

func (f *fakeStore) CreateCA(ctx context.Context, ca *storage.CertificateAuthority) error {
	notImplemented("CreateCA")
	return nil
}
func (f *fakeStore) GetCA(ctx context.Context, id uuid.UUID) (*storage.CertificateAuthority, error) {
	notImplemented("GetCA")
	return nil, nil
}
func (f *fakeStore) GetCAByName(ctx context.Context, name string) (*storage.CertificateAuthority, error) {
	notImplemented("GetCAByName")
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
func (f *fakeStore) CreateCertificate(ctx context.Context, cert *storage.Certificate) error {
	notImplemented("CreateCertificate")
	return nil
}
func (f *fakeStore) GetCertificate(ctx context.Context, id uuid.UUID) (*storage.Certificate, error) {
	notImplemented("GetCertificate")
	return nil, nil
}
func (f *fakeStore) GetCertificateBySerial(ctx context.Context, serial string) (*storage.Certificate, error) {
	notImplemented("GetCertificateBySerial")
	return nil, nil
}
func (f *fakeStore) ListCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	notImplemented("ListCertificatesByCA")
	return nil, nil
}
func (f *fakeStore) ListRevokedByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	notImplemented("ListRevokedByCA")
	return nil, nil
}
func (f *fakeStore) RevokeCertificate(ctx context.Context, id uuid.UUID, reason int) error {
	notImplemented("RevokeCertificate")
	return nil
}
func (f *fakeStore) CreateProvisioner(ctx context.Context, p *storage.Provisioner) error {
	notImplemented("CreateProvisioner")
	return nil
}
func (f *fakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	notImplemented("GetProvisioner")
	return nil, nil
}
func (f *fakeStore) ListProvisionersByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Provisioner, error) {
	notImplemented("ListProvisionersByCA")
	return nil, nil
}
func (f *fakeStore) UpdateProvisionerStatus(ctx context.Context, id uuid.UUID, status storage.ProvisionerStatus) error {
	notImplemented("UpdateProvisionerStatus")
	return nil
}
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
func (f *fakeStore) CreateACMEAccount(ctx context.Context, a *storage.ACMEAccount) error {
	notImplemented("CreateACMEAccount")
	return nil
}
func (f *fakeStore) GetACMEAccountByKeyID(ctx context.Context, keyID string) (*storage.ACMEAccount, error) {
	notImplemented("GetACMEAccountByKeyID")
	return nil, nil
}
func (f *fakeStore) GetACMEAccount(ctx context.Context, id uuid.UUID) (*storage.ACMEAccount, error) {
	notImplemented("GetACMEAccount")
	return nil, nil
}
func (f *fakeStore) UpdateACMEAccountStatus(ctx context.Context, id uuid.UUID, status storage.ACMEAccountStatus) error {
	notImplemented("UpdateACMEAccountStatus")
	return nil
}
func (f *fakeStore) UpdateACMEAccountContact(ctx context.Context, id uuid.UUID, contact []string) error {
	notImplemented("UpdateACMEAccountContact")
	return nil
}
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
func (f *fakeStore) CreateACMEOrder(ctx context.Context, o *storage.ACMEOrder) error {
	notImplemented("CreateACMEOrder")
	return nil
}
func (f *fakeStore) GetACMEOrder(ctx context.Context, id uuid.UUID) (*storage.ACMEOrder, error) {
	notImplemented("GetACMEOrder")
	return nil, nil
}
func (f *fakeStore) ListACMEOrdersByAccount(ctx context.Context, accountID uuid.UUID) ([]*storage.ACMEOrder, error) {
	notImplemented("ListACMEOrdersByAccount")
	return nil, nil
}
func (f *fakeStore) UpdateACMEOrderStatus(ctx context.Context, id uuid.UUID, status storage.ACMEOrderStatus) error {
	notImplemented("UpdateACMEOrderStatus")
	return nil
}
func (f *fakeStore) FinalizeACMEOrder(ctx context.Context, orderID uuid.UUID, certID uuid.UUID) error {
	notImplemented("FinalizeACMEOrder")
	return nil
}
func (f *fakeStore) CreateACMEChallenge(ctx context.Context, c *storage.ACMEChallenge) error {
	notImplemented("CreateACMEChallenge")
	return nil
}
func (f *fakeStore) GetACMEChallenge(ctx context.Context, id uuid.UUID) (*storage.ACMEChallenge, error) {
	notImplemented("GetACMEChallenge")
	return nil, nil
}
func (f *fakeStore) ListChallengesByOrder(ctx context.Context, orderID uuid.UUID) ([]*storage.ACMEChallenge, error) {
	notImplemented("ListChallengesByOrder")
	return nil, nil
}
func (f *fakeStore) UpdateChallengeStatus(ctx context.Context, id uuid.UUID, status storage.ACMEChallengeStatus, validatedAt *time.Time) error {
	notImplemented("UpdateChallengeStatus")
	return nil
}
func (f *fakeStore) ListChallengesByAuthorization(ctx context.Context, authID uuid.UUID) ([]*storage.ACMEChallenge, error) {
	notImplemented("ListChallengesByAuthorization")
	return nil, nil
}
func (f *fakeStore) CreateACMEAuthorization(ctx context.Context, a *storage.ACMEAuthorization) error {
	notImplemented("CreateACMEAuthorization")
	return nil
}
func (f *fakeStore) GetACMEAuthorization(ctx context.Context, id uuid.UUID) (*storage.ACMEAuthorization, error) {
	notImplemented("GetACMEAuthorization")
	return nil, nil
}
func (f *fakeStore) UpdateACMEAuthorizationStatus(ctx context.Context, id uuid.UUID, status storage.ACMEAuthorizationStatus) error {
	notImplemented("UpdateACMEAuthorizationStatus")
	return nil
}
func (f *fakeStore) ListAuthorizationsByOrder(ctx context.Context, orderID uuid.UUID) ([]*storage.ACMEAuthorization, error) {
	notImplemented("ListAuthorizationsByOrder")
	return nil, nil
}
func (f *fakeStore) WriteAuditLog(ctx context.Context, entry *storage.AuditLog) error { return nil }
func (f *fakeStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]*storage.AuditLog, error) {
	notImplemented("ListAuditLogs")
	return nil, nil
}
func (f *fakeStore) ListAuditLogsByCA(ctx context.Context, caID uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
	notImplemented("ListAuditLogsByCA")
	return nil, nil
}
func (f *fakeStore) UpsertCRL(ctx context.Context, crl *storage.CRLCache) error {
	notImplemented("UpsertCRL")
	return nil
}
func (f *fakeStore) GetCRL(ctx context.Context, caID uuid.UUID) (*storage.CRLCache, error) {
	notImplemented("GetCRL")
	return nil, nil
}
func (f *fakeStore) NextCRLNumber(ctx context.Context, caID uuid.UUID) (int64, error) {
	notImplemented("NextCRLNumber")
	return 0, nil
}
func (f *fakeStore) ListRevokedByCASince(ctx context.Context, caID uuid.UUID, since time.Time) ([]*storage.Certificate, error) {
	notImplemented("ListRevokedByCASince")
	return nil, nil
}
func (f *fakeStore) UpsertDeltaCRL(ctx context.Context, d *storage.DeltaCRLCache) error {
	notImplemented("UpsertDeltaCRL")
	return nil
}
func (f *fakeStore) GetDeltaCRL(ctx context.Context, caID uuid.UUID) (*storage.DeltaCRLCache, error) {
	notImplemented("GetDeltaCRL")
	return nil, nil
}
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
func (f *fakeStore) CreateNonce(ctx context.Context, nonce string, expiresAt time.Time) error {
	notImplemented("CreateNonce")
	return nil
}
func (f *fakeStore) ConsumeNonce(ctx context.Context, nonce string) (bool, error) {
	notImplemented("ConsumeNonce")
	return false, nil
}
func (f *fakeStore) PruneExpiredNonces(ctx context.Context) error {
	notImplemented("PruneExpiredNonces")
	return nil
}
func (f *fakeStore) GetACMEAuthorizationByIdentifier(ctx context.Context, accountID uuid.UUID, identifierType, identifierValue string) (*storage.ACMEAuthorization, error) {
	notImplemented("GetACMEAuthorizationByIdentifier")
	return nil, nil
}
func (f *fakeStore) ListAuthorizationsByAccount(ctx context.Context, accountID uuid.UUID) ([]*storage.ACMEAuthorization, error) {
	notImplemented("ListAuthorizationsByAccount")
	return nil, nil
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
	notImplemented("IncrementRateLimitCounter")
	return nil
}
func (f *fakeStore) PruneExpiredRateLimitCounters(ctx context.Context, olderThan time.Time) error {
	notImplemented("PruneExpiredRateLimitCounters")
	return nil
}
func (f *fakeStore) UpdateACMEAccountKey(ctx context.Context, accountID uuid.UUID, newKeyID string, newKeyJWK storage.JSON) error {
	notImplemented("UpdateACMEAccountKey")
	return nil
}
func (f *fakeStore) MarkKeyIDRetired(ctx context.Context, keyID string) error {
	notImplemented("MarkKeyIDRetired")
	return nil
}
func (f *fakeStore) IsKeyIDRetired(ctx context.Context, keyID string) (bool, error) {
	notImplemented("IsKeyIDRetired")
	return false, nil
}

var errNotFound = fmt.Errorf("sshca fakeStore: record not found")
