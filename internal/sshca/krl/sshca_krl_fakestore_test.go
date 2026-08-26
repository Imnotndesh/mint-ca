package krl

import (
	"context"
	"sync"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// krlFakeStore is a minimal in-memory storage.Store covering only what the
// krl.Manager touches. It embeds a nil storage.Store so it satisfies the full
// interface; any method not overridden below will panic on the nil embedded
// interface, which is the "fails loudly" behaviour we want for the methods
// the KRL tests never exercise.
type krlFakeStore struct {
	storage.Store
	mu    sync.Mutex
	cas   map[uuid.UUID]*storage.SSHCertificateAuthority
	certs map[uuid.UUID]*storage.SSHCertificate
	krls  map[uuid.UUID]*storage.SSHKRLCache
}

func (f *krlFakeStore) Close() error { return nil }

func newKRLFakeStore() *krlFakeStore {
	return &krlFakeStore{
		cas:   make(map[uuid.UUID]*storage.SSHCertificateAuthority),
		certs: make(map[uuid.UUID]*storage.SSHCertificate),
		krls:  make(map[uuid.UUID]*storage.SSHKRLCache),
	}
}

func (f *krlFakeStore) CreateSSHCA(ctx context.Context, ca *storage.SSHCertificateAuthority) error {
	f.mu.Lock(); defer f.mu.Unlock()
	f.cas[ca.ID] = ca
	return nil
}
func (f *krlFakeStore) GetSSHCA(ctx context.Context, id uuid.UUID) (*storage.SSHCertificateAuthority, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	return f.cas[id], nil
}
func (f *krlFakeStore) GetSSHCAByName(ctx context.Context, name string) (*storage.SSHCertificateAuthority, error) {
	panic("not implemented")
}
func (f *krlFakeStore) ListSSHCAs(ctx context.Context) ([]*storage.SSHCertificateAuthority, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	var out []*storage.SSHCertificateAuthority
	for _, c := range f.cas {
		out = append(out, c)
	}
	return out, nil
}
func (f *krlFakeStore) CreateSSHCertificate(ctx context.Context, cert *storage.SSHCertificate) error {
	f.mu.Lock(); defer f.mu.Unlock()
	f.certs[cert.ID] = cert
	return nil
}
func (f *krlFakeStore) GetSSHCertificate(ctx context.Context, id uuid.UUID) (*storage.SSHCertificate, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	return f.certs[id], nil
}
func (f *krlFakeStore) GetSSHCertificateBySerial(ctx context.Context, caID uuid.UUID, serial uint64) (*storage.SSHCertificate, error) {
	panic("not implemented")
}
func (f *krlFakeStore) ListSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.SSHCertificate, error) {
	panic("not implemented")
}
func (f *krlFakeStore) ListRevokedSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.SSHCertificate, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	var out []*storage.SSHCertificate
	for _, c := range f.certs {
		if c.CAID == caID && c.Status == storage.SSHCertStatusRevoked {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *krlFakeStore) RevokeSSHCertificate(ctx context.Context, id uuid.UUID) error {
	f.mu.Lock(); defer f.mu.Unlock()
	c, ok := f.certs[id]
	if !ok {
		return errKRLNotFound
	}
	now := time.Now().UTC()
	c.Status = storage.SSHCertStatusRevoked
	c.RevokedAt = &now
	return nil
}
func (f *krlFakeStore) UpsertSSHKRL(ctx context.Context, k *storage.SSHKRLCache) error {
	f.mu.Lock(); defer f.mu.Unlock()
	f.krls[k.CAID] = k
	return nil
}
func (f *krlFakeStore) GetSSHKRL(ctx context.Context, caID uuid.UUID) (*storage.SSHKRLCache, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	return f.krls[caID], nil
}

var errKRLNotFound = &krlErr{"krl fakeStore: record not found"}

type krlErr struct{ s string }

func (e *krlErr) Error() string { return e.s }
