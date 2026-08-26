package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// testFakeStore implements the subset of storage.Store the CRLManager touches,
// backed by in-memory maps. It embeds a nil storage.Store so it satisfies the
// full interface; any unoverridden method panics on the nil embedded interface.
type testFakeStore struct {
	storage.Store

	mu       sync.Mutex
	cas      map[uuid.UUID]*storage.CertificateAuthority
	certs    map[uuid.UUID]*storage.Certificate
	crls     map[uuid.UUID]*storage.CRLCache
	deltaCRLs map[uuid.UUID]*storage.DeltaCRLCache
	counters map[uuid.UUID]int64
}

func newTestFakeStore() *testFakeStore {
	return &testFakeStore{
		cas:       make(map[uuid.UUID]*storage.CertificateAuthority),
		certs:     make(map[uuid.UUID]*storage.Certificate),
		crls:      make(map[uuid.UUID]*storage.CRLCache),
		deltaCRLs: make(map[uuid.UUID]*storage.DeltaCRLCache),
		counters:  make(map[uuid.UUID]int64),
	}
}

func (f *testFakeStore) Close() error { return nil }

func (f *testFakeStore) GetCA(ctx context.Context, id uuid.UUID) (*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cas[id], nil
}
func (f *testFakeStore) ListCAs(ctx context.Context) ([]*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.CertificateAuthority
	for _, c := range f.cas {
		out = append(out, c)
	}
	return out, nil
}
func (f *testFakeStore) GetCertificate(ctx context.Context, id uuid.UUID) (*storage.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.certs[id], nil
}
func (f *testFakeStore) RevokeCertificate(ctx context.Context, id uuid.UUID, reason int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.certs[id]
	if !ok {
		return nil
	}
	now := time.Now().UTC()
	c.Status = storage.CertStatusRevoked
	c.RevokedAt = &now
	c.RevokeReason = &reason
	return nil
}
func (f *testFakeStore) ListRevokedByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.Certificate
	for _, c := range f.certs {
		if c.CAID == caID && c.Status == storage.CertStatusRevoked {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *testFakeStore) ListRevokedByCASince(ctx context.Context, caID uuid.UUID, since time.Time) ([]*storage.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.Certificate
	for _, c := range f.certs {
		if c.CAID == caID && c.Status == storage.CertStatusRevoked && c.RevokedAt != nil && c.RevokedAt.UTC().After(since) {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *testFakeStore) NextCRLNumber(ctx context.Context, caID uuid.UUID) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counters[caID]++
	return f.counters[caID], nil
}
func (f *testFakeStore) UpsertCRL(ctx context.Context, crl *storage.CRLCache) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.crls[crl.CAID] = crl
	return nil
}
func (f *testFakeStore) GetCRL(ctx context.Context, caID uuid.UUID) (*storage.CRLCache, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.crls[caID], nil
}
func (f *testFakeStore) UpsertDeltaCRL(ctx context.Context, d *storage.DeltaCRLCache) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deltaCRLs[d.CAID] = d
	return nil
}
func (f *testFakeStore) GetDeltaCRL(ctx context.Context, caID uuid.UUID) (*storage.DeltaCRLCache, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deltaCRLs[caID], nil
}

// newTestCA generates a self-signed root CA record with an encrypted key,
// ready to be handed to a CRLManager.
func newTestCA(t *testing.T, ks *mintcrypto.Keystore) (*storage.CertificateAuthority, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Delta Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyEnc, err := ks.EncryptPEM(keyPEM)
	if err != nil {
		t.Fatalf("encrypt key: %v", err)
	}

	return &storage.CertificateAuthority{
		ID:        uuid.New(),
		Name:      "delta-test-root",
		Type:      storage.CATypeRoot,
		Status:    storage.CAStatusActive,
		CertPEM:   string(certPEM),
		KeyEnc:    keyEnc,
		KeyAlgo:   "ecdsa-p256",
		CreatedAt: time.Now().UTC(),
	}, key
}

// addCerts adds `n` active certificate records for the CA.
func addCerts(f *testFakeStore, caID uuid.UUID, n int) []*storage.Certificate {
	certs := make([]*storage.Certificate, 0, n)
	for i := 0; i < n; i++ {
		c := &storage.Certificate{
			ID:        uuid.New(),
			CAID:      caID,
			Serial:    big.NewInt(int64(100 + i)).String(),
			Status:    storage.CertStatusActive,
			CertPEM:  "PEM",
			IssuedAt: time.Now().UTC(),
		}
		certs = append(certs, c)
		f.mu.Lock()
		f.certs[c.ID] = c
		f.mu.Unlock()
	}
	return certs
}

func TestCRL_BaseNumberIsMonotonicAndPersisted(t *testing.T) {
	ctx := context.Background()
	store := newTestFakeStore()
	ks, _ := mintcrypto.NewKeystore(make([]byte, 32))
	caRec, _ := newTestCA(t, ks)
	store.cas[caRec.ID] = caRec

	mgr := NewCRLManager(store, ks, "", false)
	if err := mgr.GenerateCRL(ctx, caRec.ID, time.Hour); err != nil {
		t.Fatalf("first GenerateCRL: %v", err)
	}
	first, _ := store.GetCRL(ctx, caRec.ID)
	if first.CRLNumber <= 0 {
		t.Fatalf("expected positive CRL number, got %d", first.CRLNumber)
	}

	// A second generation must continue the sequence, not reset to a
	// timestamp-derived value.
	if err := mgr.GenerateCRL(ctx, caRec.ID, time.Hour); err != nil {
		t.Fatalf("second GenerateCRL: %v", err)
	}
	second, _ := store.GetCRL(ctx, caRec.ID)
	if second.CRLNumber <= first.CRLNumber {
		t.Fatalf("expected monotonic increase, got %d then %d", first.CRLNumber, second.CRLNumber)
	}
}

func TestCRL_DeltaExcludesRevocationsBeforeBase(t *testing.T) {
	ctx := context.Background()
	store := newTestFakeStore()
	ks, _ := mintcrypto.NewKeystore(make([]byte, 32))
	caRec, _ := newTestCA(t, ks)
	store.cas[caRec.ID] = caRec

	mgr := NewCRLManager(store, ks, "", true)

	// Two certs revoked BEFORE any base exists. We revoke them directly and
	// then explicitly build a base so we control exactly what the base contains.
	certs := addCerts(store, caRec.ID, 2)
	for _, c := range certs {
		if err := store.RevokeCertificate(ctx, c.ID, 0); err != nil {
			t.Fatalf("revoke %s: %v", c.ID, err)
		}
	}
	if err := mgr.GenerateCRL(ctx, caRec.ID, time.Hour); err != nil {
		t.Fatalf("generate base: %v", err)
	}

	// Now a fresh revocation AFTER the base exists.
	late := addCerts(store, caRec.ID, 1)[0]
	if err := mgr.RevokeAndRefresh(ctx, late.ID, 0); err != nil {
		t.Fatalf("late revoke: %v", err)
	}

	delta, err := store.GetDeltaCRL(ctx, caRec.ID)
	if err != nil || delta == nil {
		t.Fatalf("expected cached delta, err=%v", err)
	}

	// The delta should contain exactly the late revocation — the two earlier
	// ones appeared in the base and must be excluded.
	parsed, err := parseRevocationListForTest(delta.CRLPEM)
	if err != nil {
		t.Fatalf("parse delta: %v", err)
	}
	if len(parsed.RevokedCertificates) != 1 {
		t.Fatalf("expected delta to contain exactly 1 revoked cert, got %d",
			len(parsed.RevokedCertificates))
	}
	if parsed.RevokedCertificates[0].SerialNumber.String() != late.Serial {
		t.Errorf("expected delta entry serial %s, got %s",
			late.Serial, parsed.RevokedCertificates[0].SerialNumber.String())
	}
}

func TestCRL_DeltaCRLIndicatorExtensionPresent(t *testing.T) {
	ctx := context.Background()
	store := newTestFakeStore()
	ks, _ := mintcrypto.NewKeystore(make([]byte, 32))
	caRec, _ := newTestCA(t, ks)
	store.cas[caRec.ID] = caRec

	mgr := NewCRLManager(store, ks, "", true)

	// Establish a base first.
	certs := addCerts(store, caRec.ID, 1)
	if err := mgr.RevokeAndRefresh(ctx, certs[0].ID, 0); err != nil {
		t.Fatalf("revoke to seed base+delta: %v", err)
	}

	delta, _ := store.GetDeltaCRL(ctx, caRec.ID)
	parsed, err := parseRevocationListForTest(delta.CRLPEM)
	if err != nil {
		t.Fatalf("parse delta: %v", err)
	}

	var found bool
	for _, ext := range parsed.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 27}) { // id-ce-deltaCRLIndicator
			found = true
			if !ext.Critical {
				t.Error("deltaCRLIndicator must be critical per RFC 5280")
			}
			var baseNum int64
			rest, err := asn1.Unmarshal(ext.Value, &baseNum)
			if err != nil || len(rest) != 0 {
				t.Fatalf("deltaCRLIndicator value decode failed: %v (rest=%d)", err, len(rest))
			}
			// The base CRL Number this delta is anchored to.
			base, _ := store.GetCRL(ctx, caRec.ID)
			if baseNum != base.CRLNumber {
				t.Errorf("delta indicator base=%d, want %d", baseNum, base.CRLNumber)
			}
		}
	}
	if !found {
		t.Error("delta CRL missing deltaCRLIndicator extension")
	}
}

func TestCRL_FreshestCRLAdvertisesDeltaURLOnlyWhenEnabled(t *testing.T) {
	ctx := context.Background()

	// Delta disabled → base must NOT carry Freshest CRL.
	store := newTestFakeStore()
	ks, _ := mintcrypto.NewKeystore(make([]byte, 32))
	caRec, _ := newTestCA(t, ks)
	store.cas[caRec.ID] = caRec

	mgr := NewCRLManager(store, ks, "https://ca.test", false)
	if err := mgr.GenerateCRL(ctx, caRec.ID, time.Hour); err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	base, _ := store.GetCRL(ctx, caRec.ID)
	if hasExt(base.CRLPEM, []int{2, 5, 29, 46}) {
		t.Error("base CRL should not advertise Freshest CRL when deltas are disabled")
	}

	// Delta enabled + baseURL set → base carries Freshest CRL.
	store2 := newTestFakeStore()
	caRec2, _ := newTestCA(t, ks)
	store2.cas[caRec2.ID] = caRec2
	mgr2 := NewCRLManager(store2, ks, "https://ca.test/", true)
	if err := mgr2.GenerateCRL(ctx, caRec2.ID, time.Hour); err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	base2, _ := store2.GetCRL(ctx, caRec2.ID)
	if !hasExt(base2.CRLPEM, []int{2, 5, 29, 46}) {
		t.Error("base CRL missing Freshest CRL extension when deltas enabled")
	}
}

// TestCRL_GetDeltaCRL_OnFirstEverCall_BootstrapsBase exercises the lazy path
// where no base CRL exists yet: GetDeltaCRL must bootstrap a base (not panic)
// and return a valid delta anchored to it.
func TestCRL_GetDeltaCRL_OnFirstEverCall_BootstrapsBase(t *testing.T) {
	ctx := context.Background()
	store := newTestFakeStore()
	ks, _ := mintcrypto.NewKeystore(make([]byte, 32))
	caRec, _ := newTestCA(t, ks)
	store.cas[caRec.ID] = caRec

	mgr := NewCRLManager(store, ks, "https://ca.test", true)

	// No base exists yet.
	data, err := mgr.GetDeltaCRL(ctx, caRec.ID)
	if err != nil {
		t.Fatalf("GetDeltaCRL bootstrap: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("GetDeltaCRL returned empty delta")
	}

	base, _ := store.GetCRL(ctx, caRec.ID)
	if base == nil {
		t.Fatal("expected a base CRL to be bootstrapped")
	}
	parsed, err := parseRevocationListForTest(string(data))
	if err != nil {
		t.Fatalf("parse bootstrapped delta: %v", err)
	}
	if !hasExtOID(parsed, []int{2, 5, 29, 27}) {
		t.Error("bootstrapped delta missing deltaCRLIndicator extension")
	}
}

func hasExtOID(rl *x509.RevocationList, oid []int) bool {
	for _, ext := range rl.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// --- test helpers ---

func parseRevocationListForTest(pemData string) (*x509.RevocationList, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errNoPEM
	}
	return x509.ParseRevocationList(block.Bytes)
}

var errNoPEM = &testErr{"no PEM block"}

func hasExt(pemData string, oid []int) bool {
	rl, err := parseRevocationListForTest(pemData)
	if err != nil {
		return false
	}
	for _, ext := range rl.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

type testErr struct{ s string }

func (e *testErr) Error() string { return e.s }
