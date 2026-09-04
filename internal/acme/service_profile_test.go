package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"mint-ca/internal/ca"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func newProfileTestEngine(t *testing.T, store storage.Store) *ca.Engine {
	t.Helper()
	masterKey := make([]byte, 32)
	ks, err := mintcrypto.NewKeystore(masterKey)
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	return ca.NewEngine(store, ks, "https://ca.test")
}

// generateTestCSR builds a CSR PEM signed with a fresh ECDSA P-256 key
// (unless another key is supplied), for the given common name and DNS SANs.
func generateTestCSR(t *testing.T, cn string, dnsSANs []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsSANs,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der
}

func generateRSATestCSR(t *testing.T, cn string, dnsSANs []string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsSANs,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create RSA CSR: %v", err)
	}
	return der
}

func setupProfileOrderFixture(t *testing.T) (*Service, *fakeStore, *storage.CertificateAuthority, *storage.Provisioner, *storage.ACMEAccount) {
	t.Helper()
	ctx := context.Background()
	store := NewFakeStore()
	engine := newProfileTestEngine(t, store)

	root, err := engine.CreateRootCA(ctx, ca.CreateRootCARequest{
		Name: "profile-root", CommonName: "Profile Root", KeyAlgo: ca.KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	prov := &storage.Provisioner{
		ID: uuid.New(), CAID: root.ID, Name: "acme-profile-test",
		Type:   storage.ProvisionerTypeACME,
		Config: storage.JSON{"allowed_challenge_types": []string{"dns-01"}},
		Status: storage.ProvisionerStatusActive,
	}
	if err := store.CreateProvisioner(ctx, prov); err != nil {
		t.Fatalf("CreateProvisioner: %v", err)
	}

	account := &storage.ACMEAccount{
		ID: uuid.New(), ProvisionerID: prov.ID, KeyID: "thumb-profile",
		Status: storage.ACMEAccountStatusValid,
	}
	if err := store.CreateACMEAccount(ctx, account); err != nil {
		t.Fatalf("CreateACMEAccount: %v", err)
	}

	svc := NewService(store, engine, NewNonceManager(store, 0), nil, nil, "https://ca.test")
	return svc, store, root, prov, account
}

func TestNewOrder_RequestedProfile_WildcardRejected(t *testing.T) {
	ctx := context.Background()
	svc, store, _, prov, account := setupProfileOrderFixture(t)

	profile := &storage.Profile{ID: uuid.New(), Name: "no-wildcards", AllowWildcard: false}
	_ = store.CreateProfile(ctx, profile)

	_, _, prob := svc.NewOrder(ctx, account, prov, []Identifier{{Type: "dns", Value: "*.example.com"}}, "no-wildcards")
	if prob == nil {
		t.Fatal("expected NewOrder to be refused for a wildcard identifier against a no-wildcard profile")
	}
}

func TestNewOrder_RequestedProfile_AllowedIssues(t *testing.T) {
	ctx := context.Background()
	svc, store, _, prov, account := setupProfileOrderFixture(t)

	profile := &storage.Profile{ID: uuid.New(), Name: "wildcards-ok", AllowWildcard: true}
	_ = store.CreateProfile(ctx, profile)

	order, _, prob := svc.NewOrder(ctx, account, prov, []Identifier{{Type: "dns", Value: "*.example.com"}}, "wildcards-ok")
	if prob != nil {
		t.Fatalf("NewOrder should succeed: %v", prob)
	}
	if order == nil {
		t.Fatal("expected an order")
	}
}

func TestNewOrder_UnknownRequestedProfile_Rejected(t *testing.T) {
	ctx := context.Background()
	svc, _, _, prov, account := setupProfileOrderFixture(t)

	_, _, prob := svc.NewOrder(ctx, account, prov, []Identifier{{Type: "dns", Value: "example.com"}}, "does-not-exist")
	if prob == nil {
		t.Fatal("expected NewOrder to reject an unknown profile name")
	}
}

func TestNewOrder_PinnedProfile_OverridesRequested(t *testing.T) {
	ctx := context.Background()
	svc, store, _, prov, account := setupProfileOrderFixture(t)

	pinned := &storage.Profile{ID: uuid.New(), Name: "pinned", AllowWildcard: false}
	_ = store.CreateProfile(ctx, pinned)
	prov.ProfileID = &pinned.ID

	// Even though no profile is requested, the pinned profile's constraints
	// (no wildcards) must still apply.
	_, _, prob := svc.NewOrder(ctx, account, prov, []Identifier{{Type: "dns", Value: "*.example.com"}}, "")
	if prob == nil {
		t.Fatal("expected the pinned profile to reject the wildcard identifier")
	}
}

func TestFinalizeOrder_ProfileViolation_KeyAlgoRejected(t *testing.T) {
	ctx := context.Background()
	svc, store, root, prov, account := setupProfileOrderFixture(t)

	profile := &storage.Profile{ID: uuid.New(), Name: "ecdsa-only", AllowedKeyAlgos: []string{"ecdsa-p256"}}
	_ = store.CreateProfile(ctx, profile)

	order, challenges, prob := svc.NewOrder(ctx, account, prov, []Identifier{{Type: "dns", Value: "leaf.example.com"}}, "ecdsa-only")
	if prob != nil {
		t.Fatalf("NewOrder: %v", prob)
	}
	for _, ch := range challenges {
		if err := store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusValid, nil); err != nil {
			t.Fatalf("UpdateChallengeStatus: %v", err)
		}
		if ch.AuthorizationID != nil {
			if err := store.UpdateACMEAuthorizationStatus(ctx, *ch.AuthorizationID, storage.ACMEAuthorizationStatusValid); err != nil {
				t.Fatalf("UpdateACMEAuthorizationStatus: %v", err)
			}
		}
	}
	if err := store.UpdateACMEOrderStatus(ctx, order.ID, storage.ACMEOrderStatusReady); err != nil {
		t.Fatalf("UpdateACMEOrderStatus: %v", err)
	}

	// RSA CSR against an ECDSA-only profile must be refused.
	csrDER := generateRSATestCSR(t, "leaf.example.com", []string{"leaf.example.com"})

	_, _, prob = svc.FinalizeOrder(ctx, account, order.ID, csrDER, root.ID, prov.ID, 3600)
	if prob == nil {
		t.Fatal("expected FinalizeOrder to reject an RSA CSR against an ecdsa-only profile")
	}
}

func TestFinalizeOrder_ProfileSatisfied_Issues(t *testing.T) {
	ctx := context.Background()
	svc, store, root, prov, account := setupProfileOrderFixture(t)

	profile := &storage.Profile{ID: uuid.New(), Name: "ecdsa-only", AllowedKeyAlgos: []string{"ecdsa-p256"}}
	_ = store.CreateProfile(ctx, profile)

	order, challenges, prob := svc.NewOrder(ctx, account, prov, []Identifier{{Type: "dns", Value: "leaf.example.com"}}, "ecdsa-only")
	if prob != nil {
		t.Fatalf("NewOrder: %v", prob)
	}
	for _, ch := range challenges {
		if err := store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusValid, nil); err != nil {
			t.Fatalf("UpdateChallengeStatus: %v", err)
		}
		if ch.AuthorizationID != nil {
			if err := store.UpdateACMEAuthorizationStatus(ctx, *ch.AuthorizationID, storage.ACMEAuthorizationStatusValid); err != nil {
				t.Fatalf("UpdateACMEAuthorizationStatus: %v", err)
			}
		}
	}
	if err := store.UpdateACMEOrderStatus(ctx, order.ID, storage.ACMEOrderStatusReady); err != nil {
		t.Fatalf("UpdateACMEOrderStatus: %v", err)
	}

	csrDER := generateTestCSR(t, "leaf.example.com", []string{"leaf.example.com"})

	finalized, cert, prob := svc.FinalizeOrder(ctx, account, order.ID, csrDER, root.ID, prov.ID, 3600)
	if prob != nil {
		t.Fatalf("FinalizeOrder should succeed: %v", prob)
	}
	if finalized.Status != storage.ACMEOrderStatusValid {
		t.Errorf("expected order valid, got %s", finalized.Status)
	}
	if cert == nil {
		t.Fatal("expected an issued certificate")
	}
}
