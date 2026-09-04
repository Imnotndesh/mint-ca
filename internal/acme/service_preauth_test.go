package acme

import (
	"context"
	"testing"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func TestNewPreAuth_CreatesStandaloneAuthorization(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	rootCA := &storage.CertificateAuthority{ID: uuid.New(), Name: "root"}
	_ = store.CreateCA(ctx, rootCA)

	prov := &storage.Provisioner{
		ID: uuid.New(), CAID: rootCA.ID, Name: "acme-test",
		Type: storage.ProvisionerTypeACME,
		Config: storage.JSON{
			"allowed_challenge_types": []string{"http-01", "dns-01"},
		},
		Status: storage.ProvisionerStatusActive,
	}
	_ = store.CreateProvisioner(ctx, prov)

	account := &storage.ACMEAccount{
		ID: uuid.New(), ProvisionerID: prov.ID, KeyID: "thumb-a",
		Status: storage.ACMEAccountStatusValid,
	}
	_ = store.CreateACMEAccount(ctx, account)

	svc := NewService(store, nil, NewNonceManager(store, 0), nil, nil, "https://ca.test")

	auth, challenges, prob := svc.NewPreAuth(ctx, account, prov, Identifier{Type: "dns", Value: "pre.example.com"})
	if prob != nil {
		t.Fatalf("NewPreAuth failed: %v", prob)
	}
	if auth.OrderID != uuid.Nil {
		t.Errorf("expected standalone authz (OrderID == uuid.Nil), got %s", auth.OrderID)
	}
	if auth.AccountID != account.ID {
		t.Errorf("expected AccountID %s, got %s", account.ID, auth.AccountID)
	}
	if len(challenges) != 2 {
		t.Errorf("expected 2 challenges (http-01, dns-01), got %d", len(challenges))
	}
	for _, c := range challenges {
		if c.OrderID != uuid.Nil {
			t.Errorf("expected standalone challenge (OrderID == uuid.Nil), got %s", c.OrderID)
		}
	}
}

func TestNewPreAuth_ReusesValidStandaloneAuthz(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	rootCA := &storage.CertificateAuthority{ID: uuid.New(), Name: "root"}
	_ = store.CreateCA(ctx, rootCA)

	prov := &storage.Provisioner{
		ID: uuid.New(), CAID: rootCA.ID, Name: "acme-test",
		Type:   storage.ProvisionerTypeACME,
		Config: storage.JSON{"allowed_challenge_types": []string{"dns-01"}},
		Status: storage.ProvisionerStatusActive,
	}
	_ = store.CreateProvisioner(ctx, prov)

	account := &storage.ACMEAccount{
		ID: uuid.New(), ProvisionerID: prov.ID, KeyID: "thumb-b",
		Status: storage.ACMEAccountStatusValid,
	}
	_ = store.CreateACMEAccount(ctx, account)

	svc := NewService(store, nil, NewNonceManager(store, 0), nil, nil, "https://ca.test")

	first, _, prob := svc.NewPreAuth(ctx, account, prov, Identifier{Type: "dns", Value: "reuse.example.com"})
	if prob != nil {
		t.Fatalf("first NewPreAuth failed: %v", prob)
	}

	// Manually mark it valid, as if the challenge had been validated.
	if err := store.UpdateACMEAuthorizationStatus(ctx, first.ID, storage.ACMEAuthorizationStatusValid); err != nil {
		t.Fatalf("failed to mark authz valid: %v", err)
	}

	second, _, prob := svc.NewPreAuth(ctx, account, prov, Identifier{Type: "dns", Value: "reuse.example.com"})
	if prob != nil {
		t.Fatalf("second NewPreAuth failed: %v", prob)
	}
	if second.ID != first.ID {
		t.Errorf("expected reuse of existing valid authz %s, got new authz %s", first.ID, second.ID)
	}
}

func TestNewOrder_ReusesValidStandaloneAuthz_NoDuplicatePending(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	rootCA := &storage.CertificateAuthority{ID: uuid.New(), Name: "root"}
	_ = store.CreateCA(ctx, rootCA)

	prov := &storage.Provisioner{
		ID: uuid.New(), CAID: rootCA.ID, Name: "acme-test",
		Type:   storage.ProvisionerTypeACME,
		Config: storage.JSON{"allowed_challenge_types": []string{"dns-01"}},
		Status: storage.ProvisionerStatusActive,
	}
	_ = store.CreateProvisioner(ctx, prov)

	account := &storage.ACMEAccount{
		ID: uuid.New(), ProvisionerID: prov.ID, KeyID: "thumb-c",
		Status: storage.ACMEAccountStatusValid,
	}
	_ = store.CreateACMEAccount(ctx, account)

	svc := NewService(store, nil, NewNonceManager(store, 0), nil, nil, "https://ca.test")

	preAuth, _, prob := svc.NewPreAuth(ctx, account, prov, Identifier{Type: "dns", Value: "order-reuse.example.com"})
	if prob != nil {
		t.Fatalf("NewPreAuth failed: %v", prob)
	}
	if err := store.UpdateACMEAuthorizationStatus(ctx, preAuth.ID, storage.ACMEAuthorizationStatusValid); err != nil {
		t.Fatalf("failed to mark pre-auth valid: %v", err)
	}

	order, _, prob := svc.NewOrder(ctx, account, prov, []Identifier{{Type: "dns", Value: "order-reuse.example.com"}}, "")
	if prob != nil {
		t.Fatalf("NewOrder failed: %v", prob)
	}

	auths, prob := svc.GetAuthorizationsForOrder(ctx, order.ID)
	if prob != nil {
		t.Fatalf("GetAuthorizationsForOrder failed: %v", prob)
	}
	if len(auths) != 0 {
		t.Errorf("expected no order-bound authz created (pre-auth reused instead), got %d", len(auths))
	}
}

func TestNewPreAuth_OwnershipIsolation(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	rootCA := &storage.CertificateAuthority{ID: uuid.New(), Name: "root"}
	_ = store.CreateCA(ctx, rootCA)

	prov := &storage.Provisioner{
		ID: uuid.New(), CAID: rootCA.ID, Name: "acme-test",
		Type:   storage.ProvisionerTypeACME,
		Config: storage.JSON{"allowed_challenge_types": []string{"dns-01"}},
		Status: storage.ProvisionerStatusActive,
	}
	_ = store.CreateProvisioner(ctx, prov)

	accountA := &storage.ACMEAccount{ID: uuid.New(), ProvisionerID: prov.ID, KeyID: "thumb-owner", Status: storage.ACMEAccountStatusValid}
	accountB := &storage.ACMEAccount{ID: uuid.New(), ProvisionerID: prov.ID, KeyID: "thumb-other", Status: storage.ACMEAccountStatusValid}
	_ = store.CreateACMEAccount(ctx, accountA)
	_ = store.CreateACMEAccount(ctx, accountB)

	svc := NewService(store, nil, NewNonceManager(store, 0), nil, nil, "https://ca.test")

	authA, _, prob := svc.NewPreAuth(ctx, accountA, prov, Identifier{Type: "dns", Value: "isolated.example.com"})
	if prob != nil {
		t.Fatalf("NewPreAuth(A) failed: %v", prob)
	}
	if err := store.UpdateACMEAuthorizationStatus(ctx, authA.ID, storage.ACMEAuthorizationStatusValid); err != nil {
		t.Fatalf("mark valid: %v", err)
	}

	// Account B requesting the same identifier must NOT see account A's authz.
	authB, _, prob := svc.NewPreAuth(ctx, accountB, prov, Identifier{Type: "dns", Value: "isolated.example.com"})
	if prob != nil {
		t.Fatalf("NewPreAuth(B) failed: %v", prob)
	}
	if authB.ID == authA.ID {
		t.Error("account B must not reuse account A's standalone authorization")
	}
	if authB.AccountID != accountB.ID {
		t.Errorf("expected authB.AccountID = %s, got %s", accountB.ID, authB.AccountID)
	}
}
