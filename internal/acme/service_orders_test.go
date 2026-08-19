package acme

import (
	"context"
	"testing"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func TestListOrders(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()

	rootCA := &storage.CertificateAuthority{ID: uuid.New(), Name: "root"}
	_ = store.CreateCA(ctx, rootCA)

	prov := &storage.Provisioner{
		ID: uuid.New(), CAID: rootCA.ID, Name: "acme-test",
		Type: storage.ProvisionerTypeACME,
		Config: storage.JSON{
			"allowed_challenge_types": []string{"dns-01"},
		},
		Status: storage.ProvisionerStatusActive,
	}
	_ = store.CreateProvisioner(ctx, prov)

	accountA := &storage.ACMEAccount{
		ID: uuid.New(), ProvisionerID: prov.ID, KeyID: "thumb-a",
		Status: storage.ACMEAccountStatusValid,
	}
	accountB := &storage.ACMEAccount{
		ID: uuid.New(), ProvisionerID: prov.ID, KeyID: "thumb-b",
		Status: storage.ACMEAccountStatusValid,
	}
	_ = store.CreateACMEAccount(ctx, accountA)
	_ = store.CreateACMEAccount(ctx, accountB)

	svc := NewService(store, nil, NewNonceManager(store, 0), nil, "https://ca.test")

	// Two orders for account A, one for account B.
	if _, _, prob := svc.NewOrder(ctx, accountA, prov, []Identifier{{Type: "dns", Value: "a1.example.com"}}); prob != nil {
		t.Fatalf("NewOrder A1 failed: %v", prob)
	}
	if _, _, prob := svc.NewOrder(ctx, accountA, prov, []Identifier{{Type: "dns", Value: "a2.example.com"}}); prob != nil {
		t.Fatalf("NewOrder A2 failed: %v", prob)
	}
	if _, _, prob := svc.NewOrder(ctx, accountB, prov, []Identifier{{Type: "dns", Value: "b1.example.com"}}); prob != nil {
		t.Fatalf("NewOrder B1 failed: %v", prob)
	}

	ordersA, prob := svc.ListOrders(ctx, accountA.ID)
	if prob != nil {
		t.Fatalf("ListOrders(A) failed: %v", prob)
	}
	if len(ordersA) != 2 {
		t.Errorf("expected 2 orders for account A, got %d", len(ordersA))
	}
	for _, o := range ordersA {
		if o.AccountID != accountA.ID {
			t.Errorf("order %s belongs to account %s, expected %s", o.ID, o.AccountID, accountA.ID)
		}
	}

	ordersB, prob := svc.ListOrders(ctx, accountB.ID)
	if prob != nil {
		t.Fatalf("ListOrders(B) failed: %v", prob)
	}
	if len(ordersB) != 1 {
		t.Errorf("expected 1 order for account B, got %d", len(ordersB))
	}

	// Account with no orders returns an empty (not nil-erroring) result.
	emptyOrders, prob := svc.ListOrders(ctx, uuid.New())
	if prob != nil {
		t.Fatalf("ListOrders(unknown account) failed: %v", prob)
	}
	if len(emptyOrders) != 0 {
		t.Errorf("expected 0 orders for unknown account, got %d", len(emptyOrders))
	}
}

func TestOrderURLBuildsCorrectly(t *testing.T) {
	store := newFakeStore()
	svc := NewService(store, nil, NewNonceManager(store, 0), nil, "https://ca.test")

	provID := uuid.New()
	orderID := uuid.New()

	got := svc.OrderURL(provID, orderID)
	want := "https://ca.test/acme/" + provID.String() + "/order/" + orderID.String()
	if got != want {
		t.Errorf("OrderURL = %q, want %q", got, want)
	}
}
