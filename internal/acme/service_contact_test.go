package acme

import (
	"context"
	"testing"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func TestValidateContacts(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		wantErr bool
	}{
		{"valid mailto", []string{"mailto:admin@example.com"}, false},
		{"multiple valid", []string{"mailto:a@example.com", "mailto:b@example.com"}, false},
		{"empty list", nil, false},
		{"no scheme", []string{"admin@example.com"}, true},
		{"unsupported scheme", []string{"tel:+1234567890"}, true},
		{"multiple addresses in one mailto", []string{"mailto:a@example.com,b@example.com"}, true},
		{"mailto with query hfields", []string{"mailto:a@example.com?subject=hi"}, true},
		{"empty mailto address", []string{"mailto:"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prob := validateContacts(c.in)
			if (prob != nil) != c.wantErr {
				t.Errorf("validateContacts(%v) prob=%v, wantErr=%v", c.in, prob, c.wantErr)
			}
		})
	}
}

func TestNewAccount_RejectsInvalidContact(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	rootCA := &storage.CertificateAuthority{ID: uuid.New(), Name: "root"}
	_ = store.CreateCA(ctx, rootCA)
	prov := &storage.Provisioner{
		ID: uuid.New(), CAID: rootCA.ID, Name: "acme-test",
		Type: storage.ProvisionerTypeACME, Config: storage.JSON{},
		Status: storage.ProvisionerStatusActive,
	}
	_ = store.CreateProvisioner(ctx, prov)

	svc := NewService(store, nil, NewNonceManager(store, 0), nil, nil, "https://ca.test")

	_, _, prob := svc.NewAccount(ctx, prov.ID, []byte(`{"kty":"EC"}`), "thumb-1",
		[]string{"not-a-uri-no-scheme"}, nil, prov)
	if prob == nil {
		t.Fatal("expected invalid contact to be rejected")
	}
	if prob.Type != ErrInvalidContact {
		t.Errorf("expected ErrInvalidContact, got %s", prob.Type)
	}
}

func TestNewAccount_AcceptsValidMailtoContact(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	rootCA := &storage.CertificateAuthority{ID: uuid.New(), Name: "root"}
	_ = store.CreateCA(ctx, rootCA)
	prov := &storage.Provisioner{
		ID: uuid.New(), CAID: rootCA.ID, Name: "acme-test",
		Type: storage.ProvisionerTypeACME, Config: storage.JSON{},
		Status: storage.ProvisionerStatusActive,
	}
	_ = store.CreateProvisioner(ctx, prov)

	svc := NewService(store, nil, NewNonceManager(store, 0), nil, nil, "https://ca.test")

	acct, created, prob := svc.NewAccount(ctx, prov.ID, []byte(`{"kty":"EC"}`), "thumb-2",
		[]string{"mailto:admin@example.com"}, nil, prov)
	if prob != nil {
		t.Fatalf("NewAccount failed: %v", prob)
	}
	if !created || acct.Contact[0] != "mailto:admin@example.com" {
		t.Errorf("unexpected account state: created=%v contact=%v", created, acct.Contact)
	}
}

func TestUpdateAccount_RejectsInvalidContact(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()
	svc := NewService(store, nil, NewNonceManager(store, 0), nil, nil, "https://ca.test")

	account := &storage.ACMEAccount{ID: uuid.New(), Status: storage.ACMEAccountStatusValid}
	_ = store.CreateACMEAccount(ctx, account)

	_, prob := svc.UpdateAccount(ctx, account, []string{"xmpp:user@example.com"}, false)
	if prob == nil {
		t.Fatal("expected invalid contact scheme to be rejected")
	}
	if prob.Type != ErrUnsupportedContact {
		t.Errorf("expected ErrUnsupportedContact, got %s", prob.Type)
	}
}

func TestUpdateAccount_AcceptsValidContact(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()
	svc := NewService(store, nil, NewNonceManager(store, 0), nil, nil, "https://ca.test")

	account := &storage.ACMEAccount{ID: uuid.New(), Status: storage.ACMEAccountStatusValid}
	_ = store.CreateACMEAccount(ctx, account)

	updated, prob := svc.UpdateAccount(ctx, account, []string{"mailto:ops@example.com"}, false)
	if prob != nil {
		t.Fatalf("UpdateAccount failed: %v", prob)
	}
	if updated.Contact[0] != "mailto:ops@example.com" {
		t.Errorf("contact not updated: %v", updated.Contact)
	}
}
