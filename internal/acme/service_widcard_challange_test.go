package acme

import (
	"context"
	"mint-ca/internal/storage"
	"testing"

	"github.com/google/uuid"
)

func TestIsWildcardIdentifier(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"example.com", false},
		{"*.example.com", true},
		{"foo.example.com", false},
		{"*.*.example.com", true},
	}
	for _, c := range cases {
		if got := IsWildcardIdentifier(c.in); got != c.want {
			t.Errorf("IsWildcardIdentifier(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidateIdentifier(t *testing.T) {
	cases := []struct {
		name    string
		id      Identifier
		wantErr bool
	}{
		{"plain domain", Identifier{Type: "dns", Value: "example.com"}, false},
		{"valid wildcard", Identifier{Type: "dns", Value: "*.example.com"}, false},
		{"bare wildcard", Identifier{Type: "dns", Value: "*"}, true},
		{"double wildcard", Identifier{Type: "dns", Value: "*.*.example.com"}, true},
		{"mid-string wildcard", Identifier{Type: "dns", Value: "foo.*.example.com"}, true},
		{"empty value", Identifier{Type: "dns", Value: ""}, true},
		{"unsupported type", Identifier{Type: "ip", Value: "10.0.0.1"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateIdentifier(c.id)
			if (err != nil) != c.wantErr {
				t.Errorf("validateIdentifier(%+v) error = %v, wantErr %v", c.id, err, c.wantErr)
			}
		})
	}
}

// TestNewOrderWildcardChallengeRestriction verifies wildcard identifiers
// only receive dns-01 challenges, never http-01, even when the provisioner
// config allows both.
func TestNewOrderWildcardChallengeRestriction(t *testing.T) {
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
		ID: uuid.New(), ProvisionerID: prov.ID, KeyID: "test-thumb",
		Status: storage.ACMEAccountStatusValid,
	}
	_ = store.CreateACMEAccount(ctx, account)

	svc := NewService(store, nil, NewNonceManager(store, 0), nil, nil, "https://ca.test")

	order, challenges, prob := svc.NewOrder(ctx, account, prov, []Identifier{
		{Type: "dns", Value: "*.example.com"},
	}, "")
	if prob != nil {
		t.Fatalf("NewOrder failed: %v", prob)
	}
	if order == nil {
		t.Fatal("expected non-nil order")
	}
	if len(challenges) != 1 {
		t.Fatalf("expected exactly 1 challenge for wildcard identifier, got %d", len(challenges))
	}
	if challenges[0].Type != storage.ACMEChallengeTypeDNS01 {
		t.Errorf("expected dns-01 challenge, got %s", challenges[0].Type)
	}
}
