package policy

import (
	"context"
	"testing"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// --- matchDomain unit tests: lock in RFC-style wildcard semantics ---

func TestMatchDomain_Exact(t *testing.T) {
	for _, tc := range []struct{ pat, dom string }{
		{"example.com", "example.com"},
		{"EXAMPLE.com", "example.COM"}, // case-insensitive
	} {
		if !matchDomain(tc.pat, tc.dom) {
			t.Errorf("expected matchDomain(%q,%q)==true", tc.pat, tc.dom)
		}
	}
}

func TestMatchDomain_WildcardSingleLabel(t *testing.T) {
	// "*.example.com" matches exactly one label under example.com.
	ok := []struct{ pat, dom string }{
		{"*.example.com", "foo.example.com"},
		{"*.example.com", "bar.example.com"},
	}
	for _, tc := range ok {
		if !matchDomain(tc.pat, tc.dom) {
			t.Errorf("expected matchDomain(%q,%q)==true (single-label wildcard)", tc.pat, tc.dom)
		}
	}
}

func TestMatchDomain_WildcardDoesNotMatchMultiLabelOrApex(t *testing.T) {
	// "*.example.com" must NOT match multi-label subdomains or the apex.
	no := []struct{ pat, dom string }{
		{"*.example.com", "example.com"},
		{"*.example.com", "foo.bar.example.com"},
		{"*.example.com", "notexample.com"},
	}
	for _, tc := range no {
		if matchDomain(tc.pat, tc.dom) {
			t.Errorf("expected matchDomain(%q,%q)==false", tc.pat, tc.dom)
		}
	}
}

func TestMatchDomain_BareStarMatchesSingleDotlessLabel(t *testing.T) {
	// Documented contract: bare "*" matches any single (dotless) label.
	if !matchDomain("*", "foo") {
		t.Error("expected '*' to match 'foo'")
	}
	for _, dom := range []string{"foo.com", "foo.bar", ""} {
		if matchDomain("*", dom) {
			t.Errorf("expected '*' to NOT match %q", dom)
		}
	}
}

func TestMatchDomain_Misc(t *testing.T) {
	if matchDomain("", "example.com") {
		t.Error("empty pattern should not match")
	}
	if matchDomain("example.com", "") {
		t.Error("empty domain should not match")
	}
	if matchDomain("sub.example.com", "example.com") {
		t.Error("unrelated domain should not match")
	}
}

// --- policy.Evaluate wildcard SAN enforcement ---

// policyFakeStore is a minimal store satisfying the policy Evaluate path.
type policyFakeStore struct {
	storage.Store // embedded nil interface: any unoverridden method panics
	provisioners  map[uuid.UUID]*storage.Provisioner
	policies      map[uuid.UUID]*storage.Policy
}

func (f *policyFakeStore) Close() error { return nil }

func newPolicyFakeStore() *policyFakeStore {
	return &policyFakeStore{
		provisioners: map[uuid.UUID]*storage.Provisioner{},
		policies:     map[uuid.UUID]*storage.Policy{},
	}
}

func (f *policyFakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	return f.provisioners[id], nil
}
func (f *policyFakeStore) GetPolicy(ctx context.Context, id uuid.UUID) (*storage.Policy, error) {
	return f.policies[id], nil
}
func (f *policyFakeStore) ListPolicies(ctx context.Context) ([]*storage.Policy, error) {
	var out []*storage.Policy
	for _, p := range f.policies {
		out = append(out, p)
	}
	return out, nil
}

func evaluateWildcardSan(t *testing.T, allowed, denied []string, san string) error {
	t.Helper()
	return evaluate(&storage.Policy{AllowedDomains: allowed, DeniedDomains: denied}, CertRequest{
		SANsDNS: []string{san},
	})
}

func TestEvaluate_WildcardAllowedDomain(t *testing.T) {
	// SAN *.apps.example.com is permitted by a wildcard allowed pattern,
	// and the apex is NOT.
	if err := evaluateWildcardSan(t, []string{"*.apps.example.com"}, nil, "gateway.apps.example.com"); err != nil {
		t.Errorf("expected wildcard SAN allowed, got: %v", err)
	}
	if err := evaluateWildcardSan(t, []string{"*.apps.example.com"}, nil, "apps.example.com"); err == nil {
		t.Error("expected apex SAN to be rejected by wildcard allowed pattern")
	}
}

func TestEvaluate_WildcardDeniedTakesPrecedence(t *testing.T) {
	// A SAN in a denied wildcard subtree is rejected even if an allowed
	// pattern would otherwise permit it (denials take precedence).
	err := evaluateWildcardSan(t, []string{"example.com"}, []string{"*.blocked.example.com"}, "x.blocked.example.com")
	if err == nil {
		t.Error("expected denied wildcard to reject the SAN")
	}
}

func TestEvaluate_BareStarAllowedDotlessLabel(t *testing.T) {
	// Bare "*" allowed pattern matches a single (dotless) label.
	if err := evaluateWildcardSan(t, []string{"*"}, nil, "intranet"); err != nil {
		t.Errorf("bare-star allowed pattern should permit single label, got: %v", err)
	}
	if err := evaluateWildcardSan(t, []string{"*"}, nil, "intranet.example.com"); err == nil {
		t.Error("bare-star allowed pattern should reject multi-label domain")
	}
}

// TestPolicy_EngineEvaluateViaProvisioner exercises the full Evaluate path
// (provisioner lookup + policy) with a wildcard allowed domain.
func TestPolicy_EngineEvaluateViaProvisioner(t *testing.T) {
	ctx := context.Background()
	store := newPolicyFakeStore()
	engine := NewEngine(store)

	caID := uuid.New()
	pol := &storage.Policy{ID: uuid.New(), Name: "apps", AllowedDomains: []string{"*.apps.example.com"}}
	store.policies[pol.ID] = pol
	prov := &storage.Provisioner{
		ID: uuid.New(), Name: "apps-bot", Status: storage.ProvisionerStatusActive,
		CAID: caID, PolicyID: &pol.ID,
	}
	store.provisioners[prov.ID] = prov

	if _, err := engine.Evaluate(ctx, CertRequest{
		ProvisionerID: prov.ID, CAID: caID, SANsDNS: []string{"gateway.apps.example.com"},
	}); err != nil {
		t.Errorf("expected wildcard SAN allowed via provisioner, got: %v", err)
	}
	if _, err := engine.Evaluate(ctx, CertRequest{
		ProvisionerID: prov.ID, CAID: caID, SANsDNS: []string{"apps.example.com"},
	}); err == nil {
		t.Error("expected apex SAN rejected by wildcard allow policy")
	}
}
