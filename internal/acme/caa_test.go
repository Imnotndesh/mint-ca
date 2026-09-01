package acme

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// fakeCAAResolver returns CAA records keyed by label from a map, and records
// the labels queried so tests can assert the DNS tree-climb.
func fakeCAAResolver(rrByLabel map[string][]*dns.CAA, queried *[]string) func(context.Context, string) ([]*dns.CAA, error) {
	return func(_ context.Context, label string) ([]*dns.CAA, error) {
		if queried != nil {
			*queried = append(*queried, label)
		}
		return rrByLabel[label], nil
	}
}

func caa(flags uint8, tag, value string) *dns.CAA {
	return &dns.CAA{Flag: flags, Tag: tag, Value: value}
}

func newTestChecker(identity string, rrByLabel map[string][]*dns.CAA, queried *[]string) *CAAChecker {
	c := NewCAAChecker(identity, "", nil)
	c.queryFn = fakeCAAResolver(rrByLabel, queried)
	return c
}

func TestCAAChecker_NoRecordsPermits(t *testing.T) {
	c := newTestChecker("mint-ca.example.com", map[string][]*dns.CAA{}, nil)
	ok, err := c.Enforce(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected issuance permitted when no CAA records present")
	}
}

func TestCAAChecker_CloserRecordShadowsAncestor(t *testing.T) {
	rr := map[string][]*dns.CAA{
		"example.com": {caa(0, "issue", "letmein.example.net")},
		"com":         {caa(0, "issue", "mint-ca.example.com")},
	}
	c := newTestChecker("mint-ca.example.com", rr, nil)
	// example.com has its own RRset, so we must stop there and NOT climb to
	// "com" even though "com" would authorise us. That RRset only permits
	// letmein.example.net => refusal.
	ok, _ := c.Enforce(context.Background(), "example.com")
	if ok {
		t.Fatal("expected refusal: closer RRset at example.com shadows permissive ancestor")
	}
}

func TestCAAChecker_TreeClimbFindsAncestorRecord(t *testing.T) {
	rr := map[string][]*dns.CAA{
		"example.com": {caa(0, "issue", "mint-ca.example.com")},
	}
	var queried []string
	c := newTestChecker("mint-ca.example.com", rr, &queried)
	ok, _ := c.Enforce(context.Background(), "www.example.com")
	if !ok {
		t.Fatal("expected permit via ancestor CAA record")
	}
	// Must have queried www.example.com, then example.com.
	if len(queried) < 2 || queried[0] != "www.example.com" || queried[1] != "example.com" {
		t.Fatalf("expected tree-climb www -> example, got %v", queried)
	}
}

func TestCAAChecker_IssueForbidsOtherCA(t *testing.T) {
	rr := map[string][]*dns.CAA{
		"example.com": {caa(0, "issue", "letsencrypt.org")},
	}
	c := newTestChecker("mint-ca.example.com", rr, nil)
	ok, _ := c.Enforce(context.Background(), "example.com")
	if ok {
		t.Fatal("expected refusal: CAA only authorises letsencrypt.org")
	}
}

func TestCAAChecker_IssueEmptyRefusesAll(t *testing.T) {
	rr := map[string][]*dns.CAA{
		"example.com": {caa(0, "issue", ";")},
	}
	c := newTestChecker("mint-ca.example.com", rr, nil)
	ok, _ := c.Enforce(context.Background(), "example.com")
	if ok {
		t.Fatal("expected refusal for issue \";\" (no issuer authorised)")
	}
}

func TestCAAChecker_OnlyIODeFDoesNotRestrict(t *testing.T) {
	rr := map[string][]*dns.CAA{
		"example.com": {caa(0, "iodef", "mailto:abuse@example.com")},
	}
	c := newTestChecker("mint-ca.example.com", rr, nil)
	ok, _ := c.Enforce(context.Background(), "example.com")
	if !ok {
		t.Fatal("expected permit: iodef-only record set does not restrict")
	}
}

func TestCAAChecker_UnknownCriticalTagRefuses(t *testing.T) {
	// flags 0x80 = Issuer Critical Flag.
	rr := map[string][]*dns.CAA{
		"example.com": {caa(0x80, "tbs", "unknown")},
	}
	c := newTestChecker("mint-ca.example.com", rr, nil)
	ok, _ := c.Enforce(context.Background(), "example.com")
	if ok {
		t.Fatal("expected refusal for unsupported critical property")
	}
}

func TestCAAChecker_KnownCriticalTagOK(t *testing.T) {
	rr := map[string][]*dns.CAA{
		"example.com": {caa(0x80, "issue", "mint-ca.example.com")},
	}
	c := newTestChecker("mint-ca.example.com", rr, nil)
	ok, _ := c.Enforce(context.Background(), "example.com")
	if !ok {
		t.Fatal("expected permit: issue is a supported (known) critical tag")
	}
}

func TestCAAChecker_WildcardUsesIssueWild(t *testing.T) {
	// issue only authorises a non-CA; issuewild authorises us. For the
	// wildcard, issuewild takes precedence.
	rr := map[string][]*dns.CAA{
		"example.com": {
			caa(0, "issue", "someother-ca.example"),
			caa(0, "issuewild", "mint-ca.example.com"),
		},
	}
	c := newTestChecker("mint-ca.example.com", rr, nil)

	wildOK, _ := c.Enforce(context.Background(), "*.example.com")
	if !wildOK {
		t.Error("expected *.example.com permitted via issuewild")
	}
	plainOK, _ := c.Enforce(context.Background(), "example.com")
	if plainOK {
		t.Error("expected example.com refused (only other CA authorised for issue)")
	}
}

func TestCAAChecker_WildcardIgnoresIssueWhenNoIssueWild(t *testing.T) {
	rr := map[string][]*dns.CAA{
		"example.com": {caa(0, "issue", "mint-ca.example.com")},
	}
	c := newTestChecker("mint-ca.example.com", rr, nil)
	ok, _ := c.Enforce(context.Background(), "*.example.com")
	if !ok {
		t.Fatal("expected *.example.com permitted via issue record when no issuewild present")
	}
}

func TestCAAChecker_BypassLabel(t *testing.T) {
	rr := map[string][]*dns.CAA{
		"example.com": {caa(0, "issue", ";")}, // denies everyone
	}
	c := NewCAAChecker("mint-ca.example.com", "", []string{"nocaa.example.com"})
	c.queryFn = fakeCAAResolver(rr, nil)
	if _, err := c.Enforce(context.Background(), "sub.nocaa.example.com"); err != nil {
		t.Fatalf("bypass should not error: %v", err)
	}
	ok, _ := c.Enforce(context.Background(), "sub.nocaa.example.com")
	if !ok {
		t.Fatal("expected bypassed domain to be permitted")
	}
}

func TestCAAChecker_TrailingDotAndCaseNormalised(t *testing.T) {
	rr := map[string][]*dns.CAA{
		"example.com": {caa(0, "issue", "MINT-CA.EXAMPLE.COM.")},
	}
	c := newTestChecker("mint-ca.example.com", rr, nil)
	ok, _ := c.Enforce(context.Background(), "EXAMPLE.com")
	if !ok {
		t.Fatal("expected permit: issuer value normalised (case + trailing dot)")
	}
}

func TestServiceEnforceCAA_Wiring(t *testing.T) {
	ctx := context.Background()

	rr := map[string][]*dns.CAA{
		"example.com": {caa(0, "issue", "letsencrypt.org")},
	}
	c := newTestChecker("mint-ca.example.com", rr, nil)
	svc := &Service{caa: c}

	if svc.enforceCAA(ctx, "example.com") {
		t.Error("expected enforceCAA to deny identifier not in CAA policy")
	}
	// Wildcard strips to example.com and applies the same policy.
	if svc.enforceCAA(ctx, "*.example.com") {
		t.Error("expected enforceCAA to deny wildcard when base domain not allowed")
	}

	// No checker configured => always permitted.
	noCAA := &Service{}
	if !noCAA.enforceCAA(ctx, "example.com") {
		t.Error("expected enforceCAA to permit when no checker configured")
	}
}

func TestServiceEnforceCAA_FailsOpenOnLookupError(t *testing.T) {
	c := NewCAAChecker("mint-ca.example.com", "", nil)
	c.queryFn = func(context.Context, string) ([]*dns.CAA, error) {
		return nil, &dns.Error{}
	}
	svc := &Service{caa: c}
	if !svc.enforceCAA(context.Background(), "example.com") {
		t.Error("expected enforceCAA to fail open on DNS lookup error")
	}
}

func TestParseIssueValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{"mint-ca.example.com", "mint-ca.example.com"},
		{"mint-ca.example.com.", "mint-ca.example.com"},
		{"mint-ca.example.com; x", "mint-ca.example.com"},
		{";", ""},
		{"  ", ""},
		{"ca.example.com; acct=1", "ca.example.com"},
	}
	for _, tc := range cases {
		if got := parseIssueValue(tc.in); got != tc.want {
			t.Errorf("parseIssueValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
