// CAA checking per RFC 8659 (DNS Certification Authority Authorization).
//
// A compliant CA must, before issuing a certificate, check the published CAA
// RRset for each FQDN / wildcard in the request and refuse issuance unless the
// request is consistent with it. This package resolves and evaluates CAA
// records so the ACME service can enforce them at challenge-validation time.
//
// DNS is queried with github.com/miekg/dns because the Go standard library's
// net.Resolver has no CAA (RR type 257) lookup.
package acme

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// CAA property tags mint-ca recognises. The ones relevant to the issuance
// decision are "issue" and "issuewild"; the others are reporting directives
// that do not restrict issuance.
const (
	caaTagIssue        = "issue"
	caaTagIssueWild    = "issuewild"
	caaTagIODeF        = "iodef"
	caaTagContactemail = "contactemail"
	caaTagContactphone = "contactphone"
)

// CAAChecker resolves and evaluates CAA records against a configured CA
// identity. The identity is the fully-qualified domain name this CA announces
// in its own CAA issue/issuewild records — the value operators must grant in
// their CAA policy for mint-ca to be permitted to issue.
type CAAChecker struct {
	// identity is the CA's public domain, e.g. "mint-ca.example.com". Empty
	// disables issuance restriction matching (CAA still checked but never
	// grants/denies by matching). Configured via ACME.CAADomain.
	identity string

	// dnsServer is the resolver address used for CAA lookups, in host:port
	// form. Empty means read the system resolvers from resolv.conf.
	dnsServer string

	// bypassLabels, if non-empty, skips CAA checking for domains ending in
	// any of these labels (an explicit CP/CPS exception per RFC 8659 §3).
	bypassLabels []string

	// client is the DNS client used for queries; substituted in tests.
	client *dns.Client

	// queryFn performs the DNS CAA lookup for one label. Kept as a field so
	// tests can substitute a fake resolver without touching the network.
	queryFn func(ctx context.Context, label string) ([]*dns.CAA, error)
}

// NewCAAChecker constructs a CAAChecker. identity is the CA's public domain
// (empty to disable identity matching); dnsServer defaults to the system
// resolver when empty.
func NewCAAChecker(identity, dnsServer string, bypassLabels []string) *CAAChecker {
	c := &CAAChecker{
		identity:     strings.ToLower(strings.TrimSuffix(identity, ".")),
		dnsServer:    dnsServer,
		bypassLabels: sanitiseBypassLabels(bypassLabels),
		client:       &dns.Client{Timeout: 5 * time.Second},
	}
	c.queryFn = c.queryCAA
	return c
}

// systemResolver returns a DNS server address from resolv.conf, preferring
// the first configured nameserver. Returns "8.8.8.8:53" as a last resort.
func systemResolver() string {
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		return net.JoinHostPort(cfg.Servers[0], cfg.Port)
	}
	return "8.8.8.8:53"
}

// SplitBypassLabels parses a comma-separated configuration string into a
// slice of bypass domain labels. Used by the router to turn the env/config
// value into the slice NewCAAChecker expects.
func SplitBypassLabels(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sanitiseBypassLabels(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		l = strings.ToLower(strings.TrimSpace(l))
		l = strings.TrimPrefix(l, "*.")
		l = strings.TrimSuffix(l, ".")
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Enforce checks CAA for identifier and returns an error describing why
// issuance must be refused, or nil if permitted. Identifier may be an FQDN or
// a wildcard ("*.example.com"). It returns (permitted bool, err error); when
// the DNS query itself fails the caller decides whether to fail open.
func (c *CAAChecker) Enforce(ctx context.Context, identifier string) (permitted bool, err error) {
	// RFC 8659 §3: the "domain" for a Wildcard Domain Name is the FQDN with
	// the "*. " label removed — CAA RRsets are never published under "*.".
	domain := strings.TrimPrefix(strings.TrimSpace(identifier), "*.")
	wildcard := strings.HasPrefix(identifier, "*.")

	for _, b := range c.bypassLabels {
		if domain == b || strings.HasSuffix(domain, "."+b) {
			return true, nil
		}
	}

	set, err := c.resolvableCAASet(ctx, domain)
	if err != nil {
		return false, err
	}
	return c.evaluate(set, wildcard), nil
}

// resolvableCAASet implements RelevantCAASet from RFC 8659 §3: it walks the
// DNS name tree from domain toward the root, returning the first non-empty CAA
// RRset found. CNAME/DNAME chasing is left to the recursive resolver.
func (c *CAAChecker) resolvableCAASet(ctx context.Context, domain string) ([]*dns.CAA, error) {
	cur := strings.TrimSuffix(domain, ".")
	for cur != "" {
		rrs, err := c.queryFn(ctx, cur)
		if err != nil {
			return nil, err
		}
		if len(rrs) > 0 {
			return rrs, nil
		}
		// Climb one label toward the root.
		parent := nextParentLabel(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return nil, nil
}

// nextParentLabel strips the leftmost label of an FQDN, returning "" for a
// single-label name (parent of that is the DNS root, where we stop).
func nextParentLabel(domain string) string {
	i := strings.IndexByte(domain, '.')
	if i < 0 {
		return ""
	}
	return domain[i+1:]
}

// queryCAA asks the resolver for the CAA RRset at the given label.
func (c *CAAChecker) queryCAA(ctx context.Context, label string) ([]*dns.CAA, error) {
	m := new(dns.Msg)
	m.SetQuestion(label+".", dns.TypeCAA)

	resp, _, err := c.client.ExchangeContext(ctx, m, c.dnsServer)
	if err != nil {
		return nil, fmt.Errorf("caa: query %s: %w", label, err)
	}
	if resp == nil {
		return nil, fmt.Errorf("caa: no response for %s", label)
	}
	if resp.Rcode != dns.RcodeSuccess {
		// NXDOMAIN / NODATA / SERVFAIL all mean "no CAA records here";
		// the tree-climb continues. A SERVFAIL raised this high up is
		// worth logging.
		if resp.Rcode == dns.RcodeServerFailure {
			slog.Warn("caa: DNS server failure on lookup", "domain", label)
		}
		return nil, nil
	}

	var out []*dns.CAA
	for _, rr := range resp.Answer {
		if caa, ok := rr.(*dns.CAA); ok {
			out = append(out, caa)
		}
	}
	return out, nil
}

// evaluate applies RFC 8659 §4 processing to the Relevant RRset:
//   - A critical-flagged property with an unrecognised tag refuses issuance.
//   - For an FQDN, only "issue" tags restrict. For a wildcard, "issuewild"
//     tags take precedence over "issue" tags; if neither kind of restricting
//     tag is present the record set does not restrict issuance.
//   - A restricting tag value of "x" permits the CA iff x matches this CA's
//     configured identity (empty values refuse all CAs).
func (c *CAAChecker) evaluate(set []*dns.CAA, wildcard bool) bool {
	if len(set) == 0 {
		return true
	}

	for _, rr := range set {
		if rr.Flag&0x80 != 0 { // Issuer Critical Flag (bit 0 of the flags octet)
			switch strings.ToLower(rr.Tag) {
			case caaTagIssue, caaTagIssueWild, caaTagIODeF, caaTagContactemail, caaTagContactphone:
				// Recognised tags are understood, so critical is fine.
			default:
				return false // unknown critical property => deny
			}
		}
	}

	// Choose which property tag restricts issuance.
	tag := caaTagIssue
	if wildcard {
		// If any issuewild property is present it takes precedence and each
		// issue property is ignored (RFC 8659 §4.3).
		if hasTag(set, caaTagIssueWild) {
			tag = caaTagIssueWild
		}
	}

	values := valuesForTag(set, tag)
	if len(values) == 0 {
		// No issue/issuewild property => the record set does not restrict.
		return true
	}

	// If we have no configured identity, a restricting record can never be
	// satisfied — refuse rather than silently issuing.
	if c.identity == "" {
		return false
	}

	for _, v := range values {
		issuer := parseIssueValue(v)
		if issuer != "" && strings.EqualFold(issuer, c.identity) {
			return true
		}
	}
	return false
}

func hasTag(set []*dns.CAA, tag string) bool {
	for _, rr := range set {
		if strings.EqualFold(rr.Tag, tag) {
			return true
		}
	}
	return false
}

func valuesForTag(set []*dns.CAA, tag string) []string {
	var out []string
	for _, rr := range set {
		if strings.EqualFold(rr.Tag, tag) {
			out = append(out, rr.Value)
		}
	}
	return out
}

// parseIssueValue extracts the issuer-domain-name from an issue/issuewild
// value, dropping any parameters after ';'. Empty string means "no issuer
// authorised" (e.g. "issue ;" or a malformed value).
func parseIssueValue(v string) string {
	v = strings.TrimSpace(v)
	// Drop parameters.
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	// Normalise trailing dot so "ca.example.com." matches "ca.example.com".
	return strings.ToLower(strings.TrimSuffix(v, "."))
}
