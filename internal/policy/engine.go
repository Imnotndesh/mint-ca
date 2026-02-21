package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// CertRequest is the normalised description of a certificate issuance request
// that the policy engine evaluates. It is populated by the API handler from
// the incoming HTTP request before calling Evaluate.
type CertRequest struct {
	// CAID is the CA that would issue the certificate.
	CAID uuid.UUID

	// ProvisionerID is the provisioner authorising the request.
	ProvisionerID uuid.UUID

	// Subject
	CommonName string

	// SANs
	SANsDNS   []string
	SANsIP    []net.IP
	SANsEmail []string

	// TTLSeconds is the requested certificate lifetime.
	TTLSeconds int64

	// KeyAlgo is the algorithm requested for the leaf keypair.
	// Empty string means the engine default and is always permitted.
	KeyAlgo string
}

// Engine evaluates certificate issuance requests against the policies stored
// in the database. It is stateless beyond its store reference — it does not
// cache policies, so changes take effect on the next request without restart.
type Engine struct {
	store storage.Store
}

// NewEngine constructs a policy Engine.
func NewEngine(store storage.Store) *Engine {
	return &Engine{store: store}
}

// Evaluate checks req against the applicable policies and returns nil if the
// request is permitted, or a descriptive error if it is denied.
//
// Resolution order:
//  1. Load the provisioner. If it does not exist or is disabled, deny.
//  2. If the provisioner has a policy attached, evaluate it. Result is final.
//  3. If not, look for a CA-scoped policy. Evaluate it if found. Result is final.
//  4. If no policy applies, permit.
func (e *Engine) Evaluate(ctx context.Context, req CertRequest) error {
	if req.ProvisionerID == uuid.Nil {
		return errors.New("policy: ProvisionerID is required")
	}
	if req.CAID == uuid.Nil {
		return errors.New("policy: CAID is required")
	}

	provisioner, err := e.store.GetProvisioner(ctx, req.ProvisionerID)
	if err != nil {
		return fmt.Errorf("policy: load provisioner: %w", err)
	}
	if provisioner == nil {
		return fmt.Errorf("policy: provisioner %s does not exist", req.ProvisionerID)
	}
	if provisioner.Status != storage.ProvisionerStatusActive {
		return fmt.Errorf("policy: provisioner %q is disabled", provisioner.Name)
	}

	// Confirm the provisioner actually belongs to the CA being requested.
	if provisioner.CAID != req.CAID {
		return fmt.Errorf(
			"policy: provisioner %q belongs to CA %s, not %s",
			provisioner.Name, provisioner.CAID, req.CAID,
		)
	}

	if provisioner.PolicyID != nil {
		pol, err := e.store.GetPolicy(ctx, *provisioner.PolicyID)
		if err != nil {
			return fmt.Errorf("policy: load provisioner policy: %w", err)
		}
		if pol != nil {
			if err := evaluate(pol, req); err != nil {
				return fmt.Errorf("policy: provisioner %q denied: %w", provisioner.Name, err)
			}
			// Provisioner policy passed — result is final.
			return nil
		}
	}

	caPolicy, err := e.findCAPolicy(ctx, req.CAID)
	if err != nil {
		return fmt.Errorf("policy: load CA policy: %w", err)
	}
	if caPolicy != nil {
		if err := evaluate(caPolicy, req); err != nil {
			return fmt.Errorf("policy: CA policy denied: %w", err)
		}
		return nil
	}

	return nil
}

// findCAPolicy scans all policies looking for one scoped to the given CA.
// This is a scan rather than a direct lookup because the current schema does
// not have a direct FK from certificate_authorities to policies — policies are
// attached via provisioners or by convention of scope. A CA-scoped policy is
// one where Scope == PolicyScopeCA. We return the first one found.
//
// If this becomes a hot path (many policies, high issuance rate) the schema
// can be extended with a ca_id column on the policies table and a direct lookup.
func (e *Engine) findCAPolicy(ctx context.Context, caID uuid.UUID) (*storage.Policy, error) {
	policies, err := e.store.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	for _, pol := range policies {
		if pol.Scope == storage.PolicyScopeCA {
			return pol, nil
		}
	}
	return nil, nil
}

// evaluate checks a single policy against a request. It is a pure function —
// no database access, no side effects. All rules are checked and the most
// specific denial reason is returned. Order of checks:
//
//  1. TTL
//  2. SAN presence
//  3. Key algorithm
//  4. Denied domains (checked before allowed so denials take precedence)
//  5. Allowed domains
//  6. Allowed IPs
func evaluate(pol *storage.Policy, req CertRequest) error {

	if pol.MaxTTL > 0 {
		maxDuration := time.Duration(pol.MaxTTL) * time.Second
		reqDuration := time.Duration(req.TTLSeconds) * time.Second
		if reqDuration > maxDuration {
			return fmt.Errorf(
				"requested TTL %s exceeds policy maximum of %s",
				formatDuration(reqDuration),
				formatDuration(maxDuration),
			)
		}
	}

	if pol.RequireSAN {
		hasSAN := len(req.SANsDNS) > 0 || len(req.SANsIP) > 0 || len(req.SANsEmail) > 0
		if !hasSAN {
			return errors.New("policy requires at least one Subject Alternative Name")
		}
	}

	if len(pol.KeyAlgos) > 0 && req.KeyAlgo != "" {
		if !containsString(pol.KeyAlgos, req.KeyAlgo) {
			return fmt.Errorf(
				"key algorithm %q is not permitted; allowed algorithms: %s",
				req.KeyAlgo,
				strings.Join(pol.KeyAlgos, ", "),
			)
		}
	}

	// Denials take precedence over allowances. A domain that matches a denied
	// pattern is rejected even if it also matches an allowed pattern.

	if len(pol.DeniedDomains) > 0 {
		for _, san := range req.SANsDNS {
			for _, pattern := range pol.DeniedDomains {
				if matchDomain(pattern, san) {
					return fmt.Errorf(
						"DNS SAN %q matches denied domain pattern %q",
						san, pattern,
					)
				}
			}
		}
	}

	// If the policy specifies allowed domains, every DNS SAN must match at
	// least one of them. If no allowed domains are configured, all domains
	// pass (subject to the denied list above).

	if len(pol.AllowedDomains) > 0 {
		for _, san := range req.SANsDNS {
			matched := false
			for _, pattern := range pol.AllowedDomains {
				if matchDomain(pattern, san) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf(
					"DNS SAN %q does not match any allowed domain pattern (%s)",
					san,
					strings.Join(pol.AllowedDomains, ", "),
				)
			}
		}
	}

	// If the policy specifies allowed IPs or CIDRs, every IP SAN must fall
	// within at least one of them.

	if len(pol.AllowedIPs) > 0 {
		for _, ip := range req.SANsIP {
			if !ipPermitted(pol.AllowedIPs, ip) {
				return fmt.Errorf(
					"IP SAN %s is not within any allowed IP or CIDR (%s)",
					ip.String(),
					strings.Join(pol.AllowedIPs, ", "),
				)
			}
		}
	}

	return nil
}

// matchDomain reports whether domain matches pattern.
//
// Rules:
//   - Matching is case-insensitive.
//   - An exact pattern matches only that domain: "example.com" matches
//     "example.com" but not "sub.example.com".
//   - A wildcard pattern "*.example.com" matches exactly one label deep:
//     "foo.example.com" matches, "foo.bar.example.com" does not,
//     "example.com" does not.
//   - A bare "*" matches any single label with no dots.
func matchDomain(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	domain = strings.ToLower(strings.TrimSpace(domain))

	if pattern == "" || domain == "" {
		return false
	}

	// Exact match.
	if pattern == domain {
		return true
	}

	// Wildcard match: pattern must start with "*." and the remainder must
	// be a non-empty suffix of the domain with exactly one label before it.
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g. ".example.com"
		if !strings.HasSuffix(domain, suffix) {
			return false
		}
		// The part of the domain before the suffix must be a single label
		// (no dots). E.g. for domain "foo.example.com" and suffix ".example.com",
		// prefix is "foo" — no dots, valid.
		prefix := domain[:len(domain)-len(suffix)]
		if prefix == "" || strings.Contains(prefix, ".") {
			return false
		}
		return true
	}

	return false
}

// ipPermitted reports whether ip is covered by at least one entry in allowed.
// Each entry in allowed is either a plain IP address ("192.168.1.1") or a
// CIDR range ("10.0.0.0/8"). Both IPv4 and IPv6 are supported.
func ipPermitted(allowed []string, ip net.IP) bool {
	for _, entry := range allowed {
		entry = strings.TrimSpace(entry)
		if strings.Contains(entry, "/") {
			// CIDR notation.
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				// Skip malformed entries rather than denying everything.
				continue
			}
			if network.Contains(ip) {
				return true
			}
		} else {
			// Plain IP address.
			allowed := net.ParseIP(entry)
			if allowed != nil && allowed.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// formatDuration produces a human-readable duration string for error messages.
// time.Duration.String() produces output like "24h0m0s" which is clear enough
// but we strip redundant zero segments for readability.
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}

	return strings.Join(parts, "")
}
