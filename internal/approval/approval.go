// Package approval implements CSR auto-approval rules. A rule whitelists which
// CSRs a provisioner may auto-sign without caller review. The evaluator is a
// pure function (no DB, no side effects) so it is easy to test and reuse.
package approval

import (
	"fmt"
	"regexp"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// DefaultMaxTTLSeconds is applied when a rule sets no explicit cap, keeping
// auto-issued certificates short-lived.
const DefaultMaxTTLSeconds = 90 * 24 * 3600

// Request is the CSR data the evaluator inspects.
type Request struct {
	ProvisionerID uuid.UUID
	CommonName    string
	SANsDNS       []string
	// TTLSeconds is the requested certificate lifetime.
	TTLSeconds int64
}

// Evaluate approves a CSR iff an enabled rule for the provisioner is satisfied.
// Returns nil (approved) or a denial reason. When no enabled rule exists for
// the provisioner, Decided is false (no auto-approval policy applies).
func Evaluate(rule *storage.CSRAutoApproveRule, req Request) (approved bool, decided bool, reason string) {
	if rule == nil || !rule.Enabled {
		return false, false, ""
	}
	if rule.ProvisionerID != uuid.Nil && rule.ProvisionerID != req.ProvisionerID {
		return false, false, ""
	}

	// CommonName whitelist.
	if len(rule.AllowedCommonNames) > 0 && !matchesAny(rule.AllowedCommonNames, req.CommonName) {
		return false, true, fmt.Sprintf("common name %q not in allowlist", req.CommonName)
	}

	// Every DNS SAN must match an AllowedDNS pattern.
	for _, san := range req.SANsDNS {
		if !matchesAny(rule.AllowedDNS, san) {
			return false, true, fmt.Sprintf("DNS SAN %q not in allowlist", san)
		}
	}

	// TTL cap.
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = DefaultMaxTTLSeconds
	}
	max := rule.MaxTTLSeconds
	if max <= 0 {
		max = DefaultMaxTTLSeconds
	}
	if ttl > max {
		return false, true, fmt.Sprintf("requested TTL %d exceeds rule maximum %d", ttl, max)
	}

	return true, true, ""
}

func matchesAny(patterns []string, value string) bool {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if re.MatchString(value) {
			return true
		}
	}
	return false
}
