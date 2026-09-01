package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// SSHPolicyBody holds SSH CA issuance constraints. It is the SSH counterpart
// to the X.509 fields on storage.Policy, and is intended to be JSON-encoded
// and stored alongside a policy record. Zero-value means "no constraint for
// this dimension".
type SSHPolicyBody struct {
	// PrincipalAllowlist restricts which principals (usernames for user
	// certs, hostnames for host certs) may appear. Empty means allow all.
	// Entries may be exact names or "*" / "*.suffix" patterns.
	PrincipalAllowlist []string `json:"principal_allowlist,omitempty"`

	// PrincipalDenylist rejects principals even if they would otherwise be
	// allowed. Denials take precedence over the allowlist.
	PrincipalDenylist []string `json:"principal_denylist,omitempty"`

	// MinTTLSeconds bounds the low end of the requested validity window.
	MinTTLSeconds int64 `json:"min_ttl_seconds,omitempty"`

	// MaxTTLSeconds bounds the high end; requested TTLs above this are clamped
	// down to the maximum rather than causing a hard denial.
	MaxTTLSeconds int64 `json:"max_ttl_seconds,omitempty"`

	// DefaultTTLSeconds overrides the engine/requester default when a zero
	// TTL is requested. If a non-zero TTL is requested it is honoured
	// (subject to min/max clamping).
	DefaultTTLSeconds int64 `json:"default_ttl_seconds,omitempty"`

	// KeyAlgoAllowlist restricts the certificate's public key type, using the
	// OpenSSH type strings (e.g. "ssh-ed25519", "ecdsa-sha2-nistp256",
	// "ssh-rsa"). Empty means allow all.
	KeyAlgoAllowlist []string `json:"key_algo_allowlist,omitempty"`

	// CriticalOptionAllowlist permits only these critical-option names on the
	// certificate. Empty means no critical options are permitted. Requested
	// options outside the list are denied.
	CriticalOptionAllowlist []string `json:"critical_option_allowlist,omitempty"`

	// ExtensionAllowlist permits only these extension names. Empty means no
	// extensions are permitted (the OpenSSH default permit-* set is NOT
	// auto-injected). Requested extensions outside the list are denied.
	ExtensionAllowlist []string `json:"extension_allowlist,omitempty"`

	// DefaultCriticalOptions are injected on every permitted user cert when
	// the requester did not supply one of these names.
	DefaultCriticalOptions map[string]string `json:"default_critical_options,omitempty"`

	// DefaultExtensions are injected on every permitted user cert, merging
	// over / alongside the OpenSSH default set when the policy permits them.
	DefaultExtensions map[string]string `json:"default_extensions,omitempty"`
}

// SSHCertRequest is the normalised description of an SSH issuance request the
// policy engine evaluates.
type SSHCertRequest struct {
	// CertType is "user" or "host".
	CertType string `json:"cert_type"`

	// KeyAlgo is the certificate's public key type string as reported by
	// ssh.PublicKey.Type(), e.g. "ssh-ed25519". Empty when unknown.
	KeyAlgo string `json:"key_algo"`

	// Principals is the requested set of usernames / hostnames.
	Principals []string `json:"principals"`

	// TTLSeconds is the requested validity in seconds (0 = engine default).
	TTLSeconds int64 `json:"ttl_seconds"`

	// CriticalOptions and Extensions are the requested certificate options.
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
	Extensions      map[string]string `json:"extensions,omitempty"`
}

// SSHDecision is the set of effective constraints the engine must apply to a
// permitted request before signing.
type SSHDecision struct {
	// Principals is the final principal set (allowlist-filtered, denylist
	// removed). Always non-empty on success.
	Principals []string

	// TTLSeconds is the effective validity computed after defaults and
	// clamping to [MinTTL, MaxTTL].
	TTLSeconds int64

	// CriticalOptions is the final critical-option map (defaults merged in,
	// allowlist-filtered).
	CriticalOptions map[string]string

	// Extensions is the final extension map (defaults merged in, allowlist-
	// filtered, over the OpenSSH default set).
	Extensions map[string]string
}

// defaultUserTTL defaults an SSH user certificate lifetime to 8 hours.
const defaultUserTTL = 8 * 3600

// defaultHostTTL defaults an SSH host certificate lifetime to 1 year.
const defaultHostTTL = 365 * 24 * 3600

// EvaluateSSH checks a single SSH policy body against a request and returns
// the effective decision. It is a pure function — no DB access, no side
// effects. Order of checks: TTL defaults/clamp → denylist principals → key
// algorithm → allowed principals → critical options → extensions.
func EvaluateSSH(body *SSHPolicyBody, req SSHCertRequest) (*SSHDecision, error) {
	if body == nil {
		body = &SSHPolicyBody{}
	}

	// 1. TTL: apply default, then clamp into [Min, Max].
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = body.DefaultTTLSeconds
	}
	if ttl <= 0 {
		if strings.EqualFold(req.CertType, "host") {
			ttl = defaultHostTTL
		} else {
			ttl = defaultUserTTL
		}
	}
	if body.MaxTTLSeconds > 0 && ttl > body.MaxTTLSeconds {
		ttl = body.MaxTTLSeconds
	}
	if body.MinTTLSeconds > 0 && ttl < body.MinTTLSeconds {
		ttl = body.MinTTLSeconds
	}
	if ttl <= 0 {
		return nil, errors.New("policy: ssh: computed TTL is non-positive")
	}

	// 2. Key algorithm allowlist.
	if len(body.KeyAlgoAllowlist) > 0 && req.KeyAlgo != "" {
		if !containsString(body.KeyAlgoAllowlist, req.KeyAlgo) {
			return nil, fmt.Errorf(
				"policy: ssh: key algorithm %q is not permitted; allowed: %s",
				req.KeyAlgo, strings.Join(body.KeyAlgoAllowlist, ", "),
			)
		}
	}

	// 3. Principals: denylist first (denial precedence), then allowlist.
	principals := req.Principals
	if len(principals) == 0 {
		return nil, errors.New("policy: ssh: at least one principal is required")
	}
	principals, err := filterPrincipals(body, principals)
	if err != nil {
		return nil, err
	}
	if len(principals) == 0 {
		return nil, errors.New("policy: ssh: all requested principals were denied or filtered")
	}

	// 4. Critical options allowlist.
	crit, err := filterNamed(body.CriticalOptionAllowlist, req.CriticalOptions, body.DefaultCriticalOptions, "critical option")
	if err != nil {
		return nil, err
	}

	// 5. Extension allowlist (merged over the OpenSSH default set).
	extras, err := filterNamed(body.ExtensionAllowlist, req.Extensions, body.DefaultExtensions, "extension")
	if err != nil {
		return nil, err
	}

	if isUserCert(req.CertType) {
		for k, v := range defaultSSHExtensions {
			if extras == nil {
				extras = map[string]string{}
			}
			if _, exists := extras[k]; !exists {
				extras[k] = v
			}
		}
	}

	return &SSHDecision{
		Principals:      principals,
		TTLSeconds:      ttl,
		CriticalOptions: crit,
		Extensions:      extras,
	}, nil
}

// filterPrincipals removes denied principals and keeps only those matching an
// allowlist entry (when an allowlist is present). The returned slice preserves
// request order and de-duplicates.
func filterPrincipals(body *SSHPolicyBody, principals []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, p := range principals {
		if seen[p] {
			continue
		}
		seen[p] = true

		// Deny takes precedence.
		if matchesAny(body.PrincipalDenylist, p) {
			return nil, fmt.Errorf("policy: ssh: principal %q matches a denied pattern (%s)", p, strings.Join(body.PrincipalDenylist, ", "))
		}

		if len(body.PrincipalAllowlist) > 0 && !matchesAny(body.PrincipalAllowlist, p) {
			return nil, fmt.Errorf(
				"policy: ssh: principal %q does not match any allowed pattern (%s)",
				p, strings.Join(body.PrincipalAllowlist, ", "),
			)
		}
		out = append(out, p)
	}
	return out, nil
}

// filterNamed applies an allowlist (if non-empty) to a requested map of SSH
// certificate options/extensions, merging in defaults. It returns an error if
// any requested name falls outside the allowlist.
func filterNamed(allowlist []string, requested, defaults map[string]string, what string) (map[string]string, error) {
	out := map[string]string{}

	// Requested entries must all be allowed.
	for name, val := range requested {
		if len(allowlist) > 0 && !containsString(allowlist, name) {
			return nil, fmt.Errorf(
				"policy: ssh: %s %q is not permitted; allowed: %s",
				what, name, strings.Join(allowlist, ", "),
			)
		}
		if _, exists := out[name]; !exists {
			out[name] = val
		}
	}

	// Defaults are only injected if the operator granted them in the allowlist
	// (when an allowlist is present) and they weren't already requested.
	for name, val := range defaults {
		if len(allowlist) > 0 && !containsString(allowlist, name) {
			continue
		}
		if _, exists := out[name]; !exists {
			out[name] = val
		}
	}

	return out, nil
}

// defaultSSHExtensions is the OpenSSH default interactive user-cert extension
// set (mirrors internal/sshca/engine.go).
var defaultSSHExtensions = map[string]string{
	"permit-X11-forwarding":   "",
	"permit-agent-forwarding": "",
	"permit-port-forwarding":  "",
	"permit-pty":              "",
	"permit-user-rc":          "",
}

func isUserCert(ct string) bool {
	return ct == "" || strings.EqualFold(ct, "user")
}

// matchesAny reports whether name matches any pattern using matchName
// (exact, bare "*", or "*.",suffix wildcard).
func matchesAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if matchName(p, name) {
			return true
		}
	}
	return false
}

// matchName is like matchDomain but for principal names. Patterns support:
//   - exact: "ops" matches "ops"
//   - bare "*": matches any name
//   - trailing "*": "dev-*" matches any name with that prefix
//   - "*.suffix": matches names ending in the suffix
func matchName(pattern, name string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || name == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	// Trailing wildcard: prefix match.
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if prefix == "" {
			return true
		}
		return strings.HasPrefix(name, prefix)
	}
	// "*.suffix": name must be <label>.suffix with a non-empty label.
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(name, suffix) && name != suffix[1:]
	}
	return pattern == name
}

// SortPrincipals returns a sorted copy of principals for deterministic
// comparisons in tests and audit output.
func SortPrincipals(p []string) []string {
	out := append([]string(nil), p...)
	sort.Strings(out)
	return out
}
