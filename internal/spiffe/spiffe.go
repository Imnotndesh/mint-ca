// Package spiffe validates SPIFFE IDs (https://github.com/spiffe/spiffe) so
// mint-ca can issue X.509-SVIDs: ordinary leaf certificates carrying a
// spiffe://trust-domain/path URI SAN, consumable by SPIFFE-aware service
// mesh/workload tooling (Envoy, Istio, SPIRE-adjacent stacks) without any
// SPIFFE-specific protocol support on mint-ca's part.
package spiffe

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateID parses and validates id as a SPIFFE ID per the SPIFFE-ID
// specification: scheme "spiffe", a non-empty trust domain (host), no
// query string or fragment, and no userinfo.
func ValidateID(id string) (*url.URL, error) {
	if id == "" {
		return nil, fmt.Errorf("spiffe: empty ID")
	}
	u, err := url.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("spiffe: parse %q: %w", id, err)
	}
	if u.Scheme != "spiffe" {
		return nil, fmt.Errorf("spiffe: %q must use the spiffe:// scheme", id)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("spiffe: %q is missing a trust domain", id)
	}
	if strings.ToLower(u.Host) != u.Host {
		return nil, fmt.Errorf("spiffe: %q trust domain must be lowercase", id)
	}
	if u.User != nil {
		return nil, fmt.Errorf("spiffe: %q must not contain userinfo", id)
	}
	if u.RawQuery != "" {
		return nil, fmt.Errorf("spiffe: %q must not contain a query string", id)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("spiffe: %q must not contain a fragment", id)
	}
	if len(id) > 2048 {
		return nil, fmt.Errorf("spiffe: %q exceeds the 2048-byte maximum length", id)
	}
	return u, nil
}
