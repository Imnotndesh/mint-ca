package challenge

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// DNS01Validator validates dns-01 ACME challenges.
type DNS01Validator struct {
	resolver *net.Resolver
}

// NewDNS01Validator constructs a validator using the system resolver.
// For environments with a custom DNS server (e.g. internal split-horizon),
// pass a custom *net.Resolver; otherwise nil uses the system default.
func NewDNS01Validator(resolver *net.Resolver) *DNS01Validator {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &DNS01Validator{resolver: resolver}
}

// Validate looks up the _acme-challenge TXT record for domain and checks
// whether expectedDigest (base64url(SHA-256(keyAuthorization))) is present.
// Returns nil on success.
func (v *DNS01Validator) Validate(ctx context.Context, domain, expectedDigest string) error {
	// Strip wildcard label if present ("*.example.com" → "example.com").
	lookup := strings.TrimPrefix(domain, "*.")
	fqdn := "_acme-challenge." + lookup

	txts, err := v.resolver.LookupTXT(ctx, fqdn)
	if err != nil {
		return fmt.Errorf("dns-01: TXT lookup for %s: %w", fqdn, err)
	}

	if len(txts) == 0 {
		return fmt.Errorf("dns-01: no TXT records found at %s", fqdn)
	}

	// Any one of the TXT records may carry the expected value (clients may
	// publish multiple records during key rollover).
	for _, txt := range txts {
		if txt == expectedDigest {
			return nil
		}
	}

	return fmt.Errorf(
		"dns-01: expected TXT record %q not found at %s (found: %v)",
		expectedDigest, fqdn, txts,
	)
}
