package challenge

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	http01PathPrefix = "/.well-known/acme-challenge/"
	http01MaxBody    = 512 // RFC 8555 §8.3: body should be the key authorization, no more
	http01Timeout    = 30 * time.Second
)

// HTTP01Validator validates http-01 ACME challenges.
type HTTP01Validator struct {
	client *http.Client
}

// NewHTTP01Validator constructs a validator with a suitable HTTP client.
func NewHTTP01Validator() *HTTP01Validator {
	return &HTTP01Validator{
		client: &http.Client{
			Timeout: http01Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("http-01: too many redirects")
				}
				return nil
			},
		},
	}
}

// Validate fetches the challenge URL for the given domain and token, then
// compares the response body to expectedKeyAuth. Returns nil on success.
func (v *HTTP01Validator) Validate(ctx context.Context, domain, token, expectedKeyAuth string) error {
	url := "http://" + domain + http01PathPrefix + token

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("http-01: build request for %s: %w", domain, err)
	}
	// Some servers return 404 for unexpected User-Agents; use a neutral one.
	req.Header.Set("User-Agent", "mint-ca-acme-validator/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("http-01: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http-01: %s returned HTTP %d", url, resp.StatusCode)
	}

	// Read at most http01MaxBody+1 bytes so we can detect oversized responses.
	body, err := io.ReadAll(io.LimitReader(resp.Body, http01MaxBody+1))
	if err != nil {
		return fmt.Errorf("http-01: read body from %s: %w", url, err)
	}

	// The body should be exactly the key authorization (possibly with trailing newline).
	got := strings.TrimSpace(string(body))
	if got != expectedKeyAuth {
		return fmt.Errorf("http-01: key authorization mismatch for %s (got %q)", domain, got)
	}

	return nil
}
