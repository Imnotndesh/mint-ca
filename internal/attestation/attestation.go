// Package attestation gates certificate issuance on proof that the requested
// key is bound to a hardware root of trust (a TPM, a secure enclave, a
// WebAuthn/FIDO2 authenticator, ...). It defines the generic Statement/
// Verifier/Registry contract; concrete verifiers live in subpackages
// (attestation/tpm2, attestation/webauthn) and are plugged in by whoever
// wires up the server (see internal/api/router.go).
package attestation

import (
	"context"
	"fmt"
	"sync"
)

// Statement is the caller-supplied attestation evidence accompanying a CSR.
// Format selects which registered Verifier interprets Data; Data's shape is
// entirely up to that Verifier.
type Statement struct {
	Format string
	Data   []byte
}

// Result is what a Verifier concludes about a Statement.
type Result struct {
	// Verified is true only if the statement cryptographically proves the
	// requested key is bound to the attested hardware.
	Verified bool
	// KeyID identifies the attested key/authenticator (e.g. an EK certificate
	// serial, or a WebAuthn credential ID), for audit trails.
	KeyID string
	// Metadata carries verifier-specific details worth recording (e.g. AAGUID,
	// TPM manufacturer, attestation format).
	Metadata map[string]string
}

// Verifier checks one attestation format. csrDER is the raw PKCS#10 CSR the
// attestation is claimed to cover; implementations bind the statement to it
// (typically by requiring a challenge/signature over a digest of csrDER) so a
// captured attestation can't be replayed against a different CSR.
type Verifier interface {
	Format() string
	Verify(ctx context.Context, csrDER []byte, stmt Statement) (Result, error)
}

// Registry dispatches attestation statements to the Verifier registered for
// their format. A Registry starts empty: requesting attestation for a format
// with no registered Verifier is a configuration error, not a silent pass.
type Registry struct {
	mu        sync.RWMutex
	verifiers map[string]Verifier
}

// NewRegistry builds an empty Registry.
func NewRegistry() *Registry {
	return &Registry{verifiers: map[string]Verifier{}}
}

// Register adds v, keyed by v.Format(). A later Register with the same format
// replaces the earlier one.
func (r *Registry) Register(v Verifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifiers[v.Format()] = v
}

// Verify dispatches stmt to the Verifier registered for stmt.Format.
func (r *Registry) Verify(ctx context.Context, csrDER []byte, stmt Statement) (Result, error) {
	r.mu.RLock()
	v, ok := r.verifiers[stmt.Format]
	r.mu.RUnlock()
	if !ok {
		return Result{}, fmt.Errorf("attestation: no verifier registered for format %q", stmt.Format)
	}
	return v.Verify(ctx, csrDER, stmt)
}

// Formats returns the currently registered formats, for diagnostics.
func (r *Registry) Formats() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.verifiers))
	for f := range r.verifiers {
		out = append(out, f)
	}
	return out
}
