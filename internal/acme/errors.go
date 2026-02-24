package acme

import (
	"encoding/json"
	"net/http"
)

// Error type URNs defined by RFC 8555 §6.7.
const (
	ErrAccountDoesNotExist     = "urn:ietf:params:acme:error:accountDoesNotExist"
	ErrAlreadyRevoked          = "urn:ietf:params:acme:error:alreadyRevoked"
	ErrBadCSR                  = "urn:ietf:params:acme:error:badCSR"
	ErrBadNonce                = "urn:ietf:params:acme:error:badNonce"
	ErrBadPublicKey            = "urn:ietf:params:acme:error:badPublicKey"
	ErrBadRevocationReason     = "urn:ietf:params:acme:error:badRevocationReason"
	ErrBadSignatureAlg         = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	ErrCAA                     = "urn:ietf:params:acme:error:caa"
	ErrCompound                = "urn:ietf:params:acme:error:compound"
	ErrConnection              = "urn:ietf:params:acme:error:connection"
	ErrDNS                     = "urn:ietf:params:acme:error:dns"
	ErrExternalAccountRequired = "urn:ietf:params:acme:error:externalAccountRequired"
	ErrIncorrectResponse       = "urn:ietf:params:acme:error:incorrectResponse"
	ErrInvalidContact          = "urn:ietf:params:acme:error:invalidContact"
	ErrMalformed               = "urn:ietf:params:acme:error:malformed"
	ErrOrderNotReady           = "urn:ietf:params:acme:error:orderNotReady"
	ErrRateLimited             = "urn:ietf:params:acme:error:rateLimited"
	ErrRejectedIdentifier      = "urn:ietf:params:acme:error:rejectedIdentifier"
	ErrServerInternal          = "urn:ietf:params:acme:error:serverInternal"
	ErrTLS                     = "urn:ietf:params:acme:error:tls"
	ErrUnauthorized            = "urn:ietf:params:acme:error:unauthorized"
	ErrUnsupportedContact      = "urn:ietf:params:acme:error:unsupportedContact"
	ErrUnsupportedIdentifier   = "urn:ietf:params:acme:error:unsupportedIdentifier"
	ErrUserActionRequired      = "urn:ietf:params:acme:error:userActionRequired"
)

// Problem is an RFC 7807 / RFC 8555 problem detail object.
type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (p *Problem) Error() string { return p.Type + ": " + p.Detail }

// NewProblem constructs a Problem with the given ACME error type, HTTP status,
// and human-readable detail.
func NewProblem(errType string, status int, detail string) *Problem {
	return &Problem{Type: errType, Status: status, Detail: detail}
}

// Common constructors for the errors we return most often.

func ErrBadNonceProblem(detail string) *Problem {
	return NewProblem(ErrBadNonce, http.StatusBadRequest, detail)
}

func ErrMalformedProblem(detail string) *Problem {
	return NewProblem(ErrMalformed, http.StatusBadRequest, detail)
}

func ErrUnauthorizedProblem(detail string) *Problem {
	return NewProblem(ErrUnauthorized, http.StatusUnauthorized, detail)
}

func ErrServerInternalProblem(detail string) *Problem {
	return NewProblem(ErrServerInternal, http.StatusInternalServerError, detail)
}

func ErrOrderNotReadyProblem(detail string) *Problem {
	return NewProblem(ErrOrderNotReady, http.StatusForbidden, detail)
}

func ErrBadCSRProblem(detail string) *Problem {
	return NewProblem(ErrBadCSR, http.StatusBadRequest, detail)
}

func ErrExternalAccountRequiredProblem() *Problem {
	return NewProblem(
		ErrExternalAccountRequired,
		http.StatusUnauthorized,
		"this provisioner requires an external account binding",
	)
}

// WriteProblem writes a Problem as an application/problem+json HTTP response.
// It always adds a fresh Replay-Nonce header so clients can immediately retry.
func WriteProblem(w http.ResponseWriter, nonce string, p *Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	if nonce != "" {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}
