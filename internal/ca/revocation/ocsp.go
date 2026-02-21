package revocation

import (
	"context"
	"crypto"
	"fmt"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"
)

// OCSPResponder handles OCSP requests for certificates issued by mint-ca CAs.
//
// OCSP (RFC 6960) works like this:
//  1. A TLS client receives a certificate and wants to check its revocation status.
//  2. The client sends a DER-encoded OCSPRequest to the CA's OCSP endpoint
//     (the URL is baked into the certificate's Authority Information Access extension).
//  3. The OCSP responder parses the request, looks up the serial number, and
//     returns a signed OCSPResponse: Good, Revoked, or Unknown.
//  4. The client verifies the response signature against the issuing CA's cert.
//
// Traefik uses OCSP stapling — it fetches the OCSP response itself and bundles
// it into the TLS handshake so the client never has to make a separate request.
// Our responder must therefore be reachable by Traefik, not just end-user clients.
type OCSPResponder struct {
	store    storage.Store
	keystore *mintcrypto.Keystore
}

// NewOCSPResponder constructs an OCSPResponder.
func NewOCSPResponder(store storage.Store, keystore *mintcrypto.Keystore) *OCSPResponder {
	return &OCSPResponder{store: store, keystore: keystore}
}

// Respond parses a raw DER-encoded OCSP request body and returns a signed
// DER-encoded OCSP response. This is what the HTTP handler calls directly —
// it reads r.Body, passes the bytes here, and writes the returned bytes to
// the response with Content-Type: application/ocsp-response.
//
// caID identifies which CA's key should sign the response. In practice the
// OCSP URL embeds the CA ID so the handler can extract it from the path.
//
// This method never returns a Go error to the caller — if anything goes wrong
// internally it returns a valid but error-typed OCSP response (InternalError),
// because the HTTP layer must always write a proper OCSP response body, not an
// HTTP error. OCSP clients do not understand HTTP error status codes.
func (r *OCSPResponder) Respond(ctx context.Context, caID uuid.UUID, requestDER []byte) []byte {
	resp, err := r.respond(ctx, caID, requestDER)
	if err != nil {
		// Return a standards-compliant OCSP error response.
		// ocsp.InternalErrorErrorResponse is a pre-built DER blob defined
		// in golang.org/x/crypto/ocsp for exactly this situation.
		return ocsp.InternalErrorErrorResponse
	}
	return resp
}

// respond is the internal implementation that can return a Go error.
// Respond() wraps it and converts errors to OCSP error responses.
func (r *OCSPResponder) respond(ctx context.Context, caID uuid.UUID, requestDER []byte) ([]byte, error) {
	// Parse the OCSP request.
	req, err := ocsp.ParseRequest(requestDER)
	if err != nil {
		return nil, fmt.Errorf("ocsp: parse request: %w", err)
	}

	// Load the CA. We need its certificate to sign the response and to
	// verify that the request is actually asking about one of our certs.
	caRecord, err := r.store.GetCA(ctx, caID)
	if err != nil {
		return nil, fmt.Errorf("ocsp: load CA: %w", err)
	}
	if caRecord == nil {
		return nil, fmt.Errorf("ocsp: CA %s not found", caID)
	}

	caCert, err := parseCertPEM([]byte(caRecord.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("ocsp: parse CA cert: %w", err)
	}

	caKey, err := r.loadKey(caRecord)
	if err != nil {
		return nil, fmt.Errorf("ocsp: load CA key: %w", err)
	}

	// Look up the certificate by serial number.
	// req.SerialNumber is a *big.Int; we store serials as decimal strings.
	serial := req.SerialNumber.String()
	cert, err := r.store.GetCertificateBySerial(ctx, serial)
	if err != nil {
		return nil, fmt.Errorf("ocsp: look up serial %s: %w", serial, err)
	}

	now := time.Now().UTC()

	// OCSP responses should be short-lived so clients do not cache stale
	// status for too long. One hour is a common production value.
	// For revoked certificates, we use a longer window — there is no reason
	// to re-check a revoked cert frequently.
	thisUpdate := now
	nextUpdate := now.Add(1 * time.Hour)

	var template ocsp.Response

	switch {
	case cert == nil:
		// Serial not found in our database — respond Unknown.
		// RFC 6960 says: "The OCSP responder SHALL respond 'unknown' for
		// certificates that have not been issued."
		template = ocsp.Response{
			Status:     ocsp.Unknown,
			ThisUpdate: thisUpdate,
			NextUpdate: nextUpdate,
		}

	case cert.Status == storage.CertStatusRevoked:
		// Certificate is revoked — include the revocation time and reason.
		revokedAt := now
		if cert.RevokedAt != nil {
			revokedAt = cert.RevokedAt.UTC()
		}
		reason := ocsp.Unspecified
		if cert.RevokeReason != nil {
			reason = *cert.RevokeReason
		}

		// Revoked certs can have a longer NextUpdate — the status will not
		// change back to good.
		nextUpdate = now.Add(24 * time.Hour)

		template = ocsp.Response{
			Status:           ocsp.Revoked,
			SerialNumber:     req.SerialNumber,
			ThisUpdate:       thisUpdate,
			NextUpdate:       nextUpdate,
			RevokedAt:        revokedAt,
			RevocationReason: reason,
		}

	default:
		// Certificate is active and known — respond Good.
		template = ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: req.SerialNumber,
			ThisUpdate:   thisUpdate,
			NextUpdate:   nextUpdate,
		}
	}

	// Sign the response. We sign with the CA certificate itself acting as
	// both the issuer and the responder — this is the "direct" response model
	// in RFC 6960. An alternative is a delegated responder (a separate cert
	// with the OCSPSigning EKU), but for mint-ca the direct model is simpler
	// and avoids managing an additional keypair.
	responseDER, err := ocsp.CreateResponse(caCert, caCert, template, caKey)
	if err != nil {
		return nil, fmt.Errorf("ocsp: create response: %w", err)
	}

	return responseDER, nil
}

func (r *OCSPResponder) loadKey(ca *storage.CertificateAuthority) (crypto.Signer, error) {
	keyPEM, err := r.keystore.DecryptPEM(ca.KeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt key for CA %q: %w", ca.Name, err)
	}
	return parseKeyPEM(keyPEM)
}
