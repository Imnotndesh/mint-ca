// Package tpm2 implements a TPM 2.0-style attestation.Verifier: it proves the
// caller holds the private key matching a TPM Endorsement Key (EK) by
// checking a signature, made with that key, over the CSR being attested.
//
// This is a deliberately simplified binding compared to full TPM 2.0 remote
// attestation (which exchanges an actual TPM2B_ATTEST quote over PCRs signed
// by an Attestation Key certified by the EK). Implementing the TPM2 wire
// protocol needs a TPM simulator/library this repo doesn't depend on yet.
// What's here is the generically useful, protocol-agnostic core — "does this
// hardware-resident key's certificate check out, and did it sign this
// specific request" — behind the same attestation.Verifier interface, so a
// full TPM2B_ATTEST quote parser can be dropped in later without touching any
// caller.
package tpm2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"mint-ca/internal/attestation"
)

// Format is the attestation.Statement.Format this verifier handles.
const Format = "tpm2"

// statement is the JSON shape expected in attestation.Statement.Data.
type statement struct {
	// EKCertPEM is the TPM Endorsement Key certificate (or an AK certificate
	// chained to one), PEM-encoded.
	EKCertPEM string `json:"ek_cert_pem"`
	// SignatureB64 is a base64-encoded signature, made with the EK/AK private
	// key, over sha256(csrDER). This is what binds the attestation to this
	// specific certificate request.
	SignatureB64 string `json:"signature_b64"`
}

// Verifier checks TPM2-style attestation statements. Roots, when non-nil,
// restricts accepted EK certificates to those chaining to a trusted TPM
// manufacturer root (recommended for production; a nil pool accepts any
// well-formed EK certificate and only proves possession of its private key,
// not that the key lives in genuine TPM hardware).
type Verifier struct {
	Roots *x509.CertPool
}

// New builds a Verifier. roots may be nil (see Verifier.Roots).
func New(roots *x509.CertPool) *Verifier {
	return &Verifier{Roots: roots}
}

// Format implements attestation.Verifier.
func (v *Verifier) Format() string { return Format }

// Verify implements attestation.Verifier.
func (v *Verifier) Verify(ctx context.Context, csrDER []byte, stmt attestation.Statement) (attestation.Result, error) {
	var s statement
	if err := json.Unmarshal(stmt.Data, &s); err != nil {
		return attestation.Result{}, fmt.Errorf("tpm2: parse statement: %w", err)
	}

	block, _ := pem.Decode([]byte(s.EKCertPEM))
	if block == nil {
		return attestation.Result{}, fmt.Errorf("tpm2: ek_cert_pem: no PEM block found")
	}
	ekCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return attestation.Result{}, fmt.Errorf("tpm2: parse EK certificate: %w", err)
	}

	if v.Roots != nil {
		if _, err := ekCert.Verify(x509.VerifyOptions{Roots: v.Roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return attestation.Result{}, fmt.Errorf("tpm2: EK certificate does not chain to a trusted root: %w", err)
		}
	}

	sig, err := base64.StdEncoding.DecodeString(s.SignatureB64)
	if err != nil {
		return attestation.Result{}, fmt.Errorf("tpm2: decode signature_b64: %w", err)
	}
	digest := sha256.Sum256(csrDER)

	if err := verifySignature(ekCert.PublicKey, digest[:], sig); err != nil {
		return attestation.Result{}, fmt.Errorf("tpm2: signature verification failed: %w", err)
	}

	return attestation.Result{
		Verified: true,
		KeyID:    ekCert.SerialNumber.String(),
		Metadata: map[string]string{
			"format":      Format,
			"ek_subject":  ekCert.Subject.String(),
			"chain_check": fmt.Sprintf("%t", v.Roots != nil),
		},
	}, nil
}

// verifySignature checks sig over digest under pub, supporting the two key
// types TPM 2.0 endorsement keys commonly use.
func verifySignature(pub crypto.PublicKey, digest, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return fmt.Errorf("ECDSA signature does not verify")
		}
		return nil
	default:
		return fmt.Errorf("unsupported EK public key type %T", pub)
	}
}
