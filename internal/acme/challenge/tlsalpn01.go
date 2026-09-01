package challenge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	acmeTLS1Protocol = "acme-tls/1"
	tlsALPN01Timeout = 15 * time.Second
)

// idPeACMEIdentifier is the OID for the acmeIdentifier X.509 extension
// (RFC 8737 §3): 1.3.6.1.5.5.7.1.31.
var idPeACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// TLSALPN01Validator validates tls-alpn-01 ACME challenges (RFC 8737).
// mint-ca is the CA here, so validation means dialing OUT to the domain
// being validated and inspecting the self-signed cert it presents during
// a TLS handshake that negotiates the "acme-tls/1" ALPN protocol.
type TLSALPN01Validator struct {
	port     int
	dialAddr string
}

// NewTLSALPN01Validator constructs a validator. port is overridable so
// tests can point it at a local listener instead of real port 443.
func NewTLSALPN01Validator(port int) *TLSALPN01Validator {
	if port <= 0 {
		port = 443
	}
	return &TLSALPN01Validator{port: port}
}

// Validate dials domain on the configured port, requires ALPN negotiation
// of "acme-tls/1", and checks the presented self-signed certificate embeds
// SHA-256(keyAuth) in a critical id-pe-acmeIdentifier extension.
func (v *TLSALPN01Validator) Validate(ctx context.Context, domain, keyAuth string) error {
	if strings.HasPrefix(domain, "*.") {
		return fmt.Errorf("tls-alpn-01: wildcard identifiers are not permitted for this challenge type (RFC 8737 §3)")
	}

	dialer := &net.Dialer{Timeout: tlsALPN01Timeout}
	addr := v.dialAddr
	if addr == "" {
		addr = net.JoinHostPort(domain, fmt.Sprintf("%d", v.port))
	}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         domain,
		NextProtos:         []string{acmeTLS1Protocol},
		InsecureSkipVerify: true, // we verify the ACME-specific extension ourselves, not the chain
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("tls-alpn-01: TLS dial %s: %w", addr, err)
	}
	defer func(tlsConn *tls.Conn) {
		err = tlsConn.Close()
		if err != nil {
			return
		}
	}(tlsConn)

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != acmeTLS1Protocol {
		return fmt.Errorf("tls-alpn-01: server did not negotiate %q ALPN protocol (got %q)",
			acmeTLS1Protocol, state.NegotiatedProtocol)
	}

	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("tls-alpn-01: server presented no certificate")
	}
	cert := state.PeerCertificates[0]

	if err := verifySelfSigned(cert); err != nil {
		return fmt.Errorf("tls-alpn-01: %w", err)
	}

	if err := verifyExactSAN(cert, domain); err != nil {
		return fmt.Errorf("tls-alpn-01: %w", err)
	}

	digest, err := extractACMEIdentifierDigest(cert)
	if err != nil {
		return fmt.Errorf("tls-alpn-01: %w", err)
	}

	expected := sha256.Sum256([]byte(keyAuth))
	if !bytes.Equal(digest, expected[:]) {
		return fmt.Errorf("tls-alpn-01: acmeIdentifier digest mismatch for %s", domain)
	}

	return nil
}

// verifySelfSigned requires the presented cert be self-signed, as mandated
// by RFC 8737 §3 ("the certificate MUST be signed using the private key
// corresponding to the public key in the certificate").
func verifySelfSigned(cert *x509.Certificate) error {
	if cert.Subject.String() != cert.Issuer.String() {
		return fmt.Errorf("certificate is not self-signed (subject %q != issuer %q)", cert.Subject, cert.Issuer)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("certificate self-signature invalid: %w", err)
	}
	return nil
}

// verifyExactSAN requires the certificate carry exactly one dNSName SAN,
// matching domain case-insensitively, and no other SAN types — RFC 8737
// §3: "the certificate MUST have exactly one subjectAltName extension
// ... containing exactly one dNSName".
func verifyExactSAN(cert *x509.Certificate, domain string) error {
	if len(cert.DNSNames) != 1 {
		return fmt.Errorf("certificate must have exactly one dNSName SAN, got %d", len(cert.DNSNames))
	}
	if len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 || len(cert.URIs) != 0 {
		return fmt.Errorf("certificate must not have SAN types other than dNSName")
	}
	if !strings.EqualFold(cert.DNSNames[0], domain) {
		return fmt.Errorf("certificate SAN %q does not match identifier %q", cert.DNSNames[0], domain)
	}
	return nil
}

// extractACMEIdentifierDigest locates the critical id-pe-acmeIdentifier
// extension and returns its inner OCTET STRING payload (the raw SHA-256
// digest), per RFC 8737 §3.
func extractACMEIdentifierDigest(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(idPeACMEIdentifier) {
			continue
		}
		if !ext.Critical {
			return nil, fmt.Errorf("acmeIdentifier extension MUST be marked critical")
		}
		var digest []byte
		if _, err := asn1.Unmarshal(ext.Value, &digest); err != nil {
			return nil, fmt.Errorf("acmeIdentifier extension: invalid DER OCTET STRING: %w", err)
		}
		if len(digest) != sha256.Size {
			return nil, fmt.Errorf("acmeIdentifier extension: expected %d-byte digest, got %d", sha256.Size, len(digest))
		}
		return digest, nil
	}
	return nil, fmt.Errorf("certificate is missing the id-pe-acmeIdentifier extension")
}
