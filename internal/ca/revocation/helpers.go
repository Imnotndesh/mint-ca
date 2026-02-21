package revocation

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// parseCertPEM decodes the first certificate block from PEM bytes.
func parseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("revocation: parseCertPEM: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("revocation: parseCertPEM: %w", err)
	}
	return cert, nil
}

// parseKeyPEM decodes a PEM-encoded private key.
// Handles EC PRIVATE KEY, RSA PRIVATE KEY, and PRIVATE KEY (PKCS8).
func parseKeyPEM(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("revocation: parseKeyPEM: no PEM block found")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("revocation: parseKeyPEM: PKCS8: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("revocation: parseKeyPEM: type %T does not implement crypto.Signer", key)
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("revocation: parseKeyPEM: unrecognised block type %q", block.Type)
	}
}
