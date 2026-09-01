package sshca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// generateSSHKey produces a crypto.Signer and its PKCS8 PEM encoding for the
// given SSH CA key algorithm. PKCS8 is used (rather than the SEC1/PKCS1
// forms used elsewhere in mint-ca) because it uniformly supports both
// Ed25519 and ECDSA keys with a single parse/marshal path.
func generateSSHKey(algo KeyAlgo) (crypto.Signer, []byte, error) {
	var key crypto.Signer
	var err error

	switch algo {
	case KeyAlgoEd25519:
		_, priv, genErr := ed25519.GenerateKey(rand.Reader)
		err = genErr
		key = priv
	case KeyAlgoECDSAP256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, nil, fmt.Errorf("generateSSHKey: unsupported algorithm %q", algo)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("generateSSHKey %s: %w", algo, err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("generateSSHKey %s: marshal PKCS8: %w", algo, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	return key, keyPEM, nil
}

// parseKeyPEMToSigner decodes a PKCS8 PEM-encoded private key (as produced
// by generateSSHKey) back into a crypto.Signer.
func parseKeyPEMToSigner(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("parseKeyPEMToSigner: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parseKeyPEMToSigner: PKCS8: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("parseKeyPEMToSigner: key type %T does not implement crypto.Signer", key)
	}
	return signer, nil
}

// sshBase64Decode decodes a raw base64-encoded SSH wire-format public key,
// tolerating both standard and raw (no-padding) encodings since clients
// sometimes strip padding.
func sshBase64Decode(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
