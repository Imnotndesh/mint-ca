package handlers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"mint-ca/internal/ca"
	"mint-ca/internal/storage"

	"software.sslmate.com/src/go-pkcs12"
)

// exportCert bundles an issued certificate into a tar.gz artifact for
// download/distribution: the leaf cert, the full CA chain, a machine-readable
// manifest, and a short README. When keyPEM is non-nil (the key was escrowed
// and the caller supplied a valid passcode) it is included as key.pem so the
// bundle is a self-contained key+cert+chain artifact.
func exportCert(ctx context.Context, engine *ca.Engine, cert *storage.Certificate, keyPEM []byte) ([]byte, error) {
	chainPEM, err := engine.GetLeafChainPEM(ctx, cert.CAID, []byte(cert.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("export: build chain: %w", err)
	}

	manifest := map[string]interface{}{
		"id":             cert.ID,
		"ca_id":          cert.CAID,
		"serial":         cert.Serial,
		"subject_cn":     cert.SubjectCN,
		"sans":           cert.SANs,
		"status":         cert.Status,
		"not_before":     cert.NotBefore,
		"not_after":      cert.NotAfter,
		"issued_at":      cert.IssuedAt,
		"provisioner_id": cert.ProvisionerID,
		"requester":      cert.Requester,
		"metadata":       cert.Metadata,
		"key_included":   len(keyPEM) > 0,
	}
	mjson, _ := json.MarshalIndent(manifest, "", "  ")

	readme := fmt.Sprintf(`mint-ca certificate export
==========================
Certificate : %s (%s)
Serial      : %s
CA          : %s
Not valid   : %s -> %s
Status      : %s

Files:
  cert.json    machine-readable metadata manifest
  cert.pem     leaf certificate (PEM)
  chain.pem    full chain: leaf + intermediates + root (PEM)
  key.pem      private key (only when the issuance opted into key escrow and a
               valid passcode was supplied)

The private key is included only for escrowed certificates. mint-ca never
persists leaf keys unless store_key=true was set at issue time.
`, cert.SubjectCN, cert.ID, cert.Serial, cert.CAID, cert.NotBefore, cert.NotAfter, cert.Status)

	files := map[string][]byte{
		"cert.json":  append(mjson, '\n'),
		"cert.pem":   []byte(cert.CertPEM),
		"chain.pem":  chainPEM,
		"README.txt": []byte(readme),
	}
	if len(keyPEM) > 0 {
		files["key.pem"] = keyPEM
	}
	return tarGz(files)
}

// pkcs12DefaultPassword is used when the caller doesn't supply ?p12_password=.
const pkcs12DefaultPassword = pkcs12.DefaultPassword

// exportP12 bundles a leaf certificate, its private key, and its CA chain
// into a password-protected PKCS#12 (.p12/.pfx) file for legacy consumers
// (Windows cert stores, Java keystores, network appliances) that expect one
// self-contained keystore file rather than separate PEM parts. certPEM is the
// leaf certificate; chainPEM is the leaf followed by its intermediates and
// root (as returned by ca.Engine.GetLeafChainPEM); keyPEM is the leaf's
// private key and must be non-empty (a p12 file always carries a key).
func exportP12(certPEM, chainPEM, keyPEM []byte, password string) ([]byte, error) {
	if len(keyPEM) == 0 {
		return nil, errors.New("export: pkcs12 export requires an escrowed key with a valid passcode")
	}
	leaf, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("export: parse leaf cert: %w", err)
	}
	chain, err := parseCertChainPEM(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("export: parse chain: %w", err)
	}
	var caCerts []*x509.Certificate
	for _, c := range chain {
		if c.Equal(leaf) {
			continue
		}
		caCerts = append(caCerts, c)
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("export: parse key: %w", err)
	}
	data, err := pkcs12.Encode(rand.Reader, key, leaf, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("export: pkcs12 encode: %w", err)
	}
	return data, nil
}

// parseCertPEM decodes the first certificate in a PEM block.
func parseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parseCertChainPEM decodes every CERTIFICATE block in pemBytes, in order.
func parseCertChainPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in chain PEM")
	}
	return certs, nil
}

// parseKeyPEM decodes a PEM-encoded private key. Handles EC PRIVATE KEY,
// RSA PRIVATE KEY, and PRIVATE KEY (PKCS8) blocks.
func parseKeyPEM(pemBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unrecognised PEM block type %q", block.Type)
	}
}

// tarGz packs entries into a gzip-compressed tar archive.
func tarGz(files map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	now := time.Now()
	for name, data := range files {
		hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: now}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("tar: header %s: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return nil, fmt.Errorf("tar: write %s: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("tar: close: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("gzip: close: %w", err)
	}
	return buf.Bytes(), nil
}
