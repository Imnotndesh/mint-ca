package handlers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"mint-ca/internal/ca"
	"mint-ca/internal/storage"
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
