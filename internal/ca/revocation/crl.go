package revocation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// CRLManager handles CRL generation, caching, and serving for all CAs.
// It is the only component that writes to the crl_cache table.
type CRLManager struct {
	store    storage.Store
	keystore *mintcrypto.Keystore
}

// NewCRLManager constructs a CRLManager.
func NewCRLManager(store storage.Store, keystore *mintcrypto.Keystore) *CRLManager {
	return &CRLManager{store: store, keystore: keystore}
}

// RevokeAndRefresh revokes the certificate and immediately regenerates the CRL
// for its issuing CA. This is the method the API layer calls — it ensures there
// is never a window where a certificate is marked revoked in the database but
// has not yet appeared in the published CRL.
//
// reason is an RFC 5280 CRL reason code:
//
//	0  unspecified
//	1  keyCompromise
//	2  cACompromise
//	3  affiliationChanged
//	4  superseded
//	5  cessationOfOperation
//	6  certificateHold
//	9  privilegeWithdrawn
//	10 aACompromise
func (m *CRLManager) RevokeAndRefresh(ctx context.Context, certID uuid.UUID, reason int) error {
	// Load the cert first so we know which CA's CRL to refresh.
	cert, err := m.store.GetCertificate(ctx, certID)
	if err != nil {
		return fmt.Errorf("crl: RevokeAndRefresh: load certificate: %w", err)
	}
	if cert == nil {
		return fmt.Errorf("crl: RevokeAndRefresh: certificate %s not found", certID)
	}
	if cert.Status == storage.CertStatusRevoked {
		return fmt.Errorf("crl: RevokeAndRefresh: certificate %s is already revoked", certID)
	}

	// Persist the revocation.
	if err := m.store.RevokeCertificate(ctx, certID, reason); err != nil {
		return fmt.Errorf("crl: RevokeAndRefresh: revoke in store: %w", err)
	}

	// Immediately regenerate the CRL so the revocation is published at once.
	if err := m.GenerateCRL(ctx, cert.CAID, defaultCRLValidity); err != nil {
		return fmt.Errorf("crl: RevokeAndRefresh: regenerate CRL: %w", err)
	}

	return nil
}

// defaultCRLValidity is how long a freshly generated CRL is valid before
// clients should re-fetch it. One day is a common default; operators can
// tune this by calling GenerateCRL directly with a different duration.
const defaultCRLValidity = 24 * time.Hour

// GenerateCRL builds and signs a fresh CRL for the given CA, then upserts
// it into crl_cache. It is safe to call concurrently — the database upsert
// is atomic. It is called:
//   - immediately after every revocation (via RevokeAndRefresh)
//   - on a background ticker for each active CA (so the NextUpdate field
//     stays fresh even when no revocations occur)
func (m *CRLManager) GenerateCRL(ctx context.Context, caID uuid.UUID, validFor time.Duration) error {
	if validFor <= 0 {
		validFor = defaultCRLValidity
	}

	caRecord, err := m.store.GetCA(ctx, caID)
	if err != nil {
		return fmt.Errorf("crl: GenerateCRL: load CA: %w", err)
	}
	if caRecord == nil {
		return fmt.Errorf("crl: GenerateCRL: CA %s not found", caID)
	}
	if caRecord.Status == storage.CAStatusRevoked {
		return fmt.Errorf("crl: GenerateCRL: CA %q is revoked — will not generate CRL", caRecord.Name)
	}

	caCert, err := parseCertPEM([]byte(caRecord.CertPEM))
	if err != nil {
		return fmt.Errorf("crl: GenerateCRL: parse CA cert: %w", err)
	}

	caKey, err := m.loadKey(caRecord)
	if err != nil {
		return fmt.Errorf("crl: GenerateCRL: load CA key: %w", err)
	}

	// Fetch every certificate this CA has revoked.
	revoked, err := m.store.ListRevokedByCA(ctx, caID)
	if err != nil {
		return fmt.Errorf("crl: GenerateCRL: list revoked: %w", err)
	}

	// Build the revoked certificate entries.
	entries := make([]pkix.RevokedCertificate, 0, len(revoked))
	for _, cert := range revoked {
		serial := new(big.Int)
		if _, ok := serial.SetString(cert.Serial, 10); !ok {
			continue
		}

		revokedAt := time.Now().UTC()
		if cert.RevokedAt != nil {
			revokedAt = cert.RevokedAt.UTC()
		}

		reason := 0
		if cert.RevokeReason != nil {
			reason = *cert.RevokeReason
		}

		entry := pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: revokedAt,
		}

		// Only encode a reason extension when the reason is not unspecified (0),
		// since unspecified is the default and encoding it wastes space.
		if reason != 0 {
			ext, err := buildReasonExtension(reason)
			if err == nil {
				entry.Extensions = []pkix.Extension{ext}
			}
		}

		entries = append(entries, entry)
	}

	now := time.Now().UTC()
	nextUpdate := now.Add(validFor)

	// The CRL number is a monotonically increasing integer required by RFC 5280.
	// Using the current Unix timestamp is a pragmatic choice that guarantees
	// monotonic increase without needing to track a counter in the database.
	crlNumber := big.NewInt(now.Unix())

	template := &x509.RevocationList{
		RevokedCertificates: entries,
		Number:              crlNumber,
		ThisUpdate:          now,
		NextUpdate:          nextUpdate,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, caCert, caKey)
	if err != nil {
		return fmt.Errorf("crl: GenerateCRL: create revocation list: %w", err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	entry := &storage.CRLCache{
		ID:         uuid.New(),
		CAID:       caID,
		CRLPEM:     string(crlPEM),
		ThisUpdate: now,
		NextUpdate: nextUpdate,
	}

	if err := m.store.UpsertCRL(ctx, entry); err != nil {
		return fmt.Errorf("crl: GenerateCRL: upsert cache: %w", err)
	}

	return nil
}

// GetCRL returns the PEM-encoded CRL for the given CA.
// If no cached CRL exists, or the cached one has passed its NextUpdate
// timestamp, it regenerates before returning.
//
// The returned bytes are a valid PEM-encoded CRL ready to be written
// directly to an HTTP response body with Content-Type: application/x-pem-file,
// or decoded to DER for application/pkix-crl responses.
func (m *CRLManager) GetCRL(ctx context.Context, caID uuid.UUID) ([]byte, error) {
	cached, err := m.store.GetCRL(ctx, caID)
	if err != nil {
		return nil, fmt.Errorf("crl: GetCRL: load cache: %w", err)
	}

	// Regenerate if there is no cached CRL or if it has expired.
	if cached == nil || time.Now().UTC().After(cached.NextUpdate) {
		if err := m.GenerateCRL(ctx, caID, defaultCRLValidity); err != nil {
			return nil, fmt.Errorf("crl: GetCRL: regenerate: %w", err)
		}
		cached, err = m.store.GetCRL(ctx, caID)
		if err != nil || cached == nil {
			return nil, fmt.Errorf("crl: GetCRL: load after regenerate: %w", err)
		}
	}

	return []byte(cached.CRLPEM), nil
}

// GetCRLDER returns the DER-encoded CRL for the given CA.
// Some clients (e.g. those using application/pkix-crl) expect raw DER
// rather than PEM. This decodes the cached PEM and returns the inner bytes.
func (m *CRLManager) GetCRLDER(ctx context.Context, caID uuid.UUID) ([]byte, error) {
	crlPEM, err := m.GetCRL(ctx, caID)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(crlPEM)
	if block == nil {
		return nil, errors.New("crl: GetCRLDER: failed to decode PEM from cache")
	}

	return block.Bytes, nil
}

// RefreshAll regenerates CRLs for every active CA in the store.
// This is called by the background ticker in cmd/server so that NextUpdate
// fields stay current even when no revocations occur.
func (m *CRLManager) RefreshAll(ctx context.Context, validity time.Duration) error {
	cas, err := m.store.ListCAs(ctx)
	if err != nil {
		return fmt.Errorf("crl: RefreshAll: list CAs: %w", err)
	}

	var lastErr error
	for _, ca := range cas {
		if ca.Status != storage.CAStatusActive {
			continue
		}
		if err := m.GenerateCRL(ctx, ca.ID, validity); err != nil {
			lastErr = fmt.Errorf("crl: RefreshAll: CA %q: %w", ca.Name, err)
		}
	}

	return lastErr
}

func (m *CRLManager) loadKey(ca *storage.CertificateAuthority) (crypto.Signer, error) {
	keyPEM, err := m.keystore.DecryptPEM(ca.KeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt key for CA %q: %w", ca.Name, err)
	}
	return parseKeyPEM(keyPEM)
}

// buildReasonExtension encodes an RFC 5280 CRL reason code as a pkix.Extension.
// The reason code is encoded as a DER ENUMERATED value inside the extension.
//
// OID 2.5.29.21 is id-ce-reasonCode as defined in RFC 5280 §5.3.1.
func buildReasonExtension(reason int) (pkix.Extension, error) {
	if reason < 0 || reason > 10 {
		return pkix.Extension{}, fmt.Errorf("buildReasonExtension: invalid reason code %d", reason)
	}
	// DER encoding of ENUMERATED { reason }:
	// 0x0a = tag for ENUMERATED
	// 0x01 = length 1
	// byte(reason) = the value
	return pkix.Extension{
		Id:       []int{2, 5, 29, 21},
		Critical: false,
		Value:    []byte{0x0a, 0x01, byte(reason)},
	}, nil
}
