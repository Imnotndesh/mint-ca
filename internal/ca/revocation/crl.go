package revocation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// CRLManager handles CRL generation, caching, and serving for all CAs.
// It is the only component that writes to the crl_cache table.
type CRLManager struct {
	store        storage.Store
	keystore     *mintcrypto.Keystore
	baseURL      string
	deltaEnabled bool
}

// NewCRLManager constructs a CRLManager.
func NewCRLManager(store storage.Store, keystore *mintcrypto.Keystore, baseURL string, deltaEnabled bool) *CRLManager {
	return &CRLManager{store: store, keystore: keystore, baseURL: strings.TrimRight(baseURL, "/"), deltaEnabled: deltaEnabled}
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

	if err := m.store.RevokeCertificate(ctx, certID, reason); err != nil {
		return fmt.Errorf("crl: RevokeAndRefresh: revoke in store: %w", err)
	}

	if m.deltaEnabled {
		base, err := m.store.GetCRL(ctx, cert.CAID)
		if err != nil {
			return fmt.Errorf("crl: RevokeAndRefresh: load base for delta: %w", err)
		}
		if base == nil {
			// No base yet — must generate one before a delta makes sense, then
			// also publish an initial (empty) delta so the artifact exists.
			if err := m.GenerateCRL(ctx, cert.CAID, defaultCRLValidity); err != nil {
				return fmt.Errorf("crl: RevokeAndRefresh: bootstrap base: %w", err)
			}
			if err := m.GenerateDeltaCRL(ctx, cert.CAID, defaultCRLValidity); err != nil {
				return fmt.Errorf("crl: RevokeAndRefresh: bootstrap delta: %w", err)
			}
			return nil
		}
		if err := m.GenerateDeltaCRL(ctx, cert.CAID, defaultCRLValidity); err != nil {
			return fmt.Errorf("crl: RevokeAndRefresh: regenerate delta: %w", err)
		}
		return nil
	}

	if err := m.GenerateCRL(ctx, cert.CAID, defaultCRLValidity); err != nil {
		return fmt.Errorf("crl: RevokeAndRefresh: regenerate CRL: %w", err)
	}
	return nil
}

// defaultCRLValidity is how long a freshly generated CRL is valid before
// clients should re-fetch it. One day is a common default; operators can
// tune this by calling GenerateCRL directly with a different duration.
const defaultCRLValidity = 24 * time.Hour

// GenerateCRL builds and signs a fresh base CRL for the given CA, then
// upserts it into crl_cache. It is safe to call concurrently — the database
// upsert is atomic. It is called:
//   - immediately after every revocation (via RevokeAndRefresh, in non-delta mode)
//   - on a background ticker for each active CA (so the NextUpdate field
//     stays fresh even when no revocations occur)
//
// The base CRL carries a persisted, per-CA monotonic CRL Number (RFC 5280
// §5.2.4) obtained from the crl_number_counters table, so delta CRLs can
// reference it via the deltaCRLIndicator extension. When delta CRLs are
// enabled and a public base URL is configured, the base CRL also advertises
// the delta endpoint in a Freshest CRL (id-ce-freshestCRL) extension so
// clients can discover it.
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

	// RFC 5280 §5.2.4 mandates a monotonically increasing CRL Number. Using a
	// persisted counter (not a timestamp) guarantees deltas can reference a
	// stable, retrievable base even across restarts.
	crlNumber, err := m.store.NextCRLNumber(ctx, caID)
	if err != nil {
		return fmt.Errorf("crl: GenerateCRL: next CRL number: %w", err)
	}

	template := &x509.RevocationList{
		RevokedCertificates: entries,
		Number:              big.NewInt(crlNumber),
		ThisUpdate:          now,
		NextUpdate:          nextUpdate,
		AuthorityKeyId:      caCert.SubjectKeyId,
	}

	// When deltas are enabled, advertise the delta endpoint in a Freshest CRL
	// extension so RFC 5280-compliant clients can discover and fetch deltas.
	if m.deltaEnabled && m.baseURL != "" {
		deltaURL := m.baseURL + "/v1/pki/ca/" + caID.String() + "/crl/delta.der"
		if err := appendFreshestCRLExtension(template, deltaURL); err != nil {
			return fmt.Errorf("crl: GenerateCRL: freshest CRL extension: %w", err)
		}
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
		CRLNumber:  crlNumber,
		ThisUpdate: now,
		NextUpdate: nextUpdate,
	}

	if err := m.store.UpsertCRL(ctx, entry); err != nil {
		return fmt.Errorf("crl: GenerateCRL: upsert cache: %w", err)
	}

	return nil
}

// GenerateDeltaCRL builds and signs a delta CRL for the CA relative to its
// most recently published base CRL. A delta carries only the certificates
// revoked AFTER the base CRL's ThisUpdate, plus a deltaCRLIndicator extension
// (RFC 5280 §5.2.4) whose value is the base CRL Number. The result is
// upserted into crl_delta_cache.
//
// If no base CRL exists yet, a delta cannot be anchored and a full base CRL
// is generated instead (callers such as RevokeAndRefresh already bootstrap
// the base before calling this).
func (m *CRLManager) GenerateDeltaCRL(ctx context.Context, caID uuid.UUID, validFor time.Duration) error {
	if validFor <= 0 {
		validFor = defaultCRLValidity
	}

	base, err := m.store.GetCRL(ctx, caID)
	if err != nil {
		return fmt.Errorf("crl: GenerateDeltaCRL: load base: %w", err)
	}
	if base == nil {
		// No base to anchor a delta against — fall back to a full base CRL.
		return m.GenerateCRL(ctx, caID, validFor)
	}

	caRecord, err := m.store.GetCA(ctx, caID)
	if err != nil {
		return fmt.Errorf("crl: GenerateDeltaCRL: load CA: %w", err)
	}
	if caRecord == nil {
		return fmt.Errorf("crl: GenerateDeltaCRL: CA %s not found", caID)
	}
	if caRecord.Status == storage.CAStatusRevoked {
		return fmt.Errorf("crl: GenerateDeltaCRL: CA %q is revoked — will not generate delta", caRecord.Name)
	}

	caCert, err := parseCertPEM([]byte(caRecord.CertPEM))
	if err != nil {
		return fmt.Errorf("crl: GenerateDeltaCRL: parse CA cert: %w", err)
	}

	caKey, err := m.loadKey(caRecord)
	if err != nil {
		return fmt.Errorf("crl: GenerateDeltaCRL: load CA key: %w", err)
	}

	// Only revocations that happened after the base CRL's ThisUpdate belong
	// in the delta. Anything already reflected in the base is excluded.
	revoked, err := m.store.ListRevokedByCASince(ctx, caID, base.ThisUpdate)
	if err != nil {
		return fmt.Errorf("crl: GenerateDeltaCRL: list revoked since base: %w", err)
	}

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
		if reason != 0 {
			ext, err := buildReasonExtension(reason)
			if err == nil {
				entry.Extensions = []pkix.Extension{ext}
			}
		}
		entries = append(entries, entry)
	}

	now := time.Now().UTC()
	crlNumber, err := m.store.NextCRLNumber(ctx, caID)
	if err != nil {
		return fmt.Errorf("crl: GenerateDeltaCRL: next CRL number: %w", err)
	}

	template := &x509.RevocationList{
		RevokedCertificates: entries,
		Number:              big.NewInt(crlNumber),
		ThisUpdate:          now,
		NextUpdate:          now.Add(validFor),
		AuthorityKeyId:      caCert.SubjectKeyId,
	}

	// RFC 5280 §5.2.4: the deltaCRLIndicator extension must be critical and
	// carry the base CRL Number as a DER INTEGER.
	baseNumber, err := asn1.Marshal(base.CRLNumber)
	if err != nil {
		return fmt.Errorf("crl: GenerateDeltaCRL: marshal base CRL number: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       idCeDeltaCRLIndicator,
		Critical: true,
		Value:    baseNumber,
	})

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, caCert, caKey)
	if err != nil {
		return fmt.Errorf("crl: GenerateDeltaCRL: create revocation list: %w", err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	delta := &storage.DeltaCRLCache{
		ID:            uuid.New(),
		CAID:          caID,
		CRLPEM:        string(crlPEM),
		CRLNumber:     crlNumber,
		BaseCRLNumber: base.CRLNumber,
		ThisUpdate:    now,
		NextUpdate:    now.Add(validFor),
	}

	if err := m.store.UpsertDeltaCRL(ctx, delta); err != nil {
		return fmt.Errorf("crl: GenerateDeltaCRL: upsert delta cache: %w", err)
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

// GetDeltaCRL returns the PEM-encoded delta CRL for the given CA. Like
// GetCRL, it lazily regenerates when no cached delta exists or when the
// cached one has expired. Delta regeneration first ensures a base CRL exists.
func (m *CRLManager) GetDeltaCRL(ctx context.Context, caID uuid.UUID) ([]byte, error) {
	base, err := m.store.GetCRL(ctx, caID)
	if err != nil {
		return nil, fmt.Errorf("crl: GetDeltaCRL: load base: %w", err)
	}
	if base == nil {
		// Anchor a base first so the delta has a CRL Number to reference.
		if err := m.GenerateCRL(ctx, caID, defaultCRLValidity); err != nil {
			return nil, fmt.Errorf("crl: GetDeltaCRL: bootstrap base: %w", err)
		}
		base, err = m.store.GetCRL(ctx, caID)
		if err != nil || base == nil {
			return nil, fmt.Errorf("crl: GetDeltaCRL: load base after bootstrap: %w", err)
		}
	}

	cached, err := m.store.GetDeltaCRL(ctx, caID)
	if err != nil {
		return nil, fmt.Errorf("crl: GetDeltaCRL: load cache: %w", err)
	}
	if cached == nil || time.Now().UTC().After(cached.NextUpdate) || cached.BaseCRLNumber != base.CRLNumber {
		if err := m.GenerateDeltaCRL(ctx, caID, defaultCRLValidity); err != nil {
			return nil, fmt.Errorf("crl: GetDeltaCRL: regenerate: %w", err)
		}
		cached, err = m.store.GetDeltaCRL(ctx, caID)
		if err != nil || cached == nil {
			return nil, fmt.Errorf("crl: GetDeltaCRL: load after regenerate: %w", err)
		}
	}

	return []byte(cached.CRLPEM), nil
}

// GetDeltaCRLDER returns the DER-encoded delta CRL for the given CA.
func (m *CRLManager) GetDeltaCRLDER(ctx context.Context, caID uuid.UUID) ([]byte, error) {
	deltaPEM, err := m.GetDeltaCRL(ctx, caID)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(deltaPEM)
	if block == nil {
		return nil, errors.New("crl: GetDeltaCRLDER: failed to decode PEM from cache")
	}

	return block.Bytes, nil
}

// RefreshAll regenerates CRLs for every active CA in the store.
// This is called by the background ticker in cmd/server so that NextUpdate
// fields stay current even when no revocations occur. When delta CRLs are
// enabled this also regenerates each CA's delta.
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
		if m.deltaEnabled {
			if err := m.GenerateDeltaCRL(ctx, ca.ID, validity); err != nil {
				lastErr = fmt.Errorf("crl: RefreshAll: CA %q delta: %w", ca.Name, err)
			}
		}
	}

	return lastErr
}

// RefreshDeltas regenerates the delta CRL for every active CA without
// touching the base CRLs. Used by the background worker between base refresh
// ticks when delta mode is enabled. Base CRLs are bootstrapped on demand if
// a CA has none yet.
func (m *CRLManager) RefreshDeltas(ctx context.Context, validity time.Duration) error {
	cas, err := m.store.ListCAs(ctx)
	if err != nil {
		return fmt.Errorf("crl: RefreshDeltas: list CAs: %w", err)
	}

	var lastErr error
	for _, ca := range cas {
		if ca.Status != storage.CAStatusActive {
			continue
		}
		if err := m.GenerateDeltaCRL(ctx, ca.ID, validity); err != nil {
			lastErr = fmt.Errorf("crl: RefreshDeltas: CA %q: %w", ca.Name, err)
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

// OIDs for the delta-CRL supporting extensions defined in RFC 5280.
var (
	// id-ce-deltaCRLIndicator (2.5.29.27).
	idCeDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}
	// id-ce-freshestCRL (2.5.29.46).
	idCeFreshestCRL = asn1.ObjectIdentifier{2, 5, 29, 46}
)

// appendFreshestCRLExtension adds an id-ce-freshestCRL extension to a base
// CRL template advertising the URL of its delta CRL. The extension value is
// an ASN.1 SEQUENCE OF DistributionPoint; a single URI distribution point is
// the common and interoperable form (RFC 5280 §4.2.1.15, §5.2.6).
func appendFreshestCRLExtension(template *x509.RevocationList, deltaURL string) error {
	// Build GeneralNames { uniformResourceIdentifier = deltaURL }.
	gnDer, err := asn1.Marshal([]asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(deltaURL)},
	})
	if err != nil {
		return fmt.Errorf("appendFreshestCRLExtension: marshal general names: %w", err)
	}
	dp := asn1DistributionPoint{
		DistributionPoint: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0, // distributionPoint
			IsCompound: true,
			Bytes:      gnDer,
		},
	}
	der, err := asn1.Marshal([]asn1DistributionPoint{dp})
	if err != nil {
		return fmt.Errorf("appendFreshestCRLExtension: marshal distribution point: %w", err)
	}

	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       idCeFreshestCRL,
		Critical: false,
		Value:    der,
	})
	return nil
}

// asn1DistributionPoint mirrors the DistributionPoint structure from
// RFC 5280 §4.2.1.13 using raw ASN.1 field placement.
type asn1DistributionPoint struct {
	DistributionPoint asn1.RawValue
	Reasons           asn1.RawValue `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue `asn1:"optional,tag:2"`
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
