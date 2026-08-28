package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// KeyAlgo identifies the algorithm and key size used for a generated keypair.
type KeyAlgo string
type NameConstraints = storage.NameConstraints

const (
	KeyAlgoECDSAP256 KeyAlgo = "ecdsa-p256"
	KeyAlgoECDSAP384 KeyAlgo = "ecdsa-p384"
	KeyAlgoRSA2048   KeyAlgo = "rsa-2048"
	KeyAlgoRSA4096   KeyAlgo = "rsa-4096"
	KeyAlgoEd25519   KeyAlgo = "ed25519"
)

// DefaultKeyAlgo is what the engine uses when no algorithm is specified.
const DefaultKeyAlgo = KeyAlgoECDSAP256

// Valid returns true if the algorithm string is one we support.
func (a KeyAlgo) Valid() bool {
	switch a {
	case KeyAlgoECDSAP256, KeyAlgoECDSAP384, KeyAlgoRSA2048, KeyAlgoRSA4096, KeyAlgoEd25519:
		return true
	}
	return false
}

// CreateRootCARequest contains everything needed to generate a self-signed root CA.
type CreateRootCARequest struct {
	// Name is the unique human-readable identifier stored in the database.
	// It is not the X.509 Common Name — it is mint-ca's internal label.
	Name         string
	CommonName   string
	Organization string
	Country      string
	State        string
	Locality     string

	// KeyAlgo is the algorithm to use for the CA's private key.
	// Defaults to KeyAlgoECDSAP256 if empty.
	KeyAlgo KeyAlgo

	// TTLDays is how long the root CA certificate is valid.
	// A root CA typically has a long lifetime: 10–20 years.
	TTLDays int
}

func (r *CreateRootCARequest) setDefaults() {
	if r.KeyAlgo == "" {
		r.KeyAlgo = DefaultKeyAlgo
	}
	if r.TTLDays <= 0 {
		r.TTLDays = 3650 // 10 years
	}
}

func (r *CreateRootCARequest) validate() error {
	if r.Name == "" {
		return errors.New("ca: CreateRootCARequest: Name is required")
	}
	if r.CommonName == "" {
		return errors.New("ca: CreateRootCARequest: CommonName is required")
	}
	if !r.KeyAlgo.Valid() {
		return fmt.Errorf("ca: CreateRootCARequest: unsupported KeyAlgo %q", r.KeyAlgo)
	}
	if r.TTLDays <= 0 {
		return errors.New("ca: CreateRootCARequest: TTLDays must be positive")
	}
	return nil
}

// CreateIntermediateCARequest contains everything needed to generate an
// intermediate (child) CA signed by an existing CA in the store.
// The parent can itself be an intermediate — depth is not limited.
type CreateIntermediateCARequest struct {
	ParentCAID uuid.UUID

	Name         string
	CommonName   string
	Organization string
	Country      string
	State        string
	Locality     string

	KeyAlgo KeyAlgo

	TTLDays int

	MaxPathLen int

	NameConstraints *NameConstraints
}

func (r *CreateIntermediateCARequest) setDefaults() {
	if r.KeyAlgo == "" {
		r.KeyAlgo = DefaultKeyAlgo
	}
	if r.TTLDays <= 0 {
		r.TTLDays = 1825 // 5 years
	}
}

// RekeyCARequest contains the parameters for rotating a CA's signing key
// while preserving its identity/hierarchy position. The result is a NEW,
// active CA row (new ID, new key, new SKI) with the same subject, signed by
// the same issuer (or self for a root). The previous CA row is marked
// superseded: it no longer signs new certificates but already-issued leafs
// remain valid and keep their original CAID.
type RekeyCARequest struct {
	// CAID is the existing CA to re-key.
	CAID uuid.UUID

	// KeyAlgo for the new key. Defaults to the re-keyed CA's current algo if
	// empty.
	KeyAlgo KeyAlgo

	// TTLDays for the new CA certificate. Defaults to the re-keyed CA's
	// remaining lifetime if <= 0.
	TTLDays int
}

func (r *RekeyCARequest) validate() error {
	if r.CAID == uuid.Nil {
		return errors.New("ca: RekeyCARequest: CAID is required")
	}
	if r.KeyAlgo != "" && !r.KeyAlgo.Valid() {
		return fmt.Errorf("ca: RekeyCARequest: unsupported KeyAlgo %q", r.KeyAlgo)
	}
	return nil
}

// CrossSignCARequest contains the parameters for issuing a cross-signed
// certificate: a second, parallel certificate for an existing CA's public key
// and subject, signed by a DIFFERENT CA (the signer). This builds a trust
// bridge during root/intermediate transitions — e.g. an old root cross-signs
// a new root so clients that trust the old root can validate the new one's
// chain. The target CA's keypair is shared, not regenerated.
type CrossSignCARequest struct {
	// SigningCAID is the CA whose private key signs the cross certificate.
	SigningCAID uuid.UUID

	// TargetCAID is the existing CA whose public key+subject get a second
	// certificate from the signer.
	TargetCAID uuid.UUID

	// TTLDays for the cross certificate. Cannot exceed the signer or target
	// CA certificate's NotAfter.
	TTLDays int
}

func (r *CrossSignCARequest) validate() error {
	if r.SigningCAID == uuid.Nil {
		return errors.New("ca: CrossSignCARequest: SigningCAID is required")
	}
	if r.TargetCAID == uuid.Nil {
		return errors.New("ca: CrossSignCARequest: TargetCAID is required")
	}
	if r.SigningCAID == r.TargetCAID {
		return errors.New("ca: CrossSignCARequest: signing CA and target CA must differ (a CA cannot cross-sign itself)")
	}
	return nil
}

// validateNameConstraints checks that every entry is well-formed per
// RFC 5280 §4.2.1.10: DNS entries are plain suffixes (no wildcards), IP
// entries are valid CIDR, email entries are either a bare domain or a
// full "user@domain" address.
func validateNameConstraints(nc *NameConstraints) error {
	if nc == nil {
		return nil
	}

	checkDNS := func(label string, domains []string) error {
		for _, d := range domains {
			if d == "" {
				return fmt.Errorf("name constraints: %s: empty DNS domain", label)
			}
			if strings.Contains(d, "*") {
				return fmt.Errorf("name constraints: %s: %q must be a plain DNS suffix — wildcards are forbidden by RFC 5280", label, d)
			}
		}
		return nil
	}
	if err := checkDNS("permitted_dns_domains", nc.PermittedDNSDomains); err != nil {
		return err
	}
	if err := checkDNS("excluded_dns_domains", nc.ExcludedDNSDomains); err != nil {
		return err
	}

	checkCIDR := func(label string, ranges []string) error {
		for _, r := range ranges {
			if _, _, err := net.ParseCIDR(r); err != nil {
				return fmt.Errorf("name constraints: %s: %q is not a valid CIDR range: %w", label, r, err)
			}
		}
		return nil
	}
	if err := checkCIDR("permitted_ip_ranges", nc.PermittedIPRanges); err != nil {
		return err
	}
	if err := checkCIDR("excluded_ip_ranges", nc.ExcludedIPRanges); err != nil {
		return err
	}

	checkEmail := func(label string, domains []string) error {
		for _, d := range domains {
			if d == "" {
				return fmt.Errorf("name constraints: %s: empty email domain", label)
			}
			at := strings.LastIndex(d, "@")
			domainPart := d
			if at >= 0 {
				domainPart = d[at+1:]
			}
			if domainPart == "" {
				return fmt.Errorf("name constraints: %s: %q has no domain part", label, d)
			}
			if strings.Contains(d, "*") {
				return fmt.Errorf("name constraints: %s: %q must not contain wildcards", label, d)
			}
		}
		return nil
	}
	if err := checkEmail("permitted_email_domains", nc.PermittedEmailDomains); err != nil {
		return err
	}
	if err := checkEmail("excluded_email_domains", nc.ExcludedEmailDomains); err != nil {
		return err
	}

	return nil
}

// applyNameConstraintsToTemplate translates the storage-shape NameConstraints
// into the stdlib x509.Certificate fields, parsing CIDR ranges into
// *net.IPNet. Callers must have already validated nc via
// validateNameConstraints. RFC 5280 recommends the DNS constraint be
// critical; CA/Browser Forum baseline requirements mandate it — mint-ca
// hardcodes this to true and does not expose it as configurable.
func applyNameConstraintsToTemplate(template *x509.Certificate, nc *NameConstraints) error {
	if nc == nil {
		return nil
	}

	template.PermittedDNSDomains = append([]string(nil), nc.PermittedDNSDomains...)
	template.ExcludedDNSDomains = append([]string(nil), nc.ExcludedDNSDomains...)
	template.PermittedEmailAddresses = append([]string(nil), nc.PermittedEmailDomains...)
	template.ExcludedEmailAddresses = append([]string(nil), nc.ExcludedEmailDomains...)

	for _, cidr := range nc.PermittedIPRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("applyNameConstraintsToTemplate: permitted IP range %q: %w", cidr, err)
		}
		template.PermittedIPRanges = append(template.PermittedIPRanges, ipnet)
	}
	for _, cidr := range nc.ExcludedIPRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("applyNameConstraintsToTemplate: excluded IP range %q: %w", cidr, err)
		}
		template.ExcludedIPRanges = append(template.ExcludedIPRanges, ipnet)
	}
	template.PermittedDNSDomainsCritical = true

	return nil
}
func (r *CreateIntermediateCARequest) validate() error {
	if r.ParentCAID == uuid.Nil {
		return errors.New("ca: CreateIntermediateCARequest: ParentCAID is required")
	}
	if r.Name == "" {
		return errors.New("ca: CreateIntermediateCARequest: Name is required")
	}
	if r.CommonName == "" {
		return errors.New("ca: CreateIntermediateCARequest: CommonName is required")
	}
	if !r.KeyAlgo.Valid() {
		return fmt.Errorf("ca: CreateIntermediateCARequest: unsupported KeyAlgo %q", r.KeyAlgo)
	}
	if r.TTLDays <= 0 {
		return errors.New("ca: CreateIntermediateCARequest: TTLDays must be positive")
	}
	if err := validateNameConstraints(r.NameConstraints); err != nil {
		return fmt.Errorf("ca: CreateIntermediateCARequest: %w", err)
	}
	return nil
}

// idCeCertificatePolicies is the OID for the certificatePolicies extension
// (RFC 5280 §4.2.1.4): 2.5.29.32.
var idCeCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}

// idQtCPS is the policyQualifierId for a CPS pointer qualifier (RFC 5280
// §4.2.1.4): 1.3.6.1.5.5.7.2.1.
var idQtCPS = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}

// asn1PolicyQualifierInfo and asn1PolicyInformation mirror the RFC 5280
// §4.2.1.4 ASN.1 structures. The stdlib's x509.Certificate.PolicyIdentifiers
// field only supports bare OIDs with no qualifier support, so we hand-roll
// the extension via ExtraExtensions when a CPS URI is requested — same
// pattern already used elsewhere in this file for AIA/CRLDP-style extras.
type asn1PolicyQualifierInfo struct {
	PolicyQualifierID asn1.ObjectIdentifier
	Qualifier         asn1.RawValue
}

type asn1PolicyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	Qualifiers       []asn1PolicyQualifierInfo `asn1:"optional"`
}

// validateCertPolicyOIDs checks that every OID string parses as a valid
// dotted-decimal ASN.1 object identifier.
func validateCertPolicyOIDs(oids []string) error {
	for _, s := range oids {
		if s == "" {
			return fmt.Errorf("certificate policies: empty OID string")
		}
		parts := strings.Split(s, ".")
		if len(parts) < 2 {
			return fmt.Errorf("certificate policies: %q is not a valid dotted-decimal OID", s)
		}
		for _, p := range parts {
			if p == "" {
				return fmt.Errorf("certificate policies: %q is not a valid dotted-decimal OID", s)
			}
			for _, c := range p {
				if c < '0' || c > '9' {
					return fmt.Errorf("certificate policies: %q is not a valid dotted-decimal OID", s)
				}
			}
		}
	}
	return nil
}

// parseOIDString parses a dotted-decimal OID string into an
// asn1.ObjectIdentifier. Callers must have already validated the string via
// validateCertPolicyOIDs.
func parseOIDString(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("parseOIDString: %q: %w", s, err)
		}
		oid[i] = n
	}
	return oid, nil
}

// applyCertPoliciesToTemplate embeds an RFC 5280 §4.2.1.4 Certificate
// Policies extension via ExtraExtensions when oids is non-empty. When
// cpsURI is non-empty, every policyInformation entry gets a CPS-pointer
// qualifier; otherwise OIDs are emitted bare — the default, and the
// recommended mode for a private/internal CA per plan discussion.
func applyCertPoliciesToTemplate(template *x509.Certificate, oids []string, cpsURI string) error {
	if len(oids) == 0 {
		return nil
	}

	infos := make([]asn1PolicyInformation, 0, len(oids))
	for _, s := range oids {
		oid, err := parseOIDString(s)
		if err != nil {
			return fmt.Errorf("applyCertPoliciesToTemplate: %w", err)
		}
		info := asn1PolicyInformation{PolicyIdentifier: oid}
		if cpsURI != "" {
			qualifierBytes, err := asn1.Marshal(cpsURI)
			if err != nil {
				return fmt.Errorf("applyCertPoliciesToTemplate: marshal CPS URI: %w", err)
			}
			info.Qualifiers = []asn1PolicyQualifierInfo{
				{
					PolicyQualifierID: idQtCPS,
					Qualifier:         asn1.RawValue{FullBytes: qualifierBytes},
				},
			}
		}
		infos = append(infos, info)
	}

	der, err := asn1.Marshal(infos)
	if err != nil {
		return fmt.Errorf("applyCertPoliciesToTemplate: marshal certificatePolicies: %w", err)
	}

	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       idCeCertificatePolicies,
		Critical: false,
		Value:    der,
	})
	return nil
}

// IssueCertRequest describes a leaf certificate that mint-ca should generate
// the keypair for and sign. The private key is returned to the caller once and
// never stored.
type IssueCertRequest struct {
	CAID             uuid.UUID
	ProvisionerID    uuid.UUID
	Requester        string
	CommonName       string
	SANsDNS          []string
	SANsIP           []net.IP
	SANsEmail        []string
	KeyUsage         x509.KeyUsage
	ExtKeyUsage      []x509.ExtKeyUsage
	TTLSeconds       int64
	KeyAlgo          KeyAlgo
	Metadata         storage.JSON
	CertPolicyOIDs   []string
	CertPolicyCPSURI string
}

func (r *IssueCertRequest) setDefaults() {
	if r.KeyAlgo == "" {
		r.KeyAlgo = DefaultKeyAlgo
	}
	if r.TTLSeconds <= 0 {
		r.TTLSeconds = 86400
	}
	if r.KeyUsage == 0 && len(r.ExtKeyUsage) == 0 {
		r.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		r.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
	}
}

func (r *IssueCertRequest) validate() error {
	if r.CAID == uuid.Nil {
		return errors.New("ca: IssueCertRequest: CAID is required")
	}
	if r.ProvisionerID == uuid.Nil {
		return errors.New("ca: IssueCertRequest: ProvisionerID is required")
	}
	if r.CommonName == "" {
		return errors.New("ca: IssueCertRequest: CommonName is required")
	}
	if !r.KeyAlgo.Valid() {
		return fmt.Errorf("ca: IssueCertRequest: unsupported KeyAlgo %q", r.KeyAlgo)
	}
	if r.TTLSeconds <= 0 {
		return errors.New("ca: IssueCertRequest: TTLSeconds must be positive")
	}
	if err := validateCertPolicyOIDs(r.CertPolicyOIDs); err != nil {
		return fmt.Errorf("ca: IssueCertRequest: %w", err)
	}
	return nil
}

// SignCSRRequest asks the engine to sign an externally-provided CSR.
// The caller already holds the private key; we only issue the certificate.
type SignCSRRequest struct {
	CAID             uuid.UUID
	ProvisionerID    uuid.UUID
	Requester        string
	CSRPEM           []byte
	TTLSeconds       int64
	Metadata         storage.JSON
	CertPolicyOIDs   []string
	CertPolicyCPSURI string
}

func (r *SignCSRRequest) setDefaults() {
	if r.TTLSeconds <= 0 {
		r.TTLSeconds = 86400
	}
}

func (r *SignCSRRequest) validate() error {
	if r.CAID == uuid.Nil {
		return errors.New("ca: SignCSRRequest: CAID is required")
	}
	if r.ProvisionerID == uuid.Nil {
		return errors.New("ca: SignCSRRequest: ProvisionerID is required")
	}
	if len(r.CSRPEM) == 0 {
		return errors.New("ca: SignCSRRequest: CSRPEM is required")
	}
	if err := validateCertPolicyOIDs(r.CertPolicyOIDs); err != nil {
		return fmt.Errorf("ca: SignCSRRequest: %w", err)
	}
	return nil
}

// IssuedCertificate is returned after a successful leaf certificate issuance.
type IssuedCertificate struct {
	// Record is the database record created for this certificate.
	Record *storage.Certificate
	// CertPEM is the PEM-encoded certificate (leaf only).
	CertPEM []byte
	// KeyPEM is the PEM-encoded private key. This is only populated when
	KeyPEM []byte
	// ChainPEM is the full certificate chain: leaf + all intermediates + root.
	ChainPEM []byte
}

// Engine is the core CA signing engine. It is the only component in mint-ca that performs cryptographic operations on CA private keys.
type Engine struct {
	store    storage.Store
	keystore *mintcrypto.Keystore
	baseUrl  string
}

// NewEngine constructs an Engine. Both arguments are required.
func NewEngine(store storage.Store, keystore *mintcrypto.Keystore, baseUrl string) *Engine {
	return &Engine{store: store, keystore: keystore, baseUrl: baseUrl}
}
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("subjectKeyID: marshal public key: %w", err)
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("subjectKeyID: parse SubjectPublicKeyInfo: %w", err)
	}

	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:], nil
}

// ensureSKI returns cert.SubjectKeyId if already populated, or computes it
// on the fly from cert.PublicKey otherwise. This makes AKI chaining work
// correctly even against CA certificates that were issued before explicit
// SKI/AKI support existed.
func ensureSKI(cert *x509.Certificate) ([]byte, error) {
	if len(cert.SubjectKeyId) > 0 {
		return cert.SubjectKeyId, nil
	}
	return subjectKeyID(cert.PublicKey)
}

// CreateRootCA generates a self-signed root CA and persists it to the store.
func (e *Engine) CreateRootCA(ctx context.Context, req CreateRootCARequest) (*storage.CertificateAuthority, error) {
	req.setDefaults()
	if err := req.validate(); err != nil {
		return nil, err
	}

	// Check name uniqueness before doing any crypto work.
	existing, err := e.store.GetCAByName(ctx, req.Name)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateRootCA: check name: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("ca: CreateRootCA: a CA named %q already exists", req.Name)
	}

	privKey, privKeyPEM, err := generateKey(req.KeyAlgo)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateRootCA: generate key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: CreateRootCA: generate serial: %w", err)
	}

	now := time.Now().UTC()
	notAfter := now.AddDate(0, 0, req.TTLDays)

	subject := pkix.Name{
		CommonName:   req.CommonName,
		Organization: nonEmpty(req.Organization),
		Country:      nonEmpty(req.Country),
		Province:     nonEmpty(req.State),
		Locality:     nonEmpty(req.Locality),
	}
	ski, err := subjectKeyID(pubkey(privKey))
	if err != nil {
		return nil, fmt.Errorf("ca: CreateRootCA: compute subject key id: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            -1,
		MaxPathLenZero:        false,
		SubjectKeyId:          ski,
		AuthorityKeyId:        ski,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubkey(privKey), privKey)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateRootCA: sign certificate: %w", err)
	}
	certPEM := encodeCertPEM(certDER)

	encKey, err := e.keystore.EncryptPEM(privKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateRootCA: encrypt key: %w", err)
	}

	record := &storage.CertificateAuthority{
		ID:          uuid.New(),
		LogicalCAID: nil, // set below to self
		ParentID:    nil, // root has no parent
		Name:        req.Name,
		Type:        storage.CATypeRoot,
		Status:      storage.CAStatusActive,
		CertPEM:     string(certPEM),
		KeyEnc:      encKey,
		KeyAlgo:     string(req.KeyAlgo),
		NotBefore:   now,
		NotAfter:    notAfter,
		CreatedAt:   now,
	}
	record.LogicalCAID = &record.ID

	if err := e.store.CreateCA(ctx, record); err != nil {
		return nil, fmt.Errorf("ca: CreateRootCA: store: %w", err)
	}

	return record, nil
}

// CreateIntermediateCA generates a new CA signed by an existing parent CA.
func (e *Engine) CreateIntermediateCA(ctx context.Context, req CreateIntermediateCARequest) (*storage.CertificateAuthority, error) {
	req.setDefaults()
	if err := req.validate(); err != nil {
		return nil, err
	}

	// Load and validate the parent CA.
	parentRecord, err := e.store.GetCA(ctx, req.ParentCAID)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: load parent: %w", err)
	}
	if parentRecord == nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: parent CA %s not found", req.ParentCAID)
	}
	if parentRecord.Status != storage.CAStatusActive {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: parent CA %q is not active (status: %s)", parentRecord.Name, parentRecord.Status)
	}

	// Name uniqueness.
	existing, err := e.store.GetCAByName(ctx, req.Name)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: check name: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: a CA named %q already exists", req.Name)
	}

	parentCert, err := parseCertPEM([]byte(parentRecord.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: parse parent cert: %w", err)
	}

	parentKey, err := e.loadKey(parentRecord)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: load parent key: %w", err)
	}

	privKey, privKeyPEM, err := generateKey(req.KeyAlgo)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: generate key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: generate serial: %w", err)
	}

	now := time.Now().UTC()
	notAfter := now.AddDate(0, 0, req.TTLDays)

	if notAfter.After(parentCert.NotAfter) {
		notAfter = parentCert.NotAfter
	}

	subject := pkix.Name{
		CommonName:   req.CommonName,
		Organization: nonEmpty(req.Organization),
		Country:      nonEmpty(req.Country),
		Province:     nonEmpty(req.State),
		Locality:     nonEmpty(req.Locality),
	}

	maxPathLen := req.MaxPathLen
	maxPathLenZero := false
	if maxPathLen == 0 {
		maxPathLenZero = true
	}
	ski, err := subjectKeyID(pubkey(privKey))
	if err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: compute subject key id: %w", err)
	}
	// Parent may predate explicit SKI support — fall back to recomputing it
	aki, err := ensureSKI(parentCert)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: compute parent authority key id: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLenZero,
		SubjectKeyId:          ski,
		AuthorityKeyId:        aki,
		CRLDistributionPoints: []string{
			fmt.Sprintf("%s/v1/pki/ca/%s/crl", e.baseUrl, req.ParentCAID),
		},
		OCSPServer: []string{
			fmt.Sprintf("%s/v1/pki/ocsp", e.baseUrl),
		},
		IssuingCertificateURL: []string{
			fmt.Sprintf("%s/v1/pki/ca/%s/crt", e.baseUrl, req.ParentCAID),
		},
	}

	if err := applyNameConstraintsToTemplate(template, req.NameConstraints); err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: apply name constraints: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parentCert, pubkey(privKey), parentKey)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: sign certificate: %w", err)
	}
	certPEM := encodeCertPEM(certDER)

	encKey, err := e.keystore.EncryptPEM(privKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: encrypt key: %w", err)
	}

	parentID := req.ParentCAID
	record := &storage.CertificateAuthority{
		ID:              uuid.New(),
		LogicalCAID:     nil, // set below to self
		ParentID:        &parentID,
		Name:            req.Name,
		Type:            storage.CATypeIntermediate,
		Status:          storage.CAStatusActive,
		CertPEM:         string(certPEM),
		KeyEnc:          encKey,
		KeyAlgo:         string(req.KeyAlgo),
		NameConstraints: req.NameConstraints,
		NotBefore:       now,
		NotAfter:        notAfter,
		CreatedAt:       now,
	}
	record.LogicalCAID = &record.ID

	if err := e.store.CreateCA(ctx, record); err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: store: %w", err)
	}

	return record, nil
}

// RekeyCA rotates a CA's signing key while keeping its identity and hierarchy
// position. It creates a NEW active CA row: new ID, new key, new SubjectKeyId,
// same Subject — signed by the same issuer (or self for a root), with the same
// name constraints. The original CA row is marked superseded so it stops
// signing new certificates but its already-issued leafs stay valid (they keep
// their immutable CAID; the old row is never revoked or destroyed).
func (e *Engine) RekeyCA(ctx context.Context, req RekeyCARequest) (*storage.CertificateAuthority, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}

	old, err := e.store.GetCA(ctx, req.CAID)
	if err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: load CA: %w", err)
	}
	if old == nil {
		return nil, fmt.Errorf("ca: RekeyCA: CA %s not found", req.CAID)
	}
	if old.Status != storage.CAStatusActive {
		return nil, fmt.Errorf("ca: RekeyCA: CA %q is not active (status: %s)", old.Name, old.Status)
	}

	algo := req.KeyAlgo
	if algo == "" {
		algo = KeyAlgo(old.KeyAlgo)
	}
	if algo == "" {
		algo = DefaultKeyAlgo
	}

	ttlDays := req.TTLDays
	if ttlDays <= 0 {
		ttlDays = int(time.Until(old.NotAfter).Hours() / 24)
		if ttlDays <= 0 {
			ttlDays = 365
		}
	}

	oldCert, err := parseCertPEM([]byte(old.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: parse old cert: %w", err)
	}

	// Determine the issuer: the CA's parent for an intermediate, itself for a root.
	issuerCAID := old.ID
	if old.ParentID != nil {
		issuerCAID = *old.ParentID
	}
	issuerRecord, issuerCert, issuerKey, err := e.loadIssuer(ctx, issuerCAID)
	if err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: load issuer: %w", err)
	}
	_ = issuerRecord
	// For self-signed root re-key, the new key signs its own cert, so the issuer
	// is the NEW certificate itself (we generate it below). For an intermediate,
	// the parent signs.

	privKey, privKeyPEM, err := generateKey(algo)
	if err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: generate key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: generate serial: %w", err)
	}

	now := time.Now().UTC()
	notAfter := now.AddDate(0, 0, ttlDays)
	if notAfter.After(oldCert.NotAfter) {
		notAfter = oldCert.NotAfter
	}
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}

	ski, err := subjectKeyID(pubkey(privKey))
	if err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: compute subject key id: %w", err)
	}
	aki, err := ensureSKI(issuerCert)
	if err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: compute issuer authority key id: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               oldCert.Subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            oldCert.MaxPathLen,
		MaxPathLenZero:        oldCert.MaxPathLenZero,
		SubjectKeyId:          ski,
		AuthorityKeyId:        aki,
		CRLDistributionPoints: oldCert.CRLDistributionPoints,
		OCSPServer:            oldCert.OCSPServer,
		IssuingCertificateURL: oldCert.IssuingCertificateURL,
	}

	// Sign with the issuer's key (for a root, issuerCert/key are the OLD self-signed
	// cert — but the new root should be self-signed by its OWN new key, so override
	// the signing authority for the root case).
	var signerCert *x509.Certificate
	var signerKey crypto.Signer
	if old.ParentID == nil {
		// Root: the new root cert is self-signed by the new key.
		signerCert = template
		signerKey = privKey
		template.AuthorityKeyId = ski
	} else {
		signerCert = issuerCert
		signerKey = issuerKey
	}

	if err := applyNameConstraintsToTemplate(template, old.NameConstraints); err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: apply name constraints: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, signerCert, pubkey(privKey), signerKey)
	if err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: sign certificate: %w", err)
	}
	certPEM := encodeCertPEM(certDER)

	encKey, err := e.keystore.EncryptPEM(privKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: encrypt key: %w", err)
	}

	// The re-keyed CA belongs to the same LOGICAL CA as its predecessor, so
	// provisioners pointed at that logical CA keep resolving to the new row.
	// Fresh CAs use own ID; prefer an existing logical id if present.
	newRecord := &storage.CertificateAuthority{
		ID:              uuid.New(),
		LogicalCAID:     old.LogicalCAID,
		ParentID:        old.ParentID,
		Name:            old.Name,
		Type:            old.Type,
		Status:          storage.CAStatusActive,
		CertPEM:         string(certPEM),
		KeyEnc:          encKey,
		KeyAlgo:         string(algo),
		NameConstraints: old.NameConstraints,
		NotBefore:       now,
		NotAfter:        notAfter,
		CreatedAt:       now,
	}
	if newRecord.LogicalCAID == nil {
		newRecord.LogicalCAID = &old.ID
	}

	// Mark the old CA superseded first.
	if err := e.store.UpdateCAStatus(ctx, old.ID, storage.CAStatusSuperseded); err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: supersede old CA: %w", err)
	}
	if err := e.store.CreateCA(ctx, newRecord); err != nil {
		return nil, fmt.Errorf("ca: RekeyCA: store: %w", err)
	}

	return newRecord, nil
}

// CrossSignCA issues a cross-signed certificate for an existing CA's public key
// and subject, signed by a different CA. The target's keypair is reused — this
// is a second, parallel certificate from another issuer, used to build trust
// bridges during CA transitions (e.g. an old root cross-signing a new root so
// clients that trust the old root can validate the new root). The result is
// stored in ca_cross_certs, keyed by (target, signer).
func (e *Engine) CrossSignCA(ctx context.Context, req CrossSignCARequest) (*storage.CrossCert, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}

	signerRecord, signerCert, signerKey, err := e.loadIssuer(ctx, req.SigningCAID)
	if err != nil {
		return nil, fmt.Errorf("ca: CrossSignCA: load signer: %w", err)
	}
	_ = signerRecord

	targetRecord, err := e.store.GetCA(ctx, req.TargetCAID)
	if err != nil {
		return nil, fmt.Errorf("ca: CrossSignCA: load target: %w", err)
	}
	if targetRecord == nil {
		return nil, fmt.Errorf("ca: CrossSignCA: target CA %s not found", req.TargetCAID)
	}
	if targetRecord.Status == storage.CAStatusRevoked {
		return nil, fmt.Errorf("ca: CrossSignCA: target CA %q is revoked — refusing to cross-sign a compromised CA", targetRecord.Name)
	}

	targetCert, err := parseCertPEM([]byte(targetRecord.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("ca: CrossSignCA: parse target cert: %w", err)
	}

	now := time.Now().UTC()
	notAfter := now.AddDate(0, 0, req.TTLDays)
	if notAfter.After(signerCert.NotAfter) {
		notAfter = signerCert.NotAfter
	}
	if notAfter.After(targetCert.NotAfter) {
		notAfter = targetCert.NotAfter
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: CrossSignCA: generate serial: %w", err)
	}
	aki, err := ensureSKI(signerCert)
	if err != nil {
		return nil, fmt.Errorf("ca: CrossSignCA: compute signer aki: %w", err)
	}

	// The cross cert reuses the TARGET's public key and subject; only the SKI
	// stays the target's (it identifies the subject key), the AKI becomes the
	// signer's.
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               targetCert.Subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            targetCert.MaxPathLen,
		MaxPathLenZero:        targetCert.MaxPathLenZero,
		SubjectKeyId:          targetCert.SubjectKeyId,
		AuthorityKeyId:        aki,
		CRLDistributionPoints: signerCert.CRLDistributionPoints,
		OCSPServer:            signerCert.OCSPServer,
		IssuingCertificateURL: []string{
			fmt.Sprintf("%s/v1/pki/ca/%s/crt", e.baseUrl, req.SigningCAID),
		},
	}

	if err := applyNameConstraintsToTemplate(template, targetRecord.NameConstraints); err != nil {
		return nil, fmt.Errorf("ca: CrossSignCA: apply name constraints: %w", err)
	}

	// Sign with the signer's key over the TARGET's public key.
	certDER, err := x509.CreateCertificate(rand.Reader, template, signerCert, pubkeyForCert(targetCert), signerKey)
	if err != nil {
		return nil, fmt.Errorf("ca: CrossSignCA: sign certificate: %w", err)
	}
	certPEM := encodeCertPEM(certDER)

	cc := &storage.CrossCert{
		ID:          uuid.New(),
		TargetCAID:  req.TargetCAID,
		SigningCAID: req.SigningCAID,
		CertPEM:     string(certPEM),
		Serial:      serial.String(),
		NotBefore:   now,
		NotAfter:    notAfter,
		CreatedAt:   now,
	}

	if err := e.store.CreateCrossCert(ctx, cc); err != nil {
		return nil, fmt.Errorf("ca: CrossSignCA: store: %w", err)
	}
	return cc, nil
}

// pubkeyForCert extracts the public key from a parsed certificate as a
// crypto.PublicKey, panicking-safe helper for cross-sign reuse.
func pubkeyForCert(c *x509.Certificate) interface{} {
	return c.PublicKey
}

// IssueCert generates a keypair, signs a leaf certificate with the specified CA,
func (e *Engine) IssueCert(ctx context.Context, req IssueCertRequest) (*IssuedCertificate, error) {
	req.setDefaults()
	if err := req.validate(); err != nil {
		return nil, err
	}

	issuerRecord, issuerCert, issuerKey, err := e.loadIssuer(ctx, req.CAID)
	if err != nil {
		return nil, fmt.Errorf("ca: IssueCert: %w", err)
	}

	leafKey, leafKeyPEM, err := generateKey(req.KeyAlgo)
	if err != nil {
		return nil, fmt.Errorf("ca: IssueCert: generate leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: IssueCert: generate serial: %w", err)
	}

	now := time.Now().UTC()
	notAfter := now.Add(time.Duration(req.TTLSeconds) * time.Second)
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}

	ski, err := subjectKeyID(pubkey(leafKey))
	if err != nil {
		return nil, fmt.Errorf("ca: IssueCert: compute subject key id: %w", err)
	}
	// Issuer may predate explicit SKI support — fall back to recomputing it.
	aki, err := ensureSKI(issuerCert)
	if err != nil {
		return nil, fmt.Errorf("ca: IssueCert: compute authority key id: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: req.CommonName,
		},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              req.KeyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
		DNSNames:              req.SANsDNS,
		IPAddresses:           req.SANsIP,
		EmailAddresses:        req.SANsEmail,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
		AuthorityKeyId:        aki,
		CRLDistributionPoints: []string{
			fmt.Sprintf("%s/v1/pki/ca/%s/crl", e.baseUrl, req.CAID),
		},
		OCSPServer: []string{
			fmt.Sprintf("%s/v1/pki/ocsp", e.baseUrl),
		},
		IssuingCertificateURL: []string{
			fmt.Sprintf("%s/v1/pki/ca/%s/crt", e.baseUrl, req.CAID),
		},
	}

	if err := applyCertPoliciesToTemplate(template, req.CertPolicyOIDs, req.CertPolicyCPSURI); err != nil {
		return nil, fmt.Errorf("ca: IssueCert: %w", err)
	}

	// Enforce every ancestor CA's name constraints before signing, exactly as
	// SignCSR does. x509.CreateCertificate does NOT enforce name constraints —
	// only x509.Verify does at validation time — so without this check a caller
	// could mint a spec-non-compliant certificate that relies on a validator
	// (correctly) refusing it. Failing here gives an immediate, actionable error.
	constraintsChain, err := e.collectNameConstraints(ctx, issuerRecord)
	if err != nil {
		return nil, fmt.Errorf("ca: IssueCert: collect name constraints: %w", err)
	}
	if err := enforceNameConstraints(constraintsChain, req.SANsDNS, req.SANsIP, req.SANsEmail); err != nil {
		return nil, fmt.Errorf("ca: IssueCert: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, pubkey(leafKey), issuerKey)
	if err != nil {
		return nil, fmt.Errorf("ca: IssueCert: sign certificate: %w", err)
	}

	certPEM := encodeCertPEM(certDER)

	chainPEM, err := e.buildChain(ctx, issuerRecord, certPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: IssueCert: build chain: %w", err)
	}
	ipStrings := make([]string, len(req.SANsIP))
	for i, ip := range req.SANsIP {
		ipStrings[i] = ip.String()
	}
	record := &storage.Certificate{
		ID:            uuid.New(),
		CAID:          req.CAID,
		Serial:        serial.String(),
		SubjectCN:     req.CommonName,
		SANs:          storage.SANs{DNS: req.SANsDNS, IP: ipStrings, Email: req.SANsEmail},
		KeyUsage:      keyUsageStrings(req.KeyUsage, req.ExtKeyUsage),
		CertPEM:       string(certPEM),
		Status:        storage.CertStatusActive,
		NotBefore:     now,
		NotAfter:      notAfter,
		IssuedAt:      now,
		ProvisionerID: req.ProvisionerID,
		Requester:     req.Requester,
		Metadata:      req.Metadata,
	}

	if err := e.store.CreateCertificate(ctx, record); err != nil {
		return nil, fmt.Errorf("ca: IssueCert: store certificate: %w", err)
	}

	return &IssuedCertificate{
		Record:   record,
		CertPEM:  certPEM,
		KeyPEM:   leafKeyPEM,
		ChainPEM: chainPEM,
	}, nil
}

// SignCSR signs an externally provided CSR with the specified CA.
func (e *Engine) SignCSR(ctx context.Context, req SignCSRRequest) (*IssuedCertificate, error) {
	req.setDefaults()
	if err := req.validate(); err != nil {
		return nil, err
	}

	issuerRecord, issuerCert, issuerKey, err := e.loadIssuer(ctx, req.CAID)
	if err != nil {
		return nil, fmt.Errorf("ca: SignCSR: %w", err)
	}

	// Decode and parse the CSR.
	block, _ := pem.Decode(req.CSRPEM)
	if block == nil {
		return nil, errors.New("ca: SignCSR: CSRPEM does not contain a valid PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: SignCSR: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ca: SignCSR: CSR signature invalid: %w", err)
	}

	constraintsChain, err := e.collectNameConstraints(ctx, issuerRecord)
	if err != nil {
		return nil, fmt.Errorf("ca: SignCSR: %w", err)
	}
	if err := enforceNameConstraints(constraintsChain, csr.DNSNames, csr.IPAddresses, csr.EmailAddresses); err != nil {
		return nil, fmt.Errorf("ca: SignCSR: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: SignCSR: generate serial: %w", err)
	}

	now := time.Now().UTC()
	notAfter := now.Add(time.Duration(req.TTLSeconds) * time.Second)
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}
	ski, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ca: SignCSR: compute subject key id: %w", err)
	}
	// Issuer may predate explicit SKI support — fall back to recomputing it.
	aki, err := ensureSKI(issuerCert)
	if err != nil {
		return nil, fmt.Errorf("ca: SignCSR: compute authority key id: %w", err)
	}

	// We honour the Subject and SANs from the CSR.
	// Key usage is set to sensible TLS defaults — callers cannot inject
	// arbitrary key usage via a CSR.
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
		AuthorityKeyId:        aki,
	}

	if err := applyCertPoliciesToTemplate(template, req.CertPolicyOIDs, req.CertPolicyCPSURI); err != nil {
		return nil, fmt.Errorf("ca: SignCSR: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, csr.PublicKey, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("ca: SignCSR: sign certificate: %w", err)
	}

	certPEM := encodeCertPEM(certDER)

	chainPEM, err := e.buildChain(ctx, issuerRecord, certPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: SignCSR: build chain: %w", err)
	}

	ipStrings := make([]string, len(csr.IPAddresses))
	for i, ip := range csr.IPAddresses {
		ipStrings[i] = ip.String()
	}

	record := &storage.Certificate{
		ID:            uuid.New(),
		CAID:          req.CAID,
		Serial:        serial.String(),
		SubjectCN:     csr.Subject.CommonName,
		SANs:          storage.SANs{DNS: csr.DNSNames, IP: ipStrings, Email: csr.EmailAddresses},
		KeyUsage:      []string{"digital_signature", "key_encipherment", "server_auth", "client_auth"},
		CertPEM:       string(certPEM),
		Status:        storage.CertStatusActive,
		NotBefore:     now,
		NotAfter:      notAfter,
		IssuedAt:      now,
		ProvisionerID: req.ProvisionerID,
		Requester:     req.Requester,
		Metadata:      req.Metadata,
	}

	if err := e.store.CreateCertificate(ctx, record); err != nil {
		return nil, fmt.Errorf("ca: SignCSR: store certificate: %w", err)
	}

	return &IssuedCertificate{
		Record:   record,
		CertPEM:  certPEM,
		KeyPEM:   nil, // caller already has this
		ChainPEM: chainPEM,
	}, nil
}

// GetChainPEM returns the full CA chain for a given CA: the CA's own cert
// followed by all ancestors up to and including the root.
// This is what trust store installers and ACME clients need.
func (e *Engine) GetChainPEM(ctx context.Context, caID uuid.UUID) ([]byte, error) {
	caRecord, err := e.store.GetCA(ctx, caID)
	if err != nil {
		return nil, fmt.Errorf("ca: GetChainPEM: load CA: %w", err)
	}
	if caRecord == nil {
		return nil, fmt.Errorf("ca: GetChainPEM: CA %s not found", caID)
	}
	// buildChain with nil leafPEM returns only the CA chain.
	return e.buildChain(ctx, caRecord, nil)
}

// GetCrossChainPEM returns the cross-signing chain for a target CA: the
// cross certificate (target's public key+subject signed by the signer)
// followed by the signer's own chain up to its root. This lets clients that
// trust the signing CA (but not the target's native issuer) validate the
// target during a CA transition.
func (e *Engine) GetCrossChainPEM(ctx context.Context, targetCAID, signingCAID uuid.UUID) ([]byte, error) {
	cc, err := e.store.GetCrossCert(ctx, targetCAID, signingCAID)
	if err != nil {
		return nil, fmt.Errorf("ca: GetCrossChainPEM: load cross cert: %w", err)
	}
	if cc == nil {
		return nil, fmt.Errorf("ca: GetCrossChainPEM: no cross cert for target %s signed by %s", targetCAID, signingCAID)
	}
	signer, err := e.store.GetCA(ctx, signingCAID)
	if err != nil {
		return nil, fmt.Errorf("ca: GetCrossChainPEM: load signer: %w", err)
	}
	if signer == nil {
		return nil, fmt.Errorf("ca: GetCrossChainPEM: signer CA %s not found", signingCAID)
	}
	// Cross cert + signer's chain up to root.
	chain, err := e.buildChain(ctx, signer, []byte(cc.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("ca: GetCrossChainPEM: build signer chain: %w", err)
	}
	return chain, nil
}

// buildChain assembles: leafPEM (if non-nil) + issuerCert + all ancestors up to root.
// It walks the parent_id tree upward, so it works for any depth.
func (e *Engine) buildChain(ctx context.Context, issuer *storage.CertificateAuthority, leafPEM []byte) ([]byte, error) {
	var chain []byte

	if leafPEM != nil {
		chain = append(chain, leafPEM...)
	}

	// Walk from issuer up to root, appending each CA's cert PEM.
	current := issuer
	for {
		chain = append(chain, []byte(current.CertPEM)...)
		if current.ParentID == nil {
			// Reached the root.
			break
		}
		parent, err := e.store.GetCA(ctx, *current.ParentID)
		if err != nil {
			return nil, fmt.Errorf("ca: buildChain: load parent %s: %w", *current.ParentID, err)
		}
		if parent == nil {
			return nil, fmt.Errorf("ca: buildChain: parent CA %s not found — broken chain", *current.ParentID)
		}
		current = parent
	}

	return chain, nil
}

// loadIssuer loads a CA record, parses its certificate, and decrypts its
// private key. It validates that the CA is active before doing any work.
// Returns the record, parsed cert, and decrypted signing key together so that
// callers do not have to repeat this boilerplate.
func (e *Engine) loadIssuer(ctx context.Context, caID uuid.UUID) (
	*storage.CertificateAuthority, *x509.Certificate, crypto.Signer, error,
) {
	record, err := e.store.GetCA(ctx, caID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load issuer CA: %w", err)
	}
	if record == nil {
		return nil, nil, nil, fmt.Errorf("issuer CA %s not found", caID)
	}
	if record.Status != storage.CAStatusActive {
		return nil, nil, nil, fmt.Errorf("issuer CA %q is not active (status: %s)", record.Name, record.Status)
	}

	cert, err := parseCertPEM([]byte(record.CertPEM))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse issuer cert: %w", err)
	}

	key, err := e.loadKey(record)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load issuer key: %w", err)
	}

	return record, cert, key, nil
}

// loadKey decrypts the private key stored in a CA record.
// ResolveActiveCA returns the ACTIVE CA row belonging to a logical CA identity.
// After a re-key the old row is superseded and a new row carries the same
// LogicalCAID, so this returns the newest active row automatically. Returns an
// error if no active row exists (e.g. the CA was revoked).
func (e *Engine) ResolveActiveCA(ctx context.Context, logicalCAID uuid.UUID) (*storage.CertificateAuthority, error) {
	cas, err := e.store.ListCAs(ctx)
	if err != nil {
		return nil, fmt.Errorf("ca: ResolveActiveCA: list CAs: %w", err)
	}
	var active *storage.CertificateAuthority
	for _, ca := range cas {
		if ca.LogicalCAID != nil && *ca.LogicalCAID == logicalCAID && ca.Status == storage.CAStatusActive {
			// Prefer the most recently created active row.
			if active == nil || ca.CreatedAt.After(active.CreatedAt) {
				active = ca
			}
		}
	}
	if active == nil {
		return nil, fmt.Errorf("ca: ResolveActiveCA: no active CA for logical CA %s", logicalCAID)
	}
	return active, nil
}

func (e *Engine) loadKey(record *storage.CertificateAuthority) (crypto.Signer, error) {
	keyPEM, err := e.keystore.DecryptPEM(record.KeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt key for CA %q: %w", record.Name, err)
	}
	return parseKeyPEM(keyPEM)
}

// generateKey produces a private key and its PEM encoding for the given algorithm.
func generateKey(algo KeyAlgo) (crypto.Signer, []byte, error) {
	var key crypto.Signer
	var err error

	switch algo {
	case KeyAlgoECDSAP256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyAlgoECDSAP384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyAlgoRSA2048:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case KeyAlgoRSA4096:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	case KeyAlgoEd25519:
		_, priv, genErr := ed25519.GenerateKey(rand.Reader)
		key, err = priv, genErr
	default:
		return nil, nil, fmt.Errorf("generateKey: unsupported algorithm %q", algo)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("generateKey %s: %w", algo, err)
	}

	keyPEM, err := encodeKeyPEM(key)
	if err != nil {
		return nil, nil, fmt.Errorf("generateKey %s: encode: %w", algo, err)
	}

	return key, keyPEM, nil
}

// encodeKeyPEM marshals a private key to PEM.
func encodeKeyPEM(key crypto.Signer) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), nil
	case ed25519.PrivateKey:
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	default:
		return nil, fmt.Errorf("encodeKeyPEM: unsupported key type %T", key)
	}
}

// parseKeyPEM decodes a PEM-encoded private key into a crypto.Signer.
// Handles EC PRIVATE KEY, RSA PRIVATE KEY, and PRIVATE KEY (PKCS8).
func parseKeyPEM(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("parseKeyPEM: no PEM block found")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parseKeyPEM: PKCS8: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("parseKeyPEM: PKCS8 key type %T does not implement crypto.Signer", key)
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("parseKeyPEM: unrecognised PEM block type %q", block.Type)
	}
}

// parseCertPEM decodes the first certificate in a PEM block.
func parseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("parseCertPEM: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parseCertPEM: %w", err)
	}
	return cert, nil
}

// encodeCertPEM encodes a DER certificate into PEM.
func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// pubkey extracts the public key from a crypto.Signer.
func pubkey(s crypto.Signer) crypto.PublicKey {
	return s.Public()
}

// randomSerial generates a cryptographically random 128-bit serial number.
// RFC 5280 requires serial numbers to be unique per CA and no longer than
// 20 octets (160 bits). 128 bits gives us more than enough uniqueness.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("randomSerial: %w", err)
	}
	return n, nil
}

// nonEmpty returns a single-element slice if s is non-empty, or nil otherwise.
func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// keyUsageStrings converts x509 key usage bitfields into human-readable strings
// for storage in the certificates table.
func keyUsageStrings(ku x509.KeyUsage, eku []x509.ExtKeyUsage) []string {
	var out []string

	if ku&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, "digital_signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		out = append(out, "content_commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		out = append(out, "key_encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		out = append(out, "data_encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		out = append(out, "key_agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		out = append(out, "cert_sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		out = append(out, "crl_sign")
	}

	for _, e := range eku {
		switch e {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "server_auth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "client_auth")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "email_protection")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "code_signing")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "time_stamping")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "ocsp_signing")
		}
	}

	return out
}

// collectNameConstraints walks from issuer up through every ancestor CA
// (via ParentID) to the root, returning the list of NameConstraints found
// along the way (nearest ancestor first). Since only intermediates carry
// name constraints in mint-ca, the root contributes nothing, but any
// intermediate ancestor might — this must not stop at the immediate
// issuer alone.
func (e *Engine) collectNameConstraints(ctx context.Context, issuer *storage.CertificateAuthority) ([]*NameConstraints, error) {
	var out []*NameConstraints

	current := issuer
	for {
		if current.NameConstraints != nil {
			out = append(out, current.NameConstraints)
		}
		if current.ParentID == nil {
			break
		}
		parent, err := e.store.GetCA(ctx, *current.ParentID)
		if err != nil {
			return nil, fmt.Errorf("collectNameConstraints: load parent %s: %w", *current.ParentID, err)
		}
		if parent == nil {
			return nil, fmt.Errorf("collectNameConstraints: parent CA %s not found — broken chain", *current.ParentID)
		}
		current = parent
	}

	return out, nil
}

// enforceNameConstraints checks a candidate leaf's SANs against every
// ancestor's name constraints, failing fast with a clear error naming the
// offending SAN and constraint if any ancestor rejects it. This is called
// at issuance time (both IssueCert and SignCSR) since x509.CreateCertificate
// itself does not enforce name constraints — only x509.Verify does, at
// validation time by relying parties. Enforcing here gives operators an
// immediate, actionable error instead of silently minting a
// spec-non-compliant (or policy-violating) certificate.
func enforceNameConstraints(constraintsChain []*NameConstraints, dnsNames []string, ips []net.IP, emails []string) error {
	for _, nc := range constraintsChain {
		if nc == nil {
			continue
		}

		for _, dns := range dnsNames {
			if err := checkDNSAgainstConstraints(dns, nc); err != nil {
				return err
			}
		}
		for _, ip := range ips {
			if err := checkIPAgainstConstraints(ip, nc); err != nil {
				return err
			}
		}
		for _, email := range emails {
			if err := checkEmailAgainstConstraints(email, nc); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkDNSAgainstConstraints(dns string, nc *NameConstraints) error {
	dns = strings.ToLower(strings.TrimSuffix(dns, "."))

	for _, excluded := range nc.ExcludedDNSDomains {
		if dnsMatchesConstraint(dns, excluded) {
			return fmt.Errorf("name constraints: DNS SAN %q is excluded by ancestor CA constraint %q", dns, excluded)
		}
	}

	if len(nc.PermittedDNSDomains) == 0 {
		return nil
	}
	for _, permitted := range nc.PermittedDNSDomains {
		if dnsMatchesConstraint(dns, permitted) {
			return nil
		}
	}
	return fmt.Errorf("name constraints: DNS SAN %q does not match any permitted domain of an ancestor CA (%s)",
		dns, strings.Join(nc.PermittedDNSDomains, ", "))
}

// dnsMatchesConstraint implements RFC 5280 §4.2.1.10 DNS name-constraint
// matching: the constraint "example.com" matches "example.com" and any
// subdomain "*.example.com" (host.example.com, a.b.example.com, ...), but
// not "notexample.com".
func dnsMatchesConstraint(name, constraint string) bool {
	constraint = strings.ToLower(strings.TrimSuffix(constraint, "."))
	if name == constraint {
		return true
	}
	return strings.HasSuffix(name, "."+constraint)
}

func checkIPAgainstConstraints(ip net.IP, nc *NameConstraints) error {
	for _, cidr := range nc.ExcludedIPRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue // already validated at CA-creation time; skip defensively
		}
		if ipnet.Contains(ip) {
			return fmt.Errorf("name constraints: IP SAN %s is excluded by ancestor CA constraint %q", ip, cidr)
		}
	}

	if len(nc.PermittedIPRanges) == 0 {
		return nil
	}
	for _, cidr := range nc.PermittedIPRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipnet.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("name constraints: IP SAN %s does not match any permitted range of an ancestor CA (%s)",
		ip, strings.Join(nc.PermittedIPRanges, ", "))
}

func checkEmailAgainstConstraints(email string, nc *NameConstraints) error {
	email = strings.ToLower(email)
	domain := email
	if at := strings.LastIndex(email, "@"); at >= 0 {
		domain = email[at+1:]
	}

	matches := func(constraint string) bool {
		constraint = strings.ToLower(constraint)
		// A constraint containing "@" must match the full address; a bare
		// domain constraint matches the domain part or any subdomain.
		if strings.Contains(constraint, "@") {
			return email == constraint
		}
		return domain == constraint || strings.HasSuffix(domain, "."+constraint)
	}

	for _, excluded := range nc.ExcludedEmailDomains {
		if matches(excluded) {
			return fmt.Errorf("name constraints: email SAN %q is excluded by ancestor CA constraint %q", email, excluded)
		}
	}

	if len(nc.PermittedEmailDomains) == 0 {
		return nil
	}
	for _, permitted := range nc.PermittedEmailDomains {
		if matches(permitted) {
			return nil
		}
	}
	return fmt.Errorf("name constraints: email SAN %q does not match any permitted domain of an ancestor CA (%s)",
		email, strings.Join(nc.PermittedEmailDomains, ", "))
}
