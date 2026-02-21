// internal/ca/engine.go
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// KeyAlgo identifies the algorithm and key size used for a generated keypair.
type KeyAlgo string

const (
	KeyAlgoECDSAP256 KeyAlgo = "ecdsa-p256"
	KeyAlgoECDSAP384 KeyAlgo = "ecdsa-p384"
	KeyAlgoRSA2048   KeyAlgo = "rsa-2048"
	KeyAlgoRSA4096   KeyAlgo = "rsa-4096"
)

// DefaultKeyAlgo is what the engine uses when no algorithm is specified.
const DefaultKeyAlgo = KeyAlgoECDSAP256

// Valid returns true if the algorithm string is one we support.
func (a KeyAlgo) Valid() bool {
	switch a {
	case KeyAlgoECDSAP256, KeyAlgoECDSAP384, KeyAlgoRSA2048, KeyAlgoRSA4096:
		return true
	}
	return false
}

// CreateRootCARequest contains everything needed to generate a self-signed root CA.
type CreateRootCARequest struct {
	// Name is the unique human-readable identifier stored in the database.
	// It is not the X.509 Common Name — it is mint-ca's internal label.
	Name string

	// Subject fields become the CA certificate's Subject and Issuer (self-signed).
	CommonName   string
	Organization string
	Country      string // two-letter ISO code, e.g. "US"
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
	// ParentCAID is the database ID of the CA that will sign this one.
	ParentCAID uuid.UUID

	Name         string
	CommonName   string
	Organization string
	Country      string
	State        string
	Locality     string

	KeyAlgo KeyAlgo

	// TTLDays is how long this intermediate's certificate is valid.
	// The engine automatically clamps this to the parent's remaining lifetime.
	TTLDays int

	// MaxPathLen controls how many further intermediates can be issued below
	// this one. Set to 0 to only allow leaf certificates. Set to -1 for
	// unlimited (not recommended for intermediates).
	MaxPathLen int
}

func (r *CreateIntermediateCARequest) setDefaults() {
	if r.KeyAlgo == "" {
		r.KeyAlgo = DefaultKeyAlgo
	}
	if r.TTLDays <= 0 {
		r.TTLDays = 1825 // 5 years
	}
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
	return nil
}

// IssueCertRequest describes a leaf certificate that mint-ca should generate
// the keypair for and sign. The private key is returned to the caller once and
// never stored.
type IssueCertRequest struct {
	// CAID is the issuing CA.
	CAID uuid.UUID

	// ProvisionerID is the provisioner authorising this issuance. It must exist
	// and be active. It is recorded on the certificate for audit purposes.
	ProvisionerID uuid.UUID

	// Requester is a free-form string identifying who asked — e.g. an API key
	// name, an ACME account key thumbprint, etc.
	Requester string

	// Subject
	CommonName string

	// SANs — at least one is strongly recommended; policy may require them.
	SANsDNS   []string
	SANsIP    []net.IP
	SANsEmail []string

	// KeyUsage and ExtKeyUsage control the certificate's intended purpose.
	// If both are zero-value the engine sets sensible TLS server+client defaults.
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage

	// TTLSeconds is the certificate lifetime. Must be positive.
	// The engine clamps it to the issuing CA's remaining lifetime.
	TTLSeconds int64

	// KeyAlgo is the algorithm for the generated leaf keypair.
	KeyAlgo KeyAlgo

	// Metadata is arbitrary key-value data stored alongside the certificate.
	Metadata storage.JSON
}

func (r *IssueCertRequest) setDefaults() {
	if r.KeyAlgo == "" {
		r.KeyAlgo = DefaultKeyAlgo
	}
	if r.TTLSeconds <= 0 {
		r.TTLSeconds = 86400 // 24 hours
	}
	// If caller did not specify key usage, default to TLS server + client.
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
	return nil
}

// SignCSRRequest asks the engine to sign an externally-provided CSR.
// The caller already holds the private key; we only issue the certificate.
type SignCSRRequest struct {
	CAID          uuid.UUID
	ProvisionerID uuid.UUID
	Requester     string
	// CSRPEM is the PEM-encoded certificate signing request.
	CSRPEM []byte
	// TTLSeconds is the certificate lifetime.
	TTLSeconds int64
	// Metadata is arbitrary key-value data stored alongside the certificate.
	Metadata storage.JSON
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
	return nil
}

// IssuedCertificate is returned after a successful leaf certificate issuance.
type IssuedCertificate struct {
	// Record is the database record created for this certificate.
	Record *storage.Certificate
	// CertPEM is the PEM-encoded certificate (leaf only).
	CertPEM []byte
	// KeyPEM is the PEM-encoded private key. This is only populated when
	// mint-ca generated the keypair (IssueCert). For SignCSR it is nil
	// because the caller already holds the private key.
	KeyPEM []byte
	// ChainPEM is the full certificate chain: leaf + all intermediates + root.
	// This is what TLS servers should present.
	ChainPEM []byte
}

// Engine is the core CA signing engine. It is the only component in mint-ca that performs cryptographic operations on CA private keys.

// Private keys are decrypted from the store on demand for each operation and
// are not held in memory beyond the scope of a single function call.
type Engine struct {
	store    storage.Store
	keystore *mintcrypto.Keystore
}

// NewEngine constructs an Engine. Both arguments are required.
func NewEngine(store storage.Store, keystore *mintcrypto.Keystore) *Engine {
	return &Engine{store: store, keystore: keystore}
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
		ID:        uuid.New(),
		ParentID:  nil, // root has no parent
		Name:      req.Name,
		Type:      storage.CATypeRoot,
		Status:    storage.CAStatusActive,
		CertPEM:   string(certPEM),
		KeyEnc:    encKey,
		KeyAlgo:   string(req.KeyAlgo),
		NotBefore: now,
		NotAfter:  notAfter,
		CreatedAt: now,
	}

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
	}

	// Signed by the parent CA — template is the new cert, parent is the issuer.
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
		ID:        uuid.New(),
		ParentID:  &parentID,
		Name:      req.Name,
		Type:      storage.CATypeIntermediate,
		Status:    storage.CAStatusActive,
		CertPEM:   string(certPEM),
		KeyEnc:    encKey,
		KeyAlgo:   string(req.KeyAlgo),
		NotBefore: now,
		NotAfter:  notAfter,
		CreatedAt: now,
	}

	if err := e.store.CreateCA(ctx, record); err != nil {
		return nil, fmt.Errorf("ca: CreateIntermediateCA: store: %w", err)
	}

	return record, nil
}

// IssueCert generates a keypair, signs a leaf certificate with the specified CA,
// stores the certificate record, and returns the cert PEM, key PEM, and full chain.
// The private key is returned once and never stored
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

	// Convert net.IP slice to strings for storage.
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
	// Verify the CSR's self-signature so we know the caller holds the private key.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ca: SignCSR: CSR signature invalid: %w", err)
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
