package sshca

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// KeyAlgo identifies the algorithm used for an SSH CA signing key.
type KeyAlgo string

const (
	KeyAlgoEd25519   KeyAlgo = "ed25519"
	KeyAlgoECDSAP256 KeyAlgo = "ecdsa-p256"
)

// DefaultKeyAlgo is used when no algorithm is specified.
const DefaultKeyAlgo = KeyAlgoEd25519

// Valid reports whether the algorithm string is one sshca supports.
func (a KeyAlgo) Valid() bool {
	switch a {
	case KeyAlgoEd25519, KeyAlgoECDSAP256:
		return true
	}
	return false
}

func (a KeyAlgo) storageAlgo() storage.SSHKeyAlgo {
	switch a {
	case KeyAlgoEd25519:
		return storage.SSHKeyAlgoEd25519
	case KeyAlgoECDSAP256:
		return storage.SSHKeyAlgoECDSAP256
	default:
		return storage.SSHKeyAlgo(a)
	}
}

// CreateCARequest describes a new SSH CA signing key to generate.
type CreateCARequest struct {
	// Name is the unique internal identifier for this SSH CA.
	Name string
	// KeyAlgo is the algorithm for the CA signing key. Defaults to ed25519.
	KeyAlgo KeyAlgo
}

func (r *CreateCARequest) setDefaults() {
	if r.KeyAlgo == "" {
		r.KeyAlgo = DefaultKeyAlgo
	}
}

func (r *CreateCARequest) validate() error {
	if r.Name == "" {
		return errors.New("sshca: CreateCARequest: Name is required")
	}
	if !r.KeyAlgo.Valid() {
		return fmt.Errorf("sshca: CreateCARequest: unsupported KeyAlgo %q", r.KeyAlgo)
	}
	return nil
}

// IssueCertRequest describes an SSH user or host certificate to sign.
type IssueCertRequest struct {
	// CAID is the signing CA.
	CAID uuid.UUID

	// ProvisionerID authorising this issuance, recorded for audit purposes.
	ProvisionerID uuid.UUID

	// Requester is a free-form string identifying who asked.
	Requester string

	// CertType is "user" or "host".
	CertType storage.SSHCertType

	// PublicKeyInput is the client-supplied public key to sign, accepted as
	// either an OpenSSH authorized_keys line ("ssh-ed25519 AAAA... comment")
	// or raw base64-encoded SSH wire format. Auto-detected.
	PublicKeyInput string

	// KeyID is an informational label embedded in the certificate
	// (ssh.Certificate.KeyId) — typically a username or hostname.
	KeyID string

	// Principals lists the usernames (user cert) or hostnames (host cert)
	// this certificate is valid for. At least one is required.
	Principals []string

	// TTLSeconds is the certificate validity window. Defaults to 8 hours
	// for user certs — short-lived by design — and 1 year for host certs.
	TTLSeconds int64

	// CriticalOptions are OpenSSH certificate critical options (e.g.
	// "force-command", "source-address"), applied to both user and host certs
	// when set. Values carry the option payload as OpenSSH expects; empty-string
	// values are permitted. If nil, no critical options are added.
	CriticalOptions map[string]string

	// Extensions are additional OpenSSH certificate extensions (e.g.
	// "permit-open", "permit-listen"). These MERGE OVER the built-in default
	// permit-* set: keys supplied here override/join the defaults, they never
	// silently drop them.
	Extensions map[string]string
}

func (r *IssueCertRequest) setDefaults() {
	if r.TTLSeconds <= 0 {
		if r.CertType == storage.SSHCertTypeHost {
			r.TTLSeconds = int64((365 * 24 * time.Hour).Seconds())
		} else {
			r.TTLSeconds = int64((8 * time.Hour).Seconds())
		}
	}
}

func (r *IssueCertRequest) validate() error {
	if r.CAID == uuid.Nil {
		return errors.New("sshca: IssueCertRequest: CAID is required")
	}
	if r.CertType != storage.SSHCertTypeUser && r.CertType != storage.SSHCertTypeHost {
		return fmt.Errorf("sshca: IssueCertRequest: CertType must be %q or %q", storage.SSHCertTypeUser, storage.SSHCertTypeHost)
	}
	if r.PublicKeyInput == "" {
		return errors.New("sshca: IssueCertRequest: PublicKeyInput is required")
	}
	if len(r.Principals) == 0 {
		return errors.New("sshca: IssueCertRequest: at least one principal is required")
	}
	if r.TTLSeconds <= 0 {
		return errors.New("sshca: IssueCertRequest: TTLSeconds must be positive")
	}
	return nil
}

// IssuedCertificate is returned after successfully signing an SSH certificate.
type IssuedCertificate struct {
	// Record is the database record created for this certificate.
	Record *storage.SSHCertificate
	// CertData is the full serialized OpenSSH certificate
	// (authorized_keys / -cert.pub format), ready to write to disk.
	CertData string
}

// Engine issues SSH CAs and certificates. It is the only component that
// performs cryptographic operations on SSH CA private keys.
type Engine struct {
	store    storage.Store
	keystore *mintcrypto.Keystore
}

// NewEngine constructs an Engine. Both arguments are required.
func NewEngine(store storage.Store, keystore *mintcrypto.Keystore) *Engine {
	return &Engine{store: store, keystore: keystore}
}

// CreateCA generates a new SSH CA signing key and persists it to the store.
func (e *Engine) CreateCA(ctx context.Context, req CreateCARequest) (*storage.SSHCertificateAuthority, error) {
	req.setDefaults()
	if err := req.validate(); err != nil {
		return nil, err
	}

	existing, err := e.store.GetSSHCAByName(ctx, req.Name)
	if err != nil {
		return nil, fmt.Errorf("sshca: CreateCA: check name: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("sshca: CreateCA: an SSH CA named %q already exists", req.Name)
	}

	signer, keyPEM, err := generateSSHKey(req.KeyAlgo)
	if err != nil {
		return nil, fmt.Errorf("sshca: CreateCA: generate key: %w", err)
	}

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("sshca: CreateCA: wrap signer: %w", err)
	}
	authorizedKey := ssh.MarshalAuthorizedKey(sshSigner.PublicKey())

	encKey, err := e.keystore.EncryptPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("sshca: CreateCA: encrypt key: %w", err)
	}

	record := &storage.SSHCertificateAuthority{
		ID:        uuid.New(),
		Name:      req.Name,
		KeyAlgo:   req.KeyAlgo.storageAlgo(),
		PublicKey: strings.TrimSpace(string(authorizedKey)),
		KeyEnc:    encKey,
		Status:    storage.CAStatusActive,
		CreatedAt: time.Now().UTC(),
	}

	if err := e.store.CreateSSHCA(ctx, record); err != nil {
		return nil, fmt.Errorf("sshca: CreateCA: store: %w", err)
	}

	return record, nil
}

// IssueCert signs a client-supplied public key as an SSH user or host
// certificate using the specified CA.
func (e *Engine) IssueCert(ctx context.Context, req IssueCertRequest) (*IssuedCertificate, error) {
	req.setDefaults()
	if err := req.validate(); err != nil {
		return nil, err
	}

	caRecord, caSigner, err := e.loadCA(ctx, req.CAID)
	if err != nil {
		return nil, fmt.Errorf("sshca: IssueCert: %w", err)
	}

	pub, err := parsePublicKeyInput(req.PublicKeyInput)
	if err != nil {
		return nil, fmt.Errorf("sshca: IssueCert: parse public key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("sshca: IssueCert: generate serial: %w", err)
	}

	now := time.Now().UTC()
	validAfter := now.Add(-1 * time.Minute) // small clock-skew buffer
	validBefore := now.Add(time.Duration(req.TTLSeconds) * time.Second)

	var sshCertType uint32
	var extensions map[string]string
	switch req.CertType {
	case storage.SSHCertTypeHost:
		sshCertType = ssh.HostCert
		// Host certs carry no extensions by convention.
	default:
		sshCertType = ssh.UserCert
		// Standard OpenSSH default extension set for interactive user certs.
		extensions = map[string]string{
			"permit-X11-forwarding":   "",
			"permit-agent-forwarding": "",
			"permit-port-forwarding":  "",
			"permit-pty":              "",
			"permit-user-rc":          "",
		}
	}

	// Merge operator-supplied extensions over the OpenSSH default set (defaults
	// stay unless explicitly overridden, so existing behaviour is unchanged).
	for k, v := range req.Extensions {
		extensions[k] = v
	}

	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        sshCertType,
		KeyId:           req.KeyID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions: ssh.Permissions{
			// Critical options are only meaningful on user certs; OpenSSH ignores
			// them on host certs, but we still carry whatever the operator set.
			CriticalOptions: req.CriticalOptions,
			Extensions:      extensions,
		},
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("sshca: IssueCert: sign certificate: %w", err)
	}

	certData := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))

	record := &storage.SSHCertificate{
		ID:            uuid.New(),
		CAID:          caRecord.ID,
		Serial:        serial,
		CertType:      req.CertType,
		KeyID:         req.KeyID,
		Principals:    req.Principals,
		PublicKey:     strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		CertData:      certData,
		ValidAfter:    validAfter,
		ValidBefore:   validBefore,
		Status:        storage.SSHCertStatusActive,
		ProvisionerID: req.ProvisionerID,
		Requester:     req.Requester,
		CreatedAt:     now,
	}

	if err := e.store.CreateSSHCertificate(ctx, record); err != nil {
		return nil, fmt.Errorf("sshca: IssueCert: store certificate: %w", err)
	}

	return &IssuedCertificate{Record: record, CertData: certData}, nil
}

// loadCA loads an SSH CA record, decrypts its private key, and wraps it as
// an ssh.Signer. It validates that the CA is active before doing any work.
func (e *Engine) loadCA(ctx context.Context, caID uuid.UUID) (*storage.SSHCertificateAuthority, ssh.Signer, error) {
	record, err := e.store.GetSSHCA(ctx, caID)
	if err != nil {
		return nil, nil, fmt.Errorf("load SSH CA: %w", err)
	}
	if record == nil {
		return nil, nil, fmt.Errorf("SSH CA %s not found", caID)
	}
	if record.Status != storage.CAStatusActive {
		return nil, nil, fmt.Errorf("SSH CA %q is not active (status: %s)", record.Name, record.Status)
	}

	keyPEM, err := e.keystore.DecryptPEM(record.KeyEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt key for SSH CA %q: %w", record.Name, err)
	}

	cryptoSigner, err := parseKeyPEMToSigner(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse key for SSH CA %q: %w", record.Name, err)
	}

	signer, err := ssh.NewSignerFromSigner(cryptoSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap signer for SSH CA %q: %w", record.Name, err)
	}

	return record, signer, nil
}

// parsePublicKeyInput accepts either an OpenSSH authorized_keys line
// ("ssh-ed25519 AAAA... comment") or raw base64-encoded SSH wire format,
// auto-detecting which one was supplied.
func parsePublicKeyInput(raw string) (ssh.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty public key input")
	}

	// Try the authorized_keys line format first — this is the common case
	// and also handles input with leading options or trailing comments.
	if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw)); err == nil {
		return pub, nil
	}

	// Fall back to raw base64-encoded SSH wire format (no "ssh-xxx " prefix).
	wire, err := sshBase64Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("not a valid authorized_keys line or base64 SSH wire key: %w", err)
	}
	pub, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return nil, fmt.Errorf("not a valid authorized_keys line or base64 SSH wire key: %w", err)
	}
	return pub, nil
}

// randomSerial generates a random non-zero uint64 SSH certificate serial.
// SSH certs use a plain 64-bit integer (not the ASN.1 INTEGER X.509 uses).
func randomSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("randomSerial: %w", err)
	}
	n := binary.BigEndian.Uint64(b[:])
	if n == 0 {
		n = 1 // 0 has special meaning in some SSH cert tooling; avoid it
	}
	return n, nil
}
