package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type CAType string
type SetupState string

const (
	StateUninitialized SetupState = "uninitialized"
	StateSetup         SetupState = "setup"
	StateReady         SetupState = "ready"
)

const (
	CATypeRoot         CAType = "root"
	CATypeIntermediate CAType = "intermediate"
)

type CAStatus string

const (
	CAStatusActive  CAStatus = "active"
	CAStatusRevoked CAStatus = "revoked"
	CAStatusExpired CAStatus = "expired"
)

type CertStatus string

const (
	CertStatusActive  CertStatus = "active"
	CertStatusRevoked CertStatus = "revoked"
	CertStatusExpired CertStatus = "expired"
)

type ProvisionerType string

const (
	ProvisionerTypeACME   ProvisionerType = "acme"
	ProvisionerTypeAPIKey ProvisionerType = "apikey"
	ProvisionerTypeMTLS   ProvisionerType = "mtls"
)

type ProvisionerStatus string

const (
	ProvisionerStatusActive   ProvisionerStatus = "active"
	ProvisionerStatusDisabled ProvisionerStatus = "disabled"
)

type PolicyScope string

const (
	PolicyScopeCA          PolicyScope = "ca"
	PolicyScopeProvisioner PolicyScope = "provisioner"
)

type ACMEAccountStatus string

const (
	ACMEAccountStatusValid       ACMEAccountStatus = "valid"
	ACMEAccountStatusDeactivated ACMEAccountStatus = "deactivated"
	ACMEAccountStatusRevoked     ACMEAccountStatus = "revoked"
)

type ACMEOrderStatus string

const (
	ACMEOrderStatusPending    ACMEOrderStatus = "pending"
	ACMEOrderStatusReady      ACMEOrderStatus = "ready"
	ACMEOrderStatusProcessing ACMEOrderStatus = "processing"
	ACMEOrderStatusValid      ACMEOrderStatus = "valid"
	ACMEOrderStatusInvalid    ACMEOrderStatus = "invalid"
)

type ACMEChallengeType string

const (
	ACMEChallengeTypeHTTP01    ACMEChallengeType = "http-01"
	ACMEChallengeTypeDNS01     ACMEChallengeType = "dns-01"
	ACMEChallengeTypeTLSALPN01 ACMEChallengeType = "tls-alpn-01"
)

type ACMEChallengeStatus string

const (
	ACMEChallengeStatusPending ACMEChallengeStatus = "pending"
	ACMEChallengeStatusValid   ACMEChallengeStatus = "valid"
	ACMEChallengeStatusInvalid ACMEChallengeStatus = "invalid"
)

// SANs holds the Subject Alternative Names for a certificate.
type SANs struct {
	DNS   []string `json:"dns,omitempty"`
	IP    []string `json:"ip,omitempty"`
	Email []string `json:"email,omitempty"`
}

// CertificateAuthority represents a root or intermediate CA stored in mint-ca.
type CertificateAuthority struct {
	ID        uuid.UUID  `json:"id"`
	ParentID  *uuid.UUID `json:"parent_id,omitempty"`
	Name      string     `json:"name"`
	Type      CAType     `json:"type"`
	Status    CAStatus   `json:"status"`
	CertPEM   string     `json:"cert_pem"`
	KeyEnc    []byte     `json:"-"`
	KeyAlgo   string     `json:"key_algo"`
	NotBefore time.Time  `json:"not_before"`
	NotAfter  time.Time  `json:"not_after"`
	CreatedAt time.Time  `json:"created_at"`
}

// Certificate represents a leaf certificate issued by one of the stored CAs.
type Certificate struct {
	ID            uuid.UUID  `json:"id"`
	CAID          uuid.UUID  `json:"ca_id"`
	Serial        string     `json:"serial"`
	SubjectCN     string     `json:"subject_cn"`
	SANs          SANs       `json:"sans"`
	KeyUsage      []string   `json:"key_usage"`
	CertPEM       string     `json:"cert_pem"`
	Status        CertStatus `json:"status"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokeReason  *int       `json:"revoke_reason,omitempty"`
	NotBefore     time.Time  `json:"not_before"`
	NotAfter      time.Time  `json:"not_after"`
	IssuedAt      time.Time  `json:"issued_at"`
	ProvisionerID uuid.UUID  `json:"provisioner_id"`
	Requester     string     `json:"requester"`
	Metadata      JSON       `json:"metadata,omitempty"`
}

// Provisioner is the entity authorised to request certificates from a CA.
type Provisioner struct {
	ID        uuid.UUID         `json:"id"`
	CAID      uuid.UUID         `json:"ca_id"`
	Name      string            `json:"name"`
	Type      ProvisionerType   `json:"type"`
	Config    JSON              `json:"config"`
	PolicyID  *uuid.UUID        `json:"policy_id,omitempty"`
	Status    ProvisionerStatus `json:"status"`
	CreatedAt time.Time         `json:"created_at"`
}

// Policy defines the rules that govern what a provisioner or CA may issue.
type Policy struct {
	ID             uuid.UUID   `json:"id"`
	Name           string      `json:"name"`
	Scope          PolicyScope `json:"scope"`
	MaxTTL         int64       `json:"max_ttl_seconds"`
	AllowedDomains []string    `json:"allowed_domains"`
	DeniedDomains  []string    `json:"denied_domains"`
	AllowedIPs     []string    `json:"allowed_ips"`
	AllowedSANs    []string    `json:"allowed_sans"`
	RequireSAN     bool        `json:"require_san"`
	KeyAlgos       []string    `json:"key_algos"`
	CreatedAt      time.Time   `json:"created_at"`
}

// ACMEAccount is an ACME client account, keyed by its JWK thumbprint.
type ACMEAccount struct {
	ID            uuid.UUID         `json:"id"`
	ProvisionerID uuid.UUID         `json:"provisioner_id"`
	KeyID         string            `json:"key_id"` // JWK thumbprint
	KeyJWK        JSON              `json:"key_jwk"`
	EABID         *uuid.UUID        `json:"eab_id,omitempty"`
	Status        ACMEAccountStatus `json:"status"`
	Contact       []string          `json:"contact"`
	CreatedAt     time.Time         `json:"created_at"`
}

// EABCredential is an External Account Binding key pair used to associate
type EABCredential struct {
	ID            uuid.UUID  `json:"id"`
	ProvisionerID uuid.UUID  `json:"provisioner_id"`
	HMACKey       []byte     `json:"-"` // never exposed after creation
	KeyID         string     `json:"key_id"`
	Used          bool       `json:"used"`
	UsedAt        *time.Time `json:"used_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

// ACMEOrder represents an in-progress or completed ACME certificate order.
type ACMEOrder struct {
	ID            uuid.UUID       `json:"id"`
	AccountID     uuid.UUID       `json:"account_id"`
	Status        ACMEOrderStatus `json:"status"`
	Identifiers   JSON            `json:"identifiers"`
	CertificateID *uuid.UUID      `json:"certificate_id,omitempty"`
	ExpiresAt     time.Time       `json:"expires_at"`
	CreatedAt     time.Time       `json:"created_at"`
}

// ACMEChallenge is one challenge within an ACME order.
type ACMEChallenge struct {
	ID          uuid.UUID           `json:"id"`
	OrderID     uuid.UUID           `json:"order_id"`
	Type        ACMEChallengeType   `json:"type"`
	Token       string              `json:"token"`
	Status      ACMEChallengeStatus `json:"status"`
	ValidatedAt *time.Time          `json:"validated_at,omitempty"`
}

// AuditLog is an append-only record of every mutating action in the system.
type AuditLog struct {
	ID        uuid.UUID  `json:"id"`
	EventType string     `json:"event_type"`
	Actor     string     `json:"actor"`
	CAID      *uuid.UUID `json:"ca_id,omitempty"`
	CertID    *uuid.UUID `json:"cert_id,omitempty"`
	Payload   JSON       `json:"payload"`
	IPAddress string     `json:"ip_address"`
	CreatedAt time.Time  `json:"created_at"`
}

// CRLCache holds the most recently generated CRL PEM for each CA.
type CRLCache struct {
	ID         uuid.UUID `json:"id"`
	CAID       uuid.UUID `json:"ca_id"`
	CRLPEM     string    `json:"crl_pem"`
	ThisUpdate time.Time `json:"this_update"`
	NextUpdate time.Time `json:"next_update"`
}

// APIKey is a bearer token used to authenticate calls to the management API.
type APIKey struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	KeyHash   string     `json:"-"`
	Scopes    []string   `json:"scopes"`
	CAID      *uuid.UUID `json:"ca_id,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// JSON is a free-form map that round-trips through the database as a JSON string.
type JSON map[string]interface{}

// Store is the single database abstraction used by every package in mint-ca.
type Store interface {

	// CreateCA persists a new CA record. The CA's private key must already be
	// encrypted before calling this — the store never sees plaintext keys.
	CreateCA(ctx context.Context, ca *CertificateAuthority) error

	// GetCA returns the CA with the given ID, or (nil, nil) if not found.
	GetCA(ctx context.Context, id uuid.UUID) (*CertificateAuthority, error)

	// GetCAByName returns the CA with the given name, or (nil, nil) if not found.
	GetCAByName(ctx context.Context, name string) (*CertificateAuthority, error)

	// ListCAs returns all CAs ordered by creation time ascending.
	ListCAs(ctx context.Context) ([]*CertificateAuthority, error)

	// ListChildCAs returns all CAs whose parent_id equals parentID.
	ListChildCAs(ctx context.Context, parentID uuid.UUID) ([]*CertificateAuthority, error)

	// UpdateCAStatus changes the status field of a CA (active → revoked/expired).
	UpdateCAStatus(ctx context.Context, id uuid.UUID, status CAStatus) error

	// CreateCertificate persists a newly-issued leaf certificate.
	CreateCertificate(ctx context.Context, cert *Certificate) error

	// GetCertificate returns the certificate with the given ID, or (nil, nil).
	GetCertificate(ctx context.Context, id uuid.UUID) (*Certificate, error)

	// GetCertificateBySerial returns the certificate matching serial (decimal string), or (nil, nil).
	GetCertificateBySerial(ctx context.Context, serial string) (*Certificate, error)

	// ListCertificatesByCA returns all certificates issued by caID, newest first.
	ListCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*Certificate, error)

	// ListRevokedByCA returns only revoked certificates for caID, used for CRL generation.
	ListRevokedByCA(ctx context.Context, caID uuid.UUID) ([]*Certificate, error)

	// RevokeCertificate marks a certificate revoked with the given RFC 5280 reason code.
	RevokeCertificate(ctx context.Context, id uuid.UUID, reason int) error

	// CreateProvisioner persists a new provisioner.
	CreateProvisioner(ctx context.Context, p *Provisioner) error

	// GetProvisioner returns the provisioner with the given ID, or (nil, nil).
	GetProvisioner(ctx context.Context, id uuid.UUID) (*Provisioner, error)

	// ListProvisionersByCA returns all provisioners for a given CA.
	ListProvisionersByCA(ctx context.Context, caID uuid.UUID) ([]*Provisioner, error)

	// UpdateProvisionerStatus enables or disables a provisioner.
	UpdateProvisionerStatus(ctx context.Context, id uuid.UUID, status ProvisionerStatus) error

	// CreatePolicy persists a new issuance policy.
	CreatePolicy(ctx context.Context, p *Policy) error

	// GetPolicy returns the policy with the given ID, or (nil, nil).
	GetPolicy(ctx context.Context, id uuid.UUID) (*Policy, error)

	// ListPolicies returns all policies.
	ListPolicies(ctx context.Context) ([]*Policy, error)

	// UpdatePolicy replaces all mutable fields of an existing policy.
	UpdatePolicy(ctx context.Context, p *Policy) error

	// DeletePolicy removes a policy. Callers must ensure no provisioner references it.
	DeletePolicy(ctx context.Context, id uuid.UUID) error

	// CreateACMEAccount persists a new ACME account.
	CreateACMEAccount(ctx context.Context, a *ACMEAccount) error

	// GetACMEAccountByKeyID looks up an account by its JWK thumbprint.
	GetACMEAccountByKeyID(ctx context.Context, keyID string) (*ACMEAccount, error)

	// GetACMEAccount returns the account with the given ID, or (nil, nil).
	GetACMEAccount(ctx context.Context, id uuid.UUID) (*ACMEAccount, error)

	// UpdateACMEAccountStatus deactivates or revokes an ACME account.
	UpdateACMEAccountStatus(ctx context.Context, id uuid.UUID, status ACMEAccountStatus) error

	// UpdateACMEAccountContact replaces the contact list of an existing account.
	UpdateACMEAccountContact(ctx context.Context, id uuid.UUID, contact []string) error

	// CreateEABCredential persists a new External Account Binding key.
	CreateEABCredential(ctx context.Context, e *EABCredential) error

	// GetEABCredential looks up an EAB credential by its key_id string.
	GetEABCredential(ctx context.Context, keyID string) (*EABCredential, error)

	// MarkEABUsed records that an EAB credential has been consumed by an account registration.
	MarkEABUsed(ctx context.Context, id uuid.UUID) error

	// CreateACMEOrder persists a new ACME order.
	CreateACMEOrder(ctx context.Context, o *ACMEOrder) error

	// GetACMEOrder returns the order with the given ID, or (nil, nil).
	GetACMEOrder(ctx context.Context, id uuid.UUID) (*ACMEOrder, error)

	// ListACMEOrdersByAccount returns all orders for a given account, newest first.
	ListACMEOrdersByAccount(ctx context.Context, accountID uuid.UUID) ([]*ACMEOrder, error)

	// UpdateACMEOrderStatus transitions an order to a new status.
	UpdateACMEOrderStatus(ctx context.Context, id uuid.UUID, status ACMEOrderStatus) error

	// FinalizeACMEOrder sets order status to valid and links it to the issued certificate.
	FinalizeACMEOrder(ctx context.Context, orderID uuid.UUID, certID uuid.UUID) error

	// CreateACMEChallenge persists a challenge associated with an order.
	CreateACMEChallenge(ctx context.Context, c *ACMEChallenge) error

	// GetACMEChallenge returns the challenge with the given ID, or (nil, nil).
	GetACMEChallenge(ctx context.Context, id uuid.UUID) (*ACMEChallenge, error)

	// ListChallengesByOrder returns all challenges belonging to an order.
	ListChallengesByOrder(ctx context.Context, orderID uuid.UUID) ([]*ACMEChallenge, error)

	// UpdateChallengeStatus sets the status and optionally the validated_at timestamp.
	UpdateChallengeStatus(ctx context.Context, id uuid.UUID, status ACMEChallengeStatus, validatedAt *time.Time) error

	// WriteAuditLog appends an audit entry. This must never fail silently —
	// callers should log errors, but not block the main operation on them.
	WriteAuditLog(ctx context.Context, entry *AuditLog) error

	// ListAuditLogs returns audit entries newest first with pagination.
	ListAuditLogs(ctx context.Context, limit, offset int) ([]*AuditLog, error)

	// ListAuditLogsByCA returns audit entries for a specific CA, newest first.
	ListAuditLogsByCA(ctx context.Context, caID uuid.UUID, limit, offset int) ([]*AuditLog, error)

	// UpsertCRL inserts or replaces the cached CRL for a CA.
	UpsertCRL(ctx context.Context, crl *CRLCache) error

	// GetCRL returns the cached CRL for a CA, or (nil, nil) if none exists yet.
	GetCRL(ctx context.Context, caID uuid.UUID) (*CRLCache, error)

	// CreateAPIKey persists a new API key. KeyHash must already be hashed.
	CreateAPIKey(ctx context.Context, k *APIKey) error

	// GetAPIKeyByHash looks up an API key by the SHA-256 hash of the raw bearer token.
	GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error)

	// ListAPIKeys returns all API keys (hashes are not included in results).
	ListAPIKeys(ctx context.Context) ([]*APIKey, error)

	// DeleteAPIKey permanently removes an API key.
	DeleteAPIKey(ctx context.Context, id uuid.UUID) error

	// TouchAPIKey updates the last_used timestamp of an API key.
	TouchAPIKey(ctx context.Context, id uuid.UUID) error

	// Migrate runs schema creation idempotently. Safe to call on every startup.
	Migrate(ctx context.Context) error

	GetSetupState(ctx context.Context) (SetupState, error)

	// SetSetupState writes or updates the single setup state row.
	SetSetupState(ctx context.Context, state SetupState) error

	// GetAPIKeyByName returns the API key with the given name, or (nil, nil).
	// Used during setup to locate the bootstrap key.
	GetAPIKeyByName(ctx context.Context, name string) (*APIKey, error)

	// CreateNonce inserts a single-use ACME replay nonce that expires at expiresAt.
	CreateNonce(ctx context.Context, nonce string, expiresAt time.Time) error

	// ConsumeNonce atomically validates and deletes a nonce.
	// Returns (true, nil) if valid, (false, nil) if unknown/expired, or (false, err) on a database error.
	ConsumeNonce(ctx context.Context, nonce string) (bool, error)

	// PruneExpiredNonces removes nonces past their expiry timestamp.
	PruneExpiredNonces(ctx context.Context) error
	// Close releases all connections held by the store.
	Close() error
}
