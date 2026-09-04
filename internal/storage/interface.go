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
	// CAStatusSuperseded marks a CA that has been re-keyed. It no longer signs
	// new certificates, but already-issued leafs remain valid and are NOT to be
	// treated as compromised (unlike revoked). Distinct from revoked: the leaf
	// CRL/OCSP status of a superseded CA's issued certificates is unchanged.
	CAStatusSuperseded CAStatus = "superseded"
)

// SSHKRLCache holds the most recently generated KRL for each SSH CA.
type SSHKRLCache struct {
	ID         uuid.UUID `json:"id"`
	CAID       uuid.UUID `json:"ca_id"`
	KRLData    []byte    `json:"-"`
	KRLVersion uint64    `json:"krl_version"`
	ThisUpdate time.Time `json:"this_update"`
	NextUpdate time.Time `json:"next_update"`
}
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

type SSHKeyAlgo string

const (
	SSHKeyAlgoEd25519   SSHKeyAlgo = "ssh-ed25519"
	SSHKeyAlgoECDSAP256 SSHKeyAlgo = "ecdsa-p256"
)

type SSHCertType string

const (
	SSHCertTypeUser SSHCertType = "user"
	SSHCertTypeHost SSHCertType = "host"
)

type SSHCertStatus string

const (
	SSHCertStatusActive  SSHCertStatus = "active"
	SSHCertStatusRevoked SSHCertStatus = "revoked"
	SSHCertStatusExpired SSHCertStatus = "expired"
)

// SANs holds the Subject Alternative Names for a certificate.
type SANs struct {
	DNS   []string `json:"dns,omitempty"`
	IP    []string `json:"ip,omitempty"`
	Email []string `json:"email,omitempty"`
	// URI holds URI SAN values, notably SPIFFE IDs (spiffe://trust-domain/path)
	// for issuing X.509-SVIDs (see internal/spiffe).
	URI []string `json:"uri,omitempty"`
}

// CertificateAuthority represents a root or intermediate CA stored in mint-ca.
type CertificateAuthority struct {
	ID uuid.UUID `json:"id"`
	// LogicalCAID is the stable identity a CA row belongs to. Re-key creates a
	// new row with a new physical ID but the SAME LogicalCAID, so provisioners
	// can keep pointing at one logical CA across rotations. Fresh CAs get their
	// own ID as their LogicalCAID (backfilled on migration for existing rows).
	LogicalCAID     *uuid.UUID       `json:"logical_ca_id,omitempty"`
	ParentID        *uuid.UUID       `json:"parent_id,omitempty"`
	Name            string           `json:"name"`
	Type            CAType           `json:"type"`
	Status          CAStatus         `json:"status"`
	CertPEM         string           `json:"cert_pem"`
	KeyEnc          []byte           `json:"-"`
	KeyAlgo         string           `json:"key_algo"`
	NameConstraints *NameConstraints `json:"name_constraints,omitempty"`
	// TenantID is the owning tenant (uuid.Nil means legacy/unset, treated as
	// the default tenant by isolation checks).
	TenantID  uuid.UUID `json:"tenant_id,omitempty"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	CreatedAt time.Time `json:"created_at"`
}

// SSHCertificateAuthority is a signing key used to issue SSH user/host
// certificates. Unlike X.509 CAs, SSH CAs are flat — no parent/child chain.
type SSHCertificateAuthority struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	// TenantID is the owning tenant (uuid.Nil means legacy/unset).
	TenantID  uuid.UUID  `json:"tenant_id,omitempty"`
	KeyAlgo   SSHKeyAlgo `json:"key_algo"`
	PublicKey string     `json:"public_key"` // OpenSSH authorized_keys format
	KeyEnc    []byte     `json:"-"`
	Status    CAStatus   `json:"status"`
	// LogicalCAID is the stable identity this SSH CA belongs to. Key rotation
	// creates a new row with a new physical ID but the SAME LogicalCAID, so
	// downstream consumers can keep referring to one logical id. Set to the
	// row's own ID at creation.
	LogicalCAID *uuid.UUID `json:"logical_ca_id,omitempty"`
	// ParentID records the SSH CA row this row supersedes (nil for a root).
	ParentID  *uuid.UUID `json:"parent_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// CrossCert is a cross-signed certificate: a certificate issued for an
// existing CA's public key and subject, signed by a DIFFERENT CA (the
// signer). Used to build trust bridges during root/intermediate transitions
// (e.g. an old root cross-signs a new root). It shares the target's keypair
// and identity but carries a different issuer/chain.
type CrossCert struct {
	ID          uuid.UUID `json:"id"`
	TargetCAID  uuid.UUID `json:"target_ca_id"`
	SigningCAID uuid.UUID `json:"signing_ca_id"`
	CertPEM     string    `json:"cert_pem"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Serial      string    `json:"serial"`
	CreatedAt   time.Time `json:"created_at"`
}

// CRLCache holds the most recently generated base CRL PEM for each CA.
type CRLCache struct {
	ID         uuid.UUID `json:"id"`
	CAID       uuid.UUID `json:"ca_id"`
	CRLPEM     string    `json:"crl_pem"`
	CRLNumber  int64     `json:"crl_number"` // NEW: persisted monotonic CRL Number
	ThisUpdate time.Time `json:"this_update"`
	NextUpdate time.Time `json:"next_update"`
}

// DeltaCRLCache holds the most recently generated delta CRL for each CA.
type DeltaCRLCache struct {
	ID            uuid.UUID `json:"id"`
	CAID          uuid.UUID `json:"ca_id"`
	CRLPEM        string    `json:"crl_pem"`
	CRLNumber     int64     `json:"crl_number"`
	BaseCRLNumber int64     `json:"base_crl_number"`
	ThisUpdate    time.Time `json:"this_update"`
	NextUpdate    time.Time `json:"next_update"`
}

// SSHCertificate is an issued SSH user or host certificate.
type SSHCertificate struct {
	ID            uuid.UUID     `json:"id"`
	CAID          uuid.UUID     `json:"ca_id"`
	Serial        uint64        `json:"serial"`
	CertType      SSHCertType   `json:"cert_type"`
	KeyID         string        `json:"key_id"`
	Principals    []string      `json:"principals"`
	PublicKey     string        `json:"public_key"` // signed public key, OpenSSH format
	CertData      string        `json:"cert_data"`  // full serialized -cert.pub
	ValidAfter    time.Time     `json:"valid_after"`
	ValidBefore   time.Time     `json:"valid_before"`
	Status        SSHCertStatus `json:"status"`
	RevokedAt     *time.Time    `json:"revoked_at,omitempty"`
	ProvisionerID uuid.UUID     `json:"provisioner_id"`
	Requester     string        `json:"requester"`
	CreatedAt     time.Time     `json:"created_at"`
}

// RateLimitConfig is a single named limiter's configuration, persisted so
// it can be edited at runtime (e.g. via a future web UI) without a restart.
type RateLimitConfig struct {
	Name          string    `json:"name"`
	Scope         string    `json:"scope"`
	Algorithm     string    `json:"algorithm"`
	WindowSeconds int       `json:"window_seconds"`
	MaxRequests   int       `json:"max_requests"`
	Enabled       bool      `json:"enabled"`
	UpdatedAt     time.Time `json:"updated_at"`
}
type ACMEAuthorizationStatus string

const (
	ACMEAuthorizationStatusPending ACMEAuthorizationStatus = "pending"
	ACMEAuthorizationStatusValid   ACMEAuthorizationStatus = "valid"
	ACMEAuthorizationStatusInvalid ACMEAuthorizationStatus = "invalid"
)

type ACMEAuthorization struct {
	ID              uuid.UUID               `json:"id"`
	OrderID         uuid.UUID               `json:"order_id"`
	AccountID       uuid.UUID               `json:"account_id"`
	IdentifierType  string                  `json:"identifier_type"`
	IdentifierValue string                  `json:"identifier_value"`
	Status          ACMEAuthorizationStatus `json:"status"`
	ExpiresAt       time.Time               `json:"expires_at"`
	CreatedAt       time.Time               `json:"created_at"`
}

// Certificate represents a leaf certificate issued by one of the stored CAs.
type Certificate struct {
	ID        uuid.UUID `json:"id"`
	CAID      uuid.UUID `json:"ca_id"`
	Serial    string    `json:"serial"`
	SubjectCN string    `json:"subject_cn"`
	SANs      SANs      `json:"sans"`
	KeyUsage  []string  `json:"key_usage"`
	CertPEM   string    `json:"cert_pem"`
	// KeyEncrypted holds the keystore-encrypted leaf private key when the
	// issuer opted into key escrow (store_key=true). Empty otherwise.
	KeyEncrypted []byte `json:"-"`
	// KeyPasscodeRequired records whether retrieval of the escrowed key also
	// requires a caller-supplied passcode (key_passcode was set at issue).
	KeyPasscodeRequired bool       `json:"-"`
	Status              CertStatus `json:"status"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	RevokeReason        *int       `json:"revoke_reason,omitempty"`
	NotBefore           time.Time  `json:"not_before"`
	NotAfter            time.Time  `json:"not_after"`
	IssuedAt            time.Time  `json:"issued_at"`
	ProvisionerID       uuid.UUID  `json:"provisioner_id"`
	Requester           string     `json:"requester"`
	Metadata            JSON       `json:"metadata,omitempty"`
}

// Provisioner is the entity authorised to request certificates from a CA.
// Profile is a named set of issuance constraints that can be pinned to a
// provisioner (Provisioner.ProfileID) or requested per issuance. An empty
// profile imposes no constraints.
type Profile struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	// TenantID is the owning tenant (uuid.Nil means legacy/unset).
	TenantID uuid.UUID `json:"tenant_id,omitempty"`

	// AllowedKeyAlgos restricts the leaf key algorithm (e.g. "ecdsa-p256",
	// "rsa-2048", "ed25519"). Empty means any.
	AllowedKeyAlgos []string `json:"allowed_key_algos,omitempty"`

	// MinTTLSeconds / MaxTTLSeconds bound the certificate lifetime. 0 means
	// "no constraint" on that side.
	MinTTLSeconds int64 `json:"min_ttl_seconds"`
	MaxTTLSeconds int64 `json:"max_ttl_seconds"`

	// RequireSAN forces every issued certificate to carry at least one SAN.
	RequireSAN bool `json:"require_san"`

	// AllowWildcard permits wildcard DNS SANs (e.g. "*.example.com").
	// Default false = wildcard SANs rejected.
	AllowWildcard bool `json:"allow_wildcard"`

	CreatedAt time.Time `json:"created_at"`
}

// CSRAutoApproveRule is a stored CSR auto-approval rule controlling which
// CSRs a provisioner may auto-sign without caller review.
type CSRAutoApproveRule struct {
	ID            uuid.UUID `json:"id"`
	ProvisionerID uuid.UUID `json:"provisioner_id"`
	Name          string    `json:"name"`
	// AllowedCommonNames are regex patterns the CSR CommonName must match.
	AllowedCommonNames []string `json:"allowed_common_names,omitempty"`
	// AllowedDNS are regex patterns every DNS SAN must match.
	AllowedDNS []string `json:"allowed_dns,omitempty"`
	// MaxTTLSeconds caps the signed certificate lifetime (0 uses an approval default).
	MaxTTLSeconds int64     `json:"max_ttl_seconds"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
}

type Provisioner struct {
	ID   uuid.UUID `json:"id"`
	CAID uuid.UUID `json:"ca_id"`
	// TenantID is the CA/tenant ownership (uuid.Nil means legacy/unset).
	TenantID  uuid.UUID         `json:"tenant_id,omitempty"`
	Name      string            `json:"name"`
	Type      ProvisionerType   `json:"type"`
	Config    JSON              `json:"config"`
	PolicyID  *uuid.UUID        `json:"policy_id,omitempty"`
	ProfileID *uuid.UUID        `json:"profile_id,omitempty"`
	Status    ProvisionerStatus `json:"status"`
	CreatedAt time.Time         `json:"created_at"`
}

// Policy defines the rules that govern what a provisioner or CA may issue.
type Policy struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	// TenantID is the owning tenant (uuid.Nil means legacy/unset).
	TenantID       uuid.UUID   `json:"tenant_id,omitempty"`
	Scope          PolicyScope `json:"scope"`
	MaxTTL         int64       `json:"max_ttl_seconds"`
	AllowedDomains []string    `json:"allowed_domains"`
	DeniedDomains  []string    `json:"denied_domains"`
	AllowedIPs     []string    `json:"allowed_ips"`
	AllowedSANs    []string    `json:"allowed_sans"`
	RequireSAN     bool        `json:"require_san"`
	KeyAlgos       []string    `json:"key_algos"`
	PolicyOIDs     []string    `json:"policy_oids,omitempty"` // dotted-decimal OID strings
	CPSURI         string      `json:"cps_uri,omitempty"`
	// SSHPolicy holds the SSH CA issuance constraints as an SSHPolicyBody JSON.
	// Non-nil when the policy applies to SSH issuance; nil when X.509-only.
	SSHPolicy []byte    `json:"ssh_policy,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
type NameConstraints struct {
	PermittedDNSDomains   []string `json:"permitted_dns_domains,omitempty"`
	ExcludedDNSDomains    []string `json:"excluded_dns_domains,omitempty"`
	PermittedIPRanges     []string `json:"permitted_ip_ranges,omitempty"`
	ExcludedIPRanges      []string `json:"excluded_ip_ranges,omitempty"`
	PermittedEmailDomains []string `json:"permitted_email_domains,omitempty"`
	ExcludedEmailDomains  []string `json:"excluded_email_domains,omitempty"`
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
	ID              uuid.UUID           `json:"id"`
	OrderID         uuid.UUID           `json:"order_id"`
	Type            ACMEChallengeType   `json:"type"`
	AuthorizationID *uuid.UUID          `json:"authorization_id,omitempty"`
	Token           string              `json:"token"`
	Status          ACMEChallengeStatus `json:"status"`
	ValidatedAt     *time.Time          `json:"validated_at,omitempty"`
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
	// PrevHash and EntryHash form a tamper-evident hash chain (see
	// internal/audit): EntryHash is derived from this entry's fields plus the
	// previous entry's EntryHash, so editing, deleting, or reordering any
	// entry is detectable. Populated by the storage backend on write.
	PrevHash  string `json:"prev_hash"`
	EntryHash string `json:"entry_hash"`
}

// APIKey is a bearer token used to authenticate calls to the management API.
type APIKey struct {
	ID      uuid.UUID  `json:"id"`
	Name    string     `json:"name"`
	KeyHash string     `json:"-"`
	Scopes  []string   `json:"scopes"`
	CAID    *uuid.UUID `json:"ca_id,omitempty"`
	// TenantID scopes this key to exactly one tenant (nil = platform admin).
	// A tenant-scoped key can only see/act on rows belonging to its own tenant.
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// TenantStatus is the lifecycle state of a Tenant.
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
)

// Tenant is the multi-tenancy scoping unit: every tenant-private resource is
// owned by exactly one tenant.
type Tenant struct {
	ID        uuid.UUID    `json:"id"`
	Name      string       `json:"name"`
	Status    TenantStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
}

// DefaultTenantID is the fixed, well-known UUID of the seeded default tenant
// that pre-existing single-tenant rows are backfilled to. Chosen so existing
// deployments migrate deterministically without a runtime-generated ID.
var DefaultTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000000")

// TenantStore is the CRUD surface the multi-tenancy handlers need. It is kept
// separate from Store (which the whole codebase depends on) so the extensive
// fake-store test suite is not forced to implement tenant methods. The real
// backends satisfy it via a local interface assertion, mirroring the repo's
// profileStore/csrApprovalStore convention.
type TenantStore interface {
	CreateTenant(ctx context.Context, t *Tenant) error
	GetTenant(ctx context.Context, id uuid.UUID) (*Tenant, error)
	GetTenantByName(ctx context.Context, name string) (*Tenant, error)
	ListTenants(ctx context.Context) ([]*Tenant, error)
	UpdateTenantStatus(ctx context.Context, id uuid.UUID, status TenantStatus) error
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

	// CreateCrossCert stores a cross-signed certificate for the target CA.
	CreateCrossCert(ctx context.Context, cc *CrossCert) error

	// GetCrossCert returns the cross cert for targetCAID signed by signingCAID,
	// or (nil, nil) if none exists.
	GetCrossCert(ctx context.Context, targetCAID, signingCAID uuid.UUID) (*CrossCert, error)

	// ListCrossCertsByTarget returns all cross certs issued for the target CA.
	ListCrossCertsByTarget(ctx context.Context, targetCAID uuid.UUID) ([]*CrossCert, error)

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
	ConsumeNonce(ctx context.Context, nonce string) (bool, error)
	CreateACMEAuthorization(ctx context.Context, auth *ACMEAuthorization) error
	GetACMEAuthorization(ctx context.Context, id uuid.UUID) (*ACMEAuthorization, error)
	UpdateACMEAuthorizationStatus(ctx context.Context, id uuid.UUID, status ACMEAuthorizationStatus) error
	ListAuthorizationsByOrder(ctx context.Context, orderID uuid.UUID) ([]*ACMEAuthorization, error)
	ListChallengesByAuthorization(ctx context.Context, authID uuid.UUID) ([]*ACMEChallenge, error)
	GetACMEAuthorizationByIdentifier(ctx context.Context, accountID uuid.UUID, identifierType, identifierValue string) (*ACMEAuthorization, error)
	ListAuthorizationsByAccount(ctx context.Context, accountID uuid.UUID) ([]*ACMEAuthorization, error)
	// (Update CreateACMEChallenge to use the new struct)

	// PruneExpiredNonces removes nonces past their expiry timestamp.
	PruneExpiredNonces(ctx context.Context) error
	// CreateSSHCA persists a new SSH signing CA. Key must already be encrypted.
	CreateSSHCA(ctx context.Context, ca *SSHCertificateAuthority) error

	// GetSSHCA returns the SSH CA with the given ID, or (nil, nil) if not found.
	GetSSHCA(ctx context.Context, id uuid.UUID) (*SSHCertificateAuthority, error)

	// GetSSHCAByName returns the SSH CA with the given name, or (nil, nil).
	GetSSHCAByName(ctx context.Context, name string) (*SSHCertificateAuthority, error)

	// ListSSHCAs returns all SSH CAs ordered by creation time ascending.
	ListSSHCAs(ctx context.Context) ([]*SSHCertificateAuthority, error)

	// CreateSSHCertificate persists a newly issued SSH certificate record.
	CreateSSHCertificate(ctx context.Context, cert *SSHCertificate) error

	// GetSSHCertificate returns the SSH certificate with the given ID, or (nil, nil).
	GetSSHCertificate(ctx context.Context, id uuid.UUID) (*SSHCertificate, error)

	// GetSSHCertificateBySerial returns the SSH certificate matching caID+serial, or (nil, nil).
	GetSSHCertificateBySerial(ctx context.Context, caID uuid.UUID, serial uint64) (*SSHCertificate, error)

	// ListSSHCertificatesByCA returns all SSH certificates issued by caID, newest first.
	ListSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*SSHCertificate, error)

	// RevokeSSHCertificate marks an SSH certificate revoked. Schema/plumbing
	// only in phase 1 — no API endpoint wired up to it yet.
	RevokeSSHCertificate(ctx context.Context, id uuid.UUID) error
	// --- Add to the Store interface ---

	// GetRateLimitConfig returns the config for a named limiter, or (nil, nil).
	GetRateLimitConfig(ctx context.Context, name string) (*RateLimitConfig, error)

	// ListRateLimitConfigs returns all configured limiters.
	ListRateLimitConfigs(ctx context.Context) ([]*RateLimitConfig, error)

	// UpsertRateLimitConfigIfAbsent inserts cfg only if no row with that
	// name already exists. Used to seed defaults at boot without ever
	// clobbering a value a future web UI has changed.
	UpsertRateLimitConfigIfAbsent(ctx context.Context, cfg *RateLimitConfig) error

	// UpdateRateLimitConfig unconditionally overwrites a limiter's config.
	// Intended for the future web UI's edit endpoint.
	UpdateRateLimitConfig(ctx context.Context, cfg *RateLimitConfig) error

	// IncrementRateLimitCounter is a best-effort, write-through persistence
	// of a fixed-window counter increment. Never authoritative — the caller
	// (ratelimit.Engine) has already made its allow/deny decision from
	// in-memory state before calling this.
	IncrementRateLimitCounter(ctx context.Context, limiterName, bucketKey string, windowStart time.Time) error

	// PruneExpiredRateLimitCounters deletes counter rows whose window
	// started before olderThan.
	PruneExpiredRateLimitCounters(ctx context.Context, olderThan time.Time) error
	// --- Add to Store interface ---

	// UpdateACMEAccountKey swaps an account's key_id/key_jwk (key rollover).
	UpdateACMEAccountKey(ctx context.Context, accountID uuid.UUID, newKeyID string, newKeyJWK JSON) error

	// MarkKeyIDRetired permanently blocks a JWK thumbprint from being used as
	// a NEW account key again (common CA practice: an old key from a rollover
	// can never come back into service, even on a different account).
	MarkKeyIDRetired(ctx context.Context, keyID string) error

	// IsKeyIDRetired reports whether keyID was retired via a prior key-change.
	IsKeyIDRetired(ctx context.Context, keyID string) (bool, error)
	// ListRevokedSSHCertificatesByCA returns only revoked SSH certs for caID.
	ListRevokedSSHCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*SSHCertificate, error)

	// UpsertSSHKRL inserts or replaces the cached KRL for an SSH CA.
	UpsertSSHKRL(ctx context.Context, krl *SSHKRLCache) error

	// GetSSHKRL returns the cached KRL for an SSH CA, or (nil, nil).
	GetSSHKRL(ctx context.Context, caID uuid.UUID) (*SSHKRLCache, error)
	// NextCRLNumber atomically returns the next monotonic CRL Number for
	// caID, shared across base and delta CRLs so the sequence is global
	// per-CA as RFC 5280 §5.2.4 requires.
	NextCRLNumber(ctx context.Context, caID uuid.UUID) (int64, error)

	// ListRevokedByCASince returns certificates revoked after `since`,
	// used to compute delta CRL contents relative to a base CRL.
	ListRevokedByCASince(ctx context.Context, caID uuid.UUID, since time.Time) ([]*Certificate, error)

	// UpsertDeltaCRL inserts or replaces the cached delta CRL for a CA.
	UpsertDeltaCRL(ctx context.Context, delta *DeltaCRLCache) error

	// GetDeltaCRL returns the cached delta CRL for a CA, or (nil, nil).
	GetDeltaCRL(ctx context.Context, caID uuid.UUID) (*DeltaCRLCache, error)
	// Close releases all connections held by the store.
	Close() error
}
