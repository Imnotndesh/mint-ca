package acme

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"mint-ca/internal/acme/challenge"
	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/storage"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ProvisionerConfig is the JSON stored in provisioners.config for ACME
// provisioners. It controls per-provisioner ACME behaviour.
type ProvisionerConfig struct {
	// EABRequired, when true, requires every new-account request to carry a
	// valid External Account Binding. Defaults to false.
	EABRequired bool `json:"eab_required"`

	// DefaultTTLSeconds is the certificate lifetime granted to ACME orders
	// from this provisioner. Defaults to 90 days.
	DefaultTTLSeconds int64 `json:"default_ttl_seconds"`

	// AllowedChallengeTypes lists the challenge types this provisioner will
	// accept. Supported values: "http-01", "dns-01". Empty means all supported.
	AllowedChallengeTypes []string `json:"allowed_challenge_types"`

	// RenewalLeadPeriodSeconds overrides the renewal-info lead time (how long
	// before NotAfter the renewal window opens) for this provisioner. 0 means
	// the default (max(lifetime/5, 24h)).
	RenewalLeadPeriodSeconds int64 `json:"renewal_lead_period_seconds"`
}

type KeyChangeRequest struct {
	Account json.RawMessage `json:"account"` // account URL, as string
	OldKey  json.RawMessage `json:"oldKey"`
}

// SetDefaults fills in zero-value fields with sensible defaults.
// Exported so handlers can call it without reflection.
func (c *ProvisionerConfig) SetDefaults() {
	if c.DefaultTTLSeconds <= 0 {
		c.DefaultTTLSeconds = 90 * 24 * 3600 // 90 days
	}
	if len(c.AllowedChallengeTypes) == 0 {
		c.AllowedChallengeTypes = []string{"http-01", "dns-01"}
	}
}

// Identifier is an ACME order identifier (RFC 8555 §7.1.3).
type Identifier struct {
	Type  string `json:"type"`  // always "dns" for now
	Value string `json:"value"` // e.g. "example.com" or "*.example.com"
}

type NewAccountRequest struct {
	ProvisionerID uuid.UUID
	JWS           *RawJWS
	Header        *ProtectedHeader
	// Decoded payload fields
	TermsAgreed bool     `json:"termsOfServiceAgreed"`
	Contact     []string `json:"contact"`
	// EAB sub-object from payload (optional)
	EAB *RawJWS `json:"externalAccountBinding,omitempty"`
}

type NewOrderRequest struct {
	Account       *storage.ACMEAccount
	ProvisionerID uuid.UUID
	CAID          uuid.UUID
	Identifiers   []Identifier
	TTLSeconds    int64
}

type ValidateChallengeRequest struct {
	Account   *storage.ACMEAccount
	Challenge *storage.ACMEChallenge
	Order     *storage.ACMEOrder
}

type FinalizeOrderRequest struct {
	Account *storage.ACMEAccount
	Order   *storage.ACMEOrder
	CSRPEM  []byte
	CAID    uuid.UUID
	ProvID  uuid.UUID
	TTLSecs int64
}

// Store is the minimal storage.Store surface the service needs.
// Using the full interface is fine — this alias just documents the dependency.
type Store interface {
	storage.Store
	NonceStore
}

// Service provides all ACME business logic.
type Service struct {
	store     Store
	engine    *ca.Engine
	nonces    *NonceManager
	crlMgr    *revocation.CRLManager
	http01    *challenge.HTTP01Validator
	dns01     *challenge.DNS01Validator
	tlsalpn01 *challenge.TLSALPN01Validator
	caa       *CAAChecker
	baseURL   string
}

var allowedACMERevocationReasons = map[int]bool{
	0: true, 1: true, 3: true, 4: true, 5: true, 6: true, 9: true, 10: true,
}

// NewService constructs a Service.
//
// baseURL is the public-facing URL of this mint-ca instance
// (e.g. "https://ca.example.com"). It is embedded in directory responses
// and used to build account KID URLs.
func NewService(
	store Store,
	engine *ca.Engine,
	nonces *NonceManager,
	crlMgr *revocation.CRLManager,
	caa *CAAChecker,
	baseURL string,
) *Service {
	return &Service{
		store:     store,
		engine:    engine,
		nonces:    nonces,
		crlMgr:    crlMgr,
		http01:    challenge.NewHTTP01Validator(),
		dns01:     challenge.NewDNS01Validator(nil),
		tlsalpn01: challenge.NewTLSALPN01Validator(443),
		caa:       caa,
		baseURL:   strings.TrimRight(baseURL, "/"),
	}
}

// preAuthExpiry is how long a standalone (pre-)authorization remains valid
// before it must be re-created. Matches the order/authz TTL used in NewOrder.
const preAuthExpiry = 24 * time.Hour

// NewPreAuth creates (or reuses) a standalone authorization for a single
// identifier, independent of any order — RFC 8555 §7.4.1.
func (s *Service) NewPreAuth(
	ctx context.Context,
	account *storage.ACMEAccount,
	provisioner *storage.Provisioner,
	identifier Identifier,
) (*storage.ACMEAuthorization, []*storage.ACMEChallenge, *Problem) {

	if err := validateIdentifier(identifier); err != nil {
		return nil, nil, NewProblem(ErrRejectedIdentifier, 400, err.Error())
	}

	var cfg ProvisionerConfig
	_ = json.Unmarshal(mustMarshalJSON(provisioner.Config), &cfg)
	cfg.SetDefaults()

	now := time.Now().UTC()

	// Reuse an existing valid, unexpired standalone authz for this
	// account + identifier if one exists.
	existing, err := s.store.GetACMEAuthorizationByIdentifier(ctx, account.ID, identifier.Type, identifier.Value)
	if err != nil {
		return nil, nil, ErrServerInternalProblem("look up existing pre-authorization: " + err.Error())
	}
	if existing != nil && existing.Status == storage.ACMEAuthorizationStatusValid && existing.ExpiresAt.After(now) {
		challenges, err := s.store.ListChallengesByAuthorization(ctx, existing.ID)
		if err != nil {
			return nil, nil, ErrServerInternalProblem("list existing challenges: " + err.Error())
		}
		return existing, challenges, nil
	}

	expiresAt := now.Add(preAuthExpiry)
	authID := uuid.New()
	auth := &storage.ACMEAuthorization{
		ID:              authID,
		OrderID:         uuid.Nil, // standalone pre-authorization
		AccountID:       account.ID,
		IdentifierType:  identifier.Type,
		IdentifierValue: identifier.Value,
		Status:          storage.ACMEAuthorizationStatusPending,
		ExpiresAt:       expiresAt,
		CreatedAt:       now,
	}
	if err := s.store.CreateACMEAuthorization(ctx, auth); err != nil {
		return nil, nil, ErrServerInternalProblem("create pre-authorization: " + err.Error())
	}

	var challenges []*storage.ACMEChallenge
	for _, challType := range cfg.AllowedChallengeTypes {
		if IsWildcardIdentifier(identifier.Value) && challType != string(storage.ACMEChallengeTypeDNS01) {
			continue
		}
		token, err := generateToken()
		if err != nil {
			return nil, nil, ErrServerInternalProblem("generate challenge token: " + err.Error())
		}
		ch := &storage.ACMEChallenge{
			ID:              uuid.New(),
			OrderID:         uuid.Nil, // standalone pre-authorization challenge
			AuthorizationID: &authID,
			Type:            storage.ACMEChallengeType(challType),
			Token:           token,
			Status:          storage.ACMEChallengeStatusPending,
		}
		if err := s.store.CreateACMEChallenge(ctx, ch); err != nil {
			return nil, nil, ErrServerInternalProblem("create challenge: " + err.Error())
		}
		challenges = append(challenges, ch)
	}

	return auth, challenges, nil
}

// IssueNonce generates and persists a fresh nonce.
func (s *Service) IssueNonce(ctx context.Context) (string, error) {
	return s.nonces.Issue(ctx)
}
func (s *Service) KeyChange(
	ctx context.Context,
	outerAccount *storage.ACMEAccount,
	innerJWS *RawJWS,
	expectedAccountURL string,
) (*storage.ACMEAccount, *Problem) {

	innerHdr, err := innerJWS.ParseProtected()
	if err != nil {
		return nil, ErrMalformedProblem("keyChange: parse inner protected header: " + err.Error())
	}
	if len(innerHdr.JWK) == 0 {
		return nil, ErrMalformedProblem("keyChange: inner JWS must carry jwk, not kid")
	}
	newPub, err := ParseJWK(innerHdr.JWK)
	if err != nil {
		return nil, NewProblem(ErrBadPublicKey, 400, "keyChange: "+err.Error())
	}
	if err := innerJWS.Verify(newPub, innerHdr.Algorithm); err != nil {
		return nil, ErrUnauthorizedProblem("keyChange: inner JWS signature invalid: " + err.Error())
	}

	innerPayload, err := innerJWS.PayloadBytes()
	if err != nil || innerPayload == nil {
		return nil, ErrMalformedProblem("keyChange: inner JWS requires a payload")
	}
	var req KeyChangeRequest
	if err := json.Unmarshal(innerPayload, &req); err != nil {
		return nil, ErrMalformedProblem("keyChange: decode inner payload: " + err.Error())
	}

	var accountURL string
	_ = json.Unmarshal(req.Account, &accountURL)
	if strings.TrimRight(accountURL, "/") != strings.TrimRight(expectedAccountURL, "/") {
		return nil, NewProblem(ErrMalformed, 400, "keyChange: inner account URL does not match authenticated account")
	}

	oldThumb, err := Thumbprint(req.OldKey)
	if err != nil {
		return nil, ErrMalformedProblem("keyChange: thumbprint oldKey: " + err.Error())
	}
	if oldThumb != outerAccount.KeyID {
		return nil, NewProblem(ErrMalformed, 400, "keyChange: oldKey does not match authenticated account's current key")
	}

	newThumb, err := Thumbprint(innerHdr.JWK)
	if err != nil {
		return nil, ErrServerInternalProblem("keyChange: thumbprint new key: " + err.Error())
	}
	if newThumb == oldThumb {
		return nil, NewProblem(ErrMalformed, 400, "keyChange: new key is identical to current key")
	}

	// New key must not already be in use, nor be a previously-retired key
	// (common CA practice: rolled-off keys are permanently blocked from re-use).
	existing, err := s.store.GetACMEAccountByKeyID(ctx, newThumb)
	if err != nil {
		return nil, ErrServerInternalProblem("keyChange: check new key: " + err.Error())
	}
	if existing != nil {
		return nil, NewProblem(ErrMalformed, 409, "keyChange: new key is already in use by another account")
	}
	retired, err := s.store.IsKeyIDRetired(ctx, newThumb)
	if err != nil {
		return nil, ErrServerInternalProblem("keyChange: check retired keys: " + err.Error())
	}
	if retired {
		return nil, NewProblem(ErrMalformed, 409, "keyChange: this key was previously retired and cannot be reused")
	}

	if err := s.store.UpdateACMEAccountKey(ctx, outerAccount.ID, newThumb, storage.JSON(mustUnmarshalRawJSON(innerHdr.JWK))); err != nil {
		return nil, ErrServerInternalProblem("keyChange: update account key: " + err.Error())
	}
	if err := s.store.MarkKeyIDRetired(ctx, oldThumb); err != nil {
		slog.Warn("keyChange: failed to retire old key", "account_id", outerAccount.ID, "err", err)
	}

	outerAccount.KeyID = newThumb
	outerAccount.KeyJWK = storage.JSON(mustUnmarshalRawJSON(innerHdr.JWK))
	return outerAccount, nil
}

// RevokeCert handles RFC 8555 §7.6 certificate revocation. Exactly one of
// authAccount or authJWK must be non-nil, matching whichever auth mode the
// handler resolved from the JWS protected header.
func (s *Service) RevokeCert(
	ctx context.Context,
	certDER []byte,
	authAccount *storage.ACMEAccount,
	authJWK json.RawMessage,
	reason *int,
) *Problem {
	if reason != nil && !allowedACMERevocationReasons[*reason] {
		return NewProblem(ErrBadRevocationReason, 400,
			fmt.Sprintf("reason code %d is not permitted", *reason))
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return ErrMalformedProblem("parse certificate: " + err.Error())
	}

	record, err := s.store.GetCertificateBySerial(ctx, leaf.SerialNumber.String())
	if err != nil {
		return ErrServerInternalProblem("load certificate: " + err.Error())
	}
	if record == nil {
		return NewProblem(ErrMalformed, 404, "certificate not found")
	}

	// Confirm the supplied DER actually matches the stored cert, not just
	// a serial collision.
	storedCert, err := parseCertPEMBytes([]byte(record.CertPEM))
	if err != nil {
		return ErrServerInternalProblem("parse stored certificate: " + err.Error())
	}
	if !storedCert.Equal(leaf) {
		return ErrMalformedProblem("supplied certificate does not match a certificate issued by this CA")
	}

	if record.Status == storage.CertStatusRevoked {
		return NewProblem(ErrAlreadyRevoked, 400, "certificate is already revoked")
	}

	switch {
	case authAccount != nil:
		want := fmt.Sprintf("acme-account:%s", authAccount.ID)
		if record.Requester != want {
			return ErrUnauthorizedProblem("account did not request this certificate")
		}
	case authJWK != nil:
		pub, err := ParseJWK(authJWK)
		if err != nil {
			return NewProblem(ErrBadPublicKey, 400, err.Error())
		}
		if !publicKeysEqual(pub, leaf.PublicKey) {
			return ErrUnauthorizedProblem("JWK does not match certificate public key")
		}
	default:
		return ErrServerInternalProblem("revoke: no authentication context supplied")
	}

	reasonCode := 0
	if reason != nil {
		reasonCode = *reason
	}
	if err := s.crlMgr.RevokeAndRefresh(ctx, record.ID, reasonCode); err != nil {
		return ErrServerInternalProblem("revoke: " + err.Error())
	}
	return nil
}

func parseCertPEMBytes(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// publicKeysEqual compares two public keys for the algorithm types ParseJWK
// and x509 certificates can produce (ECDSA, RSA).
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(x crypto.PublicKey) bool }
	if ea, ok := a.(equaler); ok {
		return ea.Equal(b)
	}
	return false
}

// AuthenticateJWK is used for newAccount requests (no existing account yet).
// It parses the JWK from the protected header, verifies the JWS signature,
// and returns the parsed public key and its thumbprint.
func (s *Service) AuthenticateJWK(jws *RawJWS, hdr *ProtectedHeader) (json.RawMessage, string, *Problem) {
	if len(hdr.JWK) == 0 {
		return nil, "", ErrMalformedProblem("newAccount requires a JWK in the protected header")
	}
	pub, err := ParseJWK(hdr.JWK)
	if err != nil {
		return nil, "", NewProblem(ErrBadPublicKey, 400, err.Error())
	}
	if err := AlgorithmMatchesKey(hdr.Algorithm, pub); err != nil {
		return nil, "", NewProblem(ErrBadSignatureAlg, 400, err.Error())
	}
	if err := jws.Verify(pub, hdr.Algorithm); err != nil {
		return nil, "", ErrUnauthorizedProblem("JWS signature verification failed: " + err.Error())
	}
	thumb, err := Thumbprint(hdr.JWK)
	if err != nil {
		return nil, "", ErrServerInternalProblem("thumbprint computation failed")
	}
	return hdr.JWK, thumb, nil
}

// AuthenticateKID is used for all requests after account creation.
// It extracts the account from the KID URL, loads it, verifies the JWS.
func (s *Service) AuthenticateKID(ctx context.Context, jws *RawJWS, hdr *ProtectedHeader) (*storage.ACMEAccount, *Problem) {
	if hdr.KID == "" {
		return nil, ErrMalformedProblem("missing kid in protected header")
	}

	// KID URL format: {baseURL}/acme/{provisionerID}/account/{accountID}
	accountID, err := s.accountIDFromKID(hdr.KID)
	if err != nil {
		return nil, ErrMalformedProblem("invalid kid URL: " + err.Error())
	}

	account, err := s.store.GetACMEAccount(ctx, accountID)
	if err != nil {
		return nil, ErrServerInternalProblem("load account: " + err.Error())
	}
	if account == nil {
		return nil, NewProblem(ErrAccountDoesNotExist, 400, "account not found")
	}
	if account.Status != storage.ACMEAccountStatusValid {
		return nil, ErrUnauthorizedProblem(fmt.Sprintf("account status is %s", account.Status))
	}
	jwkBytes, err := json.Marshal(account.KeyJWK)
	if err != nil {
		return nil, ErrServerInternalProblem("marshal stored account key: " + err.Error())
	}
	pub, err := ParseJWK(jwkBytes)
	if err != nil {
		return nil, ErrServerInternalProblem("parse stored account key: " + err.Error())
	}
	if err := AlgorithmMatchesKey(hdr.Algorithm, pub); err != nil {
		return nil, NewProblem(ErrBadSignatureAlg, 400, err.Error())
	}
	if err := jws.Verify(pub, hdr.Algorithm); err != nil {
		return nil, ErrUnauthorizedProblem("JWS signature verification failed: " + err.Error())
	}
	return account, nil
}

// ValidateNonce consumes the nonce from the protected header.
func (s *Service) ValidateNonce(ctx context.Context, hdr *ProtectedHeader) *Problem {
	return s.nonces.Consume(ctx, hdr.Nonce)
}

// ValidateURL checks that the JWS "url" header matches the request URL.
// This prevents cross-endpoint replay attacks (RFC 8555 6.4).
func (s *Service) ValidateURL(hdr *ProtectedHeader, requestURL string) *Problem {
	want := strings.TrimRight(requestURL, "/")
	got := strings.TrimRight(hdr.URL, "/")
	if want != got {
		return ErrMalformedProblem(fmt.Sprintf("JWS url %q does not match request URL %q", got, want))
	}
	return nil
}

// NewAccount creates a new ACME account, optionally validating EAB.
// Returns the created account and whether it was freshly created (true) or
// already existed (false — same key registered twice, RFC 8555 §7.3.1).
func (s *Service) NewAccount(
	ctx context.Context,
	provisionerID uuid.UUID,
	jwk json.RawMessage,
	thumbprint string,
	contact []string,
	eabJWS *RawJWS,
	provisioner *storage.Provisioner,
) (*storage.ACMEAccount, bool, *Problem) {

	// Parse provisioner config to check EAB requirement.
	var cfg ProvisionerConfig
	_ = json.Unmarshal(mustMarshalJSON(provisioner.Config), &cfg)
	cfg.SetDefaults()
	if prob := validateContacts(contact); prob != nil {
		return nil, false, prob
	}

	// Check whether this key is already registered.
	existing, err := s.store.GetACMEAccountByKeyID(ctx, thumbprint)
	if err != nil {
		return nil, false, ErrServerInternalProblem("look up account: " + err.Error())
	}
	if existing != nil {
		// RFC 8555 §7.3.1: return existing account, status 200.
		return existing, false, nil
	}

	// Handle EAB.
	var eabID *uuid.UUID
	if cfg.EABRequired {
		if eabJWS == nil {
			return nil, false, ErrExternalAccountRequiredProblem()
		}
		id, prob := s.validateEAB(ctx, provisionerID, eabJWS, jwk)
		if prob != nil {
			return nil, false, prob
		}
		eabID = id
	}

	now := time.Now().UTC()
	account := &storage.ACMEAccount{
		ID:            uuid.New(),
		ProvisionerID: provisionerID,
		KeyID:         thumbprint,
		KeyJWK:        storage.JSON(mustUnmarshalRawJSON(jwk)),
		EABID:         eabID,
		Status:        storage.ACMEAccountStatusValid,
		Contact:       contact,
		CreatedAt:     now,
	}
	if err := s.store.CreateACMEAccount(ctx, account); err != nil {
		return nil, false, ErrServerInternalProblem("create account: " + err.Error())
	}
	return account, true, nil
}

// UpdateAccount handles account updates (contact changes / deactivation).
func (s *Service) UpdateAccount(
	ctx context.Context,
	account *storage.ACMEAccount,
	contact []string,
	deactivate bool,
) (*storage.ACMEAccount, *Problem) {
	if contact != nil {
		if prob := validateContacts(contact); prob != nil {
			return nil, prob
		}
	}
	if deactivate {
		if err := s.store.UpdateACMEAccountStatus(ctx, account.ID, storage.ACMEAccountStatusDeactivated); err != nil {
			return nil, ErrServerInternalProblem("deactivate account: " + err.Error())
		}
		account.Status = storage.ACMEAccountStatusDeactivated
		return account, nil
	}
	if contact != nil {
		if err := s.store.UpdateACMEAccountContact(ctx, account.ID, contact); err != nil {
			return nil, ErrServerInternalProblem("update contact: " + err.Error())
		}
		account.Contact = contact
	}
	return account, nil
}

// validateEAB verifies an External Account Binding JWS embedded in the
// new-account request payload.
//
// The EAB is a JWS where:
//   - the protected header carries "kid" = the EAB key ID (not an account URL)
//   - the payload is the account JWK (base64url-encoded)
//   - the signature uses HMAC-SHA256 with the EAB HMAC key from the database
//
// RFC 8555 §7.3.4.
func (s *Service) validateEAB(
	ctx context.Context,
	provisionerID uuid.UUID,
	eabJWS *RawJWS,
	accountJWK json.RawMessage,
) (*uuid.UUID, *Problem) {

	hdr, err := eabJWS.ParseProtected()
	if err != nil {
		return nil, ErrMalformedProblem("EAB: parse protected header: " + err.Error())
	}

	// The EAB kid is the credential key_id string (not a URL for EAB).
	eabKeyID := hdr.KID
	if eabKeyID == "" {
		return nil, ErrMalformedProblem("EAB: missing kid in protected header")
	}

	cred, err := s.store.GetEABCredential(ctx, eabKeyID)
	if err != nil {
		return nil, ErrServerInternalProblem("EAB: load credential: " + err.Error())
	}
	if cred == nil {
		return nil, ErrUnauthorizedProblem("EAB: unknown key ID " + eabKeyID)
	}
	if cred.ProvisionerID != provisionerID {
		return nil, ErrUnauthorizedProblem("EAB: credential does not belong to this provisioner")
	}
	if cred.Used {
		return nil, ErrUnauthorizedProblem("EAB: credential has already been used")
	}
	if cred.ExpiresAt != nil && time.Now().UTC().After(*cred.ExpiresAt) {
		return nil, ErrUnauthorizedProblem("EAB: credential has expired")
	}

	// Verify HMAC-SHA256 over protected + "." + payload.
	msg := []byte(eabJWS.Protected + "." + eabJWS.Payload)
	mac := hmac.New(sha256.New, cred.HMACKey)
	mac.Write(msg)
	expectedSig := mac.Sum(nil)

	gotSig, err := b64Decode(eabJWS.Signature)
	if err != nil {
		return nil, ErrMalformedProblem("EAB: decode signature: " + err.Error())
	}

	if !hmac.Equal(expectedSig, gotSig) {
		return nil, ErrUnauthorizedProblem("EAB: HMAC signature invalid")
	}

	// The payload must be the account JWK.
	payloadBytes, err := b64Decode(eabJWS.Payload)
	if err != nil {
		return nil, ErrMalformedProblem("EAB: decode payload: " + err.Error())
	}
	// Canonicalize both for comparison.
	var eabPayloadKey, acctKey interface{}
	if err := json.Unmarshal(payloadBytes, &eabPayloadKey); err != nil {
		return nil, ErrMalformedProblem("EAB: parse payload as JSON: " + err.Error())
	}
	if err := json.Unmarshal(accountJWK, &acctKey); err != nil {
		return nil, ErrMalformedProblem("EAB: parse account JWK as JSON: " + err.Error())
	}
	epBytes, _ := json.Marshal(eabPayloadKey)
	akBytes, _ := json.Marshal(acctKey)
	if string(epBytes) != string(akBytes) {
		return nil, ErrUnauthorizedProblem("EAB: payload does not match account JWK")
	}

	// Mark EAB as used.
	if err := s.store.MarkEABUsed(ctx, cred.ID); err != nil {
		return nil, ErrServerInternalProblem("EAB: mark used: " + err.Error())
	}

	return &cred.ID, nil
}

// NewOrder creates a new ACME order and its associated challenges.
func (s *Service) NewOrder(
	ctx context.Context,
	account *storage.ACMEAccount,
	provisioner *storage.Provisioner,
	identifiers []Identifier,
) (*storage.ACMEOrder, []*storage.ACMEChallenge, *Problem) {

	var cfg ProvisionerConfig
	_ = json.Unmarshal(mustMarshalJSON(provisioner.Config), &cfg)
	cfg.SetDefaults()

	// Validate identifiers — we only support DNS, plus wildcard shape checks.
	for _, id := range identifiers {
		if err := validateIdentifier(id); err != nil {
			return nil, nil, NewProblem(ErrRejectedIdentifier, 400, err.Error())
		}
	}

	// Build the identifier JSON for storage (order level).
	idObj := map[string]interface{}{"identifiers": identifiers}
	idJSON, err := json.Marshal(idObj)
	if err != nil {
		return nil, nil, ErrServerInternalProblem("marshal identifiers: " + err.Error())
	}
	var idsJSON storage.JSON
	if err := json.Unmarshal(idJSON, &idsJSON); err != nil {
		return nil, nil, ErrServerInternalProblem("unmarshal identifiers: " + err.Error())
	}

	now := time.Now().UTC()
	expiresAt := now.Add(24 * time.Hour)

	// Create the order.
	order := &storage.ACMEOrder{
		ID:          uuid.New(),
		AccountID:   account.ID,
		Status:      storage.ACMEOrderStatusPending,
		Identifiers: idsJSON,
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
	}
	if err := s.store.CreateACMEOrder(ctx, order); err != nil {
		return nil, nil, ErrServerInternalProblem("create order: " + err.Error())
	}

	// Create authorizations and challenges — reusing any valid, unexpired
	// standalone pre-authorization for this account+identifier if present.
	var allChallenges []*storage.ACMEChallenge
	for _, id := range identifiers {
		existing, err := s.store.GetACMEAuthorizationByIdentifier(ctx, account.ID, id.Type, id.Value)
		if err != nil {
			return nil, nil, ErrServerInternalProblem("look up pre-authorization: " + err.Error())
		}
		if existing != nil && existing.Status == storage.ACMEAuthorizationStatusValid && existing.ExpiresAt.After(now) {
			// Reuse: no new pending authz/challenges needed for this identifier.
			existingChallenges, err := s.store.ListChallengesByAuthorization(ctx, existing.ID)
			if err != nil {
				return nil, nil, ErrServerInternalProblem("list reused challenges: " + err.Error())
			}
			allChallenges = append(allChallenges, existingChallenges...)
			continue
		}

		// Create authorization for this identifier.
		authID := uuid.New()
		auth := &storage.ACMEAuthorization{
			ID:              authID,
			OrderID:         order.ID,
			AccountID:       account.ID,
			IdentifierType:  id.Type,
			IdentifierValue: id.Value,
			Status:          storage.ACMEAuthorizationStatusPending,
			ExpiresAt:       expiresAt,
			CreatedAt:       now,
		}
		if err := s.store.CreateACMEAuthorization(ctx, auth); err != nil {
			return nil, nil, ErrServerInternalProblem("create authorization: " + err.Error())
		}

		// Create challenges for each allowed type — wildcards get dns-01 only.
		for _, challType := range cfg.AllowedChallengeTypes {
			if IsWildcardIdentifier(id.Value) && challType != string(storage.ACMEChallengeTypeDNS01) {
				continue
			}
			token, err := generateToken()
			if err != nil {
				return nil, nil, ErrServerInternalProblem("generate challenge token: " + err.Error())
			}
			ch := &storage.ACMEChallenge{
				ID:              uuid.New(),
				OrderID:         order.ID,
				AuthorizationID: &authID,
				Type:            storage.ACMEChallengeType(challType),
				Token:           token,
				Status:          storage.ACMEChallengeStatusPending,
			}
			if err := s.store.CreateACMEChallenge(ctx, ch); err != nil {
				return nil, nil, ErrServerInternalProblem("create challenge: " + err.Error())
			}
			allChallenges = append(allChallenges, ch)
		}
	}

	return order, allChallenges, nil
}
func (s *Service) GetAuthorizationsForOrder(ctx context.Context, orderID uuid.UUID) ([]*storage.ACMEAuthorization, *Problem) {
	auths, err := s.store.ListAuthorizationsByOrder(ctx, orderID)
	if err != nil {
		return nil, ErrServerInternalProblem("list authorizations: " + err.Error())
	}
	return auths, nil
}

// GetOrder loads and returns an order. The caller must verify the account owns it.
func (s *Service) GetOrder(ctx context.Context, orderID uuid.UUID) (*storage.ACMEOrder, *Problem) {
	order, err := s.store.GetACMEOrder(ctx, orderID)
	if err != nil {
		return nil, ErrServerInternalProblem("load order: " + err.Error())
	}
	if order == nil {
		return nil, NewProblem(ErrMalformed, 404, "order not found")
	}
	return order, nil
}

func (s *Service) ValidateChallenge(
	ctx context.Context,
	account *storage.ACMEAccount,
	challengeID uuid.UUID,
) (*storage.ACMEChallenge, *Problem) {

	ch, err := s.store.GetACMEChallenge(ctx, challengeID)
	if err != nil {
		return nil, ErrServerInternalProblem("load challenge: " + err.Error())
	}
	if ch == nil {
		return nil, NewProblem(ErrMalformed, 404, "challenge not found")
	}
	if ch.Status != storage.ACMEChallengeStatusPending {
		return ch, nil
	}

	if ch.OrderID == uuid.Nil {
		// Standalone pre-authorization challenge — resolve ownership via the
		// authorization instead of an order.
		if ch.AuthorizationID == nil {
			return nil, ErrServerInternalProblem("standalone challenge has no authorization")
		}
		auth, err := s.store.GetACMEAuthorization(ctx, *ch.AuthorizationID)
		if err != nil {
			return nil, ErrServerInternalProblem("load authorization: " + err.Error())
		}
		if auth == nil {
			return nil, NewProblem(ErrMalformed, 404, "authorization not found")
		}
		if auth.AccountID != account.ID {
			return nil, ErrUnauthorizedProblem("challenge does not belong to your account")
		}

		go func() {
			time.Sleep(1 * time.Second)
			bgCtx := context.Background()
			s.performPreAuthValidation(bgCtx, account, ch, auth)
		}()

		return ch, nil
	}

	order, err := s.store.GetACMEOrder(ctx, ch.OrderID)
	if err != nil {
		return nil, ErrServerInternalProblem("load order: " + err.Error())
	}
	if order.AccountID != account.ID {
		return nil, ErrUnauthorizedProblem("challenge does not belong to your account")
	}

	go func() {
		time.Sleep(1 * time.Second)
		bgCtx := context.Background()
		s.performValidation(bgCtx, account, ch, order)
	}()

	return ch, nil
}

// performPreAuthValidation validates a standalone pre-authorization
// challenge. Unlike performValidation, there is no order to update — only
// the challenge and its authorization.
// enforceCAA checks the RFC 8659 CAA policy for the given identifier during
// validation and reports whether issuance is permitted. When no CAA checker
// is configured CAA is not enforced (always permitted). On a DNS lookup error
// the service fails open (log + permit) so a transient resolver hiccup does not
// break issuance; an explicit unsupported-critical or unmatched restrictor
// still denies.
func (s *Service) enforceCAA(ctx context.Context, identifier string) bool {
	if s.caa == nil || s.caa.identity == "" {
		return true
	}
	permitted, err := s.caa.Enforce(ctx, identifier)
	if err != nil {
		slog.Warn("caa: lookup failed, failing open", "identifier", identifier, "err", err)
		return true
	}
	return permitted
}

func (s *Service) performPreAuthValidation(
	ctx context.Context,
	account *storage.ACMEAccount,
	ch *storage.ACMEChallenge,
	auth *storage.ACMEAuthorization,
) {
	domain := auth.IdentifierValue

	acctJWKRaw, err := json.Marshal(account.KeyJWK)
	if err != nil {
		_ = s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusInvalid, nil)
		_ = s.store.UpdateACMEAuthorizationStatus(ctx, auth.ID, storage.ACMEAuthorizationStatusInvalid)
		return
	}
	keyAuth, err := KeyAuthorization(ch.Token, acctJWKRaw)
	if err != nil {
		_ = s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusInvalid, nil)
		_ = s.store.UpdateACMEAuthorizationStatus(ctx, auth.ID, storage.ACMEAuthorizationStatusInvalid)
		return
	}

	var valErr error
	switch ch.Type {
	case storage.ACMEChallengeTypeHTTP01:
		valErr = s.http01.Validate(ctx, domain, ch.Token, keyAuth)
	case storage.ACMEChallengeTypeDNS01:
		digest := DNS01DigestAuthorization(keyAuth)
		valErr = s.dns01.Validate(ctx, domain, digest)
	case storage.ACMEChallengeTypeTLSALPN01:
		valErr = s.tlsalpn01.Validate(ctx, domain, keyAuth)
	default:
		valErr = fmt.Errorf("unsupported challenge type %q", ch.Type)
	}

	now := time.Now().UTC()
	if valErr != nil {
		_ = s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusInvalid, nil)
		_ = s.store.UpdateACMEAuthorizationStatus(ctx, auth.ID, storage.ACMEAuthorizationStatusInvalid)
		return
	}

	// RFC 8659: refuse issuance when CAA does not authorise this CA for the
	// identifier, even though the challenge itself validated.
	if !s.enforceCAA(ctx, auth.IdentifierValue) {
		slog.Warn("caa: refused issuance for identifier", "identifier", auth.IdentifierValue)
		_ = s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusInvalid, nil)
		_ = s.store.UpdateACMEAuthorizationStatus(ctx, auth.ID, storage.ACMEAuthorizationStatusInvalid)
		return
	}

	if err := s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusValid, &now); err != nil {
		slog.Error("failed to update challenge status", "challenge_id", ch.ID, "err", err)
		return
	}

	if err := s.store.UpdateACMEAuthorizationStatus(ctx, auth.ID, storage.ACMEAuthorizationStatusValid); err != nil {
		slog.Error("failed to update authorization status", "auth_id", auth.ID, "err", err)
		return
	}

	slog.Info("pre-authorization challenge validated", "challenge_id", ch.ID, "auth_id", auth.ID)
}
func (s *Service) performValidation(
	ctx context.Context,
	account *storage.ACMEAccount,
	ch *storage.ACMEChallenge,
	order *storage.ACMEOrder,
) {
	identifiers, prob := s.parseOrderIdentifiers(order)
	if prob != nil || len(identifiers) == 0 {
		_ = s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusInvalid, nil)
		_ = s.store.UpdateACMEOrderStatus(ctx, order.ID, storage.ACMEOrderStatusInvalid)
		if ch.AuthorizationID != nil {
			_ = s.store.UpdateACMEAuthorizationStatus(ctx, *ch.AuthorizationID, storage.ACMEAuthorizationStatusInvalid)
		}
		return
	}

	domain := identifiers[0].Value

	acctJWKRaw, err := json.Marshal(account.KeyJWK)
	if err != nil {
		_ = s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusInvalid, nil)
		_ = s.store.UpdateACMEOrderStatus(ctx, order.ID, storage.ACMEOrderStatusInvalid)
		if ch.AuthorizationID != nil {
			_ = s.store.UpdateACMEAuthorizationStatus(ctx, *ch.AuthorizationID, storage.ACMEAuthorizationStatusInvalid)
		}
		return
	}
	keyAuth, err := KeyAuthorization(ch.Token, acctJWKRaw)
	if err != nil {
		_ = s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusInvalid, nil)
		_ = s.store.UpdateACMEOrderStatus(ctx, order.ID, storage.ACMEOrderStatusInvalid)
		if ch.AuthorizationID != nil {
			_ = s.store.UpdateACMEAuthorizationStatus(ctx, *ch.AuthorizationID, storage.ACMEAuthorizationStatusInvalid)
		}
		return
	}

	var valErr error
	switch ch.Type {
	case storage.ACMEChallengeTypeHTTP01:
		valErr = s.http01.Validate(ctx, domain, ch.Token, keyAuth)
	case storage.ACMEChallengeTypeDNS01:
		digest := DNS01DigestAuthorization(keyAuth)
		valErr = s.dns01.Validate(ctx, domain, digest)
	case storage.ACMEChallengeTypeTLSALPN01:
		valErr = s.tlsalpn01.Validate(ctx, domain, keyAuth)
	default:
		valErr = fmt.Errorf("unsupported challenge type %q", ch.Type)
	}

	now := time.Now().UTC()
	if valErr != nil {
		_ = s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusInvalid, nil)
		_ = s.store.UpdateACMEOrderStatus(ctx, order.ID, storage.ACMEOrderStatusInvalid)
		if ch.AuthorizationID != nil {
			_ = s.store.UpdateACMEAuthorizationStatus(ctx, *ch.AuthorizationID, storage.ACMEAuthorizationStatusInvalid)
		}
		return
	}

	// RFC 8659: refuse issuance when CAA does not authorise this CA for the
	// identifier, even though the challenge itself validated.
	if !s.enforceCAA(ctx, identifiers[0].Value) {
		slog.Warn("caa: refused issuance for identifier", "identifier", identifiers[0].Value)
		_ = s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusInvalid, nil)
		_ = s.store.UpdateACMEOrderStatus(ctx, order.ID, storage.ACMEOrderStatusInvalid)
		if ch.AuthorizationID != nil {
			_ = s.store.UpdateACMEAuthorizationStatus(ctx, *ch.AuthorizationID, storage.ACMEAuthorizationStatusInvalid)
		}
		return
	}

	// Challenge valid: update status
	if err := s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusValid, &now); err != nil {
		slog.Error("failed to update challenge status", "challenge_id", ch.ID, "err", err)
		return
	}

	slog.Info("challenge validated", "challenge_id", ch.ID, "auth_id", ch.AuthorizationID)

	// If the challenge belongs to an authorization, mark it valid immediately.
	if ch.AuthorizationID != nil {
		slog.Info("updating authorization status", "auth_id", *ch.AuthorizationID)
		if err := s.store.UpdateACMEAuthorizationStatus(ctx, *ch.AuthorizationID, storage.ACMEAuthorizationStatusValid); err != nil {
			slog.Error("failed to update authorization status", "auth_id", *ch.AuthorizationID, "err", err)
		} else {
			slog.Info("authorization status updated to valid", "auth_id", *ch.AuthorizationID)
		}
	} else {
		slog.Warn("challenge has no authorization ID", "challenge_id", ch.ID)
	}

	// Check if all authorizations for the order are valid
	auths, err := s.store.ListAuthorizationsByOrder(ctx, order.ID)
	if err != nil {
		slog.Error("failed to list authorizations", "order_id", order.ID, "err", err)
		return
	}
	slog.Info("authorizations for order", "order_id", order.ID, "auth_statuses", func() []string {
		var ss []string
		for _, a := range auths {
			ss = append(ss, string(a.Status))
		}
		return ss
	}())

	allAuthsValid := true
	for _, a := range auths {
		if a.Status != storage.ACMEAuthorizationStatusValid {
			allAuthsValid = false
			break
		}
	}
	if allAuthsValid {
		if err := s.store.UpdateACMEOrderStatus(ctx, order.ID, storage.ACMEOrderStatusReady); err != nil {
			slog.Error("failed to update order status to ready", "order_id", order.ID, "err", err)
		} else {
			slog.Info("order marked ready", "order_id", order.ID)
		}
	}
}
func (s *Service) ListOrders(ctx context.Context, accountID uuid.UUID) ([]*storage.ACMEOrder, *Problem) {
	orders, err := s.store.ListACMEOrdersByAccount(ctx, accountID)
	if err != nil {
		return nil, ErrServerInternalProblem("list orders: " + err.Error())
	}
	return orders, nil
}

// maybeReadyOrder checks whether every challenge for an order is valid and, if so, transitions the order to the "ready" state.
func (s *Service) maybeReadyOrder(ctx context.Context, orderID uuid.UUID) error {
	challenges, err := s.store.ListChallengesByOrder(ctx, orderID)
	if err != nil {
		return err
	}
	for _, ch := range challenges {
		if ch.Status == storage.ACMEChallengeStatusPending {
			return nil
		}
		if ch.Status == storage.ACMEChallengeStatusInvalid {
			// Order already set to invalid in ValidateChallenge.
			return nil
		}
	}
	return s.store.UpdateACMEOrderStatus(ctx, orderID, storage.ACMEOrderStatusReady)
}

// FinalizeOrder processes the CSR submitted by the ACME client, signs a certificate via the CA engine, and links it to the order.
func (s *Service) FinalizeOrder(
	ctx context.Context,
	account *storage.ACMEAccount,
	orderID uuid.UUID,
	csrDER []byte,
	caID uuid.UUID,
	provisionerID uuid.UUID,
	ttlSeconds int64,
) (*storage.ACMEOrder, *storage.Certificate, *Problem) {

	order, err := s.store.GetACMEOrder(ctx, orderID)
	if err != nil {
		return nil, nil, ErrServerInternalProblem("load order: " + err.Error())
	}
	if order == nil {
		return nil, nil, NewProblem(ErrMalformed, 404, "order not found")
	}
	if order.AccountID != account.ID {
		return nil, nil, ErrUnauthorizedProblem("order does not belong to your account")
	}
	if order.Status != storage.ACMEOrderStatusReady {
		return nil, nil, ErrOrderNotReadyProblem(
			fmt.Sprintf("order status is %q; must be \"ready\" before finalizing", order.Status))
	}

	// Encode CSR as PEM so we can pass it to the engine.
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Mark order as processing while we issue the cert.
	if err := s.store.UpdateACMEOrderStatus(ctx, order.ID, storage.ACMEOrderStatusProcessing); err != nil {
		return nil, nil, ErrServerInternalProblem("mark order processing: " + err.Error())
	}
	order.Status = storage.ACMEOrderStatusProcessing

	issued, err := s.engine.SignCSR(ctx, ca.SignCSRRequest{
		CAID:          caID,
		ProvisionerID: provisionerID,
		Requester:     fmt.Sprintf("acme-account:%s", account.ID),
		CSRPEM:        csrPEM,
		TTLSeconds:    ttlSeconds,
		Metadata:      storage.JSON{"acme_order_id": order.ID.String()},
	})
	if err != nil {
		// Revert to ready so the client can retry.
		_ = s.store.UpdateACMEOrderStatus(ctx, order.ID, storage.ACMEOrderStatusReady)
		return nil, nil, ErrBadCSRProblem("sign CSR failed: " + err.Error())
	}

	// Link the certificate to the order and mark it valid.
	if err := s.store.FinalizeACMEOrder(ctx, order.ID, issued.Record.ID); err != nil {
		return nil, nil, ErrServerInternalProblem("finalize order in store: " + err.Error())
	}
	order.Status = storage.ACMEOrderStatusValid
	certID := issued.Record.ID
	order.CertificateID = &certID

	return order, issued.Record, nil
}

// GetCertificate loads the full chain PEM for a finalized order's certificate.
func (s *Service) GetCertificate(
	ctx context.Context,
	account *storage.ACMEAccount,
	certID uuid.UUID,
) ([]byte, *Problem) {
	cert, err := s.store.GetCertificate(ctx, certID)
	if err != nil {
		return nil, ErrServerInternalProblem("load certificate: " + err.Error())
	}
	if cert == nil {
		return nil, NewProblem(ErrMalformed, 404, "certificate not found")
	}

	// Build the full chain via the engine.
	chainPEM, err := s.engine.GetChainPEM(ctx, cert.CAID)
	if err != nil {
		return nil, ErrServerInternalProblem("build chain: " + err.Error())
	}

	// Prepend the leaf cert to the chain.
	full := append([]byte(cert.CertPEM), chainPEM...)
	return full, nil
}

func (s *Service) AccountURL(provisionerID, accountID uuid.UUID) string {
	return fmt.Sprintf("%s/acme/%s/account/%s", s.baseURL, provisionerID, accountID)
}

func (s *Service) OrderURL(provisionerID, orderID uuid.UUID) string {
	return fmt.Sprintf("%s/acme/%s/order/%s", s.baseURL, provisionerID, orderID)
}

func (s *Service) FinalizeURL(provisionerID, orderID uuid.UUID) string {
	return fmt.Sprintf("%s/acme/%s/order/%s/finalize", s.baseURL, provisionerID, orderID)
}

func (s *Service) ChallengeURL(provisionerID, challengeID uuid.UUID) string {
	return fmt.Sprintf("%s/acme/%s/challenge/%s", s.baseURL, provisionerID, challengeID)
}

func (s *Service) CertificateURL(provisionerID, certID uuid.UUID) string {
	return fmt.Sprintf("%s/acme/%s/certificate/%s", s.baseURL, provisionerID, certID)
}

func (s *Service) RenewalInfoURL(provisionerID, certID uuid.UUID) string {
	return fmt.Sprintf("%s/acme/%s/renewal-info/%s", s.baseURL, provisionerID, certID)
}

// renewInfoFloor is the minimum lead time before NotAfter at which the renewal
// window opens, applied when the derived fraction would be smaller (short-lived
// certificates). RFC 9779 leaves the exact policy to the CA.
const renewInfoFloor = 24 * time.Hour

// renewInfoFraction is the fraction of a certificate's lifetime used as the
// default renewal lead time (1/5 = open renewing in the final 20%).
const renewInfoFraction = 0.2

// RenewalWindow is the RFC 9779 renewal window for a certificate.
type RenewalWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// RenewalInfo returns the RFC 9779 renewal window for the given certificate.
// The window closes at NotAfter and opens one lead-time earlier, where
// leadTime = override if >0, else max(lifetime*renewInfoFraction, renewInfoFloor),
// clamped to the lifetime. Returns nil if the certificate is not found.
func (s *Service) RenewalInfo(ctx context.Context, certID uuid.UUID, override time.Duration) (*RenewalWindow, *Problem) {
	cert, err := s.store.GetCertificate(ctx, certID)
	if err != nil {
		return nil, ErrServerInternalProblem("load certificate: " + err.Error())
	}
	if cert == nil {
		return nil, NewProblem(ErrMalformed, 404, "renewal info: certificate not found")
	}

	life := cert.NotAfter.Sub(cert.NotBefore)
	if life <= 0 {
		// Degenerate lifetime — open the window immediately.
		return &RenewalWindow{Start: cert.NotBefore, End: cert.NotAfter}, nil
	}

	lead := override
	if lead <= 0 {
		lead = time.Duration(float64(life) * renewInfoFraction)
		if lead < renewInfoFloor {
			lead = renewInfoFloor
		}
	}
	if lead > life {
		lead = life
	}

	end := cert.NotAfter
	start := end.Add(-lead)
	if start.Before(cert.NotBefore) {
		start = cert.NotBefore
	}
	return &RenewalWindow{Start: start, End: end}, nil
}

func (s *Service) AuthorizationURL(provisionerID, authID uuid.UUID) string {
	return fmt.Sprintf("%s/acme/%s/auth/%s", s.baseURL, provisionerID, authID)
}

// accountIDFromKID extracts the account UUID from a KID URL of the form:
//
//	{baseURL}/acme/{provisionerID}/account/{accountID}
func (s *Service) accountIDFromKID(kid string) (uuid.UUID, error) {
	// The account ID is always the last path segment.
	parts := strings.Split(strings.TrimRight(kid, "/"), "/")
	if len(parts) == 0 {
		return uuid.Nil, fmt.Errorf("empty kid")
	}
	return uuid.Parse(parts[len(parts)-1])
}
func IsWildcardIdentifier(value string) bool {
	return strings.HasPrefix(value, "*.")
}

func validateIdentifier(id Identifier) error {
	if id.Type != "dns" {
		return fmt.Errorf("identifier type %q is not supported", id.Type)
	}
	v := id.Value
	if v == "" {
		return fmt.Errorf("identifier value is empty")
	}
	if IsWildcardIdentifier(v) {
		rest := v[2:]
		if rest == "" || strings.HasPrefix(rest, "*.") || strings.Contains(rest, "*") {
			return fmt.Errorf("malformed wildcard identifier %q", v)
		}
		return nil
	}
	if strings.Contains(v, "*") {
		return fmt.Errorf("malformed identifier %q: bare wildcards not permitted", v)
	}
	return nil
}

// parseOrderIdentifiers extracts the []Identifier slice from an order's JSON.
func (s *Service) parseOrderIdentifiers(order *storage.ACMEOrder) ([]Identifier, *Problem) {
	raw, ok := order.Identifiers["identifiers"]
	if !ok {
		return nil, ErrServerInternalProblem("order identifiers missing")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, ErrServerInternalProblem("marshal identifiers: " + err.Error())
	}
	var ids []Identifier
	if err := json.Unmarshal(b, &ids); err != nil {
		return nil, ErrServerInternalProblem("parse identifiers: " + err.Error())
	}
	return ids, nil
}

// generateToken creates a fresh 32-byte random token encoded as base64url.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := generateRandomBytes(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateRandomBytes(b []byte) (int, error) {
	return rand.Read(b)
}

func mustMarshalJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
func validateContacts(contacts []string) *Problem {
	for _, c := range contacts {
		u, err := url.Parse(c)
		if err != nil {
			return ErrInvalidContactProblem(fmt.Sprintf("contact %q is not a valid URI: %v", c, err))
		}
		if u.Scheme == "" {
			return ErrInvalidContactProblem(fmt.Sprintf("contact %q must be a URI with a scheme", c))
		}
		if u.Scheme != "mailto" {
			return ErrUnsupportedContactProblem(fmt.Sprintf("contact scheme %q is not supported; only mailto: is accepted", u.Scheme))
		}
		if u.Opaque == "" {
			return ErrInvalidContactProblem(fmt.Sprintf("contact %q has an empty mailto address", c))
		}
		if strings.Contains(u.Opaque, ",") {
			return ErrInvalidContactProblem(fmt.Sprintf("contact %q must not contain multiple addresses", c))
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return ErrInvalidContactProblem(fmt.Sprintf("contact %q must not contain hfields or a fragment", c))
		}
	}
	return nil
}

func mustUnmarshalRawJSON(b []byte) map[string]interface{} {
	var v map[string]interface{}
	_ = json.Unmarshal(b, &v)
	return v
}
