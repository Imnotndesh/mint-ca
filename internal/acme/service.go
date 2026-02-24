package acme

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"mint-ca/internal/acme/challenge"
	"mint-ca/internal/ca"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// -------------------- config --------------------

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

// -------------------- identifier --------------------

// Identifier is an ACME order identifier (RFC 8555 §7.1.3).
type Identifier struct {
	Type  string `json:"type"`  // always "dns" for now
	Value string `json:"value"` // e.g. "example.com" or "*.example.com"
}

// -------------------- service inputs/outputs --------------------

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

// -------------------- service --------------------

// Store is the minimal storage.Store surface the service needs.
// Using the full interface is fine — this alias just documents the dependency.
type Store interface {
	storage.Store
	NonceStore
}

// Service provides all ACME business logic.
type Service struct {
	store   Store
	engine  *ca.Engine
	nonces  *NonceManager
	http01  *challenge.HTTP01Validator
	dns01   *challenge.DNS01Validator
	baseURL string
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
	baseURL string,
) *Service {
	return &Service{
		store:   store,
		engine:  engine,
		nonces:  nonces,
		http01:  challenge.NewHTTP01Validator(),
		dns01:   challenge.NewDNS01Validator(nil),
		baseURL: strings.TrimRight(baseURL, "/"),
	}
}

// -------------------- nonce helpers --------------------

// IssueNonce generates and persists a fresh nonce.
func (s *Service) IssueNonce(ctx context.Context) (string, error) {
	return s.nonces.Issue(ctx)
}

// -------------------- JWS auth helpers --------------------

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

	// Reconstruct the public key from the stored JWK.
	jwkBytes, err := json.Marshal(account.KeyJWK)
	if err != nil {
		return nil, ErrServerInternalProblem("marshal stored account key: " + err.Error())
	}

	pub, err := ParseJWK(jwkBytes)
	if err != nil {
		return nil, ErrServerInternalProblem("parse stored account key: " + err.Error())
	}

	// Determine algorithm from the alg field in the protected header.
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
// This prevents cross-endpoint replay attacks (RFC 8555 §6.4).
func (s *Service) ValidateURL(hdr *ProtectedHeader, requestURL string) *Problem {
	// Normalise: strip trailing slash for comparison.
	want := strings.TrimRight(requestURL, "/")
	got := strings.TrimRight(hdr.URL, "/")
	if want != got {
		return ErrMalformedProblem(fmt.Sprintf("JWS url %q does not match request URL %q", got, want))
	}
	return nil
}

// -------------------- account operations --------------------

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

// -------------------- EAB validation --------------------

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

// -------------------- order operations --------------------

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

	// Validate identifiers — we only support DNS.
	for _, id := range identifiers {
		if id.Type != "dns" {
			return nil, nil, NewProblem(ErrUnsupportedIdentifier, 400,
				fmt.Sprintf("identifier type %q is not supported — only \"dns\" is accepted", id.Type))
		}
	}

	// Build the identifier JSON for storage.
	idJSON, _ := json.Marshal(identifiers)

	now := time.Now().UTC()
	order := &storage.ACMEOrder{
		ID:          uuid.New(),
		AccountID:   account.ID,
		Status:      storage.ACMEOrderStatusPending,
		Identifiers: storage.JSON{"identifiers": mustUnmarshalRawJSON(idJSON)},
		ExpiresAt:   now.Add(24 * time.Hour), // order expires if not finalized
		CreatedAt:   now,
	}
	if err := s.store.CreateACMEOrder(ctx, order); err != nil {
		return nil, nil, ErrServerInternalProblem("create order: " + err.Error())
	}

	// Create one challenge of each supported/allowed type per identifier.
	var allChallenges []*storage.ACMEChallenge
	for _, id := range identifiers {
		for _, challType := range cfg.AllowedChallengeTypes {
			token, err := generateToken()
			if err != nil {
				return nil, nil, ErrServerInternalProblem("generate challenge token: " + err.Error())
			}
			ch := &storage.ACMEChallenge{
				ID:      uuid.New(),
				OrderID: order.ID,
				Type:    storage.ACMEChallengeType(challType),
				Token:   token,
				Status:  storage.ACMEChallengeStatusPending,
			}
			if err := s.store.CreateACMEChallenge(ctx, ch); err != nil {
				return nil, nil, ErrServerInternalProblem("create challenge: " + err.Error())
			}
			// Annotate for the response — the identifier is needed by the handler
			// to construct the authorization object.
			_ = id // handler will group by order
			allChallenges = append(allChallenges, ch)
		}
	}

	return order, allChallenges, nil
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

// ValidateChallenge is called when the client POSTs to a challenge URL to
// indicate it is ready. We perform the actual validation asynchronously
// (in the same goroutine for simplicity — a production system might queue it)
// and update the challenge and order statuses.
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
		// Already validated or invalid — return current state.
		return ch, nil
	}

	// Load the order to find the identifier for this challenge.
	order, err := s.store.GetACMEOrder(ctx, ch.OrderID)
	if err != nil {
		return nil, ErrServerInternalProblem("load order for challenge: " + err.Error())
	}
	if order.AccountID != account.ID {
		return nil, ErrUnauthorizedProblem("challenge does not belong to your account")
	}

	// Extract the identifier value (domain) from the order.
	// Identifiers are stored as JSON: {"identifiers": [{type, value}, ...]}
	identifiers, prob := s.parseOrderIdentifiers(order)
	if prob != nil {
		return nil, prob
	}
	if len(identifiers) == 0 {
		return nil, ErrServerInternalProblem("order has no identifiers")
	}

	// For simplicity we validate against the first identifier.
	// In practice, each challenge is tied to one identifier; a more complete
	// implementation would store the identifier alongside the challenge.
	// This works correctly when there is one identifier per order (the common case).
	domain := identifiers[0].Value

	// Compute the key authorization.
	acctJWKRaw, err := json.Marshal(account.KeyJWK)
	if err != nil {
		return nil, ErrServerInternalProblem("marshal account JWK: " + err.Error())
	}
	keyAuth, err := KeyAuthorization(ch.Token, acctJWKRaw)
	if err != nil {
		return nil, ErrServerInternalProblem("compute key authorization: " + err.Error())
	}

	// Perform the actual validation.
	var valErr error
	switch ch.Type {
	case storage.ACMEChallengeTypeHTTP01:
		valErr = s.http01.Validate(ctx, domain, ch.Token, keyAuth)
	case storage.ACMEChallengeTypeDNS01:
		digest := DNS01DigestAuthorization(keyAuth)
		valErr = s.dns01.Validate(ctx, domain, digest)
	default:
		valErr = fmt.Errorf("unsupported challenge type %q", ch.Type)
	}

	now := time.Now().UTC()
	if valErr != nil {
		// Mark the challenge invalid.
		_ = s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusInvalid, nil)
		// Mark the order invalid too.
		_ = s.store.UpdateACMEOrderStatus(ctx, order.ID, storage.ACMEOrderStatusInvalid)
		ch.Status = storage.ACMEChallengeStatusInvalid
		// Return the challenge with its new status — no *Problem; the client
		// can inspect the challenge to understand what went wrong.
		return ch, nil
	}

	// Mark challenge valid.
	if err := s.store.UpdateChallengeStatus(ctx, ch.ID, storage.ACMEChallengeStatusValid, &now); err != nil {
		return nil, ErrServerInternalProblem("update challenge: " + err.Error())
	}
	ch.Status = storage.ACMEChallengeStatusValid
	ch.ValidatedAt = &now

	// Check if all challenges for this order are now valid; if so, promote
	// the order to "ready".
	if err := s.maybeReadyOrder(ctx, order.ID); err != nil {
		// Non-fatal — the client can re-poll the order to see its true state.
		_ = err
	}

	return ch, nil
}

// maybeReadyOrder checks whether every challenge for an order is valid and,
// if so, transitions the order to the "ready" state.
func (s *Service) maybeReadyOrder(ctx context.Context, orderID uuid.UUID) error {
	challenges, err := s.store.ListChallengesByOrder(ctx, orderID)
	if err != nil {
		return err
	}
	// We consider the order ready when at least one challenge per identifier
	// type grouping is valid. For simplicity: if ANY challenge is still pending,
	// we stay in "pending". If all are valid, we go to "ready".
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

// -------------------- finalize / certificate --------------------

// FinalizeOrder processes the CSR submitted by the ACME client, signs a
// certificate via the CA engine, and links it to the order.
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

// -------------------- URL helpers --------------------

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

func (s *Service) AuthorizationURL(provisionerID, orderID uuid.UUID, idx int) string {
	return fmt.Sprintf("%s/acme/%s/order/%s/auth/%d", s.baseURL, provisionerID, orderID, idx)
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

// -------------------- private helpers --------------------

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

func mustUnmarshalRawJSON(b []byte) map[string]interface{} {
	var v map[string]interface{}
	_ = json.Unmarshal(b, &v)
	return v
}
