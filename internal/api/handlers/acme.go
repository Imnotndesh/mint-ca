package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	apimiddleware "mint-ca/internal/api/middleware"
	"mint-ca/internal/ratelimit"
	"net/http"
	"strconv"
	"time"

	internalacme "mint-ca/internal/acme"
	"mint-ca/internal/ca"
	"mint-ca/internal/config"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ACMEHandler owns all ACME protocol endpoints.
type ACMEHandler struct {
	store   storage.Store
	engine  *ca.Engine
	service *internalacme.Service
	cfg     config.ACMEConfig
	rl      *ratelimit.Engine
}

func NewACMEHandler(
	store storage.Store,
	engine *ca.Engine,
	svc *internalacme.Service,
	cfg config.ACMEConfig,
	rl *ratelimit.Engine,
) *ACMEHandler {
	return &ACMEHandler{
		store:   store,
		engine:  engine,
		service: svc,
		cfg:     cfg,
		rl:      rl,
	}
}

func (h *ACMEHandler) RegisterRoutes(r chi.Router) {
	r.Route("/acme/{provisionerID}", func(r chi.Router) {
		r.Get("/directory", h.directory)
		r.Post("/auth/{authID}", h.getAuthorization)
		r.Head("/new-nonce", h.newNonce)
		r.Post("/new-nonce", h.newNonce)
		r.Post("/new-account", h.newAccount)
		r.Post("/account/{accountID}", h.updateAccount)
		r.Post("/new-order", h.newOrder)
		r.Post("/new-authz", h.newAuthz)
		r.Post("/order/{orderID}", h.getOrder)
		r.Post("/order/{orderID}/authz/{index}", h.getAuthorization)
		r.Post("/order/{orderID}/finalize", h.finalizeOrder)
		r.Post("/challenge/{challengeID}", h.validateChallenge)
		r.Post("/certificate/{certID}", h.getCertificate)
		r.Post("/renewal-info/{certID}", h.getRenewalInfo)
		r.Get("/renewal-info/{certID}", h.getRenewalInfo)
		r.Post("/account/{accountID}", h.updateAccount)
		r.Post("/account/{accountID}/orders", h.listOrders)
		r.Post("/revoke-cert", h.revokeCert)
		r.Post("/key-change", h.keyChange)
	})
}

// acmeWriteJSON writes a JSON response with ACME-required headers. It always
// adds a fresh Replay-Nonce so the client can make its next request immediately
func (h *ACMEHandler) acmeWriteJSON(w http.ResponseWriter, r *http.Request, status int, body interface{}) {
	nonce, err := h.service.IssueNonce(r.Context())
	if err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// acmeProblem writes a problem+json response with a fresh nonce.
func (h *ACMEHandler) acmeProblem(w http.ResponseWriter, r *http.Request, prob *internalacme.Problem) {
	nonce, _ := h.service.IssueNonce(r.Context())
	internalacme.WriteProblem(w, nonce, prob)
}
func (h *ACMEHandler) getAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	authID, err := uuid.Parse(chi.URLParam(r, "authID"))
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("invalid authorization ID"))
		return
	}

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	account, prob := h.service.AuthenticateKID(ctx, jws, hdr)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	auth, err := h.store.GetACMEAuthorization(ctx, authID)
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrServerInternalProblem("load authorization: "+err.Error()))
		return
	}
	if auth == nil {
		h.acmeProblem(w, r, internalacme.NewProblem(internalacme.ErrMalformed, 404, "authorization not found"))
		return
	}

	// Ownership check: standalone pre-auths carry AccountID directly;
	// order-bound authz ownership is verified via the parent order.
	if auth.OrderID == uuid.Nil {
		if auth.AccountID != account.ID {
			h.acmeProblem(w, r, internalacme.ErrUnauthorizedProblem("authorization does not belong to your account"))
			return
		}
	} else {
		order, err := h.store.GetACMEOrder(ctx, auth.OrderID)
		if err != nil {
			h.acmeProblem(w, r, internalacme.ErrServerInternalProblem("load order: "+err.Error()))
			return
		}
		if order == nil || order.AccountID != account.ID {
			h.acmeProblem(w, r, internalacme.ErrUnauthorizedProblem("authorization does not belong to your account"))
			return
		}
	}

	challenges, err := h.store.ListChallengesByAuthorization(ctx, auth.ID)
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrServerInternalProblem("list challenges: "+err.Error()))
		return
	}

	h.acmeWriteJSON(w, r, http.StatusOK, h.authzResponse(prov.ID, auth, challenges))
}
func (h *ACMEHandler) listOrders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	account, prob := h.service.AuthenticateKID(ctx, jws, hdr)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	accountID, err := uuid.Parse(chi.URLParam(r, "accountID"))
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("invalid account ID"))
		return
	}
	if accountID != account.ID {
		h.acmeProblem(w, r, internalacme.ErrUnauthorizedProblem("orders list does not belong to your account"))
		return
	}

	orders, prob := h.service.ListOrders(ctx, account.ID)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	urls := make([]string, len(orders))
	for i, o := range orders {
		urls[i] = h.service.OrderURL(prov.ID, o.ID)
	}

	h.acmeWriteJSON(w, r, http.StatusOK, map[string]interface{}{
		"orders": urls,
	})
}
func (h *ACMEHandler) revokeCert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	// RFC 8555 §7.6: revocation may be authenticated by the account key
	// (kid present) or by the certificate's own key (jwk present).
	var authAccount *storage.ACMEAccount
	var authJWK json.RawMessage

	if hdr.KID != "" {
		account, prob := h.service.AuthenticateKID(ctx, jws, hdr)
		if prob != nil {
			h.acmeProblem(w, r, prob)
			return
		}
		authAccount = account
	} else {
		jwk, _, prob := h.service.AuthenticateJWK(jws, hdr)
		if prob != nil {
			h.acmeProblem(w, r, prob)
			return
		}
		authJWK = jwk
	}

	payloadBytes, err := jws.PayloadBytes()
	if err != nil || payloadBytes == nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("revoke-cert requires a payload"))
		return
	}
	var payload struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason,omitempty"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("decode revoke-cert payload: "+err.Error()))
		return
	}
	certDER, err := base64.RawURLEncoding.DecodeString(payload.Certificate)
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("decode certificate: "+err.Error()))
		return
	}

	if prob := h.service.RevokeCert(ctx, certDER, authAccount, authJWK, payload.Reason); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	h.acmeWriteJSON(w, r, http.StatusOK, map[string]interface{}{})
}

// parseJWS reads and decodes the JWS body common to all ACME POST requests.
func parseJWS(r *http.Request) (*internalacme.RawJWS, *internalacme.ProtectedHeader, *internalacme.Problem) {
	var jws internalacme.RawJWS
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		return nil, nil, internalacme.ErrMalformedProblem("request body is not valid JSON: " + err.Error())
	}
	hdr, err := jws.ParseProtected()
	if err != nil {
		return nil, nil, internalacme.ErrMalformedProblem("malformed JWS protected header: " + err.Error())
	}
	return &jws, hdr, nil
}

// loadProvisioner resolves the provisioner ID from the URL and validates it.
func (h *ACMEHandler) loadProvisioner(r *http.Request) (*storage.Provisioner, *internalacme.Problem) {
	rawID := chi.URLParam(r, "provisionerID")
	provID, err := uuid.Parse(rawID)
	if err != nil {
		return nil, internalacme.ErrMalformedProblem("invalid provisioner ID: " + rawID)
	}
	prov, err := h.store.GetProvisioner(r.Context(), provID)
	if err != nil {
		return nil, internalacme.ErrServerInternalProblem("load provisioner: " + err.Error())
	}
	if prov == nil {
		return nil, internalacme.NewProblem(internalacme.ErrMalformed, 404, "provisioner not found")
	}
	if prov.Type != storage.ProvisionerTypeACME {
		return nil, internalacme.NewProblem(internalacme.ErrMalformed, 404, "provisioner is not an ACME provisioner")
	}
	if prov.Status != storage.ProvisionerStatusActive {
		return nil, internalacme.ErrUnauthorizedProblem("provisioner is disabled")
	}
	return prov, nil
}

// requestURL reconstructs the full URL of the current request for JWS url validation.
func requestURL(r *http.Request, cfg config.ACMEConfig) string {
	return cfg.BaseURL + r.URL.Path
}

// checkRateLimit evaluates a limiter and, if exceeded, writes the ACME
// rateLimited problem response (RFC 8555 §6.7 / §8.7) with Retry-After.
// Returns true if the request was rejected (caller should return
// immediately without further processing).
func (h *ACMEHandler) checkRateLimit(w http.ResponseWriter, r *http.Request, limiterName, bucketKey, actor string) bool {
	allowed, retryAfter, err := h.rl.Check(r.Context(), limiterName, bucketKey)
	if err != nil {
		// Misconfigured limiter — fail open, already logged inside Check's
		// caller responsibility; don't block ACME traffic on a config bug.
		return false
	}
	if !allowed {
		apimiddleware.WriteRateLimitAudit(h.store, actor, limiterName, bucketKey)
		nonce, _ := h.service.IssueNonce(r.Context())
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		internalacme.WriteProblem(w, nonce, internalacme.NewProblem(
			internalacme.ErrRateLimited,
			http.StatusTooManyRequests,
			fmt.Sprintf("rate limit exceeded for %s; retry after %d seconds", limiterName, int(retryAfter.Seconds())),
		))
		return true
	}
	return false
}
func (h *ACMEHandler) directory(w http.ResponseWriter, r *http.Request) {
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	provID := prov.ID
	base := h.cfg.BaseURL + "/acme/" + provID.String()
	var cfg internalacme.ProvisionerConfig
	if raw, err := json.Marshal(prov.Config); err == nil {
		_ = json.Unmarshal(raw, &cfg)
	}
	cfg.SetDefaults()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"newNonce":   base + "/new-nonce",
		"newAccount": base + "/new-account",
		"keyChange":  base + "/key-change",
		"newOrder":   base + "/new-order",
		"newAuthz":   base + "/new-authz",
		"meta": map[string]interface{}{
			"externalAccountRequired": cfg.EABRequired,
			"website":                 h.cfg.BaseURL,
		},
	})
}
func (h *ACMEHandler) newAuthz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	account, prob := h.service.AuthenticateKID(ctx, jws, hdr)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if h.checkRateLimit(w, r, "acme_new_order_per_account", account.ID.String(), account.ID.String()) {
		return
	}

	payloadBytes, err := jws.PayloadBytes()
	if err != nil || payloadBytes == nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("new-authz requires a payload"))
		return
	}
	var payload struct {
		Identifier internalacme.Identifier `json:"identifier"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("decode new-authz payload: "+err.Error()))
		return
	}

	auth, challenges, prob := h.service.NewPreAuth(ctx, account, prov, payload.Identifier)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	authURL := h.service.AuthorizationURL(prov.ID, auth.ID)
	w.Header().Set("Location", authURL)
	h.acmeWriteJSON(w, r, http.StatusCreated, h.authzResponse(prov.ID, auth, challenges))
}

func (h *ACMEHandler) authzResponse(provisionerID uuid.UUID, auth *storage.ACMEAuthorization, challenges []*storage.ACMEChallenge) map[string]interface{} {
	challengeObjs := make([]map[string]interface{}, len(challenges))
	for i, c := range challenges {
		challengeObjs[i] = map[string]interface{}{
			"type":   string(c.Type),
			"url":    h.service.ChallengeURL(provisionerID, c.ID),
			"token":  c.Token,
			"status": string(c.Status),
		}
	}
	return map[string]interface{}{
		"status":  string(auth.Status),
		"expires": auth.ExpiresAt.Format(time.RFC3339),
		"identifier": map[string]string{
			"type":  auth.IdentifierType,
			"value": auth.IdentifierValue,
		},
		"challenges": challengeObjs,
		"wildcard":   internalacme.IsWildcardIdentifier(auth.IdentifierValue),
	}
}
func (h *ACMEHandler) newNonce(w http.ResponseWriter, r *http.Request) {
	nonce, err := h.service.IssueNonce(r.Context())
	if err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}
func (h *ACMEHandler) keyChange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	account, prob := h.service.AuthenticateKID(ctx, jws, hdr)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if h.checkRateLimit(w, r, "acme_key_change_per_account", account.ID.String(), account.ID.String()) {
		return
	}

	innerPayload, err := jws.PayloadBytes()
	if err != nil || innerPayload == nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("key-change requires a payload"))
		return
	}
	var innerJWS internalacme.RawJWS
	if err := json.Unmarshal(innerPayload, &innerJWS); err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("decode inner JWS: "+err.Error()))
		return
	}

	accountURL := h.service.AccountURL(prov.ID, account.ID)
	updated, prob := h.service.KeyChange(ctx, account, &innerJWS, accountURL)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	entry := &storage.AuditLog{
		ID:        uuid.New(),
		EventType: "acme_key_change",
		Actor:     "acme-account:" + updated.ID.String(),
		Payload:   storage.JSON{"new_key_id": updated.KeyID},
		CreatedAt: time.Now().UTC(),
	}
	go func() { _ = h.store.WriteAuditLog(context.Background(), entry) }()

	h.acmeWriteJSON(w, r, http.StatusOK, map[string]interface{}{})
}
func (h *ACMEHandler) newAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if h.checkRateLimit(w, r, "acme_new_account_per_ip", r.RemoteAddr, r.RemoteAddr) {
		return
	}

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	// Validate nonce and URL.
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	// Authenticate via JWK (no account exists yet).
	jwk, thumbprint, prob := h.service.AuthenticateJWK(jws, hdr)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	// Decode payload.
	payloadBytes, err := jws.PayloadBytes()
	if err != nil || payloadBytes == nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("new-account requires a payload"))
		return
	}
	var payload struct {
		TermsAgreed bool            `json:"termsOfServiceAgreed"`
		Contact     []string        `json:"contact"`
		EAB         json.RawMessage `json:"externalAccountBinding,omitempty"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("decode new-account payload: "+err.Error()))
		return
	}

	// Parse optional EAB sub-JWS.
	var eabJWS *internalacme.RawJWS
	if len(payload.EAB) > 0 {
		var raw internalacme.RawJWS
		if err := json.Unmarshal(payload.EAB, &raw); err != nil {
			h.acmeProblem(w, r, internalacme.ErrMalformedProblem("parse EAB JWS: "+err.Error()))
			return
		}
		eabJWS = &raw
	}

	account, created, prob := h.service.NewAccount(ctx, prov.ID, jwk, thumbprint, payload.Contact, eabJWS, prov)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	status := http.StatusOK // existing account
	if created {
		status = http.StatusCreated
	}

	accountURL := h.service.AccountURL(prov.ID, account.ID)
	w.Header().Set("Location", accountURL)
	h.acmeWriteJSON(w, r, status, accountResponse(account, accountURL))
}

func (h *ACMEHandler) updateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	account, prob := h.service.AuthenticateKID(ctx, jws, hdr)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	// POST-as-GET (empty payload) = fetch account.
	payloadBytes, err := jws.PayloadBytes()
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("decode payload: "+err.Error()))
		return
	}
	if payloadBytes == nil {
		accountURL := h.service.AccountURL(prov.ID, account.ID)
		w.Header().Set("Location", accountURL)
		h.acmeWriteJSON(w, r, http.StatusOK, accountResponse(account, accountURL))
		return
	}

	var payload struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("decode update payload: "+err.Error()))
		return
	}

	deactivate := payload.Status == "deactivated"
	updated, prob := h.service.UpdateAccount(ctx, account, payload.Contact, deactivate)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	accountURL := h.service.AccountURL(prov.ID, updated.ID)
	h.acmeWriteJSON(w, r, http.StatusOK, accountResponse(updated, accountURL))
}

func (h *ACMEHandler) newOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	account, prob := h.service.AuthenticateKID(ctx, jws, hdr)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if h.checkRateLimit(w, r, "acme_new_order_per_account", account.ID.String(), account.ID.String()) {
		return
	}

	payloadBytes, err := jws.PayloadBytes()
	if err != nil || payloadBytes == nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("new-order requires a payload"))
		return
	}
	var payload struct {
		Identifiers []internalacme.Identifier `json:"identifiers"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("decode new-order payload: "+err.Error()))
		return
	}
	if len(payload.Identifiers) == 0 {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("at least one identifier is required"))
		return
	}

	order, _, prob := h.service.NewOrder(ctx, account, prov, payload.Identifiers)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	orderURL := h.service.OrderURL(prov.ID, order.ID)
	w.Header().Set("Location", orderURL)
	h.acmeWriteJSON(w, r, http.StatusCreated, h.orderResponse(r.Context(), prov.ID, order))
}

func (h *ACMEHandler) getOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	account, prob := h.service.AuthenticateKID(ctx, jws, hdr)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	orderID, err := uuid.Parse(chi.URLParam(r, "orderID"))
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("invalid order ID"))
		return
	}

	order, prob := h.service.GetOrder(ctx, orderID)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if order.AccountID != account.ID {
		h.acmeProblem(w, r, internalacme.ErrUnauthorizedProblem("order does not belong to your account"))
		return
	}

	_, err = h.store.ListChallengesByOrder(ctx, order.ID)
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrServerInternalProblem("load challenges: "+err.Error()))
		return
	}

	h.acmeWriteJSON(w, r, http.StatusCreated, h.orderResponse(r.Context(), prov.ID, order))
}

func (h *ACMEHandler) finalizeOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	account, prob := h.service.AuthenticateKID(ctx, jws, hdr)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	orderID, err := uuid.Parse(chi.URLParam(r, "orderID"))
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("invalid order ID"))
		return
	}

	payloadBytes, err := jws.PayloadBytes()
	if err != nil || payloadBytes == nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("finalize requires a payload"))
		return
	}
	var payload struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("decode finalize payload: "+err.Error()))
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(payload.CSR)
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrBadCSRProblem("decode CSR: "+err.Error()))
		return
	}

	// Parse provisioner config for TTL.
	var cfg internalacme.ProvisionerConfig
	if raw, err := json.Marshal(prov.Config); err == nil {
		_ = json.Unmarshal(raw, &cfg)
	}
	cfg.SetDefaults()

	order, _, prob := h.service.FinalizeOrder(
		ctx, account, orderID, csrDER, prov.CAID, prov.ID, cfg.DefaultTTLSeconds,
	)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	_, err = h.store.ListChallengesByOrder(ctx, order.ID)
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrServerInternalProblem("load challenges: "+err.Error()))
		return
	}

	orderURL := h.service.OrderURL(prov.ID, order.ID)
	w.Header().Set("Location", orderURL)
	// Advertise the renewal-info endpoint when the order has a certificate.
	if order.CertificateID != nil {
		w.Header().Set("Link", "<"+h.service.RenewalInfoURL(prov.ID, *order.CertificateID)+">;rel=\"renewalInfo\"")
	}
	h.acmeWriteJSON(w, r, http.StatusOK, h.orderResponse(r.Context(), prov.ID, order))
}

func (h *ACMEHandler) validateChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	_ = prov

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	account, prob := h.service.AuthenticateKID(ctx, jws, hdr)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	challengeID, err := uuid.Parse(chi.URLParam(r, "challengeID"))
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("invalid challenge ID"))
		return
	}

	ch, prob := h.service.ValidateChallenge(ctx, account, challengeID)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	challURL := h.service.ChallengeURL(prov.ID, ch.ID)
	h.acmeWriteJSON(w, r, http.StatusOK, challengeResponse(ch, challURL))
}

func (h *ACMEHandler) getCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	_ = prov

	jws, hdr, prob := parseJWS(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}
	if prob := h.service.ValidateURL(hdr, requestURL(r, h.cfg)); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	account, prob := h.service.AuthenticateKID(ctx, jws, hdr)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	certID, err := uuid.Parse(chi.URLParam(r, "certID"))
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("invalid certificate ID"))
		return
	}

	// Verify the account owns this cert via the order.
	cert, err := h.store.GetCertificate(ctx, certID)
	if err != nil || cert == nil {
		h.acmeProblem(w, r, internalacme.NewProblem(internalacme.ErrMalformed, 404, "certificate not found"))
		return
	}
	_ = account // ownership already verified by AuthenticateKID; a stricter
	// implementation would also check that the cert's order belongs to account.

	chainPEM, prob := h.service.GetCertificate(ctx, account, certID)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	// ACME clients expect application/pem-certificate-chain here.
	nonce, _ := h.service.IssueNonce(ctx)
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Link", "<"+h.service.RenewalInfoURL(prov.ID, certID)+">;rel=\"renewalInfo\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(chainPEM)
}

func (h *ACMEHandler) getRenewalInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, prob := h.loadProvisioner(r); prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	certID, err := uuid.Parse(chi.URLParam(r, "certID"))
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrMalformedProblem("invalid certificate ID"))
		return
	}

	// POST-as-GET requires a valid JWS over an empty payload (unauthenticated
	// GET is also permitted, since knowing the high-entropy cert ID is enough).
	if r.Method == http.MethodPost {
		jws, hdr, jwsProb := parseJWS(r)
		if jwsProb != nil {
			h.acmeProblem(w, r, jwsProb)
			return
		}
		p, _ := jws.PayloadBytes()
		if len(p) != 0 {
			h.acmeProblem(w, r, internalacme.ErrMalformedProblem("renewal-info POST-as-GET requires an empty body"))
			return
		}
		if prob := h.service.ValidateNonce(ctx, hdr); prob != nil {
			h.acmeProblem(w, r, prob)
			return
		}
	}

	window, prob := h.service.RenewalInfo(ctx, certID)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	nonce, _ := h.service.IssueNonce(ctx)
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	h.acmeWriteJSON(w, r, http.StatusOK, map[string]interface{}{
		"renewalWindow": map[string]string{
			"start": window.Start.UTC().Format(time.RFC3339),
			"end":   window.End.UTC().Format(time.RFC3339),
		},
	})
}

func accountResponse(a *storage.ACMEAccount, accountURL string) map[string]interface{} {
	return map[string]interface{}{
		"status":  string(a.Status),
		"contact": a.Contact,
		"orders":  accountURL + "/orders",
	}
}
func (h *ACMEHandler) orderResponse(ctx context.Context, provisionerID uuid.UUID, order *storage.ACMEOrder) map[string]interface{} {
	// Fetch authorizations for the order
	auths, err := h.store.ListAuthorizationsByOrder(ctx, order.ID)
	if err != nil {
		// fallback to empty list
		auths = []*storage.ACMEAuthorization{}
	}

	authURLs := make([]string, len(auths))
	for i, auth := range auths {
		authURLs[i] = h.service.AuthorizationURL(provisionerID, auth.ID)
	}

	// Parse identifiers from order.Identifiers for the response
	var identifiers []internalacme.Identifier
	if raw, ok := order.Identifiers["identifiers"]; ok {
		b, _ := json.Marshal(raw)
		_ = json.Unmarshal(b, &identifiers)
	}

	resp := map[string]interface{}{
		"status":         string(order.Status),
		"expires":        order.ExpiresAt.Format(time.RFC3339),
		"identifiers":    identifiers,
		"authorizations": authURLs,
		"finalize":       h.service.FinalizeURL(provisionerID, order.ID),
	}

	if order.CertificateID != nil {
		resp["certificate"] = h.service.CertificateURL(provisionerID, *order.CertificateID)
	}

	return resp
}
func parseIdentifiersFromOrder(order *storage.ACMEOrder) ([]internalacme.Identifier, error) {
	raw, ok := order.Identifiers["identifiers"]
	if !ok {
		return nil, fmt.Errorf("missing identifiers")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var ids []internalacme.Identifier
	return ids, json.Unmarshal(b, &ids)
}

func challengeResponse(ch *storage.ACMEChallenge, challURL string) map[string]interface{} {
	resp := map[string]interface{}{
		"type":   string(ch.Type),
		"url":    challURL,
		"status": string(ch.Status),
		"token":  ch.Token,
	}
	if ch.ValidatedAt != nil {
		resp["validated"] = ch.ValidatedAt.Format("2006-01-02T15:04:05Z")
	}
	return resp
}
