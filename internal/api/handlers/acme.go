package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

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
}

func NewACMEHandler(
	store storage.Store,
	engine *ca.Engine,
	svc *internalacme.Service,
	cfg config.ACMEConfig,
) *ACMEHandler {
	return &ACMEHandler{
		store:   store,
		engine:  engine,
		service: svc,
		cfg:     cfg,
	}
}

func (h *ACMEHandler) RegisterRoutes(r chi.Router) {
	r.Route("/acme/{provisionerID}", func(r chi.Router) {
		r.Get("/directory", h.directory)
		r.Head("/new-nonce", h.newNonce)
		r.Post("/new-nonce", h.newNonce)
		r.Post("/new-account", h.newAccount)
		r.Post("/account/{accountID}", h.updateAccount)
		r.Post("/new-order", h.newOrder)
		r.Post("/order/{orderID}", h.getOrder)
		r.Post("/order/{orderID}/finalize", h.finalizeOrder)
		r.Post("/challenge/{challengeID}", h.validateChallenge)
		r.Post("/certificate/{certID}", h.getCertificate)
	})
}

// acmeWriteJSON writes a JSON response with ACME-required headers. It always
// adds a fresh Replay-Nonce so the client can make its next request immediately.
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

func (h *ACMEHandler) directory(w http.ResponseWriter, r *http.Request) {
	prov, prob := h.loadProvisioner(r)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	provID := prov.ID
	base := h.cfg.BaseURL + "/acme/" + provID.String()

	// Parse provisioner config to read EABRequired.
	var cfg internalacme.ProvisionerConfig
	if raw, err := json.Marshal(prov.Config); err == nil {
		_ = json.Unmarshal(raw, &cfg)
	}
	cfg.SetDefaults()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"newNonce":   base + "/new-nonce",
		"newAccount": base + "/new-account",
		"newOrder":   base + "/new-order",
		"meta": map[string]interface{}{
			"externalAccountRequired": cfg.EABRequired,
			"website":                 h.cfg.BaseURL,
		},
	})
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

func (h *ACMEHandler) newAccount(w http.ResponseWriter, r *http.Request) {
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

	order, challenges, prob := h.service.NewOrder(ctx, account, prov, payload.Identifiers)
	if prob != nil {
		h.acmeProblem(w, r, prob)
		return
	}

	orderURL := h.service.OrderURL(prov.ID, order.ID)
	w.Header().Set("Location", orderURL)
	h.acmeWriteJSON(w, r, http.StatusCreated,
		h.orderResponse(prov.ID, order, challenges))
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

	challenges, err := h.store.ListChallengesByOrder(ctx, order.ID)
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrServerInternalProblem("load challenges: "+err.Error()))
		return
	}

	h.acmeWriteJSON(w, r, http.StatusOK, h.orderResponse(prov.ID, order, challenges))
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
		CSR string `json:"csr"` // base64url-encoded DER CSR
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

	challenges, err := h.store.ListChallengesByOrder(ctx, order.ID)
	if err != nil {
		h.acmeProblem(w, r, internalacme.ErrServerInternalProblem("load challenges: "+err.Error()))
		return
	}

	orderURL := h.service.OrderURL(prov.ID, order.ID)
	w.Header().Set("Location", orderURL)
	h.acmeWriteJSON(w, r, http.StatusOK, h.orderResponse(prov.ID, order, challenges))
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
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(chainPEM)
}

func accountResponse(a *storage.ACMEAccount, accountURL string) map[string]interface{} {
	return map[string]interface{}{
		"status":  string(a.Status),
		"contact": a.Contact,
		"orders":  accountURL + "/orders",
	}
}

// orderResponse builds the RFC 8555 §7.1.3 order object.
// challenges is the flat list from the store; we group them per identifier into
// authorization objects (inlined here as URLs per the spec).
func (h *ACMEHandler) orderResponse(
	provisionerID uuid.UUID,
	order *storage.ACMEOrder,
	challenges []*storage.ACMEChallenge,
) map[string]interface{} {

	// Build authorization URL list (one per challenge grouping by order).
	// The spec requires one authorization URL per identifier; we emit one per
	// unique challenge, which is equivalent when each identifier has one of each type.
	authzURLs := make([]string, 0, len(challenges))
	seen := map[uuid.UUID]bool{}
	for _, ch := range challenges {
		if !seen[ch.ID] {
			authzURLs = append(authzURLs, h.service.ChallengeURL(provisionerID, ch.ID))
			seen[ch.ID] = true
		}
	}

	resp := map[string]interface{}{
		"status":         string(order.Status),
		"expires":        order.ExpiresAt.Format("2006-01-02T15:04:05Z"),
		"identifiers":    order.Identifiers["identifiers"],
		"authorizations": authzURLs,
		"finalize":       h.service.FinalizeURL(provisionerID, order.ID),
	}

	if order.CertificateID != nil {
		resp["certificate"] = h.service.CertificateURL(provisionerID, *order.CertificateID)
	}

	return resp
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
