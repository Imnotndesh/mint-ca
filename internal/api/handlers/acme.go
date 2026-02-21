package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"mint-ca/internal/ca"
	"mint-ca/internal/config"
	"mint-ca/internal/policy"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
)

// ACMEHandler owns all ACME protocol endpoints. The full JWS/JWK verification
// and order lifecycle logic will be implemented in a dedicated internal/acme
// package — this handler is the HTTP boundary that calls into it.
// The stubs below define the complete route surface so the router is final.
type ACMEHandler struct {
	store  storage.Store
	engine *ca.Engine
	policy *policy.Engine
	cfg    config.ACMEConfig
}

func NewACMEHandler(
	store storage.Store,
	engine *ca.Engine,
	policyEngine *policy.Engine,
	cfg config.ACMEConfig,
) *ACMEHandler {
	return &ACMEHandler{
		store:  store,
		engine: engine,
		policy: policyEngine,
		cfg:    cfg,
	}
}

func (h *ACMEHandler) RegisterRoutes(r chi.Router) {
	r.Route("/acme/{provisionerID}", func(r chi.Router) {
		// Unauthenticated — clients need these before they have an account.
		r.Get("/directory", h.directory)
		r.Head("/new-nonce", h.newNonce)
		r.Post("/new-nonce", h.newNonce)

		// Account
		r.Post("/new-account", h.newAccount)
		r.Post("/account/{accountID}", h.updateAccount)

		// Order lifecycle
		r.Post("/new-order", h.newOrder)
		r.Post("/order/{orderID}", h.getOrder)
		r.Post("/order/{orderID}/finalize", h.finalizeOrder)

		// Challenge
		r.Post("/challenge/{challengeID}", h.validateChallenge)

		// Certificate download
		r.Post("/certificate/{certID}", h.getCertificate)
	})
}

func (h *ACMEHandler) directory(w http.ResponseWriter, r *http.Request) {
	provID := chi.URLParam(r, "provisionerID")
	base := h.cfg.BaseURL + "/acme/" + provID
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"newNonce":   base + "/new-nonce",
		"newAccount": base + "/new-account",
		"newOrder":   base + "/new-order",
		"meta": map[string]interface{}{
			"externalAccountRequired": h.cfg.EABRequired,
			"website":                 h.cfg.BaseURL,
		},
	})
}

func (h *ACMEHandler) newNonce(w http.ResponseWriter, r *http.Request) {
	// Nonce generation will move to internal/acme when that package is built.
	// For now we generate a random hex nonce so the directory is functional.
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return
	}
	w.Header().Set("Replay-Nonce", hex.EncodeToString(nonce))
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

func acmeNotImplemented(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusNotImplemented)
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"type":   "urn:ietf:params:acme:error:serverInternal",
		"detail": "this ACME endpoint is not yet implemented",
	})
}

func (h *ACMEHandler) newAccount(w http.ResponseWriter, r *http.Request)    { acmeNotImplemented(w) }
func (h *ACMEHandler) updateAccount(w http.ResponseWriter, r *http.Request) { acmeNotImplemented(w) }
func (h *ACMEHandler) newOrder(w http.ResponseWriter, r *http.Request)      { acmeNotImplemented(w) }
func (h *ACMEHandler) getOrder(w http.ResponseWriter, r *http.Request)      { acmeNotImplemented(w) }
func (h *ACMEHandler) finalizeOrder(w http.ResponseWriter, r *http.Request) { acmeNotImplemented(w) }
func (h *ACMEHandler) validateChallenge(w http.ResponseWriter, r *http.Request) {
	acmeNotImplemented(w)
}
func (h *ACMEHandler) getCertificate(w http.ResponseWriter, r *http.Request) { acmeNotImplemented(w) }
