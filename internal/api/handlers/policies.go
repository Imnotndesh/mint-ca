package handlers

import (
	"net/http"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type PolicyHandler struct{ store storage.Store }

func NewPolicyHandler(store storage.Store) *PolicyHandler {
	return &PolicyHandler{store: store}
}

func (h *PolicyHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/policies", func(r chi.Router) {
		r.Post("/", h.create)
		r.Get("/", h.list)
		r.Get("/{policyID}", h.get)
		r.Put("/{policyID}", h.update)
		r.Delete("/{policyID}", h.delete)
	})
}

type policyRequest struct {
	Name           string              `json:"name"`
	Scope          storage.PolicyScope `json:"scope"`
	MaxTTLSeconds  int64               `json:"max_ttl_seconds"`
	AllowedDomains []string            `json:"allowed_domains"`
	DeniedDomains  []string            `json:"denied_domains"`
	AllowedIPs     []string            `json:"allowed_ips"`
	AllowedSANs    []string            `json:"allowed_sans"`
	RequireSAN     bool                `json:"require_san"`
	KeyAlgos       []string            `json:"key_algos"`
}

func (h *PolicyHandler) create(w http.ResponseWriter, r *http.Request) {
	var req policyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pol := &storage.Policy{
		ID:             uuid.New(),
		Name:           req.Name,
		Scope:          req.Scope,
		MaxTTL:         req.MaxTTLSeconds,
		AllowedDomains: req.AllowedDomains,
		DeniedDomains:  req.DeniedDomains,
		AllowedIPs:     req.AllowedIPs,
		AllowedSANs:    req.AllowedSANs,
		RequireSAN:     req.RequireSAN,
		KeyAlgos:       req.KeyAlgos,
		CreatedAt:      time.Now().UTC(),
	}
	if err := h.store.CreatePolicy(r.Context(), pol); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, pol)
}

func (h *PolicyHandler) list(w http.ResponseWriter, r *http.Request) {
	ps, err := h.store.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ps)
}

func (h *PolicyHandler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "policyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}
	pol, err := h.store.GetPolicy(r.Context(), id)
	if err != nil || pol == nil {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	writeJSON(w, http.StatusOK, pol)
}

func (h *PolicyHandler) update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "policyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}
	var req policyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pol := &storage.Policy{
		ID:             id,
		Name:           req.Name,
		Scope:          req.Scope,
		MaxTTL:         req.MaxTTLSeconds,
		AllowedDomains: req.AllowedDomains,
		DeniedDomains:  req.DeniedDomains,
		AllowedIPs:     req.AllowedIPs,
		AllowedSANs:    req.AllowedSANs,
		RequireSAN:     req.RequireSAN,
		KeyAlgos:       req.KeyAlgos,
	}
	if err := h.store.UpdatePolicy(r.Context(), pol); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pol)
}

func (h *PolicyHandler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "policyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}
	if err := h.store.DeletePolicy(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
