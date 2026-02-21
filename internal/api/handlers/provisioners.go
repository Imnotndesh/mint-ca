package handlers

import (
	"net/http"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type ProvisionerHandler struct{ store storage.Store }

func NewProvisionerHandler(store storage.Store) *ProvisionerHandler {
	return &ProvisionerHandler{store: store}
}

func (h *ProvisionerHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/provisioners", func(r chi.Router) {
		r.Post("/", h.create)
		r.Get("/ca/{caID}", h.listByCA)
		r.Get("/{provisionerID}", h.get)
		r.Put("/{provisionerID}/enable", h.enable)
		r.Put("/{provisionerID}/disable", h.disable)
	})
}

type createProvisionerRequest struct {
	CAID     string                  `json:"ca_id"`
	Name     string                  `json:"name"`
	Type     storage.ProvisionerType `json:"type"`
	Config   storage.JSON            `json:"config"`
	PolicyID string                  `json:"policy_id"`
}

func (h *ProvisionerHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createProvisionerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	caID, err := uuid.Parse(req.CAID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ca_id")
		return
	}

	p := &storage.Provisioner{
		ID:        uuid.New(),
		CAID:      caID,
		Name:      req.Name,
		Type:      req.Type,
		Config:    req.Config,
		Status:    storage.ProvisionerStatusActive,
		CreatedAt: time.Now().UTC(),
	}

	if req.PolicyID != "" {
		pid, err := uuid.Parse(req.PolicyID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid policy_id")
			return
		}
		p.PolicyID = &pid
	}

	if err := h.store.CreateProvisioner(r.Context(), p); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (h *ProvisionerHandler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "provisionerID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provisioner ID")
		return
	}
	p, err := h.store.GetProvisioner(r.Context(), id)
	if err != nil || p == nil {
		writeError(w, http.StatusNotFound, "provisioner not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *ProvisionerHandler) listByCA(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	ps, err := h.store.ListProvisionersByCA(r.Context(), caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ps)
}

func (h *ProvisionerHandler) enable(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "provisionerID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provisioner ID")
		return
	}
	if err := h.store.UpdateProvisionerStatus(r.Context(), id, storage.ProvisionerStatusActive); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "active"})
}

func (h *ProvisionerHandler) disable(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "provisionerID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provisioner ID")
		return
	}
	if err := h.store.UpdateProvisionerStatus(r.Context(), id, storage.ProvisionerStatusDisabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}
