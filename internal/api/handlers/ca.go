package handlers

import (
	"net/http"

	"mint-ca/internal/ca"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type CAHandler struct {
	engine *ca.Engine
	store  storage.Store
}

func NewCAHandler(engine *ca.Engine, store storage.Store) *CAHandler {
	return &CAHandler{engine: engine, store: store}
}

func (h *CAHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/ca", func(r chi.Router) {
		r.Post("/root", h.createRoot)
		r.Post("/intermediate", h.createIntermediate)
		r.Get("/", h.list)
		r.Get("/{caID}", h.get)
		r.Get("/{caID}/children", h.listChildren)
		r.Put("/{caID}/revoke", h.revoke)
	})
}

type createRootRequest struct {
	Name         string `json:"name"`
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	State        string `json:"state"`
	Locality     string `json:"locality"`
	KeyAlgo      string `json:"key_algo"`
	TTLDays      int    `json:"ttl_days"`
}

func (h *CAHandler) createRoot(w http.ResponseWriter, r *http.Request) {
	var req createRootRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	record, err := h.engine.CreateRootCA(r.Context(), ca.CreateRootCARequest{
		Name:         req.Name,
		CommonName:   req.CommonName,
		Organization: req.Organization,
		Country:      req.Country,
		State:        req.State,
		Locality:     req.Locality,
		KeyAlgo:      ca.KeyAlgo(req.KeyAlgo),
		TTLDays:      req.TTLDays,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, record)
}

type createIntermediateRequest struct {
	ParentCAID   string `json:"parent_ca_id"`
	Name         string `json:"name"`
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	State        string `json:"state"`
	Locality     string `json:"locality"`
	KeyAlgo      string `json:"key_algo"`
	TTLDays      int    `json:"ttl_days"`
	MaxPathLen   int    `json:"max_path_len"`
}

func (h *CAHandler) createIntermediate(w http.ResponseWriter, r *http.Request) {
	var req createIntermediateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	parentID, err := uuid.Parse(req.ParentCAID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid parent_ca_id")
		return
	}

	record, err := h.engine.CreateIntermediateCA(r.Context(), ca.CreateIntermediateCARequest{
		ParentCAID:   parentID,
		Name:         req.Name,
		CommonName:   req.CommonName,
		Organization: req.Organization,
		Country:      req.Country,
		State:        req.State,
		Locality:     req.Locality,
		KeyAlgo:      ca.KeyAlgo(req.KeyAlgo),
		TTLDays:      req.TTLDays,
		MaxPathLen:   req.MaxPathLen,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, record)
}

func (h *CAHandler) list(w http.ResponseWriter, r *http.Request) {
	cas, err := h.store.ListCAs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cas)
}

func (h *CAHandler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	record, err := h.store.GetCA(r.Context(), id)
	if err != nil || record == nil {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (h *CAHandler) listChildren(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	children, err := h.store.ListChildCAs(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, children)
}

func (h *CAHandler) revoke(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	if err := h.store.UpdateCAStatus(r.Context(), id, storage.CAStatusRevoked); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// GetChain is called by PKIHandler — exported so pki.go can use it.
func (h *CAHandler) GetChain(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	chainPEM, err := h.engine.GetChainPEM(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	w.Write(chainPEM)
}
