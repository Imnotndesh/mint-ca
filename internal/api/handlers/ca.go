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
// getPermittedCA loads the CA by id and ensures the caller may see it. Returns
// nil after writing a 404/error response when it is missing or owned by
// another tenant. callers use the non-nil result.
func (h *CAHandler) getPermittedCA(w http.ResponseWriter, r *http.Request, id uuid.UUID) *storage.CertificateAuthority {
	record, err := h.store.GetCA(r.Context(), id)
	if err != nil || record == nil {
		writeError(w, http.StatusNotFound, "CA not found")
		return nil
	}
	caller, _ := tenantFromContext(r)
	if !tenantOwns(record.TenantID, caller) {
		writeError(w, http.StatusNotFound, "CA not found")
		return nil
	}
	return record
}

func (h *CAHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/ca", func(r chi.Router) {
		r.Post("/root", h.createRoot)
		r.Post("/intermediate", h.createIntermediate)
		r.Get("/", h.list)
		r.Get("/{caID}", h.get)
		r.Get("/{caID}/children", h.listChildren)
		r.Put("/{caID}/revoke", h.revoke)
		r.Post("/{caID}/rekey", h.rekey)
		r.Post("/{caID}/cross-sign", h.crossSign)
		r.Get("/{caID}/cross-certs", h.listCrossCerts)
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
	TenantID     string `json:"tenant_id"`
}

// createTenant resolves the owning tenant for a resource being created in this
// request. Tenant-scoped callers can only create inside their own tenant. A
// platform admin may scope via a body tenant_id, defaulting to the default
// tenant so single-tenant operator flows keep working unchanged.
func createTenant(r *http.Request, tenantID string, w http.ResponseWriter) (uuid.UUID, bool) {
	caller, ok := tenantFromContext(r)
	if !ok {
		writeError(w, http.StatusForbidden, "authentication required")
		return uuid.Nil, false
	}
	if caller != nil {
		if tenantID != "" {
			if id, err := uuid.Parse(tenantID); err != nil || id != *caller {
				writeError(w, http.StatusBadRequest, "tenant_id must match your own tenant")
				return uuid.Nil, false
			}
		}
		return *caller, true
	}
	// platform admin
	if tenantID != "" {
		id, err := uuid.Parse(tenantID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid tenant_id")
			return uuid.Nil, false
		}
		return id, true
	}
	return storage.DefaultTenantID, true
}

func (h *CAHandler) createRoot(w http.ResponseWriter, r *http.Request) {
	var req createRootRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tid, ok := createTenant(r, req.TenantID, w)
	if !ok {
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
		TenantID:     tid,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, record)
}

type createIntermediateRequest struct {
	ParentCAID      string                   `json:"parent_ca_id"`
	Name            string                   `json:"name"`
	CommonName      string                   `json:"common_name"`
	Organization    string                   `json:"organization"`
	Country         string                   `json:"country"`
	State           string                   `json:"state"`
	Locality        string                   `json:"locality"`
	KeyAlgo         string                   `json:"key_algo"`
	TTLDays         int                      `json:"ttl_days"`
	MaxPathLen      int                      `json:"max_path_len"`
	TenantID        string                   `json:"tenant_id"`
	NameConstraints *storage.NameConstraints `json:"name_constraints,omitempty"`
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
	// The parent CA must be visible to the caller (404 on cross-tenant/none),
	// which also guarantees tenant-scoped callers only branch within their own
	// tenant chain.
	if h.getPermittedCA(w, r, parentID) == nil {
		return
	}
	tid, ok := createTenant(r, req.TenantID, w)
	if !ok {
		return
	}

	record, err := h.engine.CreateIntermediateCA(r.Context(), ca.CreateIntermediateCARequest{
		ParentCAID:      parentID,
		Name:            req.Name,
		CommonName:      req.CommonName,
		Organization:    req.Organization,
		Country:         req.Country,
		State:           req.State,
		Locality:        req.Locality,
		KeyAlgo:         ca.KeyAlgo(req.KeyAlgo),
		TTLDays:         req.TTLDays,
		MaxPathLen:      req.MaxPathLen,
		NameConstraints: req.NameConstraints,
		TenantID:        tid,
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
	caller, _ := tenantFromContext(r)
	if caller != nil {
		filtered := cas[:0]
		for _, c := range cas {
			if tenantOwns(c.TenantID, caller) {
				filtered = append(filtered, c)
			}
		}
		cas = filtered
	}
	writeJSON(w, http.StatusOK, cas)
}

func (h *CAHandler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	record := h.getPermittedCA(w, r, id)
	if record == nil {
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
	if h.getPermittedCA(w, r, id) == nil {
		return
	}
	children, err := h.store.ListChildCAs(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	caller, _ := tenantFromContext(r)
	if caller != nil {
		filtered := children[:0]
		for _, c := range children {
			if tenantOwns(c.TenantID, caller) {
				filtered = append(filtered, c)
			}
		}
		children = filtered
	}
	writeJSON(w, http.StatusOK, children)
}

type createRekeyRequest struct {
	KeyAlgo string `json:"key_algo"`
	TTLDays int    `json:"ttl_days"`
}

type createCrossSignRequest struct {
	SigningCAID string `json:"signing_ca_id"`
	TTLDays     int    `json:"ttl_days"`
}

func (h *CAHandler) rekey(w http.ResponseWriter, r *http.Request) {
	var req createRekeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	if h.getPermittedCA(w, r, caID) == nil {
		return
	}
	record, err := h.engine.RekeyCA(r.Context(), ca.RekeyCARequest{
		CAID:    caID,
		KeyAlgo: ca.KeyAlgo(req.KeyAlgo),
		TTLDays: req.TTLDays,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (h *CAHandler) crossSign(w http.ResponseWriter, r *http.Request) {
	var req createCrossSignRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	signingID, err := uuid.Parse(req.SigningCAID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signing_ca_id")
		return
	}
	if h.getPermittedCA(w, r, caID) == nil || h.getPermittedCA(w, r, signingID) == nil {
		return
	}
	cc, err := h.engine.CrossSignCA(r.Context(), ca.CrossSignCARequest{
		SigningCAID: signingID,
		TargetCAID:  caID,
		TTLDays:     req.TTLDays,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, cc)
}

func (h *CAHandler) listCrossCerts(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	if h.getPermittedCA(w, r, caID) == nil {
		return
	}
	certs, err := h.store.ListCrossCertsByTarget(r.Context(), caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, certs)
}

func (h *CAHandler) revoke(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	if h.getPermittedCA(w, r, id) == nil {
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
