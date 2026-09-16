package handlers

import (
	"context"
	"io"
	"net/http"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// tenantStore is the minimal CRUD surface the tenant handler needs. Kept local
// so fake stores elsewhere don't need to implement it.
type tenantStore interface {
	CreateTenant(ctx context.Context, t *storage.Tenant) error
	GetTenant(ctx context.Context, id uuid.UUID) (*storage.Tenant, error)
	GetTenantByName(ctx context.Context, name string) (*storage.Tenant, error)
	ListTenants(ctx context.Context) ([]*storage.Tenant, error)
	UpdateTenantStatus(ctx context.Context, id uuid.UUID, status storage.TenantStatus) error
}

type TenantHandler struct{ store storage.Store }

func NewTenantHandler(store storage.Store) *TenantHandler {
	return &TenantHandler{store: store}
}

func (h *TenantHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/tenants", func(r chi.Router) {
		r.Post("/", h.create)
		r.Post("/restore", h.restore)
		r.Get("/", h.list)
		r.Get("/{tenantID}", h.get)
		r.Put("/{tenantID}/suspend", h.suspend)
		r.Put("/{tenantID}/activate", h.activate)
		r.Get("/{tenantID}/export", h.export)
	})
}

// platformAdmin reports whether the calling key is platform-scoped (nil
// tenant). Handlers requiring platform-only access return 403 otherwise.
func platformAdmin(r *http.Request) bool {
	tid, ok := tenantFromContext(r)
	return ok && tid == nil
}

func (h *TenantHandler) tenantsStore() (tenantStore, bool) {
	s, ok := h.store.(tenantStore)
	return s, ok
}

type tenantRequest struct {
	Name string `json:"name"`
}

func (h *TenantHandler) create(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	var req tenantRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	s, ok := h.tenantsStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support tenants")
		return
	}
	if got, _ := s.GetTenantByName(r.Context(), req.Name); got != nil {
		writeError(w, http.StatusConflict, "tenant name already exists")
		return
	}
	t := &storage.Tenant{
		ID:        uuid.New(),
		Name:      req.Name,
		Status:    storage.TenantStatusActive,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.CreateTenant(r.Context(), t); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (h *TenantHandler) list(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.tenantsStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support tenants")
		return
	}
	ts, err := s.ListTenants(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ts)
}

func (h *TenantHandler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}
	s, ok := h.tenantsStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support tenants")
		return
	}
	t, err := s.GetTenant(r.Context(), id)
	if err != nil || t == nil {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}
	// A tenant-scoped key may only read its own tenant.
	if tid, ok := tenantFromContext(r); ok && tid != nil && *tid != id {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (h *TenantHandler) suspend(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, storage.TenantStatusSuspended)
}

func (h *TenantHandler) activate(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, storage.TenantStatusActive)
}

func (h *TenantHandler) setStatus(w http.ResponseWriter, r *http.Request, status storage.TenantStatus) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}
	s, ok := h.tenantsStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support tenants")
		return
	}
	if err := s.UpdateTenantStatus(r.Context(), id, status); err != nil {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "status": status})
}

// tenantBackupStore is the minimal surface for tenant export/restore.
type tenantBackupStore interface {
	TenantExport(ctx context.Context, tenantID string) ([]byte, error)
	TenantRestore(ctx context.Context, data []byte) (*storage.Tenant, error)
}

// export downloads a tenant-scoped backup (platform admin, or the tenant
// itself for its own data).
func (h *TenantHandler) export(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}
	if caller, _ := tenantFromContext(r); caller != nil && *caller != id {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}
	s, ok := h.store.(tenantBackupStore)
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support tenant export")
		return
	}
	data, err := s.TenantExport(r.Context(), id.String())
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	name := "mint-ca-tenant-" + id.String() + ".json"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// restore imports a tenant-scoped backup into this instance (platform admin).
func (h *TenantHandler) restore(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.store.(tenantBackupStore)
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support tenant restore")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<30))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if len(data) == 0 {
		writeError(w, http.StatusBadRequest, "empty backup body")
		return
	}
	t, err := s.TenantRestore(r.Context(), data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
}
