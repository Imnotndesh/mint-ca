package handlers

import (
	"context"
	"net/http"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// csrApprovalStore is the minimal store surface for managing CSR auto-approval
// rules. Kept local so fake stores in other packages don't need it.
type csrApprovalStore interface {
	CreateCSRAutoApproveRule(ctx context.Context, r *storage.CSRAutoApproveRule) error
	ListCSRAutoApproveRules(ctx context.Context, provisionerID uuid.UUID) ([]*storage.CSRAutoApproveRule, error)
	UpdateCSRAutoApproveRule(ctx context.Context, r *storage.CSRAutoApproveRule) error
	DeleteCSRAutoApproveRule(ctx context.Context, id uuid.UUID) error
}

// ApprovalHandler manages CSR auto-approval rules (get / set / edit).
type ApprovalHandler struct{ store storage.Store }

func NewApprovalHandler(store storage.Store) *ApprovalHandler {
	return &ApprovalHandler{store: store}
}

func (h *ApprovalHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/approval/csr-rules", func(r chi.Router) {
		r.Get("/", h.list)
		r.Post("/", h.create)
		r.Put("/{ruleID}", h.update)
		r.Delete("/{ruleID}", h.delete)
	})
}

func (h *ApprovalHandler) rules() (csrApprovalStore, bool) {
	s, ok := h.store.(csrApprovalStore)
	return s, ok
}

// callerTenantIsPlatformAdminOr returns false after writing 404 (existence
// hiding) when the caller is tenant-scoped and does not own the provisioner.
// A platform-admin caller passes. Writes 404 when the provisioner is missing.
func (h *ApprovalHandler) permissionOnProvisioner(w http.ResponseWriter, r *http.Request, provID uuid.UUID) bool {
	prov, err := h.store.GetProvisioner(r.Context(), provID)
	if err != nil || prov == nil {
		writeError(w, http.StatusNotFound, "provisioner not found")
		return false
	}
	caller, _ := tenantFromContext(r)
	if !tenantOwns(prov.TenantID, caller) {
		writeError(w, http.StatusNotFound, "provisioner not found")
		return false
	}
	return true
}

// ruleIsOwnedByCaller resolves a rule by listing its owner provisioner and
// confirming the caller may act on it. Used for delete (no provisioner body).
func (h *ApprovalHandler) ruleIsOwnedByCaller(w http.ResponseWriter, r *http.Request, ruleID uuid.UUID) bool {
	s, ok := h.rules()
	if !ok {
		return false
	}
	caller, _ := tenantFromContext(r)
	if caller == nil {
		return true // platform admin may delete any rule
	}
	rules, err := s.ListCSRAutoApproveRules(r.Context(), uuid.Nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	for _, rule := range rules {
		if rule.ID == ruleID {
			if !h.permissionOnProvisioner(w, r, rule.ProvisionerID) {
				writeError(w, http.StatusNotFound, "rule not found")
				return false
			}
			return true
		}
	}
	writeError(w, http.StatusNotFound, "rule not found")
	return false
}

type csrRuleRequest struct {
	ProvisionerID      string   `json:"provisioner_id"`
	Name               string   `json:"name"`
	AllowedCommonNames []string `json:"allowed_common_names"`
	AllowedDNS         []string `json:"allowed_dns"`
	MaxTTLSeconds      int64    `json:"max_ttl_seconds"`
	Enabled            bool     `json:"enabled"`
}

func (h *ApprovalHandler) create(w http.ResponseWriter, r *http.Request) {
	var req csrRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	provID, err := uuid.Parse(req.ProvisionerID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provisioner_id")
		return
	}
	if !h.permissionOnProvisioner(w, r, provID) {
		return
	}
	s, ok := h.rules()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support approval rules")
		return
	}
	rule := &storage.CSRAutoApproveRule{
		ID:                 uuid.New(),
		ProvisionerID:      provID,
		Name:               req.Name,
		AllowedCommonNames: req.AllowedCommonNames,
		AllowedDNS:         req.AllowedDNS,
		MaxTTLSeconds:      req.MaxTTLSeconds,
		Enabled:            true,
		CreatedAt:          time.Now().UTC(),
	}
	if err := s.CreateCSRAutoApproveRule(r.Context(), rule); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (h *ApprovalHandler) list(w http.ResponseWriter, r *http.Request) {
	s, ok := h.rules()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support approval rules")
		return
	}
	var provID uuid.UUID
	if v := r.URL.Query().Get("provisioner_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid provisioner_id")
			return
		}
		if !h.permissionOnProvisioner(w, r, id) {
			return
		}
		provID = id
	}
	rs, err := s.ListCSRAutoApproveRules(r.Context(), provID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Tenant-scoped callers only ever see rules belonging to their own
	// provisioners.
	caller, _ := tenantFromContext(r)
	if caller != nil {
		var out []*storage.CSRAutoApproveRule
		for _, rule := range rs {
			if rule.ProvisionerID == provID {
				if out == nil {
					out = []*storage.CSRAutoApproveRule{}
				}
				out = append(out, rule)
				continue
			}
			prov, err := h.store.GetProvisioner(r.Context(), rule.ProvisionerID)
			if err == nil && prov != nil && tenantOwns(prov.TenantID, caller) {
				out = append(out, rule)
			}
		}
		rs = out
	}
	writeJSON(w, http.StatusOK, rs)
}

func (h *ApprovalHandler) update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}
	var req csrRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	provID, err := uuid.Parse(req.ProvisionerID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provisioner_id")
		return
	}
	if !h.permissionOnProvisioner(w, r, provID) {
		return
	}
	s, ok := h.rules()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support approval rules")
		return
	}
	rule := &storage.CSRAutoApproveRule{
		ID:                 id,
		ProvisionerID:      provID,
		Name:               req.Name,
		AllowedCommonNames: req.AllowedCommonNames,
		AllowedDNS:         req.AllowedDNS,
		MaxTTLSeconds:      req.MaxTTLSeconds,
		Enabled:            req.Enabled,
	}
	if err := s.UpdateCSRAutoApproveRule(r.Context(), rule); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (h *ApprovalHandler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}
	if !h.ruleIsOwnedByCaller(w, r, id) {
		return
	}
	s, ok := h.rules()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support approval rules")
		return
	}
	if err := s.DeleteCSRAutoApproveRule(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
