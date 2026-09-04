package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"mint-ca/internal/audit"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// auditChainStore is the minimal store surface for hash-chain verification.
// Kept local so fake stores in other packages don't need it.
type auditChainStore interface {
	ListAuditLogsChronological(ctx context.Context) ([]*storage.AuditLog, error)
}

type AuditHandler struct{ store storage.Store }

func NewAuditHandler(store storage.Store) *AuditHandler {
	return &AuditHandler{store: store}
}

func (h *AuditHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/audit", func(r chi.Router) {
		r.Get("/", h.list)
		r.Get("/ca/{caID}", h.listByCA)
		r.Get("/verify", h.verify)
	})
}

// verify walks the full audit log's tamper-evident hash chain (see
// internal/audit) and reports whether it is intact.
func (h *AuditHandler) verify(w http.ResponseWriter, r *http.Request) {
	s, ok := h.store.(auditChainStore)
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support audit chain verification")
		return
	}
	logs, err := s.ListAuditLogsChronological(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	entries := make([]audit.Entry, len(logs))
	for i, l := range logs {
		var caID, certID string
		if l.CAID != nil {
			caID = l.CAID.String()
		}
		if l.CertID != nil {
			certID = l.CertID.String()
		}
		payload := "{}"
		if l.Payload != nil {
			if b, err := json.Marshal(l.Payload); err == nil {
				payload = string(b)
			}
		}
		entries[i] = audit.Entry{
			ID: l.ID.String(), EventType: l.EventType, Actor: l.Actor,
			CAID: caID, CertID: certID, Payload: payload, IPAddress: l.IPAddress,
			CreatedAt: l.CreatedAt, PrevHash: l.PrevHash, EntryHash: l.EntryHash,
		}
	}

	brokenAt := audit.VerifyChain(entries)
	resp := map[string]interface{}{
		"ok":          brokenAt == -1,
		"entries":     len(entries),
		"verified_at": time.Now().UTC(),
	}
	if brokenAt != -1 {
		resp["broken_at_index"] = brokenAt
		resp["broken_entry_id"] = logs[brokenAt].ID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuditHandler) list(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationParams(r)
	logs, err := h.store.ListAuditLogs(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

func (h *AuditHandler) listByCA(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	limit, offset := paginationParams(r)
	logs, err := h.store.ListAuditLogsByCA(r.Context(), caID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logs)
}
