package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
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
		r.Get("/merkle/root", h.merkleRoot)
		r.Get("/merkle/proof/{index}", h.merkleProof)
	})
}

// requirePlatformAdmin denies tenant-scoped callers with 403. Returns ok=false
// when the caller may not proceed. A platform-admin (nil tenant) caller passes.
func requirePlatformAdmin(w http.ResponseWriter, r *http.Request) bool {
	caller, _ := tenantFromContext(r)
	if caller != nil {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return false
	}
	return true
}

// verify walks the full audit log's tamper-evident hash chain (see
// internal/audit) and reports whether it is intact. Platform-admin only, since
// verifying requires reading the whole (global, cross-tenant) chain.
func (h *AuditHandler) verify(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformAdmin(w, r) {
		return
	}
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

// merkleRoot returns the current Merkle tree head over the audit log's
// hash chain (see internal/audit), CT-log style: a public commitment
// callers can pin and compare over time. Platform-admin only.
func (h *AuditHandler) merkleRoot(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformAdmin(w, r) {
		return
	}
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
	tree, err := audit.NewMerkleTree(entryHashesOf(logs))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"root_hash": tree.RootHash(),
		"size":      tree.Size(),
	})
}

// merkleProof returns an inclusion proof for the audit log entry at the
// given (0-based, chronological) index, against the current tree.
func (h *AuditHandler) merkleProof(w http.ResponseWriter, r *http.Request) {
	index, err := strconv.Atoi(chi.URLParam(r, "index"))
	if err != nil || index < 0 {
		writeError(w, http.StatusBadRequest, "invalid index")
		return
	}
	if !requirePlatformAdmin(w, r) {
		return
	}
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
	if index >= len(logs) {
		writeError(w, http.StatusNotFound, "index out of range")
		return
	}
	tree, err := audit.NewMerkleTree(entryHashesOf(logs))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	proof, err := tree.InclusionProof(index)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"index":      index,
		"size":       tree.Size(),
		"entry_id":   logs[index].ID,
		"entry_hash": logs[index].EntryHash,
		"proof":      proof,
		"root_hash":  tree.RootHash(),
	})
}

func entryHashesOf(logs []*storage.AuditLog) []string {
	out := make([]string, len(logs))
	for i, l := range logs {
		out[i] = l.EntryHash
	}
	return out
}

func (h *AuditHandler) list(w http.ResponseWriter, r *http.Request) {
	// The unscoped, cross-tenant audit stream is platform-admin only.
	if !requirePlatformAdmin(w, r) {
		return
	}
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
	// A tenant-scoped caller may read a CA's audit trail only if that CA is its
	// own; a platform admin may read any CA's audit trail.
	if record, err := h.store.GetCA(r.Context(), caID); err == nil && record != nil {
		caller, _ := tenantFromContext(r)
		if !tenantOwns(record.TenantID, caller) {
			writeError(w, http.StatusNotFound, "CA not found")
			return
		}
	}
	limit, offset := paginationParams(r)
	logs, err := h.store.ListAuditLogsByCA(r.Context(), caID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logs)
}
