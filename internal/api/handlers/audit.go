package handlers

import (
	"net/http"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type AuditHandler struct{ store storage.Store }

func NewAuditHandler(store storage.Store) *AuditHandler {
	return &AuditHandler{store: store}
}

func (h *AuditHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/audit", func(r chi.Router) {
		r.Get("/", h.list)
		r.Get("/ca/{caID}", h.listByCA)
	})
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
