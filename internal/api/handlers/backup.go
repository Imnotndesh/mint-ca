package handlers

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
)

// backupStore is the minimal storage surface for whole-instance backup/restore.
// Kept local so fake stores elsewhere don't implement it.
type backupStore interface {
	Backup(ctx context.Context) ([]byte, error)
	Restore(ctx context.Context, data []byte) error
}

// BackupHandler exposes super-admin (platform-admin) instance backup/restore.
type BackupHandler struct{ store storage.Store }

func NewBackupHandler(store storage.Store) *BackupHandler { return &BackupHandler{store: store} }

func (h *BackupHandler) RegisterRoutes(r chi.Router) {
	r.Get("/api/v1/admin/backup", h.download)
	r.Post("/api/v1/admin/restore", h.restore)
}

func (h *BackupHandler) storeOf() (backupStore, bool) {
	s, ok := h.store.(backupStore)
	return s, ok
}

// download returns a whole-instance backup as a file attachment.
func (h *BackupHandler) download(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformAdmin(w, r) {
		return
	}
	s, ok := h.storeOf()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support backups")
		return
	}
	data, err := s.Backup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := "mint-ca-backup-" + time.Now().UTC().Format("20060102-150405") + ".db"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// restore replaces the instance's data with an uploaded backup. Platform-admin
// only; audited by the audit middleware (POST).
func (h *BackupHandler) restore(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformAdmin(w, r) {
		return
	}
	s, ok := h.storeOf()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support restore")
		return
	}
	// Cap uploads to 1 GiB to avoid unbounded memory use.
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<30))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read backup body: "+err.Error())
		return
	}
	if len(data) == 0 {
		writeError(w, http.StatusBadRequest, "empty backup body")
		return
	}
	if err := s.Restore(r.Context(), data); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "restored"})
}
