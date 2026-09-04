package handlers

import (
	"log/slog"
	"net/http"

	apimiddleware "mint-ca/internal/api/middleware"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
)

// SystemHandler exposes operator-level runtime intel about this mint-ca node:
// setup state, storage reachability, and (in HA) leadership.
type SystemHandler struct {
	store     storage.Store
	leaderChk apimiddleware.LeaderChecker
}

func NewSystemHandler(store storage.Store, leaderChk apimiddleware.LeaderChecker) *SystemHandler {
	return &SystemHandler{store: store, leaderChk: leaderChk}
}

func (h *SystemHandler) RegisterRoutes(r chi.Router) {
	r.Get("/api/v1/system/status", h.status)
}

func (h *SystemHandler) status(w http.ResponseWriter, r *http.Request) {
	// Operator-only intel: a tenant-scoped key has no business reading node state.
	if !requirePlatformAdmin(w, r) {
		return
	}
	ctx := r.Context()
	dbState, err := h.store.GetSetupState(ctx)
	if err != nil {
		slog.Warn("system status: setup-state read failed", "err", err)
		dbState = "unknown"
	}

	obj := map[string]interface{}{
		"state": string(dbState),
		"db":    "ok",
	}
	leader := false
	nodeID := ""
	if h.leaderChk != nil {
		leader = h.leaderChk.IsLeader()
		nodeID = h.leaderChk.NodeID()
	}
	obj["leader"] = leader
	if nodeID != "" {
		obj["node_id"] = nodeID
	}
	writeJSON(w, http.StatusOK, obj)
}
