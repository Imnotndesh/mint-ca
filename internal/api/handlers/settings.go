package handlers

import (
	"context"
	"net/http"
	"time"

	"mint-ca/internal/ratelimit"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
)

// settingsRateLimitStore is the minimal rate-limit config surface the
// settings handler needs.
type settingsRateLimitStore interface {
	GetRateLimitConfig(ctx context.Context, name string) (*storage.RateLimitConfig, error)
	ListRateLimitConfigs(ctx context.Context) ([]*storage.RateLimitConfig, error)
	UpdateRateLimitConfig(ctx context.Context, cfg *storage.RateLimitConfig) error
}

// SettingsHandler serves runtime-configurable server settings that are
// DB-persisted (seeded once from env at boot, then DB-authoritative — see
// internal/setup/ratelimit_seed.go). All routes are platform-admin only.
type SettingsHandler struct {
	store    storage.Store
	rlEngine *ratelimit.Engine
}

func NewSettingsHandler(store storage.Store, rlEngine *ratelimit.Engine) *SettingsHandler {
	return &SettingsHandler{store: store, rlEngine: rlEngine}
}

func (h *SettingsHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/settings/ratelimits", func(r chi.Router) {
		r.Get("/", h.list)
		r.Get("/{name}", h.get)
		r.Put("/{name}", h.update)
	})
}

func (h *SettingsHandler) rateLimitStore() (settingsRateLimitStore, bool) {
	s, ok := h.store.(settingsRateLimitStore)
	return s, ok
}

func (h *SettingsHandler) list(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.rateLimitStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support rate limit configs")
		return
	}
	configs, err := s.ListRateLimitConfigs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, configs)
}

func (h *SettingsHandler) get(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.rateLimitStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support rate limit configs")
		return
	}
	name := chi.URLParam(r, "name")
	cfg, err := s.GetRateLimitConfig(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfg == nil {
		writeError(w, http.StatusNotFound, "rate limit config not found")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// updateRateLimitRequest carries only the fields an operator should tune.
// Name and Scope are structural to the limiter and not editable.
type updateRateLimitRequest struct {
	Algorithm     string `json:"algorithm"`
	WindowSeconds int    `json:"window_seconds"`
	MaxRequests   int    `json:"max_requests"`
	Enabled       bool   `json:"enabled"`
}

func (h *SettingsHandler) update(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.rateLimitStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support rate limit configs")
		return
	}
	name := chi.URLParam(r, "name")
	existing, err := s.GetRateLimitConfig(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "rate limit config not found")
		return
	}

	var req updateRateLimitRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.WindowSeconds <= 0 {
		writeError(w, http.StatusBadRequest, "window_seconds must be positive")
		return
	}
	if req.MaxRequests <= 0 {
		writeError(w, http.StatusBadRequest, "max_requests must be positive")
		return
	}
	algo := req.Algorithm
	if algo == "" {
		algo = existing.Algorithm
	}

	if ratelimit.NewAlgorithm(algo, nil) == nil {
		writeError(w, http.StatusBadRequest, "unknown algorithm "+algo)
		return
	}

	cfg := &storage.RateLimitConfig{
		Name:          existing.Name,
		Scope:         existing.Scope,
		Algorithm:     algo,
		WindowSeconds: req.WindowSeconds,
		MaxRequests:   req.MaxRequests,
		Enabled:       req.Enabled,
		UpdatedAt:     time.Now().UTC(),
	}

	if err := s.UpdateRateLimitConfig(r.Context(), cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Best-effort hot-apply: the algorithm already validated above, so this
	// cannot fail. DB stays authoritative regardless — a restart reloads
	// from it either way.
	if h.rlEngine != nil {
		_ = h.rlEngine.UpdateConfig(ratelimit.LimiterConfig{
			Name:          cfg.Name,
			Scope:         cfg.Scope,
			Algorithm:     cfg.Algorithm,
			WindowSeconds: cfg.WindowSeconds,
			MaxRequests:   cfg.MaxRequests,
			Enabled:       cfg.Enabled,
		})
	}

	writeJSON(w, http.StatusOK, cfg)
}
