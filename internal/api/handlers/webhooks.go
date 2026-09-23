package handlers

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"mint-ca/internal/notify"
	"mint-ca/internal/storage"
	"mint-ca/internal/webhook"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type webhookStore interface {
	CreateWebhookConfig(ctx context.Context, w *storage.WebhookConfig) error
	GetWebhookConfig(ctx context.Context, id uuid.UUID) (*storage.WebhookConfig, error)
	ListWebhookConfigs(ctx context.Context) ([]*storage.WebhookConfig, error)
	UpdateWebhookConfig(ctx context.Context, w *storage.WebhookConfig) error
	DeleteWebhookConfig(ctx context.Context, id uuid.UUID) error
	SetDefaultWebhookConfig(ctx context.Context, id uuid.UUID) error

	GetWebhookRule(ctx context.Context, category string) (*storage.WebhookRule, error)
	ListWebhookRules(ctx context.Context) ([]*storage.WebhookRule, error)
	UpsertWebhookRule(ctx context.Context, rule *storage.WebhookRule) error
}

type WebhookHandler struct {
	store   storage.Store
	manager *webhook.Manager
}

func NewWebhookHandler(store storage.Store, manager *webhook.Manager) *WebhookHandler {
	return &WebhookHandler{store: store, manager: manager}
}

func (h *WebhookHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/settings/webhooks", func(r chi.Router) {
		r.Post("/", h.createConfig)
		r.Get("/", h.listConfigs)
		r.Get("/{id}", h.getConfig)
		r.Put("/{id}", h.updateConfig)
		r.Delete("/{id}", h.deleteConfig)
		r.Post("/{id}/default", h.setDefaultConfig)
		r.Post("/{id}/test", h.testConfig)

		r.Route("/rules", func(r chi.Router) {
			r.Get("/", h.listRules)
			r.Get("/{category}", h.getRule)
			r.Put("/{category}", h.updateRule)
		})
	})
}

func (h *WebhookHandler) webhookStore() (webhookStore, bool) {
	s, ok := h.store.(webhookStore)
	return s, ok
}

type webhookConfigRequest struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Secret  string `json:"secret"`
	Enabled bool   `json:"enabled"`
}

func (req webhookConfigRequest) validate() string {
	if req.Name == "" {
		return "name is required"
	}
	if req.URL == "" {
		return "url is required"
	}
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "url must be a valid http(s) URL"
	}
	return ""
}

func (h *WebhookHandler) createConfig(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.webhookStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support webhook configs")
		return
	}
	var req webhookConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if msg := req.validate(); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	secretEnc, err := h.manager.EncryptSecret(req.Secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now().UTC()
	cfg := &storage.WebhookConfig{
		ID:        uuid.New(),
		Name:      req.Name,
		URL:       req.URL,
		SecretEnc: secretEnc,
		Enabled:   req.Enabled,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.CreateWebhookConfig(r.Context(), cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, cfg)
}

func (h *WebhookHandler) listConfigs(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.webhookStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support webhook configs")
		return
	}
	configs, err := s.ListWebhookConfigs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, configs)
}

func (h *WebhookHandler) getConfig(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.webhookStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support webhook configs")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	cfg, err := s.GetWebhookConfig(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfg == nil {
		writeError(w, http.StatusNotFound, "webhook config not found")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (h *WebhookHandler) updateConfig(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.webhookStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support webhook configs")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := s.GetWebhookConfig(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "webhook config not found")
		return
	}
	var req webhookConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if msg := req.validate(); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	secretEnc := existing.SecretEnc
	if req.Secret != "" {
		enc, err := h.manager.EncryptSecret(req.Secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		secretEnc = enc
	}
	updated := &storage.WebhookConfig{
		ID:        existing.ID,
		Name:      req.Name,
		URL:       req.URL,
		SecretEnc: secretEnc,
		Enabled:   req.Enabled,
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.UpdateWebhookConfig(r.Context(), updated); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *WebhookHandler) deleteConfig(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.webhookStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support webhook configs")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.DeleteWebhookConfig(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *WebhookHandler) setDefaultConfig(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.webhookStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support webhook configs")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.SetDefaultWebhookConfig(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *WebhookHandler) testConfig(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := h.manager.SendTest(ctx, id); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (h *WebhookHandler) listRules(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.webhookStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support webhook rules")
		return
	}
	rules, err := s.ListWebhookRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	byCategory := make(map[string]*storage.WebhookRule, len(rules))
	for _, rule := range rules {
		byCategory[rule.Category] = rule
	}
	out := make([]*storage.WebhookRule, 0, len(notify.Categories.Keys()))
	for _, key := range notify.Categories.Keys() {
		if rule, ok := byCategory[key]; ok {
			out = append(out, rule)
			continue
		}
		out = append(out, &storage.WebhookRule{Category: key, Enabled: false})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *WebhookHandler) getRule(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.webhookStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support webhook rules")
		return
	}
	category := chi.URLParam(r, "category")
	if _, known := notify.Categories.Get(category); !known {
		writeError(w, http.StatusNotFound, "unknown notification category")
		return
	}
	rule, err := s.GetWebhookRule(r.Context(), category)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rule == nil {
		rule = &storage.WebhookRule{Category: category, Enabled: false}
	}
	writeJSON(w, http.StatusOK, rule)
}

type webhookRuleRequest struct {
	Enabled         bool       `json:"enabled"`
	WebhookConfigID *uuid.UUID `json:"webhook_config_id,omitempty"`
}

func (h *WebhookHandler) updateRule(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.webhookStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support webhook rules")
		return
	}
	category := chi.URLParam(r, "category")
	if _, known := notify.Categories.Get(category); !known {
		writeError(w, http.StatusNotFound, "unknown notification category")
		return
	}
	var req webhookRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rule := &storage.WebhookRule{
		Category:        category,
		Enabled:         req.Enabled,
		WebhookConfigID: req.WebhookConfigID,
		UpdatedAt:       time.Now().UTC(),
	}
	if err := s.UpsertWebhookRule(r.Context(), rule); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rule)
}
