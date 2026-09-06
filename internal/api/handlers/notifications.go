package handlers

import (
	"context"
	"net/http"
	"time"

	"mint-ca/internal/notify"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type notificationStore interface {
	CreateSMTPServer(ctx context.Context, s *storage.SMTPServer) error
	GetSMTPServer(ctx context.Context, id uuid.UUID) (*storage.SMTPServer, error)
	ListSMTPServers(ctx context.Context) ([]*storage.SMTPServer, error)
	UpdateSMTPServer(ctx context.Context, s *storage.SMTPServer) error
	DeleteSMTPServer(ctx context.Context, id uuid.UUID) error
	SetDefaultSMTPServer(ctx context.Context, id uuid.UUID) error

	GetNotificationRule(ctx context.Context, category string) (*storage.NotificationRule, error)
	ListNotificationRules(ctx context.Context) ([]*storage.NotificationRule, error)
	UpsertNotificationRule(ctx context.Context, rule *storage.NotificationRule) error
}

type NotificationHandler struct {
	store   storage.Store
	manager *notify.Manager
}

func NewNotificationHandler(store storage.Store, manager *notify.Manager) *NotificationHandler {
	return &NotificationHandler{store: store, manager: manager}
}

func (h *NotificationHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/settings/notifications", func(r chi.Router) {
		r.Get("/categories", h.listCategories)

		r.Route("/smtp-servers", func(r chi.Router) {
			r.Post("/", h.createServer)
			r.Get("/", h.listServers)
			r.Get("/{id}", h.getServer)
			r.Put("/{id}", h.updateServer)
			r.Delete("/{id}", h.deleteServer)
			r.Post("/{id}/default", h.setDefaultServer)
			r.Post("/{id}/test", h.testServer)
		})

		r.Route("/rules", func(r chi.Router) {
			r.Get("/", h.listRules)
			r.Get("/{category}", h.getRule)
			r.Put("/{category}", h.updateRule)
		})
	})
}

func (h *NotificationHandler) notificationStore() (notificationStore, bool) {
	s, ok := h.store.(notificationStore)
	return s, ok
}

func (h *NotificationHandler) listCategories(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	writeJSON(w, http.StatusOK, notify.Categories.All())
}

type smtpServerRequest struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	FromAddress string `json:"from_address"`
	FromName    string `json:"from_name"`
	Security    string `json:"security"`
	SkipVerify  bool   `json:"skip_verify"`
	Enabled     bool   `json:"enabled"`
}

func (req smtpServerRequest) validate() string {
	if req.Name == "" {
		return "name is required"
	}
	if req.Host == "" {
		return "host is required"
	}
	if req.Port <= 0 || req.Port > 65535 {
		return "port must be between 1 and 65535"
	}
	if req.FromAddress == "" {
		return "from_address is required"
	}
	switch storage.SMTPSecurityMode(req.Security) {
	case storage.SMTPSecurityNone, storage.SMTPSecurityStartTLS, storage.SMTPSecurityTLS:
	default:
		return "security must be one of: none, starttls, tls"
	}
	return ""
}

func (h *NotificationHandler) createServer(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.notificationStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support SMTP servers")
		return
	}
	var req smtpServerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if msg := req.validate(); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	passwordEnc, err := h.manager.EncryptPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now().UTC()
	server := &storage.SMTPServer{
		ID:          uuid.New(),
		Name:        req.Name,
		Host:        req.Host,
		Port:        req.Port,
		Username:    req.Username,
		PasswordEnc: passwordEnc,
		FromAddress: req.FromAddress,
		FromName:    req.FromName,
		Security:    storage.SMTPSecurityMode(req.Security),
		SkipVerify:  req.SkipVerify,
		Enabled:     req.Enabled,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.CreateSMTPServer(r.Context(), server); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, server)
}

func (h *NotificationHandler) listServers(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.notificationStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support SMTP servers")
		return
	}
	servers, err := s.ListSMTPServers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, servers)
}

func (h *NotificationHandler) getServer(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.notificationStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support SMTP servers")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	server, err := s.GetSMTPServer(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if server == nil {
		writeError(w, http.StatusNotFound, "smtp server not found")
		return
	}
	writeJSON(w, http.StatusOK, server)
}

func (h *NotificationHandler) updateServer(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.notificationStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support SMTP servers")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := s.GetSMTPServer(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "smtp server not found")
		return
	}
	var req smtpServerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if msg := req.validate(); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	passwordEnc := existing.PasswordEnc
	if req.Password != "" {
		enc, err := h.manager.EncryptPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		passwordEnc = enc
	}
	updated := &storage.SMTPServer{
		ID:          existing.ID,
		Name:        req.Name,
		Host:        req.Host,
		Port:        req.Port,
		Username:    req.Username,
		PasswordEnc: passwordEnc,
		FromAddress: req.FromAddress,
		FromName:    req.FromName,
		Security:    storage.SMTPSecurityMode(req.Security),
		SkipVerify:  req.SkipVerify,
		Enabled:     req.Enabled,
		UpdatedAt:   time.Now().UTC(),
	}
	if err := s.UpdateSMTPServer(r.Context(), updated); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *NotificationHandler) deleteServer(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.notificationStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support SMTP servers")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.DeleteSMTPServer(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *NotificationHandler) setDefaultServer(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.notificationStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support SMTP servers")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.SetDefaultSMTPServer(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type testSendRequest struct {
	To string `json:"to"`
}

func (h *NotificationHandler) testServer(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req testSendRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.To == "" {
		writeError(w, http.StatusBadRequest, "to is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := h.manager.SendTest(ctx, id, req.To); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (h *NotificationHandler) listRules(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.notificationStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support notification rules")
		return
	}
	rules, err := s.ListNotificationRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	byCategory := make(map[string]*storage.NotificationRule, len(rules))
	for _, rule := range rules {
		byCategory[rule.Category] = rule
	}
	out := make([]*storage.NotificationRule, 0, len(notify.Categories.Keys()))
	for _, key := range notify.Categories.Keys() {
		if rule, ok := byCategory[key]; ok {
			out = append(out, rule)
			continue
		}
		out = append(out, &storage.NotificationRule{Category: key, Enabled: false, Recipients: []string{}})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *NotificationHandler) getRule(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.notificationStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support notification rules")
		return
	}
	category := chi.URLParam(r, "category")
	if _, known := notify.Categories.Get(category); !known {
		writeError(w, http.StatusNotFound, "unknown notification category")
		return
	}
	rule, err := s.GetNotificationRule(r.Context(), category)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rule == nil {
		rule = &storage.NotificationRule{Category: category, Enabled: false, Recipients: []string{}}
	}
	writeJSON(w, http.StatusOK, rule)
}

type notificationRuleRequest struct {
	Enabled      bool       `json:"enabled"`
	SMTPServerID *uuid.UUID `json:"smtp_server_id,omitempty"`
	Recipients   []string   `json:"recipients"`
}

func (h *NotificationHandler) updateRule(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(r) {
		writeError(w, http.StatusForbidden, "platform admin access required")
		return
	}
	s, ok := h.notificationStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support notification rules")
		return
	}
	category := chi.URLParam(r, "category")
	if _, known := notify.Categories.Get(category); !known {
		writeError(w, http.StatusNotFound, "unknown notification category")
		return
	}
	var req notificationRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Enabled && len(req.Recipients) == 0 {
		writeError(w, http.StatusBadRequest, "recipients required when enabling a rule")
		return
	}
	rule := &storage.NotificationRule{
		Category:     category,
		Enabled:      req.Enabled,
		SMTPServerID: req.SMTPServerID,
		Recipients:   req.Recipients,
		UpdatedAt:    time.Now().UTC(),
	}
	if err := s.UpsertNotificationRule(r.Context(), rule); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rule)
}
