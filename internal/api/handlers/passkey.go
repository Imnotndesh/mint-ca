package handlers

import (
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"mint-ca/internal/passkey"

	"github.com/go-chi/chi/v5"
)

// PasskeyHandler exposes WebAuthn registration/login and step-up endpoints.
type PasskeyHandler struct {
	svc *passkey.Service
	// required is the step-up policy: off | high_risk | all.
	required string
}

func NewPasskeyHandler(svc *passkey.Service, required string) *PasskeyHandler {
	if required == "" {
		required = passkey.RequiredOff
	}
	return &PasskeyHandler{svc: svc, required: required}
}

func (h *PasskeyHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/passkeys", func(r chi.Router) {
		r.Get("/", h.list)
		r.Get("/status", h.status)
		r.Post("/register/begin", h.registerBegin)
		r.Post("/register/finish", h.registerFinish)
		r.Post("/login/begin", h.loginBegin)
		r.Post("/login/finish", h.loginFinish)
		r.Delete("/{credID}", h.delete)
	})
}

func (h *PasskeyHandler) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":      true,
		"registered":   h.svc.HasCredentials(r.Context()),
		"required_for": h.required,
	})
}

func (h *PasskeyHandler) list(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformAdmin(w, r) {
		return
	}
	creds, err := h.svc.ListCredentials(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type row struct {
		ID        string     `json:"id"`
		Name      string     `json:"name"`
		CreatedAt time.Time  `json:"created_at"`
		LastUsed  *time.Time `json:"last_used,omitempty"`
	}
	out := make([]row, 0, len(creds))
	for _, c := range creds {
		out = append(out, row{
			ID:        base64.RawURLEncoding.EncodeToString(c.ID),
			Name:      c.Name,
			CreatedAt: c.CreatedAt,
			LastUsed:  c.LastUsed,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *PasskeyHandler) registerBegin(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformAdmin(w, r) {
		return
	}
	options, sessionID, err := h.svc.BeginRegistration(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"options": options, "session_id": sessionID})
}

func (h *PasskeyHandler) registerFinish(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformAdmin(w, r) {
		return
	}
	sessionID := r.URL.Query().Get("session_id")
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if err := h.svc.FinishRegistration(r.Context(), sessionID, body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered"})
}

func (h *PasskeyHandler) loginBegin(w http.ResponseWriter, r *http.Request) {
	options, sessionID, err := h.svc.BeginLogin(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"options": options, "session_id": sessionID})
}

func (h *PasskeyHandler) loginFinish(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	token, exp, err := h.svc.FinishLogin(r.Context(), sessionID, body)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"step_up_token": token, "expires_at": exp})
}

func (h *PasskeyHandler) delete(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformAdmin(w, r) {
		return
	}
	id, err := base64.RawURLEncoding.DecodeString(chi.URLParam(r, "credID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid credential id")
		return
	}
	if err := h.svc.DeleteCredential(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// StepUpHeader carries the passkey step-up token on high-risk requests.
const StepUpHeader = "X-Passkey-Step-Up"
