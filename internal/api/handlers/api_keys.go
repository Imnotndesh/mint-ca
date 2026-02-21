package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type APIKeyHandler struct{ store storage.Store }

func NewAPIKeyHandler(store storage.Store) *APIKeyHandler {
	return &APIKeyHandler{store: store}
}

func (h *APIKeyHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/apikeys", func(r chi.Router) {
		r.Post("/", h.create)
		r.Get("/", h.list)
		r.Delete("/{keyID}", h.delete)
	})
}

type createAPIKeyRequest struct {
	Name             string   `json:"name"`
	Scopes           []string `json:"scopes"`
	CAID             string   `json:"ca_id"`
	ExpiresInSeconds int64    `json:"expires_in_seconds"`
}

func (h *APIKeyHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createAPIKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate key")
		return
	}
	rawKey := "mca_" + hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(rawKey))
	hash := hex.EncodeToString(sum[:])

	k := &storage.APIKey{
		ID:        uuid.New(),
		Name:      req.Name,
		KeyHash:   hash,
		Scopes:    req.Scopes,
		CreatedAt: time.Now().UTC(),
	}
	if req.CAID != "" {
		caID, err := uuid.Parse(req.CAID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid ca_id")
			return
		}
		k.CAID = &caID
	}
	if req.ExpiresInSeconds > 0 {
		exp := time.Now().UTC().Add(time.Duration(req.ExpiresInSeconds) * time.Second)
		k.ExpiresAt = &exp
	}

	if err := h.store.CreateAPIKey(r.Context(), k); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         k.ID,
		"name":       k.Name,
		"key":        rawKey,
		"scopes":     k.Scopes,
		"expires_at": k.ExpiresAt,
		"note":       "store the key securely — it will not be shown again",
	})
}

func (h *APIKeyHandler) list(w http.ResponseWriter, r *http.Request) {
	keys, err := h.store.ListAPIKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type safeKey struct {
		ID        uuid.UUID  `json:"id"`
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		CAID      *uuid.UUID `json:"ca_id,omitempty"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
		LastUsed  *time.Time `json:"last_used,omitempty"`
		CreatedAt time.Time  `json:"created_at"`
	}

	out := make([]safeKey, len(keys))
	for i, k := range keys {
		out[i] = safeKey{
			ID:        k.ID,
			Name:      k.Name,
			Scopes:    k.Scopes,
			CAID:      k.CAID,
			ExpiresAt: k.ExpiresAt,
			LastUsed:  k.LastUsed,
			CreatedAt: k.CreatedAt,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *APIKeyHandler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid key ID")
		return
	}
	if err := h.store.DeleteAPIKey(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
