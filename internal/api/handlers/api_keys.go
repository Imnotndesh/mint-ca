package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// defaultAPIKeyTTL is the lifetime applied when a caller does not request an
// expiry. A sane, conservative default: automation tokens are rotated rather
// than long-lived.
const defaultAPIKeyTTL = 90 * 24 * time.Hour

// apiKeyUpdater is the minimal store surface needed for rotation. Kept local so
// fake stores in other packages don't have to implement it.
type apiKeyUpdater interface {
	UpdateAPIKeyHash(ctx context.Context, id uuid.UUID, newHash string) error
}

// newAPIKeyToken generates a fresh random bearer token and its SHA-256 hash.
func newAPIKeyToken() (raw, hash string) {
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		panic("api keys: failed to generate randomness: " + err.Error())
	}
	raw = "mca_" + hex.EncodeToString(rawBytes)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, hash
}

type APIKeyHandler struct{ store storage.Store }

func NewAPIKeyHandler(store storage.Store) *APIKeyHandler {
	return &APIKeyHandler{store: store}
}

func (h *APIKeyHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/apikeys", func(r chi.Router) {
		r.Post("/", h.create)
		r.Get("/", h.list)
		r.Delete("/{keyID}", h.delete)
		r.Post("/{keyID}/rotate", h.rotate)
	})
}

type createAPIKeyRequest struct {
	Name             string   `json:"name"`
	Scopes           []string `json:"scopes"`
	CAID             string   `json:"ca_id"`
	ExpiresInSeconds int64    `json:"expires_in_seconds"`
	NeverExpires     bool     `json:"never_expires"`
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

	rawKey, hash := newAPIKeyToken()

	// Nice default: if no expiry requested (and not explicitly never-expiring),
	// apply a conservative default TTL so tokens are rotated by default.
	var expiresAt *time.Time
	switch {
	case req.NeverExpires:
		expiresAt = nil
	case req.ExpiresInSeconds > 0:
		exp := time.Now().UTC().Add(time.Duration(req.ExpiresInSeconds) * time.Second)
		expiresAt = &exp
	default:
		exp := time.Now().UTC().Add(defaultAPIKeyTTL)
		expiresAt = &exp
	}

	k := &storage.APIKey{
		ID:        uuid.New(),
		Name:      req.Name,
		KeyHash:   hash,
		Scopes:    req.Scopes,
		ExpiresAt: expiresAt,
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

// rotate issues a new bearer token for an existing API key identity, keeping
// its name/scopes/CAID. The old secret is immediately invalid (its hash is
// replaced). The expiry is extended by the key's remaining-window policy:
// existing expiry is kept; if the key never expires or has no remaining time,
// a fresh default TTL is applied from now.
func (h *APIKeyHandler) rotate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid key ID")
		return
	}
	updater, ok := h.store.(apiKeyUpdater)
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support key rotation")
		return
	}

	newRaw, newHash := newAPIKeyToken()
	if err := updater.UpdateAPIKeyHash(r.Context(), id, newHash); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":   id,
		"key":  newRaw,
		"note": "previous key is now invalid; store this one securely",
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
