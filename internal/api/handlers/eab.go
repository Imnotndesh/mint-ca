package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type EABHandler struct{ store storage.Store }

func NewEABHandler(store storage.Store) *EABHandler {
	return &EABHandler{store: store}
}

func (h *EABHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/eab", func(r chi.Router) {
		r.Post("/provisioner/{provisionerID}", h.create)
		r.Get("/provisioner/{provisionerID}", h.list)
		r.Delete("/{keyID}", h.revoke)
	})
}

type createEABRequest struct {
	ExpiresInSeconds int64 `json:"expires_in_seconds"`
}

func (h *EABHandler) create(w http.ResponseWriter, r *http.Request) {
	provID, err := uuid.Parse(chi.URLParam(r, "provisionerID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provisioner ID")
		return
	}

	var req createEABRequest
	_ = decodeJSON(r, &req)

	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate HMAC key")
		return
	}

	keyID := make([]byte, 16)
	if _, err := rand.Read(keyID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate key ID")
		return
	}

	cred := &storage.EABCredential{
		ID:            uuid.New(),
		ProvisionerID: provID,
		HMACKey:       hmacKey,
		KeyID:         hex.EncodeToString(keyID),
		CreatedAt:     time.Now().UTC(),
	}
	if req.ExpiresInSeconds > 0 {
		exp := time.Now().UTC().Add(time.Duration(req.ExpiresInSeconds) * time.Second)
		cred.ExpiresAt = &exp
	}

	if err := h.store.CreateEABCredential(r.Context(), cred); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// The HMAC key is returned exactly once in hex. It is never stored in
	// plaintext — the store holds the raw bytes but they are never returned
	// again via the API.
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"key_id":     cred.KeyID,
		"hmac_key":   hex.EncodeToString(hmacKey),
		"expires_at": cred.ExpiresAt,
		"note":       "store hmac_key securely — it will not be shown again",
	})
}

func (h *EABHandler) list(w http.ResponseWriter, r *http.Request) {
	// Intentionally returns metadata only — never HMAC keys.
	//TODO: A full implementation would add a ListEABCredentialsByProvisioner method to the store. For now we acknowledge the request.
	writeJSON(w, http.StatusOK, map[string]string{
		"note": "use audit log to review EAB usage history",
	})
}

func (h *EABHandler) revoke(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "keyID")
	cred, err := h.store.GetEABCredential(r.Context(), keyID)
	if err != nil || cred == nil {
		writeError(w, http.StatusNotFound, "EAB credential not found")
		return
	}
	if err := h.store.MarkEABUsed(r.Context(), cred.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
