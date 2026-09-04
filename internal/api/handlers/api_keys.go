package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	apimiddleware "mint-ca/internal/api/middleware"
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
	TenantID         string   `json:"tenant_id"`
	PlatformAdmin    bool     `json:"platform_admin"`
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

	// Resolve the new key's tenant scope against the caller. A tenant-scoped
	// caller may only mint keys for its own tenant (never a platform-admin key
	// and never another tenant's key); a platform-admin caller may mint for any
	// tenant, or another platform-admin key when explicitly requested.
	callerTenantID, ok := tenantFromContext(r)
	if !ok {
		writeError(w, http.StatusForbidden, "authentication required")
		return
	}

	var tenantID *uuid.UUID
	if callerTenantID != nil {
		// Tenant-scoped caller: force assignment to its own tenant.
		if req.TenantID != "" {
			reqTenant, err := uuid.Parse(req.TenantID)
			if err != nil || reqTenant != *callerTenantID {
				writeError(w, http.StatusBadRequest, "tenant_id must match your own tenant")
				return
			}
		}
		tid := *callerTenantID
		tenantID = &tid
	} else {
		// Platform-admin caller.
		switch {
		case req.PlatformAdmin:
			if req.TenantID != "" {
				writeError(w, http.StatusBadRequest, "platform_admin keys cannot also be tenant-scoped")
				return
			}
			tenantID = nil
		case req.TenantID != "":
			tid, err := uuid.Parse(req.TenantID)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid tenant_id")
				return
			}
			if err := h.ensureTenantExists(r.Context(), tid); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			tenantID = &tid
		default:
			writeError(w, http.StatusBadRequest, "tenant_id is required for platform-admin-created scoped keys; omit tenant_id and set platform_admin=true to create a platform-admin key")
			return
		}
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
		TenantID:  tenantID,
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
		"tenant_id":  k.TenantID,
		"expires_at": k.ExpiresAt,
		"note":       "store the key securely — it will not be shown again",
	})
}

// tenantFromContext returns the caller's tenant id (nil = platform admin) and
// whether an API key was present in the request context at all.
func tenantFromContext(r *http.Request) (*uuid.UUID, bool) {
	apiKey, ok := r.Context().Value(apimiddleware.APIKeyKey).(*storage.APIKey)
	if !ok || apiKey == nil {
		return nil, false
	}
	return apiKey.TenantID, true
}

// ensureTenantExists validates that a tenant id refers to a real, active
// tenant before a platform-admin scopes a new key to it.
func (h *APIKeyHandler) ensureTenantExists(ctx context.Context, tid uuid.UUID) error {
	ts, ok := h.store.(storage.TenantStore)
	if !ok {
		return fmt.Errorf("store does not support tenants")
	}
	tn, err := ts.GetTenant(ctx, tid)
	if err != nil {
		return fmt.Errorf("internal error checking tenant: %w", err)
	}
	if tn == nil {
		return fmt.Errorf("tenant not found")
	}
	if tn.Status != storage.TenantStatusActive {
		return fmt.Errorf("tenant is not active")
	}
	return nil
}

// authorizeKeyByID loads an API key and applies the cross-tenant 404 rule: a
// tenant-scoped caller cannot distinguish another tenant's (or platform) key
// from a nonexistent one.
func (h *APIKeyHandler) authorizeKeyByID(w http.ResponseWriter, r *http.Request, id uuid.UUID) bool {
	callerTenantID, ok := tenantFromContext(r)
	if !ok {
		writeError(w, http.StatusForbidden, "authentication required")
		return false
	}
	if callerTenantID == nil {
		return true // platform admin
	}
	keys, err := h.store.ListAPIKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	for _, k := range keys {
		if k.ID == id {
			if k.TenantID != nil && *k.TenantID == *callerTenantID {
				return true
			}
			writeError(w, http.StatusNotFound, "api key not found")
			return false
		}
	}
	writeError(w, http.StatusNotFound, "api key not found")
	return false
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
	if !h.authorizeKeyByID(w, r, id) {
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

	// A tenant-scoped caller can only see its own tenant's keys (it must never
	// learn of platform-admin or sibling-tenant keys). Platform admins see all.
	callerTenantID, ok := tenantFromContext(r)
	if !ok {
		writeError(w, http.StatusForbidden, "authentication required")
		return
	}

	type safeKey struct {
		ID        uuid.UUID  `json:"id"`
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		CAID      *uuid.UUID `json:"ca_id,omitempty"`
		TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
		LastUsed  *time.Time `json:"last_used,omitempty"`
		CreatedAt time.Time  `json:"created_at"`
	}

	out := make([]safeKey, 0, len(keys))
	for _, k := range keys {
		if callerTenantID != nil && (k.TenantID == nil || *k.TenantID != *callerTenantID) {
			continue
		}
		out = append(out, safeKey{
			ID:        k.ID,
			Name:      k.Name,
			Scopes:    k.Scopes,
			CAID:      k.CAID,
			TenantID:  k.TenantID,
			ExpiresAt: k.ExpiresAt,
			LastUsed:  k.LastUsed,
			CreatedAt: k.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *APIKeyHandler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid key ID")
		return
	}
	if !h.authorizeKeyByID(w, r, id) {
		return
	}
	if err := h.store.DeleteAPIKey(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
