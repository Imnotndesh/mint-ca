package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

type contextKey string

const ActorKey contextKey = "actor"
const APIKeyKey contextKey = "api_key"

// TenantIDFromContext returns the API key's tenant id from an authenticated
// request context. ok=false if no API key is present at all (should not happen
// inside the authenticated route group, but guarded anyway). A nil tenant id
// with ok=true means the caller is a platform-admin key.
func TenantIDFromContext(ctx context.Context) (tenantID *uuid.UUID, ok bool) {
	apiKey, ok := ctx.Value(APIKeyKey).(*storage.APIKey)
	if !ok || apiKey == nil {
		return nil, false
	}
	return apiKey.TenantID, true
}

func Auth(store storage.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeError(w, http.StatusUnauthorized, "missing Authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				writeError(w, http.StatusUnauthorized, "Authorization must use Bearer scheme")
				return
			}

			rawKey := parts[1]
			sum := sha256.Sum256([]byte(rawKey))
			hash := hex.EncodeToString(sum[:])

			apiKey, err := store.GetAPIKeyByHash(r.Context(), hash)
			if err != nil || apiKey == nil {
				writeError(w, http.StatusUnauthorized, "invalid API key")
				return
			}

			if apiKey.ExpiresAt != nil && time.Now().UTC().After(*apiKey.ExpiresAt) {
				writeError(w, http.StatusUnauthorized, "API key has expired")
				return
			}

			// A tenant-scoped key is refused while its tenant is suspended — the
			// lockout applies to every subsequent request from that tenant, so no
			// tenant handling logic runs for a suspended tenant.
			if apiKey.TenantID != nil {
				if ts, ok := store.(storage.TenantStore); ok {
					if tn, err := ts.GetTenant(r.Context(), *apiKey.TenantID); err == nil && tn != nil && tn.Status == storage.TenantStatusSuspended {
						writeError(w, http.StatusForbidden, "tenant is suspended")
						return
					}
				}
			}

			// Touch last_used asynchronously — never block the request on it.
			go func() {
				_ = store.TouchAPIKey(context.Background(), apiKey.ID)
			}()

			ctx := context.WithValue(r.Context(), ActorKey, apiKey.Name)
			ctx = context.WithValue(ctx, APIKeyKey, apiKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(`{"error":"` + msg + `"}`))
}
