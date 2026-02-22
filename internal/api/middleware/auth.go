package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"mint-ca/internal/storage"
)

type contextKey string

const ActorKey contextKey = "actor"
const APIKeyKey contextKey = "api_key"

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
