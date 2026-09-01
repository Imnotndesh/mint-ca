package middleware

import (
	"net/http"
	"strconv"

	"mint-ca/internal/ratelimit"
	"mint-ca/internal/storage"
)

// RateLimit wraps handlers with the "apikey_requests_per_key" limiter,
// keyed by the authenticated API key's ID. Must run after Auth so
// APIKeyKey is populated in the request context.
func RateLimit(engine *ratelimit.Engine, store storage.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := r.Context().Value(APIKeyKey)
			apiKey, ok := v.(*storage.APIKey)
			if !ok || apiKey == nil {
				// Auth middleware didn't run or failed — let the request
				// through; Auth itself already rejects unauthenticated
				// requests before this middleware would matter.
				next.ServeHTTP(w, r)
				return
			}

			bucketKey := apiKey.ID.String()
			allowed, retryAfter, err := engine.Check(r.Context(), "apikey_requests_per_key", bucketKey)
			if err != nil {
				// Misconfigured limiter — fail open, but this should be
				// investigated; Check() already fails open internally too.
				next.ServeHTTP(w, r)
				return
			}
			if !allowed {
				WriteRateLimitAudit(store, apiKey.Name, "apikey_requests_per_key", bucketKey)
				w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limit exceeded","retry_after_seconds":` +
					strconv.Itoa(int(retryAfter.Seconds())) + `}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
