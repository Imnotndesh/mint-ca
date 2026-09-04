package middleware

import (
	"net/http"
	"os"
	"strings"
)

// CORS is an opt-in same-origin allowance middleware for browser-based admin
// clients (e.g. the web UI) hosted on a different origin than the mint-ca API.
// It reads MINT_CORS_ALLOWED_ORIGINS (comma-separated). When empty, CORS is
// disabled entirely (the strict default). Reflects the single allowed origin
// that matches the request and answers OPTIONS preflights. This is a thin,
// explicit allow-list — it never uses "*".
func CORS(next http.Handler) http.Handler {
	var allowed []string
	if raw := os.Getenv("MINT_CORS_ALLOWED_ORIGINS"); strings.TrimSpace(raw) != "" {
		for _, part := range strings.Split(raw, ",") {
			if o := strings.TrimSpace(part); o != "" {
				allowed = append(allowed, o)
			}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(allowed) > 0 {
			origin := r.Header.Get("Origin")
			for _, o := range allowed {
				if o == origin {
					h := w.Header()
					h.Set("Access-Control-Allow-Origin", origin)
					h.Set("Vary", "Origin")
					h.Set("Access-Control-Allow-Credentials", "true")
					h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
					h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
					break
				}
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
