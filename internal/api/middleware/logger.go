package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

func Logger() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)
			if rid := r.Header.Get("X-Request-Id"); rid != "" {
				slog.Info("request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", ww.status,
					"duration_ms", time.Since(start).Milliseconds(),
					"remote", r.RemoteAddr,
					"request_id", rid,
				)
			} else {
				slog.Info("request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", ww.status,
					"duration_ms", time.Since(start).Milliseconds(),
					"remote", r.RemoteAddr,
				)
			}
		})
	}
}
