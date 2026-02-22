package middleware

import (
	"context"
	"net/http"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func Audit(store storage.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)

			// Only audit state-changing requests.
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				return
			}

			actor := "anonymous"
			if v := r.Context().Value(ActorKey); v != nil {
				actor = v.(string)
			}

			entry := &storage.AuditLog{
				ID:        uuid.New(),
				EventType: r.Method + " " + r.URL.Path,
				Actor:     actor,
				Payload: storage.JSON{
					"method": r.Method,
					"path":   r.URL.Path,
					"status": ww.status,
				},
				IPAddress: r.RemoteAddr,
				CreatedAt: time.Now().UTC(),
			}

			go func() {
				_ = store.WriteAuditLog(context.Background(), entry)
			}()
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}
