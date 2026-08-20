// internal/api/middleware/ratelimit_audit.go
package middleware

import (
	"context"
	"log/slog"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// WriteRateLimitAudit records a rate-limit rejection to both the audit log
// and slog, so rejections are queryable via GET /api/v1/audit and visible
// in real-time logs. Fire-and-forget, matching the existing Audit
// middleware's pattern — never blocks or fails the request path.
func WriteRateLimitAudit(store storage.Store, actor, limiterName, bucketKey string) {
	slog.Warn("rate limit exceeded", "actor", actor, "limiter", limiterName, "bucket_key", bucketKey)

	entry := &storage.AuditLog{
		ID:        uuid.New(),
		EventType: "rate_limit_exceeded",
		Actor:     actor,
		Payload: storage.JSON{
			"limiter":    limiterName,
			"bucket_key": bucketKey,
		},
		CreatedAt: time.Now().UTC(),
	}

	go func() {
		_ = store.WriteAuditLog(context.Background(), entry)
	}()
}
