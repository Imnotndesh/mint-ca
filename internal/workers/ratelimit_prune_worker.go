package workers

import (
	"context"
	"log/slog"
	"time"

	"mint-ca/internal/storage"
)

// RateLimitPruneWorker periodically deletes expired rate_limit_counters
// rows. Mirrors NonceWorker's shape.
type RateLimitPruneWorker struct {
	store    storage.Store
	interval time.Duration
	// retain is how far back to keep counter rows, independent of any
	// single limiter's window — generous enough to cover the widest
	// configured window with margin.
	retain time.Duration
}

func NewRateLimitPruneWorker(store storage.Store) *RateLimitPruneWorker {
	return &RateLimitPruneWorker{
		store:    store,
		interval: 15 * time.Minute,
		retain:   24 * time.Hour,
	}
}

func (w *RateLimitPruneWorker) Name() string { return "ratelimit-prune" }

func (w *RateLimitPruneWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cutoff := time.Now().UTC().Add(-w.retain)
			if err := w.store.PruneExpiredRateLimitCounters(ctx, cutoff); err != nil {
				slog.Warn("rate limit counter prune error", "err", err)
			}
		}
	}
}
