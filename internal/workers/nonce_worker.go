package workers

import (
	"context"
	"log/slog"
	"mint-ca/internal/storage"
	"time"
)

type NonceWorker struct {
	store    storage.Store
	interval time.Duration
}

func NewNonceWorker(store storage.Store) *NonceWorker {
	return &NonceWorker{store: store, interval: 10 * time.Minute}
}

func (w *NonceWorker) Name() string { return "nonce-prune" }

func (w *NonceWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := w.store.PruneExpiredNonces(ctx); err != nil {
				slog.Warn("nonce prune error", "err", err)
			}
		}
	}
}
