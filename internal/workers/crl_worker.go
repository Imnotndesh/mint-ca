package workers

import (
	"context"
	"log/slog"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/config"
	"time"
)

// CRLWorker is the background worker that regenerates CRLs for all active CAs
// on a fixed interval. It implements the Worker interface.
type CRLWorker struct {
	mgr      *revocation.CRLManager
	interval time.Duration
	validity time.Duration
}

func NewCRLWorker(mgr *revocation.CRLManager, cfg config.CRLConfig) *CRLWorker {
	return &CRLWorker{
		mgr:      mgr,
		interval: cfg.RefreshInterval,
		validity: cfg.Validity,
	}
}

func (w *CRLWorker) Name() string { return "crl-refresh" }

func (w *CRLWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := w.mgr.RefreshAll(refreshCtx); err != nil {
				slog.Warn("CRL refresh error", "err", err)
			} else {
				slog.Debug("CRL refresh complete")
			}
			cancel()
		}
	}
}
