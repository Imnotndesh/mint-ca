package workers

import (
	"context"
	"log/slog"
	"time"

	"mint-ca/internal/config"
	"mint-ca/internal/sshca/krl"
)

// SSHKRLWorker periodically regenerates KRLs for all active SSH CAs,
// mirroring CRLWorker. Reuses the existing CRL interval/validity config —
// no new env vars, since freshness needs are equivalent at this scale.
type SSHKRLWorker struct {
	mgr      *krl.Manager
	interval time.Duration
	validity time.Duration
}

func NewSSHKRLWorker(mgr *krl.Manager, cfg config.CRLConfig) *SSHKRLWorker {
	return &SSHKRLWorker{mgr: mgr, interval: cfg.RefreshInterval, validity: cfg.Validity}
}

func (w *SSHKRLWorker) Name() string { return "ssh-krl-refresh" }

func (w *SSHKRLWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := w.mgr.RefreshAll(refreshCtx, w.validity); err != nil {
				slog.Warn("SSH KRL refresh error", "err", err)
			} else {
				slog.Debug("SSH KRL refresh complete")
			}
			cancel()
		}
	}
}
