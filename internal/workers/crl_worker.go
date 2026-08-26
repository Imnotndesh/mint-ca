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
//
// When delta CRLs are enabled, deltas are refreshed on every tick (so they
// stay fresh and current with the base) while the full base CRL is only
// rebuilt on BaseRefreshInterval — a separate, potentially longer cadence.
type CRLWorker struct {
	mgr               *revocation.CRLManager
	interval          time.Duration
	validity          time.Duration
	deltaEnabled      bool
	baseInterval      time.Duration
	lastBaseRefresh   time.Time
}

func NewCRLWorker(mgr *revocation.CRLManager, cfg config.CRLConfig) *CRLWorker {
	return &CRLWorker{
		mgr:          mgr,
		interval:     cfg.RefreshInterval,
		validity:     cfg.Validity,
		deltaEnabled: cfg.DeltaEnabled,
		baseInterval: cfg.BaseRefreshInterval,
	}
}

func (w *CRLWorker) Name() string { return "crl-refresh" }

func (w *CRLWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	w.lastBaseRefresh = time.Now().UTC()
	for {
		// If delta mode is on but no base-refresh tick has fired yet, wait for
		// the next tick that marks the base interval before regenerating bases.
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := w.refresh(refreshCtx)
			if err != nil {
				slog.Warn("CRL refresh error", "err", err)
			} else {
				slog.Debug("CRL refresh complete")
			}
			cancel()
		}
	}
}

func (w *CRLWorker) refresh(ctx context.Context) error {
	baseDue := time.Now().UTC().Sub(w.lastBaseRefresh) >= w.baseInterval

	if w.deltaEnabled && !baseDue {
		// Only regenerate deltas this tick; the base is still fresh.
		return w.mgr.RefreshDeltas(ctx, w.validity)
	}

	// Regenerate base (in non-delta mode this is the only work) which also
	// re-bases and refreshes deltas when delta mode is on.
	if err := w.mgr.RefreshAll(ctx, w.validity); err != nil {
		return err
	}
	w.lastBaseRefresh = time.Now().UTC()
	return nil
}
