package workers

import (
	"context"
	"log/slog"
	"sync"
)

// Worker is anything that can run in the background and be stopped cleanly.
// Run blocks until ctx is cancelled. It must return promptly after cancellation.
// If Run returns a non-nil error it is logged as a warning — workers are
// expected to handle their own fatal errors internally and exit via ctx.
type Worker interface {
	Name() string
	Run(ctx context.Context) error
}

// WorkerGroup manages a set of background workers. Workers are started when
// Start is called and stopped when Stop is called. Stop waits for all workers
// to return before returning itself, so the caller can safely close shared
// resources (store, keystore) afterward.
type WorkerGroup struct {
	workers []Worker
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewWorkerGroup constructs an empty WorkerGroup.
func NewWorkerGroup() *WorkerGroup {
	return &WorkerGroup{}
}

// Add registers a worker. Must be called before Start.
func (g *WorkerGroup) Add(w Worker) {
	g.workers = append(g.workers, w)
}

// Start launches all registered workers in separate goroutines.
// The provided ctx is the parent context; an internal cancellable child is
// created so Stop can cancel all workers without touching the parent.
func (g *WorkerGroup) Start(ctx context.Context) {
	workerCtx, cancel := context.WithCancel(ctx)
	g.cancel = cancel

	for _, w := range g.workers {
		w := w // capture
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			slog.Debug("worker started", "worker", w.Name())
			if err := w.Run(workerCtx); err != nil {
				slog.Warn("worker exited with error", "worker", w.Name(), "err", err)
			} else {
				slog.Debug("worker stopped", "worker", w.Name())
			}
		}()
	}
}

// Stop cancels all workers and waits for every goroutine to return.
// Safe to call multiple times.
func (g *WorkerGroup) Stop() {
	if g.cancel != nil {
		g.cancel()
	}
	g.wg.Wait()
}
