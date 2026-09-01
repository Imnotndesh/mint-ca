package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Limiter pairs a config with its algorithm instance.
type Limiter struct {
	cfg  LimiterConfig
	algo Algorithm
}

// Engine holds all named limiters for the process. It is the only type
// call sites interact with.
type Engine struct {
	mu       sync.RWMutex
	limiters map[string]*Limiter
	store    CounterStore
}

// NewEngine constructs an empty Engine. Populate it with LoadConfigs.
func NewEngine(counterStore CounterStore) *Engine {
	return &Engine{
		limiters: make(map[string]*Limiter),
		store:    counterStore,
	}
}

// LoadConfigs (re)initializes limiters from the given configs, replacing
// any existing limiter with the same name. Existing in-memory counters for
// unchanged limiters are preserved; changed limiters get a fresh algorithm
// instance (and therefore reset counters) since window semantics may differ.
func (e *Engine) LoadConfigs(configs []LimiterConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, cfg := range configs {
		algo := NewAlgorithm(cfg.Algorithm, e.store)
		if algo == nil {
			return fmt.Errorf("ratelimit: unknown algorithm %q for limiter %q", cfg.Algorithm, cfg.Name)
		}
		e.limiters[cfg.Name] = &Limiter{cfg: cfg, algo: algo}
	}
	return nil
}

// UpdateConfig hot-swaps a single limiter's config (e.g. from a future web
// UI PUT request), replacing its algorithm instance.
func (e *Engine) UpdateConfig(cfg LimiterConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	algo := NewAlgorithm(cfg.Algorithm, e.store)
	if algo == nil {
		return fmt.Errorf("ratelimit: unknown algorithm %q for limiter %q", cfg.Algorithm, cfg.Name)
	}
	e.limiters[cfg.Name] = &Limiter{cfg: cfg, algo: algo}
	return nil
}

// Check evaluates the named limiter for bucketKey. If the limiter name is
// not registered, Check fails open (allowed=true) and returns an error so
// the caller can log a configuration problem without breaking the request
// path — a missing limiter should never itself cause a 429 or 500.
func (e *Engine) Check(ctx context.Context, limiterName, bucketKey string) (allowed bool, retryAfter time.Duration, err error) {
	e.mu.RLock()
	l, ok := e.limiters[limiterName]
	e.mu.RUnlock()

	if !ok {
		return true, 0, fmt.Errorf("ratelimit: limiter %q not configured", limiterName)
	}

	return l.algo.Allow(ctx, bucketKey, l.cfg)
}
