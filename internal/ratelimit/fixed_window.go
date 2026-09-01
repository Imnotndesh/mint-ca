package ratelimit

import (
	"context"
	"sync"
	"time"
)

func init() {
	RegisterAlgorithm("fixed_window", func(counterStore CounterStore) Algorithm {
		return newFixedWindowAlgorithm(counterStore)
	})
}

// fixedWindowAlgorithm counts requests in memory within fixed, non-overlapping
// windows aligned to windowSeconds since the Unix epoch. State is
// write-through to counterStore best-effort (fire-and-forget) for crash
// survivability; it is never read back — a restart always starts empty.
type fixedWindowAlgorithm struct {
	mu           sync.Mutex
	buckets      map[string]*windowBucket
	counterStore CounterStore
}

type windowBucket struct {
	windowStart time.Time
	count       int
}

func newFixedWindowAlgorithm(counterStore CounterStore) *fixedWindowAlgorithm {
	return &fixedWindowAlgorithm{
		buckets:      make(map[string]*windowBucket),
		counterStore: counterStore,
	}
}

func (a *fixedWindowAlgorithm) Allow(ctx context.Context, bucketKey string, cfg LimiterConfig) (bool, time.Duration, error) {
	if !cfg.Enabled {
		return true, 0, nil
	}

	window := time.Duration(cfg.WindowSeconds) * time.Second
	now := time.Now().UTC()
	windowStart := now.Truncate(window)

	mapKey := cfg.Name + "|" + bucketKey

	a.mu.Lock()
	b, ok := a.buckets[mapKey]
	if !ok || b.windowStart.Before(windowStart) {
		b = &windowBucket{windowStart: windowStart, count: 0}
		a.buckets[mapKey] = b
	}

	if b.count >= cfg.MaxRequests {
		retryAfter := windowStart.Add(window).Sub(now)
		a.mu.Unlock()
		if retryAfter < 0 {
			retryAfter = 0
		}
		return false, retryAfter, nil
	}

	b.count++
	count := b.count
	a.mu.Unlock()

	// Best-effort async write-through. Never blocks the request path and
	// never affects the Allow decision — memory is authoritative.
	if a.counterStore != nil {
		go func() {
			bgCtx := context.Background()
			_ = a.counterStore.IncrementRateLimitCounter(bgCtx, cfg.Name, bucketKey, windowStart)
			_ = count // count is intentionally unused beyond memory bookkeeping
		}()
	}

	return true, 0, nil
}
