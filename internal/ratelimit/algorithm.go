package ratelimit

import (
	"context"
	"time"
)

// LimiterConfig is the runtime configuration for a single named limiter.
// It mirrors storage.RateLimitConfig and is refreshable at runtime (e.g. by
// a future web UI) via Engine.UpdateConfig.
type LimiterConfig struct {
	Name          string
	Scope         string
	Algorithm     string
	WindowSeconds int
	MaxRequests   int
	Enabled       bool
}

// Algorithm is implemented by each rate-limiting strategy. New strategies
// (sliding window, token bucket, ...) implement this interface and register
// a constructor in the algorithm registry — call sites never depend on the
// concrete algorithm in use.
type Algorithm interface {
	// Allow checks whether a request for bucketKey is permitted under cfg,
	// incrementing internal state as a side effect if permitted. Returns
	// (allowed, retryAfter, error). retryAfter is only meaningful when
	// allowed is false.
	Allow(ctx context.Context, bucketKey string, cfg LimiterConfig) (allowed bool, retryAfter time.Duration, err error)
}

// AlgorithmFactory constructs an Algorithm instance. Registered factories
// are looked up by the "algorithm" string stored in LimiterConfig / the DB.
type AlgorithmFactory func(counterStore CounterStore) Algorithm

var algorithmRegistry = map[string]AlgorithmFactory{}

// RegisterAlgorithm makes an algorithm available for use by name. Called
// from each algorithm implementation's init() or explicitly at startup.
func RegisterAlgorithm(name string, factory AlgorithmFactory) {
	algorithmRegistry[name] = factory
}

// NewAlgorithm constructs a registered algorithm by name. Returns nil if
// the name is unknown — callers should fail loudly rather than silently
// no-op a rate limiter.
func NewAlgorithm(name string, counterStore CounterStore) Algorithm {
	factory, ok := algorithmRegistry[name]
	if !ok {
		return nil
	}
	return factory(counterStore)
}

// CounterStore is the minimal persistence surface an Algorithm needs for
// write-through durability. Implemented by storage.Store.
type CounterStore interface {
	IncrementRateLimitCounter(ctx context.Context, limiterName, bucketKey string, windowStart time.Time) error
}
