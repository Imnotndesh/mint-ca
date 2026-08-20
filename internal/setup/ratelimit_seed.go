package setup

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"mint-ca/internal/config"
	"mint-ca/internal/ratelimit"
	"mint-ca/internal/storage"
)

// SeedRateLimitConfigs seeds the DB with hardcoded default limiter configs,
// applying any first-boot-only env overrides. UpsertRateLimitConfigIfAbsent
// is a no-op for any limiter that already has a DB row, so this is safe to
// call on every boot without ever clobbering a value the web UI has since
// changed.
func SeedRateLimitConfigs(ctx context.Context, store storage.Store, cfg config.RateLimitConfig) error {
	defaults := ratelimit.DefaultConfigs()

	overrides := map[string]config.RateLimitOverride{
		"acme_new_account_per_ip":    cfg.NewAccountPerIP,
		"acme_new_order_per_account": cfg.NewOrderPerAccount,
		"acme_new_authz_per_account": cfg.NewAuthzPerAccount,
		"apikey_requests_per_key":    cfg.APIKeyRequestsPerKey,
	}

	now := time.Now().UTC()
	for _, d := range defaults {
		if o, ok := overrides[d.Name]; ok {
			if o.WindowSeconds > 0 {
				d.WindowSeconds = o.WindowSeconds
			}
			if o.MaxRequests > 0 {
				d.MaxRequests = o.MaxRequests
			}
		}

		row := &storage.RateLimitConfig{
			Name:          d.Name,
			Scope:         d.Scope,
			Algorithm:     d.Algorithm,
			WindowSeconds: d.WindowSeconds,
			MaxRequests:   d.MaxRequests,
			Enabled:       d.Enabled,
			UpdatedAt:     now,
		}
		if err := store.UpsertRateLimitConfigIfAbsent(ctx, row); err != nil {
			return fmt.Errorf("setup: seed rate limit config %q: %w", d.Name, err)
		}
	}

	slog.Info("rate limit configs seeded (existing rows left untouched)")
	return nil
}

// LoadRateLimitEngine reads all limiter configs from the DB and builds a
// ready-to-use ratelimit.Engine.
func LoadRateLimitEngine(ctx context.Context, store storage.Store) (*ratelimit.Engine, error) {
	configs, err := store.ListRateLimitConfigs(ctx)
	if err != nil {
		return nil, fmt.Errorf("setup: load rate limit configs: %w", err)
	}

	var limiterConfigs []ratelimit.LimiterConfig
	for _, c := range configs {
		limiterConfigs = append(limiterConfigs, ratelimit.LimiterConfig{
			Name:          c.Name,
			Scope:         c.Scope,
			Algorithm:     c.Algorithm,
			WindowSeconds: c.WindowSeconds,
			MaxRequests:   c.MaxRequests,
			Enabled:       c.Enabled,
		})
	}

	engine := ratelimit.NewEngine(store)
	if err := engine.LoadConfigs(limiterConfigs); err != nil {
		return nil, fmt.Errorf("setup: load rate limit engine: %w", err)
	}
	return engine, nil
}
