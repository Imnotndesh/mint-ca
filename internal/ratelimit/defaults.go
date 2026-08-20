package ratelimit

// DefaultConfigs are the hardcoded fair-use defaults seeded into the
// database on first boot, if no row for that limiter name already exists.
// These are intentionally conservative for a self-hosted CA; tune via the
// (future) web UI or the one-time env override at first boot.
func DefaultConfigs() []LimiterConfig {
	return []LimiterConfig{
		{
			Name:          "acme_new_account_per_ip",
			Scope:         "ip",
			Algorithm:     "fixed_window",
			WindowSeconds: 3600,
			MaxRequests:   10,
			Enabled:       true,
		},
		{
			Name:          "acme_new_order_per_account",
			Scope:         "account",
			Algorithm:     "fixed_window",
			WindowSeconds: 3600,
			MaxRequests:   50,
			Enabled:       true,
		},
		{
			Name:          "acme_new_authz_per_account",
			Scope:         "account",
			Algorithm:     "fixed_window",
			WindowSeconds: 3600,
			MaxRequests:   50,
			Enabled:       true,
		},
		{
			Name:          "apikey_requests_per_key",
			Scope:         "api_key",
			Algorithm:     "fixed_window",
			WindowSeconds: 60,
			MaxRequests:   300,
			Enabled:       true,
		},
	}
}
