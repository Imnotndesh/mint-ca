package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	apimiddleware "mint-ca/internal/api/middleware"
	"mint-ca/internal/ratelimit"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type settingsFakeStore struct {
	storage.Store
	mu      sync.Mutex
	configs map[string]*storage.RateLimitConfig
}

func (f *settingsFakeStore) GetRateLimitConfig(ctx context.Context, name string) (*storage.RateLimitConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.configs[name], nil
}

func (f *settingsFakeStore) ListRateLimitConfigs(ctx context.Context) ([]*storage.RateLimitConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*storage.RateLimitConfig{}
	for _, c := range f.configs {
		out = append(out, c)
	}
	return out, nil
}

func (f *settingsFakeStore) IncrementRateLimitCounter(ctx context.Context, limiterName, bucketKey string, windowStart time.Time) error {
	return nil
}

func (f *settingsFakeStore) UpdateRateLimitConfig(ctx context.Context, cfg *storage.RateLimitConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configs[cfg.Name] = cfg
	return nil
}

func doSettingsRequest(r chi.Router, method, path, body string, callerTenantID *uuid.UUID) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	caller := &storage.APIKey{Name: "caller", TenantID: callerTenantID}
	req = req.WithContext(context.WithValue(req.Context(), apimiddleware.APIKeyKey, caller))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func newSettingsTestStore() *settingsFakeStore {
	return &settingsFakeStore{
		configs: map[string]*storage.RateLimitConfig{
			"apikey_requests_per_key": {
				Name:          "apikey_requests_per_key",
				Scope:         "api_key",
				Algorithm:     "fixed_window",
				WindowSeconds: 60,
				MaxRequests:   300,
				Enabled:       true,
				UpdatedAt:     time.Now().UTC(),
			},
		},
	}
}

func TestSettingsHandler_ListRequiresPlatformAdmin(t *testing.T) {
	store := newSettingsTestStore()
	h := NewSettingsHandler(store, ratelimit.NewEngine(store))
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	tenantID := uuid.New()
	rec := doSettingsRequest(r, http.MethodGet, "/api/v1/settings/ratelimits/", "", &tenantID)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped list = %d, want 403", rec.Code)
	}
	rec = doSettingsRequest(r, http.MethodGet, "/api/v1/settings/ratelimits/", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("platform list = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSettingsHandler_GetNotFound(t *testing.T) {
	store := newSettingsTestStore()
	h := NewSettingsHandler(store, ratelimit.NewEngine(store))
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	rec := doSettingsRequest(r, http.MethodGet, "/api/v1/settings/ratelimits/does_not_exist", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get unknown = %d, want 404", rec.Code)
	}
}

func TestSettingsHandler_UpdateHotAppliesAndPersists(t *testing.T) {
	store := newSettingsTestStore()
	engine := ratelimit.NewEngine(store)
	if err := engine.LoadConfigs([]ratelimit.LimiterConfig{
		{Name: "apikey_requests_per_key", Scope: "api_key", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 300, Enabled: true},
	}); err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}
	h := NewSettingsHandler(store, engine)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	tenantID := uuid.New()
	body := `{"algorithm":"fixed_window","window_seconds":3600,"max_requests":2,"enabled":true}`
	rec := doSettingsRequest(r, http.MethodPut, "/api/v1/settings/ratelimits/apikey_requests_per_key", body, &tenantID)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped update = %d, want 403", rec.Code)
	}

	rec = doSettingsRequest(r, http.MethodPut, "/api/v1/settings/ratelimits/apikey_requests_per_key", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("platform update = %d: %s", rec.Code, rec.Body.String())
	}

	store.mu.Lock()
	got := store.configs["apikey_requests_per_key"]
	store.mu.Unlock()
	if got.WindowSeconds != 3600 || got.MaxRequests != 2 || !got.Enabled {
		t.Fatalf("persisted config not updated: %+v", got)
	}

	// Hot-applied: the engine was seeded with max_requests=300 at LoadConfigs
	// time; if the PUT didn't hot-swap it, this would allow far more than 2.
	ctx := context.Background()
	allowedCount := 0
	for range 3 {
		allowed, _, err := engine.Check(ctx, "apikey_requests_per_key", "bucket")
		if err != nil {
			t.Fatalf("Check after update: %v", err)
		}
		if allowed {
			allowedCount++
		}
	}
	if allowedCount != 2 {
		t.Fatalf("expected exactly 2 allowed requests after hot-apply of max_requests=2, got %d", allowedCount)
	}
}

func TestSettingsHandler_UpdateRejectsBadInput(t *testing.T) {
	store := newSettingsTestStore()
	h := NewSettingsHandler(store, ratelimit.NewEngine(store))
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	rec := doSettingsRequest(r, http.MethodPut, "/api/v1/settings/ratelimits/apikey_requests_per_key",
		`{"algorithm":"fixed_window","window_seconds":0,"max_requests":10,"enabled":true}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("zero window_seconds = %d, want 400", rec.Code)
	}

	rec = doSettingsRequest(r, http.MethodPut, "/api/v1/settings/ratelimits/apikey_requests_per_key",
		`{"algorithm":"not_a_real_algorithm","window_seconds":60,"max_requests":10,"enabled":true}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad algorithm = %d, want 400", rec.Code)
	}

	rec = doSettingsRequest(r, http.MethodPut, "/api/v1/settings/ratelimits/does_not_exist",
		`{"algorithm":"fixed_window","window_seconds":60,"max_requests":10,"enabled":true}`, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update unknown limiter = %d, want 404", rec.Code)
	}
}
