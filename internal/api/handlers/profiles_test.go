package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"mint-ca/internal/policy"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// profileFakeStore is a minimal in-memory profile store.
type profileFakeStore struct {
	storage.Store
	mu       sync.Mutex
	profiles map[uuid.UUID]*storage.Profile
	byName   map[string]*storage.Profile
}

func newProfileFakeStore() *profileFakeStore {
	return &profileFakeStore{
		profiles: map[uuid.UUID]*storage.Profile{},
		byName:   map[string]*storage.Profile{},
	}
}

func (f *profileFakeStore) Close() error { return nil }
func (f *profileFakeStore) CreateProfile(ctx context.Context, p *storage.Profile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.profiles[p.ID] = p
	f.byName[p.Name] = p
	return nil
}
func (f *profileFakeStore) GetProfile(ctx context.Context, id uuid.UUID) (*storage.Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.profiles[id], nil
}
func (f *profileFakeStore) GetProfileByName(ctx context.Context, name string) (*storage.Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byName[name], nil
}
func (f *profileFakeStore) ListProfiles(ctx context.Context) ([]*storage.Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*storage.Profile{}
	for _, p := range f.profiles {
		out = append(out, p)
	}
	return out, nil
}
func (f *profileFakeStore) UpdateProfile(ctx context.Context, p *storage.Profile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byName[p.Name] = p
	f.profiles[p.ID] = p
	return nil
}
func (f *profileFakeStore) DeleteProfile(ctx context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.profiles[id]
	if ok {
		delete(f.byName, p.Name)
	}
	delete(f.profiles, id)
	return nil
}

func setupProfilesRouter(store storage.Store) chi.Router {
	h := NewProfileHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	return r
}

func TestProfiles_CRUD(t *testing.T) {
	store := newProfileFakeStore()
	r := setupProfilesRouter(store)

	// Create
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/profiles/", strings.NewReader(
		`{"name":"web","allowed_key_algos":["ecdsa-p256"],"max_ttl_seconds":86400,"require_san":true}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d: %s", rec.Code, rec.Body.String())
	}
	if len(store.profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(store.profiles))
	}

	// List
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/profiles/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"web"`) {
		t.Fatalf("list: %d: %s", rec.Code, rec.Body.String())
	}

}
func TestProfiles_EnforcedOnIssue(t *testing.T) {
	store := newProfileFakeStore()
	// Profile disallows wildcard SANs.
	store.CreateProfile(context.Background(), &storage.Profile{
		ID: uuid.New(), Name: "nowild", AllowWildcard: false,
	})
	ch := &CertHandler{store: store}

	prof, err := ch.loadProfileByName(context.Background(), "nowild")
	if err != nil || prof == nil {
		t.Fatalf("loadProfileByName: %v %v", prof, err)
	}
	// Confirm a wildcard SAN returns an error via the actual profile evaluation.
	if err := policy.EvaluateProfile(prof, policy.CertRequest{SANsDNS: []string{"*.x.com"}}); err == nil {
		t.Error("expected wildcard SAN rejected by profile")
	}
}
