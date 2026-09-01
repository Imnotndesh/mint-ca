package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// apiKeyFakeStore is a minimal store for the API key handler. It embeds a nil
// storage.Store so it satisfies the full interface; only the API-key methods we
// call are overridden.
type apiKeyFakeStore struct {
	storage.Store
	mu   sync.Mutex
	keys map[uuid.UUID]*storage.APIKey
}

func (f *apiKeyFakeStore) Close() error { return nil }

func (f *apiKeyFakeStore) CreateAPIKey(ctx context.Context, k *storage.APIKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[k.ID] = k
	return nil
}
func (f *apiKeyFakeStore) ListAPIKeys(ctx context.Context) ([]*storage.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*storage.APIKey{}
	for _, k := range f.keys {
		out = append(out, k)
	}
	return out, nil
}
func (f *apiKeyFakeStore) DeleteAPIKey(ctx context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.keys, id)
	return nil
}
func (f *apiKeyFakeStore) UpdateAPIKeyHash(ctx context.Context, id uuid.UUID, newHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[id]
	if !ok {
		return errors.New("not found")
	}
	k.KeyHash = newHash
	return nil
}

func setupAPIKeys() (*apiKeyFakeStore, chi.Router) {
	store := &apiKeyFakeStore{keys: map[uuid.UUID]*storage.APIKey{}}
	h := NewAPIKeyHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	return store, r
}

// doAPIKeyRequest issues a request against the router.
func doAPIKeyRequest(r chi.Router, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestAPIKey_DefaultExpiryApplied(t *testing.T) {
	store, r := setupAPIKeys()
	rec := doAPIKeyRequest(r, http.MethodPost, "/api/v1/apikeys/", `{"name":"ci-bot"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d: %s", rec.Code, rec.Body.String())
	}
	store.mu.Lock()
	for _, k := range store.keys {
		if k.ExpiresAt == nil {
			t.Fatal("expected a default expiry to be set")
		}
		if until := time.Until(*k.ExpiresAt); until < defaultAPIKeyTTL-2*time.Hour || until > defaultAPIKeyTTL+time.Hour {
			t.Errorf("default expiry window %v, want ~%v", until, defaultAPIKeyTTL)
		}
	}
	store.mu.Unlock()
}

func TestAPIKey_ExplicitNeverExpires(t *testing.T) {
	store, r := setupAPIKeys()
	rec := doAPIKeyRequest(r, http.MethodPost, "/api/v1/apikeys/", `{"name":"long","never_expires":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, k := range store.keys {
		if k.ExpiresAt != nil {
			t.Fatal("expected no expiry when never_expires=true")
		}
	}
}

func TestAPIKey_RotateChangesHash(t *testing.T) {
	store := &apiKeyFakeStore{keys: map[uuid.UUID]*storage.APIKey{}}
	id := uuid.New()
	store.keys[id] = &storage.APIKey{ID: id, Name: "bot", KeyHash: "old"}
	h := NewAPIKeyHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	rec := doAPIKeyRequest(r, http.MethodPost, "/api/v1/apikeys/"+id.String()+"/rotate", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d: %s", rec.Code, rec.Body.String())
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.keys[id].KeyHash == "old" {
		t.Fatal("rotate must replace the key hash")
	}
}
