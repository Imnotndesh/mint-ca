package setup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
)

type stateOnlyStore struct {
	storage.Store
	st storage.SetupState
}

func (f *stateOnlyStore) GetSetupState(ctx context.Context) (storage.SetupState, error) {
	return f.st, nil
}

// RegisterStateRoute must expose GET /setup/state on its own, without the
// bootstrap-key-gated /setup subtree, so a ready-mode router (which never
// mounts the rest of Handler.RegisterRoutes) can still answer it — this is
// what the dashboard's boot-time check and other onboarding tooling rely on.
func TestRegisterStateRoute_ReadyStateReachableWithoutBootstrapKey(t *testing.T) {
	h := NewHandler(&stateOnlyStore{st: storage.StateReady}, nil, nil, nil)
	r := chi.NewRouter()
	h.RegisterStateRoute(r)

	req := httptest.NewRequest(http.MethodGet, "/setup/state", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["state"] != string(storage.StateReady) {
		t.Fatalf("expected state=ready, got %v", body["state"])
	}
	if body["configured"] != true {
		t.Fatalf("expected configured=true, got %v", body["configured"])
	}
}

func TestRegisterStateRoute_DoesNotMountProtectedSetupRoutes(t *testing.T) {
	h := NewHandler(&stateOnlyStore{st: storage.StateReady}, nil, nil, nil)
	r := chi.NewRouter()
	h.RegisterStateRoute(r)

	req := httptest.NewRequest(http.MethodPost, "/setup/root-ca", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("RegisterStateRoute must not expose the bootstrap-gated /setup subtree")
	}
}
