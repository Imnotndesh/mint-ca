package setup

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"net/http"
	"net/http/httptest"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
)

// captureStore implements just enough of storage.Store for
// GenerateBootstrapKey, recording any key created.
type captureStore struct {
	storage.Store
	mu   sync.Mutex
	adds map[string]string // name -> key_hash
	byN  map[string]string
	st   storage.SetupState
}

func (f *captureStore) Close() error { return nil }

func (f *captureStore) GetSetupState(ctx context.Context) (storage.SetupState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st, nil
}

func (f *captureStore) SetSetupState(ctx context.Context, s storage.SetupState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st = s
	return nil
}

func (f *captureStore) GetAPIKeyByName(ctx context.Context, name string) (*storage.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h, ok := f.byN[name]; ok {
		return &storage.APIKey{Name: name, KeyHash: h}, nil
	}
	return nil, nil
}

func (f *captureStore) CreateAPIKey(ctx context.Context, k *storage.APIKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adds[k.Name] = k.KeyHash
	f.byN[k.Name] = k.KeyHash
	return nil
}

func newCaptureStore() *captureStore {
	return &captureStore{adds: map[string]string{}, byN: map[string]string{}}
}

// TestGenerateBootstrapKey_OperatorSecret proves an operator-supplied secret is
// used verbatim so remote/CI onboarding can know the bootstrap key in advance.
func TestGenerateBootstrapKey_OperatorSecret(t *testing.T) {
	ctx := context.Background()
	st := newCaptureStore()

	secret := "mca-my-operator-managed-bootstrap"
	bk, err := GenerateBootstrapKey(ctx, st, secret)
	if err != nil {
		t.Fatalf("GenerateBootstrapKey: %v", err)
	}
	if bk.Raw != secret {
		t.Fatalf("raw = %q, want the operator secret %q", bk.Raw, secret)
	}
}

// TestGenerateBootstrapKey_RandomWhenEmpty proves the default path generates a
// fresh random key when no operator secret is supplied.
func TestGenerateBootstrapKey_RandomWhenEmpty(t *testing.T) {
	ctx := context.Background()
	st := newCaptureStore()
	bk, err := GenerateBootstrapKey(ctx, st, "")
	if err != nil {
		t.Fatalf("GenerateBootstrapKey: %v", err)
	}
	if bk.Raw == "" {
		t.Fatal("expected a generated raw key")
	}
}

// TestGenerateBootstrapKey_DuplicateRejected ensures a second boot (key already
// present) refuses, mirroring the console-printed-key guard.
func TestGenerateBootstrapKey_DuplicateRejected(t *testing.T) {
	ctx := context.Background()
	st := newCaptureStore()
	if _, err := GenerateBootstrapKey(ctx, st, "boot1"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := GenerateBootstrapKey(ctx, st, "boot2"); err == nil {
		t.Fatal("expected an error when a bootstrap key already exists")
	}
}

// TestSetupStateEndpoint reports the machine-readable state and is reachable
// without a bootstrap key.
func TestSetupStateEndpoint(t *testing.T) {
	st := newCaptureStore()
	h := &Handler{store: st}
	r := chi.NewRouter()
	r.Get("/setup/state", h.getState)

	for _, stt := range []storage.SetupState{storage.StateUninitialized, storage.StateSetup, storage.StateReady} {
		st.st = stt
		req := httptest.NewRequest(http.MethodGet, "/setup/state", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("state %s: got %d", stt, rec.Code)
		}
		var got struct {
			State      string `json:"state"`
			Configured bool   `json:"configured"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("state %s: decode: %v", stt, err)
		}
		if got.State != string(stt) {
			t.Fatalf("state %s: reported %s", stt, got.State)
		}
		if got.Configured != (stt == storage.StateReady) {
			t.Fatalf("state %s: configured=%v", stt, got.Configured)
		}
	}
}
