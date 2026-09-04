package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"mint-ca/internal/ca"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/events"
	"mint-ca/internal/policy"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// capturingEmitter records every emitted event for assertions.
type capturingEmitter struct {
	mu     sync.Mutex
	events []events.Event
}

func (c *capturingEmitter) Emit(e events.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *capturingEmitter) all() []events.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]events.Event, len(c.events))
	copy(out, c.events)
	return out
}

// eventsFakeStore extends batchFakeStore with GetCertificate/RevokeCertificate
// so the revoke path can be exercised.
type eventsFakeStore struct {
	*batchFakeStore
	rootID uuid.UUID
}

func (f *eventsFakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	return &storage.Provisioner{ID: id, Name: "events", Status: storage.ProvisionerStatusActive, CAID: f.rootID}, nil
}

func (f *eventsFakeStore) ListPolicies(ctx context.Context) ([]*storage.Policy, error) {
	return nil, nil
}

func (f *eventsFakeStore) GetCertificate(ctx context.Context, id uuid.UUID) (*storage.Certificate, error) {
	for _, c := range f.certs {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, nil
}

func (f *eventsFakeStore) RevokeCertificate(ctx context.Context, id uuid.UUID, reason int) error {
	for _, c := range f.certs {
		if c.ID == id {
			c.Status = storage.CertStatusRevoked
			return nil
		}
	}
	return nil
}

func setupEventsHandler(t *testing.T) (*eventsFakeStore, *capturingEmitter, chi.Router, uuid.UUID) {
	t.Helper()
	base := &batchFakeStore{cas: map[uuid.UUID]*storage.CertificateAuthority{}}
	store := &eventsFakeStore{batchFakeStore: base}
	ks, err := mintcrypto.NewKeystore(make([]byte, 32))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(store, ks, "https://ca.test")
	root, err := engine.CreateRootCA(context.Background(), ca.CreateRootCARequest{
		Name: "root", CommonName: "Events Root", KeyAlgo: ca.KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	store.rootID = root.ID
	emitter := &capturingEmitter{}
	h := NewCertHandler(engine, policy.NewEngine(store), store, emitter, nil)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	return store, emitter, r, root.ID
}

func TestCertHandler_Issue_EmitsCertIssued(t *testing.T) {
	_, emitter, r, caID := setupEventsHandler(t)

	body, _ := json.Marshal(map[string]any{
		"ca_id":          caID.String(),
		"provisioner_id": uuid.New().String(),
		"common_name":    "svc.example.com",
		"ttl_seconds":    3600,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	got := emitter.all()
	if len(got) != 1 || got[0].Type != events.CertIssued {
		t.Fatalf("expected 1 cert.issued event, got %+v", got)
	}
	if got[0].Data["subject_cn"] != "svc.example.com" {
		t.Errorf("unexpected event data: %+v", got[0].Data)
	}
}

func TestCertHandler_Revoke_EmitsCertRevoked(t *testing.T) {
	store, emitter, r, caID := setupEventsHandler(t)

	// Issue first so there's a cert to revoke.
	body, _ := json.Marshal(map[string]any{
		"ca_id":          caID.String(),
		"provisioner_id": uuid.New().String(),
		"common_name":    "svc.example.com",
		"ttl_seconds":    3600,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue status = %d, body = %s", rec.Code, rec.Body.String())
	}
	certID := store.certs[0].ID

	revokeReq := httptest.NewRequest(http.MethodPut, "/api/v1/certs/"+certID.String()+"/revoke", bytes.NewReader([]byte(`{"reason":1}`)))
	revokeRec := httptest.NewRecorder()
	r.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body = %s", revokeRec.Code, revokeRec.Body.String())
	}

	var revokedEvent *events.Event
	for _, e := range emitter.all() {
		if e.Type == events.CertRevoked {
			ev := e
			revokedEvent = &ev
		}
	}
	if revokedEvent == nil {
		t.Fatal("expected a cert.revoked event")
	}
	if revokedEvent.Data["cert_id"] != certID.String() {
		t.Errorf("unexpected event data: %+v", revokedEvent.Data)
	}
}
