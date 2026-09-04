package handlers

import (
	"context"
	"net/http"
	"testing"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// phase3FakeStore models two tenants' provisioners plus their CSR-approval
// rules and EAB credentials for the Phase-3 cross-tenant tests.
type phase3FakeStore struct {
	storage.Store
	provs   map[uuid.UUID]*storage.Provisioner
	rules   map[uuid.UUID]*storage.CSRAutoApproveRule
	eabByID map[string]*storage.EABCredential
}

func (f *phase3FakeStore) Close() error { return nil }

func (f *phase3FakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	return f.provs[id], nil
}
func (f *phase3FakeStore) CreateCSRAutoApproveRule(ctx context.Context, r *storage.CSRAutoApproveRule) error {
	f.rules[r.ID] = r
	return nil
}
func (f *phase3FakeStore) ListCSRAutoApproveRules(ctx context.Context, p uuid.UUID) ([]*storage.CSRAutoApproveRule, error) {
	out := []*storage.CSRAutoApproveRule{}
	for _, r := range f.rules {
		if p == uuid.Nil || r.ProvisionerID == p {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *phase3FakeStore) UpdateCSRAutoApproveRule(ctx context.Context, r *storage.CSRAutoApproveRule) error {
	f.rules[r.ID] = r
	return nil
}
func (f *phase3FakeStore) DeleteCSRAutoApproveRule(ctx context.Context, id uuid.UUID) error {
	delete(f.rules, id)
	return nil
}
func (f *phase3FakeStore) GetEABCredential(ctx context.Context, keyID string) (*storage.EABCredential, error) {
	return f.eabByID[keyID], nil
}
func (f *phase3FakeStore) CreateEABCredential(ctx context.Context, e *storage.EABCredential) error {
	f.eabByID[e.KeyID] = e
	return nil
}
func (f *phase3FakeStore) MarkEABUsed(ctx context.Context, id uuid.UUID) error { return nil }

func newPhase3Fake() *phase3FakeStore {
	return &phase3FakeStore{
		provs:   map[uuid.UUID]*storage.Provisioner{},
		rules:   map[uuid.UUID]*storage.CSRAutoApproveRule{},
		eabByID: map[string]*storage.EABCredential{},
	}
}

// TestPhase3_CSRRule_ForeignProvisionerRejected ensures tenant A cannot pin a
// CSR auto-approval rule to tenant B's provisioner.
func TestPhase3_CSRRule_ForeignProvisionerRejected(t *testing.T) {
	store := newPhase3Fake()
	tenantB := uuid.New()
	provB := &storage.Provisioner{ID: uuid.New(), CAID: uuid.New(), Name: "provB", TenantID: tenantB}
	store.provs[provB.ID] = provB

	tenantA := uuid.New()
	h := NewApprovalHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	body := `{"provisioner_id":"` + provB.ID.String() + `","name":"rule"}`
	if rec := doScopeRequest(r, http.MethodPost, "/api/v1/approval/csr-rules/", body, &tenantA); rec.Code != http.StatusNotFound {
		t.Fatalf("create rule on foreign provisioner = %d, want 404: %s", rec.Code, rec.Body.String())
	}
	// own provisioner succeeds
	provA := &storage.Provisioner{ID: uuid.New(), CAID: uuid.New(), Name: "provA", TenantID: tenantA}
	store.provs[provA.ID] = provA
	if rec := doScopeRequest(r, http.MethodPost, "/api/v1/approval/csr-rules/", `{"provisioner_id":"`+provA.ID.String()+`","name":"r"}`, &tenantA); rec.Code != http.StatusCreated {
		t.Fatalf("create rule on own provisioner = %d: %s", rec.Code, rec.Body.String())
	}
}

// TestPhase3_EAB_ForeignProvisionerRejected ensures tenant A cannot issue EAB
// credentials under tenant B's provisioner, nor revoke them.
func TestPhase3_EAB_ForeignProvisionerRejected(t *testing.T) {
	store := newPhase3Fake()
	tenantB := uuid.New()
	provB := &storage.Provisioner{ID: uuid.New(), CAID: uuid.New(), Name: "provB", TenantID: tenantB}
	store.provs[provB.ID] = provB
	cred := &storage.EABCredential{ID: uuid.New(), ProvisionerID: provB.ID, KeyID: "k-eabB"}
	store.eabByID[cred.KeyID] = cred

	tenantA := uuid.New()
	h := NewEABHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	if rec := doScopeRequest(r, http.MethodPost, "/api/v1/eab/provisioner/"+provB.ID.String(), "", &tenantA); rec.Code != http.StatusNotFound {
		t.Fatalf("create eab on foreign provisioner = %d, want 404", rec.Code)
	}
	if rec := doScopeRequest(r, http.MethodDelete, "/api/v1/eab/"+cred.KeyID, "", &tenantA); rec.Code != http.StatusNotFound {
		t.Fatalf("revoke foreign eab = %d, want 404", rec.Code)
	}
	// Platform admin may revoke it.
	if rec := doScopeRequest(r, http.MethodDelete, "/api/v1/eab/"+cred.KeyID, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("platform revoke foreign eab = %d", rec.Code)
	}
}
