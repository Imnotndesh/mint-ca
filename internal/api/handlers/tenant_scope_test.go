package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	apimiddleware "mint-ca/internal/api/middleware"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// scopeFakeStore is a minimal in-memory store exposing just enough of the
// resource plumbing for the Phase-2 cross-tenant isolation tests.
type scopeFakeStore struct {
	storage.Store
	mu       sync.Mutex
	cas      map[uuid.UUID]*storage.CertificateAuthority
	certs    map[uuid.UUID]*storage.Certificate
	sshcAs   map[uuid.UUID]*storage.SSHCertificateAuthority
	provs    map[uuid.UUID]*storage.Provisioner
	policies map[uuid.UUID]*storage.Policy
	profiles map[uuid.UUID]*storage.Profile
}

func newScopeFakeStore() *scopeFakeStore {
	return &scopeFakeStore{
		cas:      map[uuid.UUID]*storage.CertificateAuthority{},
		certs:    map[uuid.UUID]*storage.Certificate{},
		sshcAs:   map[uuid.UUID]*storage.SSHCertificateAuthority{},
		provs:    map[uuid.UUID]*storage.Provisioner{},
		policies: map[uuid.UUID]*storage.Policy{},
		profiles: map[uuid.UUID]*storage.Profile{},
	}
}

func (f *scopeFakeStore) Close() error { return nil }

// ---- SSH CA (list filter) ----
func (f *scopeFakeStore) GetSSHCA(ctx context.Context, id uuid.UUID) (*storage.SSHCertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sshcAs[id], nil
}
func (f *scopeFakeStore) ListSSHCAs(ctx context.Context) ([]*storage.SSHCertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*storage.SSHCertificateAuthority{}
	for _, c := range f.sshcAs {
		out = append(out, c)
	}
	return out, nil
}

// ---- CA ----
func (f *scopeFakeStore) GetCA(ctx context.Context, id uuid.UUID) (*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cas[id], nil
}
func (f *scopeFakeStore) ListCAs(ctx context.Context) ([]*storage.CertificateAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*storage.CertificateAuthority{}
	for _, c := range f.cas {
		out = append(out, c)
	}
	return out, nil
}
func (f *scopeFakeStore) ListChildCAs(ctx context.Context, parent uuid.UUID) ([]*storage.CertificateAuthority, error) {
	return nil, nil
}
func (f *scopeFakeStore) UpdateCAStatus(ctx context.Context, id uuid.UUID, s storage.CAStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.cas[id]; ok {
		f.cas[id].Status = s
	}
	return nil
}
func (f *scopeFakeStore) GetCertificate(ctx context.Context, id uuid.UUID) (*storage.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.certs[id], nil
}

// ---- Provisioner ----
func (f *scopeFakeStore) GetProvisioner(ctx context.Context, id uuid.UUID) (*storage.Provisioner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.provs[id], nil
}
func (f *scopeFakeStore) ListProvisionersByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Provisioner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*storage.Provisioner{}
	for _, p := range f.provs {
		if p.CAID == caID {
			out = append(out, p)
		}
	}
	return out, nil
}

// ---- Policy ----
func (f *scopeFakeStore) GetPolicy(ctx context.Context, id uuid.UUID) (*storage.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policies[id], nil
}
func (f *scopeFakeStore) ListPolicies(ctx context.Context) ([]*storage.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*storage.Policy{}
	for _, p := range f.policies {
		out = append(out, p)
	}
	return out, nil
}
func (f *scopeFakeStore) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.policies, id)
	return nil
}

// ---- Profile (reachable via profileStore assertion on fake embedding nil? no) ----

// doScopeRequest issues a request carrying a caller tenant (nil platform) and
// returns the response.
func doScopeRequest(r chi.Router, method, path, body string, tenant *uuid.UUID) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	caller := &storage.APIKey{Name: "caller", TenantID: tenant}
	req = req.WithContext(context.WithValue(req.Context(), apimiddleware.APIKeyKey, caller))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestPhase2_CA_CrossTenantDenied(t *testing.T) {
	store := newScopeFakeStore()
	caA := &storage.CertificateAuthority{ID: uuid.New(), Name: "caA"}
	caB := &storage.CertificateAuthority{ID: uuid.New(), Name: "caB"}
	store.cas[caA.ID] = caA
	store.cas[caB.ID] = caB

	// tenant A may read/get its own CA but not tenant B's, even though both
	// exist (404), matching existence-hiding.
	tenantA := uuid.New()
	tenantB := uuid.New()
	caA.TenantID = tenantA
	caB.TenantID = tenantB

	r := chi.NewRouter()
	caH := NewCAHandler(nil, store)
	caH.RegisterRoutes(r)

	if rec := doScopeRequest(r, http.MethodGet, "/api/v1/ca/"+caA.ID.String(), "", &tenantA); rec.Code != http.StatusOK {
		t.Fatalf("own ca get = %d", rec.Code)
	}
	if rec := doScopeRequest(r, http.MethodGet, "/api/v1/ca/"+caB.ID.String(), "", &tenantA); rec.Code != http.StatusNotFound {
		t.Fatalf("cross ca get = %d, want 404", rec.Code)
	}
	// Platform admin (nil tenant) sees tenant B's CA.
	if rec := doScopeRequest(r, http.MethodGet, "/api/v1/ca/"+caB.ID.String(), "", nil); rec.Code != http.StatusOK {
		t.Fatalf("platform ca get = %d", rec.Code)
	}
	// Cross-tenant revoke is 404 too.
	if rec := doScopeRequest(r, http.MethodPut, "/api/v1/ca/"+caB.ID.String()+"/revoke", "", &tenantA); rec.Code != http.StatusNotFound {
		t.Fatalf("cross revoke = %d, want 404", rec.Code)
	}
	// List only shows tenant A's CA for a tenant A caller.
	rec := doScopeRequest(r, http.MethodGet, "/api/v1/ca/", "", &tenantA)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"caA"`) || strings.Contains(rec.Body.String(), `"caB"`) {
		t.Fatalf("tenant list leaked other tenant: body=%s", rec.Body.String())
	}
}

func TestPhase2_Provisioner_ForeignCARejected(t *testing.T) {
	store := newScopeFakeStore()
	tenantA := uuid.New()
	caB := &storage.CertificateAuthority{ID: uuid.New(), Name: "caB", TenantID: uuid.New()}
	store.cas[caB.ID] = caB

	r := chi.NewRouter()
	NewProvisionerHandler(store).RegisterRoutes(r)

	// tenant A cannot create a provisioner under tenant B's CA.
	body := `{"ca_id":"` + caB.ID.String() + `","name":"p","type":"apikey"}`
	if rec := doScopeRequest(r, http.MethodPost, "/api/v1/provisioners/", body, &tenantA); rec.Code != http.StatusNotFound {
		t.Fatalf("provisioner under foreign CA = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

func TestPhase2_Policy_CrossTenantDenied(t *testing.T) {
	store := newScopeFakeStore()
	tenantA, tenantB := uuid.New(), uuid.New()
	polB := &storage.Policy{ID: uuid.New(), Name: "polB", TenantID: tenantB}
	store.policies[polB.ID] = polB

	r := chi.NewRouter()
	NewPolicyHandler(store).RegisterRoutes(r)

	// tenant A cannot get or delete tenant B's policy.
	if rec := doScopeRequest(r, http.MethodGet, "/api/v1/policies/"+polB.ID.String(), "", &tenantA); rec.Code != http.StatusNotFound {
		t.Fatalf("cross policy get = %d, want 404", rec.Code)
	}
	if rec := doScopeRequest(r, http.MethodDelete, "/api/v1/policies/"+polB.ID.String(), "", &tenantA); rec.Code != http.StatusNotFound {
		t.Fatalf("cross policy delete = %d, want 404", rec.Code)
	}
}

// TestPhase3_Cert_TransitiveTenantScope ensures a certificate is scoped through
// its CA: tenant A cannot read tenant B's CA's certificate (404 exists-hiding).
func TestPhase3_Cert_TransitiveTenantScope(t *testing.T) {
	store := newScopeFakeStore()
	tenantB := uuid.New()
	caB := &storage.CertificateAuthority{ID: uuid.New(), Name: "caB", TenantID: tenantB}
	cert := &storage.Certificate{ID: uuid.New(), CAID: caB.ID, Serial: "111"}
	store.cas[caB.ID] = caB
	store.certs[cert.ID] = cert

	tenantA := uuid.New()
	ch := NewCertHandler(nil, nil, store, nil, nil)
	r := chi.NewRouter()
	ch.RegisterRoutes(r)

	// Platform admin can get it.
	if rec := doScopeRequest(r, http.MethodGet, "/api/v1/certs/"+cert.ID.String(), "", nil); rec.Code != http.StatusOK {
		t.Fatalf("platform cert get = %d: %s", rec.Code, rec.Body.String())
	}
	// Tenant A (foreign) gets 404.
	if rec := doScopeRequest(r, http.MethodGet, "/api/v1/certs/"+cert.ID.String(), "", &tenantA); rec.Code != http.StatusNotFound {
		t.Fatalf("cross cert get = %d, want 404", rec.Code)
	}
}

// TestPhase4_SSHCA_ListIsTenantScoped ensures SSH CA lists only expose the
// caller's own tenant's SSH CAs.
func TestPhase4_SSHCA_ListIsTenantScoped(t *testing.T) {
	store := newScopeFakeStore()
	tenantA, tenantB := uuid.New(), uuid.New()
	sshA := &storage.SSHCertificateAuthority{ID: uuid.New(), Name: "sshA", TenantID: tenantA}
	sshB := &storage.SSHCertificateAuthority{ID: uuid.New(), Name: "sshB", TenantID: tenantB}
	store.sshcAs[sshA.ID] = sshA
	store.sshcAs[sshB.ID] = sshB

	h := NewSSHCAHandler(nil, store, nil)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	rec := doScopeRequest(r, http.MethodGet, "/api/v1/sshca/", "", &tenantA)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"sshA"`) || strings.Contains(rec.Body.String(), `"sshB"`) {
		t.Fatalf("tenant scoped sshca list leaked other tenant: %s", rec.Body.String())
	}
	// Platform admin sees both.
	rec = doScopeRequest(r, http.MethodGet, "/api/v1/sshca/", "", nil)
	if !strings.Contains(rec.Body.String(), `"sshA"`) || !strings.Contains(rec.Body.String(), `"sshB"`) {
		t.Fatalf("platform sshca list missing CAs: %s", rec.Body.String())
	}
}
