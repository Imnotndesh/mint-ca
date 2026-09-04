package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeLeaderChecker struct{ leader bool }

func (f fakeLeaderChecker) IsLeader() bool { return f.leader }
func (f fakeLeaderChecker) NodeID() string { return "test-node" }

func TestRequireLeader_NilChecker_PassesThrough(t *testing.T) {
	called := false
	h := RequireLeader(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("expected pass-through, called=%v code=%d", called, rec.Code)
	}
}

func TestRequireLeader_IsLeader_PassesThrough(t *testing.T) {
	called := false
	h := RequireLeader(fakeLeaderChecker{leader: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("expected pass-through, called=%v code=%d", called, rec.Code)
	}
}

func TestRequireLeader_NotLeader_Returns503(t *testing.T) {
	called := false
	h := RequireLeader(fakeLeaderChecker{leader: false})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if called {
		t.Fatal("expected the inner handler not to be called")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected a Retry-After header")
	}
}
