package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireStepUp(t *testing.T) {
	valid := func(tok string) bool { return tok == "good" }
	handler := func(policy string) http.Handler {
		return RequireStepUp(policy, valid)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}
	do := func(h http.Handler, method, path, tok string) int {
		req := httptest.NewRequest(method, path, nil)
		if tok != "" {
			req.Header.Set("X-Passkey-Step-Up", tok)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// off -> always allowed
	if c := do(handler("off"), http.MethodPost, "/api/v1/ca/root", ""); c != http.StatusOK {
		t.Fatalf("off = %d", c)
	}
	// high_risk without token -> 403
	if c := do(handler("high_risk"), http.MethodPost, "/api/v1/ca/root", ""); c != http.StatusForbidden {
		t.Fatalf("high_risk no token = %d, want 403", c)
	}
	// high_risk with token -> 200
	if c := do(handler("high_risk"), http.MethodPost, "/api/v1/ca/root", "good"); c != http.StatusOK {
		t.Fatalf("high_risk token = %d", c)
	}
	// GET is never gated
	if c := do(handler("high_risk"), http.MethodGet, "/api/v1/ca/root", ""); c != http.StatusOK {
		t.Fatalf("GET = %d", c)
	}
	// passkey ceremony endpoints exempt
	if c := do(handler("all"), http.MethodPost, "/api/v1/passkeys/login/finish", ""); c != http.StatusOK {
		t.Fatalf("passkey path = %d", c)
	}
	// all -> non-GET gated
	if c := do(handler("all"), http.MethodPost, "/api/v1/anything", ""); c != http.StatusForbidden {
		t.Fatalf("all = %d", c)
	}
}
