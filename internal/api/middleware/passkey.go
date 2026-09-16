package middleware

import (
	"net/http"
	"strings"
)

// stepUpValidator reports whether a step-up token is live.
type stepUpValidator func(token string) bool

// highRisk lists method+path-prefix pairs that warrant a fresh passkey
// assertion when step-up is enabled.
var highRisk = []struct {
	method string
	prefix string
}{
	{"POST", "/api/v1/certs/issue"},
	{"POST", "/api/v1/certs/sign"},
	{"POST", "/api/v1/certs/batch"},
	{"POST", "/api/v1/ca"},
	{"PUT", "/api/v1/ca/"},
	{"POST", "/api/v1/apikeys"},
	{"POST", "/api/v1/tenants"},
	{"PUT", "/api/v1/tenants/"},
	{"POST", "/api/v1/admin/restore"},
	{"POST", "/api/v1/sshca/"},
	{"POST", "/api/v1/eab/"},
	{"POST", "/api/v1/approval/"},
}

// RequireStepUp enforces a valid passkey step-up token (header
// X-Passkey-Step-Up) on high-risk requests when policy is "high_risk" or "all".
// The passkey ceremony endpoints themselves are always exempt so an operator
// can bootstrap/refresh their passkey. A no-op unless policy != "off".
func RequireStepUp(policy string, validate stepUpValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if policy == "" || policy == "off" {
				next.ServeHTTP(w, r)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/api/v1/passkeys") {
				next.ServeHTTP(w, r)
				return
			}
			if !needsStepUp(policy, r) {
				next.ServeHTTP(w, r)
				return
			}
			if !validate(r.Header.Get("X-Passkey-Step-Up")) {
				writeError(w, http.StatusForbidden, "passkey step-up required for this action")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func needsStepUp(policy string, r *http.Request) bool {
	if policy == "all" {
		return r.Method != http.MethodGet && r.Method != http.MethodHead
	}
	for _, hr := range highRisk {
		if r.Method == hr.method && strings.HasPrefix(r.URL.Path, hr.prefix) {
			return true
		}
	}
	return false
}
