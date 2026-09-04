package middleware

import (
	"net/http"
)

// LeaderChecker reports whether this node currently holds HA leadership (see
// internal/ha.Elector). Kept as a small interface so this middleware doesn't
// depend on the ha package's concrete type.
type LeaderChecker interface {
	IsLeader() bool
	NodeID() string
}

// RequireLeader refuses every request with 503 unless this node is the
// current HA leader. In active-passive HA, only the leader should serve
// mutating API traffic (or, in this simple model, any authenticated API
// traffic) — standbys stay fully passive until they win an election. A nil
// checker means HA is not configured; every request passes through.
func RequireLeader(checker LeaderChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if checker == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !checker.IsLeader() {
				w.Header().Set("Retry-After", "5")
				writeError(w, http.StatusServiceUnavailable, "this node is not the current HA leader")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
