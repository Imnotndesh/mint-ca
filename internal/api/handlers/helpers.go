package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v interface{}) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func paginationParams(r *http.Request) (limit, offset int) {
	limit = 50
	offset = 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}
	return
}

func actorFromContext(r *http.Request) string {
	if v := r.Context().Value(apimiddlewareActorKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return "unknown"
}

// apimiddlewareActorKey is the context key used by the auth middleware.
// Defined here to avoid an import cycle — the middleware package sets it,
// handler helpers read it, and both import only this package for the key type.
type contextKey string

const apimiddlewareActorKey contextKey = "actor"
