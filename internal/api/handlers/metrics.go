package handlers

import (
	"fmt"
	"net/http"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
)

type MetricsHandler struct{ store storage.Store }

func NewMetricsHandler(store storage.Store) *MetricsHandler {
	return &MetricsHandler{store: store}
}

func (h *MetricsHandler) RegisterRoutes(r chi.Router) {
	r.Get("/metrics", h.serve)
}

func (h *MetricsHandler) serve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cas, _ := h.store.ListCAs(ctx)
	logs, _ := h.store.ListAuditLogs(ctx, 10000, 0)

	var issued, revoked int
	for _, l := range logs {
		switch l.EventType {
		case "POST /api/v1/certs/issue", "POST /api/v1/certs/sign":
			issued++
		case "PUT /api/v1/certs/{certID}/revoke":
			revoked++
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "# HELP mintca_ca_total Total certificate authorities\n")
	fmt.Fprintf(w, "# TYPE mintca_ca_total gauge\n")
	fmt.Fprintf(w, "mintca_ca_total %d\n", len(cas))

	fmt.Fprintf(w, "# HELP mintca_certs_issued_total Total certificates issued\n")
	fmt.Fprintf(w, "# TYPE mintca_certs_issued_total counter\n")
	fmt.Fprintf(w, "mintca_certs_issued_total %d\n", issued)

	fmt.Fprintf(w, "# HELP mintca_certs_revoked_total Total certificates revoked\n")
	fmt.Fprintf(w, "# TYPE mintca_certs_revoked_total counter\n")
	fmt.Fprintf(w, "mintca_certs_revoked_total %d\n", revoked)
}
