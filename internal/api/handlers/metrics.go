package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
)

// X.509 and SSH issuing/revocation endpoints. The revoke routes contain a
// dynamic {certID} segment, so they are matched by prefix rather than exact
// string equality against the literal path recorded in the audit log.
const (
	certsIssuePath   = "POST /api/v1/certs/issue"
	certsSignPath    = "POST /api/v1/certs/sign"
	certsRevokeRoute = "PUT /api/v1/certs/"
	sshIssueRoute    = "POST /api/v1/sshca/"
	sshRevokeRoute   = "PUT /api/v1/sshca/certs/"
	sshCARoute       = "POST /api/v1/sshca"
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
	sshCAs, _ := h.store.ListSSHCAs(ctx)
	logs, _ := h.store.ListAuditLogs(ctx, 10000, 0)

	certIssued, certRevoked, sshIssued, sshRevoked, sshCA := countEvents(logs)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "# HELP mintca_ca_total Total X.509 certificate authorities\n")
	fmt.Fprintf(w, "# TYPE mintca_ca_total gauge\n")
	fmt.Fprintf(w, "mintca_ca_total %d\n", len(cas))

	fmt.Fprintf(w, "# HELP mintca_certs_issued_total Total X.509 certificates issued\n")
	fmt.Fprintf(w, "# TYPE mintca_certs_issued_total counter\n")
	fmt.Fprintf(w, "mintca_certs_issued_total %d\n", certIssued)

	fmt.Fprintf(w, "# HELP mintca_certs_revoked_total Total X.509 certificates revoked\n")
	fmt.Fprintf(w, "# TYPE mintca_certs_revoked_total counter\n")
	fmt.Fprintf(w, "mintca_certs_revoked_total %d\n", certRevoked)

	fmt.Fprintf(w, "# HELP mintca_sshca_total Total SSH certificate authorities\n")
	fmt.Fprintf(w, "# TYPE mintca_sshca_total gauge\n")
	fmt.Fprintf(w, "mintca_sshca_total %d\n", len(sshCAs))

	fmt.Fprintf(w, "# HELP mintca_ssh_certs_issued_total Total SSH certificates issued\n")
	fmt.Fprintf(w, "# TYPE mintca_ssh_certs_issued_total counter\n")
	fmt.Fprintf(w, "mintca_ssh_certs_issued_total %d\n", sshIssued)

	fmt.Fprintf(w, "# HELP mintca_ssh_certs_revoked_total Total SSH certificates revoked\n")
	fmt.Fprintf(w, "# TYPE mintca_ssh_certs_revoked_total counter\n")
	fmt.Fprintf(w, "mintca_ssh_certs_revoked_total %d\n", sshRevoked)

	fmt.Fprintf(w, "# HELP mintca_ssh_ca_created_total Total SSH CAs created\n")
	fmt.Fprintf(w, "# TYPE mintca_ssh_ca_created_total counter\n")
	fmt.Fprintf(w, "mintca_ssh_ca_created_total %d\n", sshCA)
}

// countEvents classifies audit-log entries into metrics counters. Because the
// revoke endpoints embed a dynamic {certID} in the URL path, they are matched
// by method+prefix against the literal path recorded in the audit log.
func countEvents(logs []*storage.AuditLog) (certIssued, certRevoked, sshIssued, sshRevoked, sshCA int) {
	for _, l := range logs {
		ev := l.EventType
		switch ev {
		case certsIssuePath, certsSignPath:
			certIssued++
		case sshCARoute:
			sshCA++
		}
		switch {
		case strings.HasPrefix(ev, certsRevokeRoute):
			certRevoked++
		case strings.HasPrefix(ev, sshIssueRoute):
			sshIssued++
		case strings.HasPrefix(ev, sshRevokeRoute):
			sshRevoked++
		}
	}
	return
}
