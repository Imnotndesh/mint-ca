package api

import (
	"net/http"

	"mint-ca/internal/api/handlers"
	apimiddleware "mint-ca/internal/api/middleware"
	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/config"
	"mint-ca/internal/policy"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func BuildRouter(
	cfg *config.Config,
	store storage.Store,
	caEngine *ca.Engine,
	crlMgr *revocation.CRLManager,
	ocspResponder *revocation.OCSPResponder,
	policyEngine *policy.Engine,
) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(apimiddleware.Logger())

	// Health check — no auth, no audit
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"mint-ca"}`))
	})

	// Public PKI endpoints — no auth required
	r.Group(func(r chi.Router) {
		handlers.NewPKIHandler(crlMgr, ocspResponder, caEngine, store).RegisterRoutes(r)
	})

	// Authenticated management API
	r.Group(func(r chi.Router) {
		r.Use(apimiddleware.Auth(store))
		r.Use(apimiddleware.Audit(store))

		handlers.NewCAHandler(caEngine, store).RegisterRoutes(r)
		handlers.NewCertHandler(caEngine, policyEngine, store).RegisterRoutes(r)
		handlers.NewProvisionerHandler(store).RegisterRoutes(r)
		handlers.NewPolicyHandler(store).RegisterRoutes(r)
		handlers.NewEABHandler(store).RegisterRoutes(r)
		handlers.NewAPIKeyHandler(store).RegisterRoutes(r)
		handlers.NewAuditHandler(store).RegisterRoutes(r)
		handlers.NewMetricsHandler(store).RegisterRoutes(r)
	})

	// ACME — conditionally registered
	if cfg.ACME.Enabled {
		handlers.NewACMEHandler(store, caEngine, policyEngine, cfg.ACME).RegisterRoutes(r)
	}

	return r
}
