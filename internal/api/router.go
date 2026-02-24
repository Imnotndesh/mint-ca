package api

import (
	internalacme "mint-ca/internal/acme"
	"net/http"

	"mint-ca/internal/api/handlers"
	apimiddleware "mint-ca/internal/api/middleware"
	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/config"
	"mint-ca/internal/policy"
	"mint-ca/internal/setup"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// BuildRouter builds the full management API router.
// Only mounted when setup state is READY.
func BuildRouter(
	cfg *config.Config,
	store storage.Store,
	caEngine *ca.Engine,
	crlMgr *revocation.CRLManager,
	ocspResponder *revocation.OCSPResponder,
	policyEngine *policy.Engine,
) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(apimiddleware.Logger())

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"mint-ca"}`))
	})

	r.Group(func(r chi.Router) {
		handlers.NewPKIHandler(crlMgr, ocspResponder, caEngine, store).RegisterRoutes(r)
	})

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

	if cfg.ACME.Enabled {
		acmeSvc := internalacme.NewService(store, caEngine, internalacme.NewNonceManager(store, 0), cfg.ACME.BaseURL)
		handlers.NewACMEHandler(store, caEngine, acmeSvc, cfg.ACME).RegisterRoutes(r)
	}

	return r
}

// BuildSetupRouter builds the minimal router active during setup mode.
// Only /healthz and /setup/* are exposed.
// Every other route returns 503 with a hint so the caller knows why.
func BuildSetupRouter(
	cfg *config.Config,
	store storage.Store,
	caEngine *ca.Engine,
	onReady setup.ReadyFunc,
) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(apimiddleware.Logger())

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"status":"setup","message":"complete setup at POST /setup/root-ca then POST /setup/api-key"}`))
		if err != nil {
			return
		}
	})

	setup.NewHandler(store, caEngine, cfg, onReady).RegisterRoutes(r)

	// Catch-all: tell callers the server is not ready yet instead of a bare 404.
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, err := w.Write([]byte(`{"error":"server is in setup mode","hint":"POST /setup/root-ca then POST /setup/api-key"}`))
		if err != nil {
			return
		}
	})

	return r
}
