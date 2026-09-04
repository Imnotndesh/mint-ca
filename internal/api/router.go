package api

import (
	"crypto/x509"
	"log/slog"
	internalacme "mint-ca/internal/acme"
	"mint-ca/internal/ratelimit"
	"net/http"
	"os"

	"mint-ca/internal/api/handlers"
	apimiddleware "mint-ca/internal/api/middleware"
	"mint-ca/internal/attestation"
	"mint-ca/internal/attestation/tpm2"
	"mint-ca/internal/attestation/webauthn"
	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/config"
	"mint-ca/internal/events"
	"mint-ca/internal/policy"
	"mint-ca/internal/setup"
	"mint-ca/internal/sshca"
	"mint-ca/internal/sshca/krl"
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
	sshcaEngine *sshca.Engine,
	crlMgr *revocation.CRLManager,
	ocspResponder *revocation.OCSPResponder,
	policyEngine *policy.Engine,
	rlEngine *ratelimit.Engine,
	sshKRLMgr *krl.Manager,
	elector apimiddleware.LeaderChecker,
) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(apimiddleware.Logger())
	r.Use(apimiddleware.CORS)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"status":"ok","service":"mint-ca"}`))
		if err != nil {
			return
		}
	})

	r.Group(func(r chi.Router) {
		handlers.NewPKIHandler(crlMgr, ocspResponder, caEngine, store).RegisterRoutes(r)
		handlers.NewSCEPHandler(caEngine, store, cfg.SCEP).RegisterRoutes(r)
		handlers.NewSSHCAHandler(sshcaEngine, store, sshKRLMgr).RegisterPublicRoutes(r)
		r.Get(setup.TermsPath, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte(setup.DefaultTermsText))
		})
	})

	r.Group(func(r chi.Router) {
		r.Use(apimiddleware.RequireLeader(elector))
		r.Use(apimiddleware.Auth(store))
		r.Use(apimiddleware.RateLimit(rlEngine, store))
		r.Use(apimiddleware.Audit(store))

		handlers.NewCAHandler(caEngine, store).RegisterRoutes(r)
		handlers.NewSSHCAHandler(sshcaEngine, store, sshKRLMgr).RegisterRoutes(r)
		var emitter events.Emitter = events.NoopEmitter{}
		if cfg.Events.WebhookURL != "" {
			emitter = events.NewWebhookEmitter(cfg.Events.WebhookURL)
		}
		handlers.NewCertHandler(caEngine, policyEngine, store, emitter, buildAttestationRegistry(cfg.Attestation)).RegisterRoutes(r)
		handlers.NewProvisionerHandler(store).RegisterRoutes(r)
		handlers.NewPolicyHandler(store).RegisterRoutes(r)
		handlers.NewProfileHandler(store).RegisterRoutes(r)
		handlers.NewApprovalHandler(store).RegisterRoutes(r)
		handlers.NewRenewalHandler(store, cfg.Renewal).RegisterRoutes(r)
		handlers.NewEABHandler(store).RegisterRoutes(r)
		handlers.NewAPIKeyHandler(store).RegisterRoutes(r)
		handlers.NewTenantHandler(store).RegisterRoutes(r)
		handlers.NewAuditHandler(store).RegisterRoutes(r)
		handlers.NewMetricsHandler(store, cfg.Renewal).RegisterRoutes(r)
	})

	if cfg.ACME.Enabled {
		caaChecker := internalacme.NewCAAChecker(
			cfg.ACME.CAADomain,
			cfg.ACME.CAADNSServer,
			internalacme.SplitBypassLabels(cfg.ACME.CAABypassLabels),
		)
		acmeSvc := internalacme.NewService(store, caEngine, internalacme.NewNonceManager(store, 0), crlMgr, caaChecker, cfg.ACME.BaseURL)
		r.Group(func(r chi.Router) {
			r.Use(apimiddleware.RequireLeader(elector))
			handlers.NewACMEHandler(store, caEngine, acmeSvc, cfg.ACME, rlEngine).RegisterRoutes(r) // rlEngine passed through
		})
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
	r.Use(apimiddleware.CORS)

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

// buildAttestationRegistry wires up the built-in attestation verifiers (see
// internal/attestation). Attestation itself is opt-in per request, so both
// are always registered; cfg only narrows what the TPM2 verifier accepts.
func buildAttestationRegistry(cfg config.AttestationConfig) *attestation.Registry {
	reg := attestation.NewRegistry()

	var roots *x509.CertPool
	if cfg.TPMRootsFile != "" {
		pemBytes, err := os.ReadFile(cfg.TPMRootsFile)
		if err != nil {
			slog.Warn("attestation: failed to read TPM roots file, EK certificates will not be chain-verified", "file", cfg.TPMRootsFile, "err", err)
		} else {
			roots = x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pemBytes) {
				slog.Warn("attestation: TPM roots file contained no usable certificates", "file", cfg.TPMRootsFile)
			}
		}
	}
	reg.Register(tpm2.New(roots))
	reg.Register(webauthn.New())
	return reg
}
