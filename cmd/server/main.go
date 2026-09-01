package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mint-ca/internal/logger"
	"mint-ca/internal/ratelimit"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mint-ca/internal/api"
	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/config"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/mtls"
	"mint-ca/internal/policy"
	"mint-ca/internal/renewal"
	"mint-ca/internal/setup"
	"mint-ca/internal/sshca"
	"mint-ca/internal/sshca/krl"
	"mint-ca/internal/storage"
	"mint-ca/internal/workers"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		_, err = os.Stderr.WriteString(err.Error() + "\n")
		if err != nil {
			return
		}
		os.Exit(1)
	}

	slog.SetDefault(buildLogger(cfg.Log))

	if b, err := json.Marshal(cfg.Redact()); err == nil {
		slog.Info("mint-ca starting", "config", string(b))
	}

	store, err := storage.New()
	if err != nil {
		slog.Error("failed to open storage", "err", err)
		os.Exit(1)
	}
	if err := setup.SeedRateLimitConfigs(context.Background(), store, cfg.RateLimit); err != nil {
		slog.Error("failed to seed rate limit configs", "err", err)
		_ = store.Close()
		os.Exit(1)
	}
	var rlEngine *ratelimit.Engine
	rlEngine, err = setup.LoadRateLimitEngine(context.Background(), store)
	if err != nil {
		slog.Error("failed to load rate limit engine", "err", err)
		_ = store.Close()
		os.Exit(1)
	}

	ks, err := mintcrypto.NewKeystore(cfg.Crypto.MasterKey)
	if err != nil {
		slog.Error("failed to initialise keystore", "err", err)
		_ = store.Close()
		os.Exit(1)
	}

	caEngine := ca.NewEngine(store, ks, cfg.ACME.BaseURL)
	policyEngine := policy.NewEngine(store)
	sshcaEngine := sshca.NewEngine(store, ks, policyEngine)
	crlManager := revocation.NewCRLManager(store, ks, cfg.ACME.BaseURL, cfg.CRL.DeltaEnabled)
	ocspResponder := revocation.NewOCSPResponder(store, ks)
	sshKRLManager := krl.NewManager(store)
	slog.Info("core services initialised")

	apiWorkers := workers.NewWorkerGroup()
	apiWorkers.Add(workers.NewCRLWorker(crlManager, cfg.CRL))
	apiWorkers.Add(workers.NewNonceWorker(store))
	apiWorkers.Add(workers.NewSSHKRLWorker(sshKRLManager, cfg.CRL))
	apiWorkers.Add(workers.NewRateLimitPruneWorker(store))
	if cfg.Renewal.Enabled {
		var deliverer renewal.Deliverer
		if cfg.Renewal.WebhookURL != "" {
			deliverer = renewal.NewWebhookDeliverer(cfg.Renewal.WebhookURL)
		}
		apiWorkers.Add(renewal.NewWorker(store, deliverer,
			time.Duration(cfg.Renewal.IntervalSeconds)*time.Second,
			time.Duration(cfg.Renewal.LeadSeconds)*time.Second))
	}
	apiWorkers.Start(context.Background())
	// Read state before starting the listener so we know which router to mount.
	state, err := store.GetSetupState(context.Background())
	if err != nil {
		slog.Error("failed to read setup state", "err", err)
		apiWorkers.Stop()
		_ = store.Close()
		ks.Zero()
		os.Exit(1)
	}
	listenErr := make(chan error, 1)

	onReady := func(certPEM, keyPEM []byte) error {
		certPath := cfg.Server.TLSCertFile
		keyPath := cfg.Server.TLSKeyFile

		if certPath == "" {
			certPath = "/data/server.crt"
		}
		if keyPath == "" {
			keyPath = "/data/server.key"
		}

		if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
			slog.Error("setup: failed to write TLS cert", "path", certPath, "err", err)
			return err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			slog.Error("setup: failed to write TLS key", "path", keyPath, "err", err)
			return err
		}

		slog.Info("setup: TLS certificate written to disk",
			"cert", certPath, "key", keyPath)
		slog.Info("setup: signalling restart — server will come back over TLS")

		// Send a sentinel that main's select will treat as a clean exit.
		// The container restart policy handles the actual restart.
		listenErr <- http.ErrServerClosed
		return nil
	}

	var router http.Handler

	switch state {
	case storage.StateUninitialized:
		slog.Info("first boot detected — entering setup mode")

		if err := store.SetSetupState(context.Background(), storage.StateSetup); err != nil {
			slog.Error("failed to transition to setup state", "err", err)
			apiWorkers.Stop()
			_ = store.Close()
			ks.Zero()
			os.Exit(1)
		}

		bk, err := setup.GenerateBootstrapKey(context.Background(), store)
		if err != nil {
			slog.Error("failed to generate bootstrap key", "err", err)
			apiWorkers.Stop()
			_ = store.Close()
			ks.Zero()
			os.Exit(1)
		}

		// Prints the bordered block with the key to stdout.
		setup.PrintBootstrapKey(bk)

		router = api.BuildSetupRouter(cfg, store, caEngine, onReady)

	case storage.StateSetup:
		// Container was restarted while in setup mode.
		// The bootstrap key is still in the DB — plaintext was printed on first boot.
		slog.Warn("restarted in setup mode — bootstrap key was printed on first boot, check earlier container logs")
		slog.Warn("if you cannot find the key, delete /data/mint-ca.db and start fresh")

		router = api.BuildSetupRouter(cfg, store, caEngine, onReady)

	case storage.StateReady:
		slog.Info("setup complete — starting full API")
		router = api.BuildRouter(cfg, store, caEngine, sshcaEngine, crlManager, ocspResponder, policyEngine, rlEngine, sshKRLManager)
	}

	srv := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Only apply TLS config when we are actually in READY state and TLS is
	// not explicitly disabled. In setup mode we always run plain HTTP so the
	// operator can reach /setup/* without a certificate.
	useTLS := state == storage.StateReady && !cfg.Server.TLSDisabled

	if useTLS {
		srv.TLSConfig = &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
			PreferServerCipherSuites: true,
		}
	}

	go func() {
		if useTLS {
			slog.Info("listening (TLS)", "addr", cfg.Server.ListenAddr,
				"cert", cfg.Server.TLSCertFile)
			listenErr <- srv.ListenAndServeTLS(
				cfg.Server.TLSCertFile,
				cfg.Server.TLSKeyFile,
			)
		} else {
			slog.Info("listening (plain HTTP)",
				"addr", cfg.Server.ListenAddr,
				"mode", state)
			listenErr <- srv.ListenAndServe()
		}
	}()

	// Optional mutual-TLS device enrollment listener. Started in READY state
	// only, on its own TLS listener that requires a device client certificate.
	var mtlsSrv *http.Server
	if cfg.MTLS.Enabled && state == storage.StateReady {
		mtlsSrv, err = startMTLSListener(cfg, store, caEngine)
		if err != nil {
			slog.Error("failed to start mtls enrollment listener", "err", err)
			allWorkers := apiWorkers
			_ = allWorkers
		}
	} else if cfg.MTLS.Enabled {
		slog.Warn("MTLS enrollment requested but server not in ready state; not starting")
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("shutdown signal received", "signal", sig.String())
	case err := <-listenErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "err", err)
			apiWorkers.Stop()
			_ = store.Close()
			ks.Zero()
			os.Exit(1)
		}
		// ErrServerClosed — fall through to clean shutdown below.
	}

	slog.Info("shutting down HTTP server")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP shutdown error", "err", err)
	}
	if mtlsSrv != nil {
		if err := mtlsSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("MTLS shutdown error", "err", err)
		}
	}

	slog.Info("stopping background workers")
	apiWorkers.Stop()

	if err := store.Close(); err != nil {
		slog.Error("error closing storage", "err", err)
	}
	ks.Zero()

	slog.Info("mint-ca stopped cleanly")
}

func buildLogger(cfg config.LogConfig) *slog.Logger {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	if cfg.JSON {
		return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		}))
	}

	return slog.New(logger.NewPrettyHandler(os.Stdout, level))
}

func startMTLSListener(cfg *config.Config, store storage.Store, caEngine *ca.Engine) (*http.Server, error) {
	issuerID, provID, err := resolveMTLSTargets(context.Background(), store)
	if err != nil {
		return nil, err
	}

	tlsConf, err := mtls.BuildServerTLSConfig(cfg.MTLS, []byte(cfg.MTLS.ClientCACertPEM))
	if err != nil {
		return nil, err
	}

	enroll := mtls.NewEnrollHandler(caEngine, store, issuerID, provID)
	r := chi.NewRouter()
	enroll.RegisterRoutes(r)

	mtlsSrv := &http.Server{
		Addr:      cfg.MTLS.ListenAddr,
		Handler:   r,
		TLSConfig: tlsConf,
	}
	go func() {
		if err := mtlsSrv.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("mtls enrollment listener error", "err", err)
		}
	}()
	slog.Info("mtls enrollment listener started", "addr", cfg.MTLS.ListenAddr)
	return mtlsSrv, nil
}

// resolveMTLSTargets finds the signing CA and an "mtls"-type provisioner bound
// to it. Prefers a provisioner whose type is mtls; otherwise fails unless an
// mtls provisioner exists for the first active CA.
func resolveMTLSTargets(ctx context.Context, store storage.Store) (uuid.UUID, uuid.UUID, error) {
	cas, err := store.ListCAs(ctx)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("mtls: list CAs: %w", err)
	}
	for _, caRec := range cas {
		provs, err := store.ListProvisionersByCA(ctx, caRec.ID)
		if err != nil {
			continue
		}
		for _, p := range provs {
			if p.Type == storage.ProvisionerTypeMTLS && p.Status == storage.ProvisionerStatusActive {
				return p.CAID, p.ID, nil
			}
		}
	}
	return uuid.Nil, uuid.Nil, errors.New("mtls: no active 'mtls' provisioner found; create one first")
}
