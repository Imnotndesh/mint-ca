package main

import (
	"context"
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
	"mint-ca/internal/ha"
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

	var elector *ha.Elector
	if cfg.HA.Enabled {
		lstore, ok := store.(ha.LeadershipStore)
		if !ok {
			slog.Error("MINT_HA_ENABLED requires a storage backend that supports leader election (postgres)")
			_ = store.Close()
			ks.Zero()
			os.Exit(1)
		}
		elector = ha.NewElector(lstore, cfg.HA.NodeID, time.Duration(cfg.HA.LeaseSeconds)*time.Second, time.Duration(cfg.HA.RenewSeconds)*time.Second)
		slog.Info("HA leader election enabled", "node_id", cfg.HA.NodeID)
	} else {
		elector = ha.NewElector(nil, cfg.HA.NodeID, 0, 0) // single-node mode: always leader
	}

	apiWorkers := workers.NewWorkerGroup()
	apiWorkers.Add(elector)
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
	// Build the router that runs initially based on setup state.
	startSetup := false
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
		setup.PrintBootstrapKey(bk)
		startSetup = true
	case storage.StateSetup:
		slog.Warn("resumed in-progress setup — bootstrap key was printed on first boot; check earlier container logs")
		slog.Warn("if you cannot find the key, delete /data/mint-ca.db and start fresh")
		startSetup = true
	case storage.StateReady:
		slog.Info("setup complete — starting full API")
	}

	readyRouter := api.BuildRouter(cfg, store, caEngine, sshcaEngine, crlManager, ocspResponder, policyEngine, rlEngine, sshKRLManager, elector)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	errCh := make(chan error, 1)
	restartCh := make(chan struct{}, 1)

	// startServer opens a listener on startAddr and serves handler. When
	// useTLS, it wraps the listener in TLS. It runs in its own goroutine and
	// reports bind/serve errors back through errCh. The returned stop func
	// gracefully shuts the server down (closing the listener).
	startServer := func(addr string, handler http.Handler, useTLS bool) (func(), error) {
		certFile, keyFile := tlsFilePaths(cfg)
		stop2, srvErr, err := serveListener(addr, handler, useTLS, certFile, keyFile,
			cfg.Server.ReadTimeout, cfg.Server.WriteTimeout, cfg.Server.IdleTimeout)
		if err != nil {
			return nil, err
		}
		go func() {
			for e := range srvErr {
				if e != nil && !errors.Is(e, http.ErrServerClosed) {
					errCh <- e
					return
				}
			}
		}()
		return stop2, nil
	}

	// onReady is invoked by the setup router when /setup/api-key completes.
	// It persists the freshly-issued TLS cert/key so the ready listener can
	// serve HTTPS, then splits setup -> ready in-process.
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
			return err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return err
		}
		slog.Info("setup: TLS certificate written to disk", "cert", certPath, "key", keyPath)
		slog.Info("setup: complete — swapping to ready API over TLS in-process")
		restartCh <- struct{}{}
		return nil
	}

	newStop := func() func() {
		return func() {}
	}()
	switch {
	case startSetup:
		// Initial serve: setup mode on plain HTTP.
		stop, err := startServer(cfg.Server.ListenAddr, api.BuildSetupRouter(cfg, store, caEngine, onReady), false)
		if err != nil {
			slog.Error("setup listen failure", "err", err)
			apiWorkers.Stop()
			_ = store.Close()
			ks.Zero()
			os.Exit(1)
		}
		newStop = stop
	default:
		// Already configured: serve the ready API (TLS unless disabled).
		stop, err := startServer(cfg.Server.ListenAddr, readyRouter, !cfg.Server.TLSDisabled)
		if err != nil {
			slog.Error("listener failure", "err", err)
			apiWorkers.Stop()
			_ = store.Close()
			ks.Zero()
			os.Exit(1)
		}
		newStop = stop
	}

	// Optional mutual-TLS device enrollment listener (ready state only).
	var mtlsStop func()
	if cfg.MTLS.Enabled && state == storage.StateReady {
		mtlsSrv, merr := startMTLSListener(cfg, store, caEngine)
		if merr != nil {
			slog.Error("failed to start mtls enrollment listener", "err", merr)
		} else {
			mtlsStop = func() {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				_ = mtlsSrv.Shutdown(ctx)
			}
		}
	} else if cfg.MTLS.Enabled {
		slog.Warn("MTLS enrollment requested but server not in ready state; not starting")
	}

	for {
		select {
		case sig := <-quit:
			slog.Info("shutdown signal received", "signal", sig.String())
			if newStop != nil {
				newStop()
			}
			if mtlsStop != nil {
				mtlsStop()
			}
			if err := store.Close(); err != nil {
				slog.Error("error closing storage", "err", err)
			}
			ks.Zero()
			slog.Info("mint-ca stopped cleanly")
			return
		case <-restartCh:
			// Setup finished: swap plain-HTTP setup -> ready over TLS. No exit.
			if newStop != nil {
				newStop()
			}
			if cfg.Server.TLSDisabled {
				slog.Warn("server not in setup; ready listener running plain HTTP because TLS is disabled")
			}
			useTLS := !cfg.Server.TLSDisabled
			stop, err := startServer(cfg.Server.ListenAddr, readyRouter, useTLS)
			if err != nil {
				slog.Error("ready listen failure", "err", err)
				apiWorkers.Stop()
				_ = store.Close()
				ks.Zero()
				os.Exit(1)
			}
			newStop = stop
			// mtls can start now in ready state.
			if cfg.MTLS.Enabled {
				slog.Warn("mtls listener not restarted after setup; restart to enable")
			}
		case serr := <-errCh:
			if serr != nil && !errors.Is(serr, http.ErrServerClosed) {
				slog.Error("server error", "err", serr)
				apiWorkers.Stop()
				_ = store.Close()
				ks.Zero()
				os.Exit(1)
			}
		}
	}
}

// tlsFilePaths returns the on-disk server TLS cert/key paths, defaulting to
// the well-known /data locations used by the setup first-boot flow.
func tlsFilePaths(cfg *config.Config) (certFile, keyFile string) {
	certFile = cfg.Server.TLSCertFile
	keyFile = cfg.Server.TLSKeyFile
	if certFile == "" {
		certFile = "/data/server.crt"
	}
	if keyFile == "" {
		keyFile = "/data/server.key"
	}
	return certFile, keyFile
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
