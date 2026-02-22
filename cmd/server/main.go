// cmd/server/main.go
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"mint-ca/internal/logger"
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
	"mint-ca/internal/policy"
	"mint-ca/internal/setup"
	"mint-ca/internal/storage"
	"mint-ca/internal/workers"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
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

	ks, err := mintcrypto.NewKeystore(cfg.Crypto.MasterKey)
	if err != nil {
		slog.Error("failed to initialise keystore", "err", err)
		_ = store.Close()
		os.Exit(1)
	}

	caEngine := ca.NewEngine(store, ks)
	crlManager := revocation.NewCRLManager(store, ks)
	ocspResponder := revocation.NewOCSPResponder(store, ks)
	policyEngine := policy.NewEngine(store)

	slog.Info("core services initialised")

	apiWorkers := workers.NewWorkerGroup()
	apiWorkers.Add(workers.NewCRLWorker(crlManager, cfg.CRL))
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

	// listenErr receives the error from whichever http.Server is active.
	// It is also used by onReady to trigger a clean shutdown so the container
	// restarts in READY state with TLS enabled.
	listenErr := make(chan error, 1)

	// onReady is the callback the setup handler calls when setup completes.
	// It writes the issued cert and key to the configured TLS paths, then
	// signals main to shut down cleanly. The container restart policy brings
	// the server back up immediately in READY state, this time over TLS.
	onReady := func(certPEM, keyPEM []byte) error {
		certPath := cfg.Server.TLSCertFile
		keyPath := cfg.Server.TLSKeyFile

		// Fall back to predictable paths if the operator has not configured them.
		// These paths are inside the /data volume so they survive restarts.
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
		router = api.BuildRouter(cfg, store, caEngine, crlManager, ocspResponder, policyEngine)
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

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("shutdown signal received", "signal", sig.String())
	case err := <-listenErr:
		if err != nil && err != http.ErrServerClosed {
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
