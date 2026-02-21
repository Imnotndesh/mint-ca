// cmd/server/main.go
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"mint-ca/internal/api"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/config"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/policy"
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

	// Future workers are added here — e.g. a certificate expiry notifier,
	// an ACME order cleanup job, a metrics aggregator, etc.

	apiWorkers.Start(context.Background())

	router := api.BuildRouter(cfg, store, caEngine, crlManager, ocspResponder, policyEngine)

	srv := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	if !cfg.Server.TLSDisabled {
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			PreferServerCipherSuites: true,
		}
	}

	listenErr := make(chan error, 1)
	go func() {
		if cfg.Server.TLSDisabled {
			slog.Info("listening (TLS disabled — development mode only)",
				"addr", cfg.Server.ListenAddr)
			listenErr <- srv.ListenAndServe()
		} else {
			slog.Info("listening",
				"addr", cfg.Server.ListenAddr,
				"tls_cert", cfg.Server.TLSCertFile)
			listenErr <- srv.ListenAndServeTLS(
				cfg.Server.TLSCertFile,
				cfg.Server.TLSKeyFile,
			)
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
	}

	// Phase 1: stop accepting new HTTP requests, drain in-flight ones.
	slog.Info("shutting down HTTP server")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP shutdown error", "err", err)
	}

	// Phase 2: stop background workers. Must happen after HTTP is down so
	// no in-flight request races with a worker touching shared state.
	slog.Info("stopping background workers")
	apiWorkers.Stop()

	// Phase 3: close storage and zero the master key.
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
	opts := &slog.HandlerOptions{Level: level}
	if cfg.JSON {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}
