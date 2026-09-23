package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"mint-ca/internal/api"
	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/config"
	"mint-ca/internal/ha"
	"mint-ca/internal/mtls"
	"mint-ca/internal/notify"
	"mint-ca/internal/policy"
	"mint-ca/internal/ratelimit"
	"mint-ca/internal/server"
	"mint-ca/internal/setup"
	"mint-ca/internal/sshca"
	"mint-ca/internal/sshca/krl"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
)

// runServer owns the server listener lifecycle: it reads setup state, decides
// the initial listener generation, runs the setup/ready supervisor, and reacts
// to setup completion by swapping in the ready router (HTTPS in auto/provided
// mode, HTTP in disabled mode) without exiting the process. It blocks until ctx
// is cancelled (signal) or a fatal listener error occurs. Teardown of workers /
// store / keystore is the caller's responsibility.
func runServer(ctx context.Context, cfg *config.Config, store storage.Store,
	rlEngine *ratelimit.Engine,
	caEngine *ca.Engine, policyEngine *policy.Engine, sshcaEngine *sshca.Engine,
	crlManager *revocation.CRLManager, ocspResponder *revocation.OCSPResponder,
	sshKRLManager *krl.Manager, elector *ha.Elector,
	notifyMgr *notify.Manager) error {

	// Read state before deciding which listener generation to start.
	state, err := store.GetSetupState(ctx)
	if err != nil {
		return fmt.Errorf("read setup state: %w", err)
	}
	startSetup := false
	switch state {
	case storage.StateUninitialized:
		slog.Info("first boot detected — entering setup mode")
		if err := store.SetSetupState(ctx, storage.StateSetup); err != nil {
			return fmt.Errorf("transition to setup state: %w", err)
		}
		bk, err := setup.GenerateBootstrapKey(ctx, store, cfg.Server.BootstrapKey)
		if err != nil {
			return fmt.Errorf("generate bootstrap key: %w", err)
		}
		setup.PrintBootstrapKey(bk)
		startSetup = true
	case storage.StateSetup:
		slog.Warn("resumed in-progress setup — bootstrap key was printed on first boot; check earlier container logs")
		slog.Warn("if you cannot find the key, delete the database and start fresh")
		startSetup = true
	case storage.StateReady:
		slog.Info("setup complete — starting full API")
	}

	// transitionPhase is the live listener-transition status reported by the
	// /setup/transition endpoint to onboarding tooling.
	var phase atomic.Value
	setPhase := func(p setup.TransitionPhase) { phase.Store(string(p)) }
	reportPhase := func() setup.TransitionPhase {
		v := phase.Load()
		if v == nil {
			return setup.TransitionSetup
		}
		return setup.TransitionPhase(v.(string))
	}
	if !startSetup {
		setPhase(setup.TransitionReady)
	}

	readyRouter := api.BuildRouter(cfg, store, caEngine, sshcaEngine, crlManager,
		ocspResponder, policyEngine, rlEngine, sshKRLManager, elector, notifyMgr, reportPhase)

	// On setup completion, onReady persists the cert (auto mode only) and emits
	// the material so the supervisor can swap to HTTPS without touching disk.
	doneCh := make(chan server.TLSMaterial, 1)
	onReady := func(certPEM, keyPEM []byte) error {
		if cfg.Server.TLSMode() == config.TLSAutoMode {
			certPath := cfg.ResolvedTLSCertFile()
			keyPath := cfg.ResolvedTLSKeyFile()
			if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
				slog.Warn("setup: could not persist server cert — live transition still uses it from memory", "cert", certPath, "err", err)
			} else if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
				slog.Warn("setup: could not persist server key", "key", keyPath, "err", err)
			} else {
				slog.Info("setup: TLS certificate persisted", "cert", certPath, "key", keyPath)
			}
		}
		select {
		case doneCh <- server.TLSMaterial{CertPEM: certPEM, KeyPEM: keyPEM}:
		default:
		}
		return nil
	}
	setupRouter := api.BuildSetupRouter(cfg, store, caEngine, onReady, reportPhase)

	sup := server.New(cfg.Server.ReadTimeout, cfg.Server.WriteTimeout, cfg.Server.IdleTimeout)

	// Resolve ready-state TLS material once (used at boot when already ready,
	// and refreshed from the event material after an in-process swap).
	resolveReadyMaterial := func() (*server.TLSMaterial, error) {
		switch cfg.Server.TLSMode() {
		case config.TLSProvidedMode:
			return loadTLSMaterial(cfg.ResolvedTLSCertFile(), cfg.ResolvedTLSKeyFile())
		case config.TLSAutoMode:
			certPath, keyPath := cfg.ResolvedTLSCertFile(), cfg.ResolvedTLSKeyFile()
			if _, err := os.Stat(certPath); err != nil {
				return nil, fmt.Errorf("auto TLS mode: server cert %s missing (run setup or restore it)", certPath)
			}
			return loadTLSMaterial(certPath, keyPath)
		default:
			return nil, nil // disabled
		}
	}

	if startSetup {
		if err := sup.Start(server.ListenerSpec{Addr: cfg.Server.ListenAddr, Handler: setupRouter}); err != nil {
			return fmt.Errorf("setup listen: %w", err)
		}
	} else {
		readyTLS, err := resolveReadyMaterial()
		if err != nil {
			return err
		}
		if err := sup.Start(server.ListenerSpec{Addr: cfg.Server.ListenAddr, Handler: readyRouter, TLS: readyTLS}); err != nil {
			return fmt.Errorf("listener: %w", err)
		}
	}

	var mtlsStop func()
	startMTLSOnce := func(mat *server.TLSMaterial) {
		if !cfg.MTLS.Enabled || mat == nil {
			return
		}
		stop, err := startMTLSListener(ctx, cfg, store, caEngine, mat)
		if err != nil {
			slog.Error("mtls enrollment listener failed", "err", err)
			return
		}
		mtlsStop = stop
	}
	if !startSetup {
		mat, _ := resolveReadyMaterial()
		startMTLSOnce(mat)
	}

	for {
		select {
		case <-ctx.Done():
			if err := sup.Shutdown(context.Background()); err != nil {
				slog.Warn("listener shutdown", "err", err)
			}
			if mtlsStop != nil {
				mtlsStop()
			}
			return nil
		case mat := <-doneCh:
			setPhase(setup.TransitionCompleting)
			readyTLS := (*server.TLSMaterial)(nil)
			if cfg.Server.TLSMode() != config.TLSDisabledMode {
				if cfg.Server.TLSMode() == config.TLSAutoMode {
					m := mat
					readyTLS = &m
				} else {
					// provided mode: keep the operator's cert, never overwrite it.
					providedTLS, err := resolveReadyMaterial()
					if err != nil {
						return fmt.Errorf("resolve provided TLS material: %w", err)
					}
					readyTLS = providedTLS
				}
			}
			spec := server.ListenerSpec{Addr: cfg.Server.ListenAddr, Handler: readyRouter, TLS: readyTLS}
			if err := swapWithCtx(ctx, sup, spec); err != nil {
				return fmt.Errorf("swap to ready listener: %w", err)
			}
			setPhase(setup.TransitionReady)
			startMTLSOnce(readyTLS)
		case serr := <-sup.Errors():
			if serr != nil {
				return serr
			}
		}
	}
}

// loadTLSMaterial reads a PEM cert/key pair into an in-memory TLS material.
func loadTLSMaterial(certFile, keyFile string) (*server.TLSMaterial, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read server cert %s: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read server key %s: %w", keyFile, err)
	}
	return &server.TLSMaterial{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// swapWithCtx swaps the listener to spec, retrying transient bind races with a
// short bounded backoff rather than taking the server down.
func swapWithCtx(ctx context.Context, sup *server.Supervisor, spec server.ListenerSpec) error {
	const maxAttempts = 5
	for attempt := 1; ; attempt++ {
		err := sup.Swap(ctx, spec)
		if err == nil {
			return nil
		}
		if attempt >= maxAttempts || ctx.Err() != nil {
			return err
		}
		slog.Warn("ready listener swap failed; retrying", "err", err, "attempt", attempt)
		select {
		case <-time.After(time.Duration(attempt) * 200 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// startMTLSListener serves the mTLS enrollment endpoint using the given TLS
// material (the running server cert), and returns a stop func.
func startMTLSListener(ctx context.Context, cfg *config.Config, store storage.Store, caEngine *ca.Engine, mat *server.TLSMaterial) (func(), error) {
	tlsConf, err := mtls.BuildServerTLSConfig(cfg.MTLS, []byte(cfg.MTLS.ClientCACertPEM))
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(mat.CertPEM, mat.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("mtls: serve keypair: %w", err)
	}
	tlsConf.Certificates = []tls.Certificate{cert}

	issuerID, provID, err := resolveMTLSTargets(ctx, store)
	if err != nil {
		return nil, err
	}
	enroll := mtls.NewEnrollHandler(caEngine, store, issuerID, provID)
	r := chi.NewRouter()
	enroll.RegisterRoutes(r)

	ln, err := net.Listen("tcp", cfg.MTLS.ListenAddr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Addr:      cfg.MTLS.ListenAddr,
		Handler:   r,
		TLSConfig: tlsConf,
	}
	go func() {
		if err := srv.Serve(tls.NewListener(ln, tlsConf)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("mtls enrollment listener error", "err", err)
		}
	}()
	slog.Info("mtls enrollment listener started", "addr", cfg.MTLS.ListenAddr)

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}
