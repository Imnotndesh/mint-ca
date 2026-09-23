package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/config"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/ha"
	"mint-ca/internal/logger"
	"mint-ca/internal/notify"
	"mint-ca/internal/policy"
	"mint-ca/internal/renewal"
	"mint-ca/internal/setup"
	"mint-ca/internal/sshca"
	"mint-ca/internal/sshca/krl"
	"mint-ca/internal/storage"
	"mint-ca/internal/workers"

	"github.com/google/uuid"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
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
	rlEngine, err := setup.LoadRateLimitEngine(context.Background(), store)
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

	notifyMgr := notify.NewManager(store, ks)

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
		var deliverers renewal.MultiDeliverer
		if cfg.Renewal.WebhookURL != "" {
			deliverers = append(deliverers, renewal.NewWebhookDeliverer(cfg.Renewal.WebhookURL))
		}
		deliverers = append(deliverers, notify.RenewalDeliverer{Manager: notifyMgr})
		apiWorkers.Add(renewal.NewWorker(store, deliverers,
			time.Duration(cfg.Renewal.IntervalSeconds)*time.Second,
			time.Duration(cfg.Renewal.LeadSeconds)*time.Second))
	}
	apiWorkers.Start(context.Background())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The listener lifecycle (setup HTTP -> ready HTTPS automatically) is owned
	// by runServer; it returns on shutdown signal or fatal listener error.
	err = runServer(ctx, cfg, store, rlEngine,
		caEngine, policyEngine, sshcaEngine, crlManager, ocspResponder, sshKRLManager,
		elector, notifyMgr)

	apiWorkers.Stop()
	if cerr := store.Close(); cerr != nil {
		slog.Error("error closing storage", "err", cerr)
	}
	ks.Zero()

	if err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
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
