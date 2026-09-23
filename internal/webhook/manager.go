package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/events"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

type Manager struct {
	store    storage.Store
	keystore *mintcrypto.Keystore
	dialer   Dialer
}

func NewManager(store storage.Store, keystore *mintcrypto.Keystore) *Manager {
	return &Manager{store: store, keystore: keystore, dialer: NewHTTPDialer()}
}

func (m *Manager) EncryptSecret(plain string) ([]byte, error) {
	if plain == "" {
		return nil, nil
	}
	return m.keystore.Encrypt([]byte(plain))
}

func (m *Manager) DecryptSecret(enc []byte) (string, error) {
	if len(enc) == 0 {
		return "", nil
	}
	plain, err := m.keystore.Decrypt(enc)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (m *Manager) Notify(category string, data map[string]any) {
	go m.dispatch(category, data)
}

func (m *Manager) dispatch(category string, data map[string]any) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rule, err := m.store.GetWebhookRule(ctx, category)
	if err != nil {
		slog.Warn("webhook: load rule failed", "category", category, "err", err)
		return
	}
	if rule == nil || !rule.Enabled {
		return
	}

	cfg, err := m.resolveConfig(ctx, rule.WebhookConfigID)
	if err != nil {
		slog.Warn("webhook: resolve config failed", "category", category, "err", err)
		return
	}
	if cfg == nil || !cfg.Enabled {
		return
	}

	secret, err := m.DecryptSecret(cfg.SecretEnc)
	if err != nil {
		slog.Warn("webhook: decrypt secret failed", "config", cfg.Name, "err", err)
		return
	}

	ev := events.New(category, data)
	if err := m.dialer.Send(ctx, *cfg, secret, ev); err != nil {
		slog.Warn("webhook: delivery failed", "category", category, "config", cfg.Name, "err", err)
	}
}

func (m *Manager) SendTest(ctx context.Context, configID uuid.UUID) error {
	cfg, err := m.store.GetWebhookConfig(ctx, configID)
	if err != nil {
		return fmt.Errorf("webhook: load config: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("webhook: config %q not found", configID)
	}
	secret, err := m.DecryptSecret(cfg.SecretEnc)
	if err != nil {
		return fmt.Errorf("webhook: decrypt secret: %w", err)
	}
	ev := events.New("test", map[string]any{"message": "This is a test notification from mint-ca."})
	return m.dialer.Send(ctx, *cfg, secret, ev)
}

func (m *Manager) resolveConfig(ctx context.Context, id *uuid.UUID) (*storage.WebhookConfig, error) {
	if id != nil {
		return m.store.GetWebhookConfig(ctx, *id)
	}
	return m.store.GetDefaultWebhookConfig(ctx)
}
