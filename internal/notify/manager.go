package notify

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"text/template"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

type Manager struct {
	store    storage.Store
	keystore *mintcrypto.Keystore
	dialer   Dialer
}

func NewManager(store storage.Store, keystore *mintcrypto.Keystore) *Manager {
	return &Manager{store: store, keystore: keystore, dialer: SMTPDialer{}}
}

func (m *Manager) EncryptPassword(plain string) ([]byte, error) {
	if plain == "" {
		return nil, nil
	}
	return m.keystore.Encrypt([]byte(plain))
}

func (m *Manager) DecryptPassword(enc []byte) (string, error) {
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

	rule, err := m.store.GetNotificationRule(ctx, category)
	if err != nil {
		slog.Warn("notify: load rule failed", "category", category, "err", err)
		return
	}
	if rule == nil || !rule.Enabled || len(rule.Recipients) == 0 {
		return
	}

	server, err := m.resolveServer(ctx, rule.SMTPServerID)
	if err != nil {
		slog.Warn("notify: resolve smtp server failed", "category", category, "err", err)
		return
	}
	if server == nil || !server.Enabled {
		return
	}

	password, err := m.DecryptPassword(server.PasswordEnc)
	if err != nil {
		slog.Warn("notify: decrypt smtp password failed", "server", server.Name, "err", err)
		return
	}

	subject, body := renderTemplate(category, data)

	var wg sync.WaitGroup
	for _, to := range rule.Recipients {
		wg.Add(1)
		go func(recipient string) {
			defer wg.Done()
			msg := Message{To: []string{recipient}, Subject: subject, Body: body, Data: data}
			if err := m.dialer.Send(ctx, *server, password, msg); err != nil {
				slog.Warn("notify: delivery failed", "category", category, "to", recipient, "err", err)
			}
		}(to)
	}
	wg.Wait()
}

func (m *Manager) SendTest(ctx context.Context, serverID uuid.UUID, to string) error {
	server, err := m.store.GetSMTPServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("notify: load smtp server: %w", err)
	}
	if server == nil {
		return fmt.Errorf("notify: smtp server %q not found", serverID)
	}
	password, err := m.DecryptPassword(server.PasswordEnc)
	if err != nil {
		return fmt.Errorf("notify: decrypt smtp password: %w", err)
	}
	msg := Message{
		To:      []string{to},
		Subject: "mint-ca: test notification",
		Body:    fmt.Sprintf("This is a test notification from mint-ca using SMTP server %q.\n", server.Name),
	}
	return m.dialer.Send(ctx, *server, password, msg)
}

func (m *Manager) resolveServer(ctx context.Context, id *uuid.UUID) (*storage.SMTPServer, error) {
	if id != nil {
		return m.store.GetSMTPServer(ctx, *id)
	}
	return m.store.GetDefaultSMTPServer(ctx)
}

func renderTemplate(category string, data map[string]any) (string, string) {
	def, ok := Categories.Get(category)
	if !ok {
		return category, fmt.Sprintf("%v", data)
	}
	return execTemplate(def.DefaultSubject, data), execTemplate(def.DefaultBody, data)
}

func execTemplate(tmplStr string, data map[string]any) string {
	tmpl, err := template.New("notify").Parse(tmplStr)
	if err != nil {
		return tmplStr
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return tmplStr
	}
	return buf.String()
}
