// Package events provides a generic fire-and-forget notification bus for
// significant CA actions (issuance, revocation, ...), so external systems
// (SIEM, ticketing, chat) can react in real time instead of polling the audit
// log. It follows the same pluggable-deliverer shape as internal/renewal.
package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const (
	CertIssued  = "cert.issued"
	CertRevoked = "cert.revoked"
)

// Event describes one notable action, in a shape stable enough for external
// consumers regardless of the underlying type of action.
type Event struct {
	Type      string         `json:"type"`
	Timestamp time.Time      `json:"timestamp"`
	Data      map[string]any `json:"data"`
}

// New builds an Event of typ with the given data, timestamped now.
func New(typ string, data map[string]any) Event {
	return Event{Type: typ, Timestamp: time.Now().UTC(), Data: data}
}

// Emitter publishes events. Implementations must be safe for concurrent use
// and must not block the caller on delivery.
type Emitter interface {
	Emit(e Event)
}

// NoopEmitter discards every event. It is the default when no webhook is
// configured.
type NoopEmitter struct{}

// Emit implements Emitter.
func (NoopEmitter) Emit(Event) {}

// WebhookEmitter POSTs each event as JSON to a configured URL, asynchronously
// so callers are never blocked or failed by a slow/unreachable receiver.
type WebhookEmitter struct {
	URL    string
	Client *http.Client
}

// NewWebhookEmitter builds an emitter that posts to url.
func NewWebhookEmitter(url string) *WebhookEmitter {
	return &WebhookEmitter{URL: url, Client: &http.Client{Timeout: 15 * time.Second}}
}

// Emit implements Emitter. Delivery happens in a background goroutine; a
// failure is logged, never returned, since events must never affect the
// outcome of the action that triggered them.
func (e *WebhookEmitter) Emit(ev Event) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := e.deliver(ctx, ev); err != nil {
			slog.Warn("events: delivery failed", "type", ev.Type, "err", err)
		}
	}()
}

func (e *WebhookEmitter) deliver(ctx context.Context, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("events: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("events: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.Client.Do(req)
	if err != nil {
		return fmt.Errorf("events: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("events: webhook returned %d", resp.StatusCode)
	}
	return nil
}
