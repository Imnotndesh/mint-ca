// Package renewal triggers certificate auto-renewal notices. The worker is the
// generic scan-and-dispatch loop; the deliverer is pluggable so future
// integrations (ACME re-issue, a management callback, a CLI) can be added
// without changing the worker.
package renewal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"mint-ca/internal/storage"
)

// Notice describes a certificate due for renewal.
type Notice struct {
	CertID    string    `json:"cert_id"`
	CAID      string    `json:"ca_id"`
	Serial    string    `json:"serial"`
	SubjectCN string    `json:"subject_cn"`
	ExpiresAt time.Time `json:"expires_at"`
	DaysLeft  int       `json:"days_left"`
	Escrowed  bool      `json:"key_escrowed"`
}

// Deliverer consumes a renewal notice. Implementations must be safe to call
// concurrently.
type Deliverer interface {
	Deliver(ctx context.Context, n Notice) error
}

// DelivererFunc adapts a function to the Deliverer interface.
type DelivererFunc func(ctx context.Context, n Notice) error

// Deliver implements Deliverer.
func (f DelivererFunc) Deliver(ctx context.Context, n Notice) error { return f(ctx, n) }

// WebhookDeliverer POSTs each notice as JSON to a configured URL using a shared
// http.Client. Failures are returned so the worker can log them.
type WebhookDeliverer struct {
	URL    string
	Client *http.Client
}

// NewWebhookDeliverer builds a deliverer that posts to url.
func NewWebhookDeliverer(url string) *WebhookDeliverer {
	return &WebhookDeliverer{URL: url, Client: &http.Client{Timeout: 15 * time.Second}}
}

// Deliver implements Deliverer.
func (d *WebhookDeliverer) Deliver(ctx context.Context, n Notice) error {
	if d.URL == "" {
		return errors.New("renewal: webhook deliverer has no URL")
	}
	body, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("renewal: marshal notice: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("renewal: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.Client.Do(req)
	if err != nil {
		return fmt.Errorf("renewal: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("renewal: webhook returned %d", resp.StatusCode)
	}
	return nil
}

// MultiDeliverer fans a notice out to several deliverers, returning the first
// error encountered (but still invoking all of them).
type MultiDeliverer []Deliverer

// Deliver implements Deliverer.
func (m MultiDeliverer) Deliver(ctx context.Context, n Notice) error {
	var firstErr error
	for _, d := range m {
		if err := d.Deliver(ctx, n); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Worker scans for certificates nearing expiry on an interval and sends a
// notice to its Deliverer for each one that is not yet marked renewed.
type Worker struct {
	store     storage.Store
	deliverer Deliverer
	interval  time.Duration
	lead      time.Duration
}

// NewWorker builds a renewal worker. deliverer must be non-nil.
func NewWorker(store storage.Store, deliverer Deliverer, interval, lead time.Duration) *Worker {
	if deliverer == nil {
		deliverer = DelivererFunc(func(context.Context, Notice) error { return nil })
	}
	return &Worker{store: store, deliverer: deliverer, interval: interval, lead: lead}
}

// Run implements the background worker loop.
func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	if err := w.scan(ctx); err != nil {
		slog.Warn("renewal: initial scan failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := w.scan(scanCtx); err != nil {
				slog.Warn("renewal: scan failed", "err", err)
			}
			cancel()
		}
	}
}

// Name implements the Worker interface.
func (w *Worker) Name() string { return "cert-renewal" }

// scan finds certs due for renewal and delivers a notice for each. It is
// exposed for tests and one-shot invocation.
func (w *Worker) scan(ctx context.Context) error {
	cutoff := time.Now().UTC().Add(w.lead)
	due, err := w.findDue(ctx, cutoff)
	if err != nil {
		return err
	}
	for _, cert := range due {
		n := Notice{
			CertID:    cert.ID.String(),
			CAID:      cert.CAID.String(),
			Serial:    cert.Serial,
			SubjectCN: cert.SubjectCN,
			ExpiresAt: cert.NotAfter,
			DaysLeft:  int(cert.NotAfter.Sub(time.Now().UTC()).Hours() / 24),
			Escrowed:  len(cert.KeyEncrypted) > 0,
		}
		if err := w.deliverer.Deliver(ctx, n); err != nil {
			slog.Warn("renewal: notice delivery failed", "cert_id", cert.ID, "err", err)
		} else {
			slog.Info("renewal: notice delivered", "cert_id", cert.ID, "expires", cert.NotAfter)
		}
	}
	return nil
}

// findDue lists all CAs and their certificates, returning active ones expiring
// at or before cutoff. Filtering happens in-process so no new store method is
// required — keeping the storage surface small and integration-friendly.
func (w *Worker) findDue(ctx context.Context, cutoff time.Time) ([]*storage.Certificate, error) {
	cas, err := w.store.ListCAs(ctx)
	if err != nil {
		return nil, fmt.Errorf("renewal: list CAs: %w", err)
	}
	var due []*storage.Certificate
	for _, ca := range cas {
		if ca.Status != storage.CAStatusActive {
			continue
		}
		certs, err := w.store.ListCertificatesByCA(ctx, ca.ID)
		if err != nil {
			return nil, fmt.Errorf("renewal: list certs for CA %s: %w", ca.ID, err)
		}
		for _, c := range certs {
			if c.Status != storage.CertStatusActive {
				continue
			}
			if !c.NotAfter.After(cutoff) {
				due = append(due, c)
			}
		}
	}
	return due, nil
}
