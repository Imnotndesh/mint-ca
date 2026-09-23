package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"mint-ca/internal/events"
	"mint-ca/internal/storage"
)

type Dialer interface {
	Send(ctx context.Context, cfg storage.WebhookConfig, secret string, ev events.Event) error
}

type HTTPDialer struct {
	Client *http.Client
}

func NewHTTPDialer() *HTTPDialer {
	return &HTTPDialer{Client: &http.Client{Timeout: 15 * time.Second}}
}

func (d *HTTPDialer) Send(ctx context.Context, cfg storage.WebhookConfig, secret string, ev events.Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("webhook: marshal event: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-MintCA-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: endpoint returned %d", resp.StatusCode)
	}
	return nil
}
