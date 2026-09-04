package events

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNoopEmitter_DoesNothing(t *testing.T) {
	// Only requirement: it must not panic.
	NoopEmitter{}.Emit(New(CertIssued, map[string]any{"cert_id": "c1"}))
}

func TestWebhookEmitter_PostsEvent(t *testing.T) {
	done := make(chan Event, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got Event
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
		done <- got
	}))
	defer ts.Close()

	e := NewWebhookEmitter(ts.URL)
	e.Emit(New(CertIssued, map[string]any{"cert_id": "c1", "serial": "42"}))

	select {
	case got := <-done:
		if got.Type != CertIssued {
			t.Errorf("type = %q, want %q", got.Type, CertIssued)
		}
		if got.Data["cert_id"] != "c1" {
			t.Errorf("data.cert_id = %v", got.Data["cert_id"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for webhook delivery")
	}
}

func TestWebhookEmitter_UnreachableDoesNotPanic(t *testing.T) {
	e := NewWebhookEmitter("http://127.0.0.1:0")
	e.Emit(New(CertRevoked, map[string]any{"cert_id": "c1"}))
	// Async and best-effort: nothing to assert beyond "did not panic/block".
}
