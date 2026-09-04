package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mint-ca/internal/audit"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type auditChainFakeStore struct {
	storage.Store
	logs []*storage.AuditLog
}

func (f *auditChainFakeStore) ListAuditLogsChronological(ctx context.Context) ([]*storage.AuditLog, error) {
	return f.logs, nil
}

// buildChain constructs n audit logs with a valid hash chain.
func buildChain(n int) []*storage.AuditLog {
	logs := make([]*storage.AuditLog, n)
	prev := audit.GenesisPrevHash
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		l := &storage.AuditLog{
			ID:        uuid.New(),
			EventType: "POST /api/v1/certs/issue",
			Actor:     "key1",
			Payload:   storage.JSON{},
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
			PrevHash:  prev,
		}
		payload, _ := json.Marshal(l.Payload)
		l.EntryHash = audit.ComputeHash(prev, audit.Entry{
			ID: l.ID.String(), EventType: l.EventType, Actor: l.Actor,
			Payload: string(payload), CreatedAt: l.CreatedAt,
		})
		logs[i] = l
		prev = l.EntryHash
	}
	return logs
}

func TestAuditHandler_Verify_IntactChain(t *testing.T) {
	store := &auditChainFakeStore{logs: buildChain(4)}
	h := NewAuditHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %+v", resp)
	}
	if int(resp["entries"].(float64)) != 4 {
		t.Errorf("expected entries=4, got %+v", resp["entries"])
	}
}

func TestAuditHandler_Verify_DetectsTampering(t *testing.T) {
	logs := buildChain(4)
	logs[2].Actor = "attacker" // mutate without recomputing the hash
	store := &auditChainFakeStore{logs: logs}
	h := NewAuditHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != false {
		t.Errorf("expected ok=false, got %+v", resp)
	}
	if int(resp["broken_at_index"].(float64)) != 2 {
		t.Errorf("expected broken_at_index=2, got %+v", resp["broken_at_index"])
	}
	if resp["broken_entry_id"] != logs[2].ID.String() {
		t.Errorf("expected broken_entry_id=%s, got %+v", logs[2].ID, resp["broken_entry_id"])
	}
}

func TestAuditHandler_Verify_EmptyChainIsOK(t *testing.T) {
	store := &auditChainFakeStore{}
	h := NewAuditHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Errorf("expected ok=true for empty chain, got %+v", resp)
	}
}
