package storage

import (
	"context"
	"testing"

	"mint-ca/internal/audit"

	"github.com/google/uuid"
	"time"
)

func TestSQLite_WriteAuditLog_ExtendsChain(t *testing.T) {
	s, err := newSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("newSQLiteStore: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	e1 := &AuditLog{ID: uuid.New(), EventType: "POST /api/v1/certs/issue", Actor: "k1", Payload: JSON{}, CreatedAt: time.Now().UTC()}
	if err := s.WriteAuditLog(ctx, e1); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if e1.PrevHash != audit.GenesisPrevHash {
		t.Errorf("first entry PrevHash = %q, want genesis", e1.PrevHash)
	}
	if e1.EntryHash == "" {
		t.Error("expected a non-empty entry hash")
	}

	e2 := &AuditLog{ID: uuid.New(), EventType: "PUT /api/v1/certs/x/revoke", Actor: "k1", Payload: JSON{}, CreatedAt: time.Now().UTC()}
	if err := s.WriteAuditLog(ctx, e2); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if e2.PrevHash != e1.EntryHash {
		t.Errorf("second entry PrevHash = %q, want %q", e2.PrevHash, e1.EntryHash)
	}

	logs, err := s.ListAuditLogsChronological(ctx)
	if err != nil {
		t.Fatalf("ListAuditLogsChronological: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(logs))
	}

	entries := make([]audit.Entry, len(logs))
	for i, l := range logs {
		var caID, certID string
		if l.CAID != nil {
			caID = l.CAID.String()
		}
		if l.CertID != nil {
			certID = l.CertID.String()
		}
		payload, _ := marshalJSON(l.Payload)
		entries[i] = audit.Entry{
			ID: l.ID.String(), EventType: l.EventType, Actor: l.Actor,
			CAID: caID, CertID: certID, Payload: payload, IPAddress: l.IPAddress,
			CreatedAt: l.CreatedAt, PrevHash: l.PrevHash, EntryHash: l.EntryHash,
		}
	}
	if broken := audit.VerifyChain(entries); broken != -1 {
		t.Errorf("VerifyChain = %d, want -1 (intact)", broken)
	}

	// Tamper with a stored entry directly and confirm verification catches it.
	if _, err := s.db.Exec(`UPDATE audit_log SET actor = 'tampered' WHERE id = ?`, e1.ID.String()); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	logs, err = s.ListAuditLogsChronological(ctx)
	if err != nil {
		t.Fatalf("ListAuditLogsChronological after tamper: %v", err)
	}
	for i, l := range logs {
		var caID, certID string
		if l.CAID != nil {
			caID = l.CAID.String()
		}
		if l.CertID != nil {
			certID = l.CertID.String()
		}
		payload, _ := marshalJSON(l.Payload)
		entries[i] = audit.Entry{
			ID: l.ID.String(), EventType: l.EventType, Actor: l.Actor,
			CAID: caID, CertID: certID, Payload: payload, IPAddress: l.IPAddress,
			CreatedAt: l.CreatedAt, PrevHash: l.PrevHash, EntryHash: l.EntryHash,
		}
	}
	if broken := audit.VerifyChain(entries); broken != 0 {
		t.Errorf("VerifyChain after tamper = %d, want 0", broken)
	}
}
