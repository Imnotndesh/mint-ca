package handlers

import (
	"testing"

	"mint-ca/internal/storage"
)

func auditEvents(evs ...string) []*storage.AuditLog {
	out := make([]*storage.AuditLog, 0, len(evs))
	for _, e := range evs {
		out = append(out, &storage.AuditLog{EventType: e})
	}
	return out
}

func TestCountEvents_X509(t *testing.T) {
	ci, cr, si, sr, sca := countEvents(auditEvents(
		"POST /api/v1/certs/issue",
		"POST /api/v1/certs/issue",
		"POST /api/v1/certs/sign",
		"PUT /api/v1/certs/6f1b2c4d-aaaa-bbbb-cccc-000000000001/revoke",
		"GET /api/v1/certs/6f1b2c4d-aaaa-bbbb-cccc-000000000001", // read, not counted
	))
	if ci != 3 {
		t.Errorf("certIssued = %d, want 3", ci)
	}
	if cr != 1 {
		t.Errorf("certRevoked = %d, want 1 (dynamic certID path must be counted)", cr)
	}
	if si != 0 || sr != 0 || sca != 0 {
		t.Errorf("unexpected SSH counts: issued=%d revoked=%d ca=%d", si, sr, sca)
	}
}

func TestCountEvents_SSH(t *testing.T) {
	ci, cr, si, sr, sca := countEvents(auditEvents(
		"POST /api/v1/sshca",
		"POST /api/v1/sshca/6f1b2c4d-aaaa-bbbb-cccc-000000000001/issue",
		"POST /api/v1/sshca/6f1b2c4d-aaaa-bbbb-cccc-000000000001/sign/user",
		"POST /api/v1/sshca/6f1b2c4d-aaaa-bbbb-cccc-000000000001/sign/host",
		"PUT /api/v1/sshca/certs/6f1b2c4d-aaaa-bbbb-cccc-000000000002/revoke",
	))
	if sca != 1 {
		t.Errorf("sshCA = %d, want 1", sca)
	}
	if si != 3 {
		t.Errorf("sshIssued = %d, want 3", si)
	}
	if sr != 1 {
		t.Errorf("sshRevoked = %d, want 1", sr)
	}
	if ci != 0 || cr != 0 {
		t.Errorf("unexpected X.509 counts: issued=%d revoked=%d", ci, cr)
	}
}

func TestCountEvents_DoesNotMatchCARevokeAsIssue(t *testing.T) {
	// A non-SSH PUT under /api/v1/sshca/ must not be counted as an SSH issue.
	ci, cr, si, sr, sca := countEvents(auditEvents(
		"PUT /api/v1/sshca/6f1b2c4d-aaaa-bbbb-cccc-000000000001",
		"DELETE /api/v1/sshca/6f1b2c4d-aaaa-bbbb-cccc-000000000001",
	))
	if ci != 0 || cr != 0 || si != 0 || sr != 0 || sca != 0 {
		t.Errorf("unexpected counts for non POST/PUT issue/revoke: ci=%d cr=%d si=%d sr=%d sca=%d", ci, cr, si, sr, sca)
	}
}
