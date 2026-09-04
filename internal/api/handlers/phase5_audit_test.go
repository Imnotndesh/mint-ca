package handlers

import (
	"context"
	"net/http"
	"testing"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// auditPhase5Fake implements enough for the Phase-5 audit gating tests.
type auditPhase5Fake struct {
	storage.Store
	caID uuid.UUID
	logs []*storage.AuditLog
}

func (f *auditPhase5Fake) Close() error { return nil }
func (f *auditPhase5Fake) GetCA(ctx context.Context, id uuid.UUID) (*storage.CertificateAuthority, error) {
	return &storage.CertificateAuthority{ID: f.caID, Name: "root", TenantID: uuid.Nil}, nil
}
func (f *auditPhase5Fake) ListAuditLogs(ctx context.Context, limit, offset int) ([]*storage.AuditLog, error) {
	return f.logs, nil
}
func (f *auditPhase5Fake) ListAuditLogsByCA(ctx context.Context, caID uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
	return []*storage.AuditLog{}, nil
}
func (f *auditPhase5Fake) ListAuditLogsChronological(ctx context.Context) ([]*storage.AuditLog, error) {
	return f.logs, nil
}

func newAuditPhase5Fake() *auditPhase5Fake {
	return &auditPhase5Fake{logs: []*storage.AuditLog{{ID: uuid.New(), EventType: "POST", CreatedAt: time.Now().UTC()}}}
}

// TestPhase5_AuditVerificationIsPlatformAdminOnly ensures tenant-scoped callers
// are denied the cross-tenant audit verification endpoints (403), while a
// platform admin may verify.
func TestPhase5_AuditVerificationIsPlatformAdminOnly(t *testing.T) {
	store := newAuditPhase5Fake()
	h := NewAuditHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	tenantA := uuid.New()

	for _, path := range []string{"/api/v1/audit/", "/api/v1/audit/verify", "/api/v1/audit/merkle/root"} {
		if rec := doScopeRequest(r, http.MethodGet, path, "", &tenantA); rec.Code != http.StatusForbidden {
			t.Fatalf("tenant %s = %d, want 403", path, rec.Code)
		}
		// Platform admin (nil tenant) may access the global/meta stream.
		if rec := doScopeRequest(r, http.MethodGet, path, "", nil); rec.Code != http.StatusOK {
			t.Fatalf("platform %s = %d, want 200", path, rec.Code)
		}
	}
}
