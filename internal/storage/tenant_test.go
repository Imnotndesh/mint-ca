package storage

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestSQLite_Boot_SeedsDefaultTenant verifies a fresh DB always contains
// exactly one seeded default tenant (Phase 0 acceptance: "a fresh sqlite DB
// boots with exactly one (default) tenant").
func TestSQLite_Boot_SeedsDefaultTenant(t *testing.T) {
	s, err := newSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("newSQLiteStore: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	ts, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(ts) != 1 {
		t.Fatalf("expected exactly one default tenant on boot, got %d", len(ts))
	}
	if ts[0].ID != DefaultTenantID {
		t.Errorf("boot tenant id = %s, want default %s", ts[0].ID, DefaultTenantID)
	}
	if ts[0].Status != TenantStatusActive {
		t.Errorf("boot tenant status = %s, want active", ts[0].Status)
	}
	// Seeding is idempotent across repeated Migrate calls.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	if ts, err = s.ListTenants(ctx); err != nil || len(ts) != 1 {
		t.Fatalf("expected still one tenant after re-migrate, got %d (err=%v)", len(ts), err)
	}
}

// TestSQLite_TenantCRUD exercises the full tenant CRUD surface plus the
// default-tenant watermark for tenant-scoped rows.
func TestSQLite_TenantCRUD(t *testing.T) {
	s, err := newSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("newSQLiteStore: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	acme := &Tenant{ID: uuid.New(), Name: "acme-corp", Status: TenantStatusActive, CreatedAt: time.Now().UTC()}
	if err := s.CreateTenant(ctx, acme); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	got, err := s.GetTenant(ctx, acme.ID)
	if err != nil || got == nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Name != "acme-corp" || got.Status != TenantStatusActive {
		t.Errorf("GetTenant = %+v", got)
	}

	byName, err := s.GetTenantByName(ctx, "acme-corp")
	if err != nil || byName == nil || byName.ID != acme.ID {
		t.Fatalf("GetTenantByName: %v", err)
	}

	names := map[string]bool{}
	ts, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	for _, tn := range ts {
		names[tn.Name] = true
	}
	if len(names) != 2 || !names["default"] || !names["acme-corp"] {
		t.Errorf("ListTenants should include default + acme-corp, got %v", names)
	}

	if err := s.UpdateTenantStatus(ctx, acme.ID, TenantStatusSuspended); err != nil {
		t.Fatalf("UpdateTenantStatus: %v", err)
	}
	got, _ = s.GetTenant(ctx, acme.ID)
	if got == nil || got.Status != TenantStatusSuspended {
		t.Errorf("expected tenant suspended after update, got %+v", got)
	}

	// Updating a nonexistent tenant is an error.
	if err := s.UpdateTenantStatus(ctx, uuid.New(), TenantStatusActive); err == nil {
		t.Error("expected error updating a nonexistent tenant")
	}
}

// TestSQLite_BootstrapAndTenantKeys_ArePlatformAdmin verifies the bootstrap
// flow and an explicitly platform-admin key recorded with a nil tenant_id.
func TestSQLite_BootstrapKeyIsPlatformAdmin(t *testing.T) {
	s, err := newSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("newSQLiteStore: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	admin := &APIKey{ID: uuid.New(), Name: "bootstrap", KeyHash: "h1", Scopes: []string{"setup"}, CreatedAt: time.Now().UTC()}
	if err := s.CreateAPIKey(ctx, admin); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	got, err := s.GetAPIKeyByHash(ctx, "h1")
	if err != nil || got == nil {
		t.Fatalf("GetAPIKeyByHash: %v", err)
	}
	if got.TenantID != nil {
		t.Errorf("bootstrap key should be platform-admin (nil tenant), got tenant %v", got.TenantID)
	}

	// A tenant-scoped key round-trips its tenant_id.
	acme := &Tenant{ID: uuid.New(), Name: "acme", Status: TenantStatusActive, CreatedAt: time.Now().UTC()}
	if err := s.CreateTenant(ctx, acme); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	scoped := &APIKey{ID: uuid.New(), Name: "acme-bot", KeyHash: "h2", Scopes: []string{"*"}, TenantID: &acme.ID, CreatedAt: time.Now().UTC()}
	if err := s.CreateAPIKey(ctx, scoped); err != nil {
		t.Fatalf("CreateAPIKey scoped: %v", err)
	}
	got, err = s.GetAPIKeyByHash(ctx, "h2")
	if err != nil || got == nil {
		t.Fatalf("GetAPIKeyByHash scoped: %v", err)
	}
	if got.TenantID == nil || *got.TenantID != acme.ID {
		t.Errorf("expected scoped key tenant %s, got %v", acme.ID, got.TenantID)
	}
}
