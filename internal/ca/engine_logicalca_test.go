package ca

import (
	"context"
	"testing"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// TestLogicalCA_FreshCA_LogicalIDIsOwnID: a freshly created CA gets its own ID
// as its logical CA id, so it resolves back to itself.
func TestLogicalCA_FreshCA_LogicalIDIsOwnID(t *testing.T) {
	ctx := context.Background()
	engine, _ := newRekeyEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root", CommonName: "LC Root", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	if root.LogicalCAID == nil || *root.LogicalCAID != root.ID {
		t.Fatalf("expected root LogicalCAID==own ID, got %v", root.LogicalCAID)
	}

	got, err := engine.ResolveActiveCA(ctx, *root.LogicalCAID)
	if err != nil || got == nil || got.ID != root.ID {
		t.Fatalf("ResolveActiveCA(fresh root): err=%v got=%v", err, got)
	}
}

// TestLogicalCA_Rekey_ResolvesToNewActiveRow: after a re-key the old row is
// superseded and ResolveActiveCA(logicalCAID) returns the NEW active row —
// provisioners pointing at the logical CA keep working without repointing.
func TestLogicalCA_Rekey_ResolvesToNewActiveRow(t *testing.T) {
	ctx := context.Background()
	engine, store := newRekeyEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root", CommonName: "LC Root", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	inter, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "inter", CommonName: "LC Inter",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 0,
	})
	if err != nil {
		t.Fatalf("create inter: %v", err)
	}
	logicalID := *inter.LogicalCAID

	// Re-key: old row superseded, new row carries the SAME logical id.
	newInter, err := engine.RekeyCA(ctx, RekeyCARequest{CAID: inter.ID, TTLDays: 365})
	if err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if newInter.LogicalCAID == nil || *newInter.LogicalCAID != logicalID {
		t.Fatalf("re-keyed CA must retain logical id %v, got %v", logicalID, newInter.LogicalCAID)
	}

	resolved, err := engine.ResolveActiveCA(ctx, logicalID)
	if err != nil {
		t.Fatalf("ResolveActiveCA: %v", err)
	}
	if resolved == nil || resolved.ID != newInter.ID {
		t.Fatalf("expected resolution to new active row %v, got %v", newInter.ID, resolved)
	}
	if resolved.Status != storage.CAStatusActive {
		t.Errorf("resolved CA should be active, got %s", resolved.Status)
	}

	// The superseded old row must NOT be returned as the active one.
	old, _ := store.GetCA(ctx, inter.ID)
	if old == nil || old.Status != storage.CAStatusSuperseded {
		t.Fatalf("expected old row superseded, got status %v", old)
	}
}

// TestLogicalCA_ResolveRejectsRevoked: a revoked logical CA (no active row
// remaining) yields an error rather than a usable CA.
func TestLogicalCA_ResolveRejectsRevoked(t *testing.T) {
	ctx := context.Background()
	engine, _ := newRekeyEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root", CommonName: "LC Root", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	logicalID := *root.LogicalCAID

	if err := engine.store.UpdateCAStatus(ctx, root.ID, storage.CAStatusRevoked); err != nil {
		t.Fatalf("revoke root: %v", err)
	}

	if _, err := engine.ResolveActiveCA(ctx, logicalID); err == nil {
		t.Fatal("expected ResolveActiveCA to error after CA revoked (no active row)")
	}
}

var _ = mintcrypto.NewKeystore // keep import used if helpers migrate
var _ = uuid.Nil
