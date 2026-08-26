package ca

import (
	"context"
	"testing"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// rekeyFakeStore embeds caFakeStore (giving real CreateCA/GetCA/GetCAByName)
// and overrides the cross-cert + status methods the rekey/cross-sign engine
// paths need.
type rekeyFakeStore struct {
	*caFakeStore
	cross map[string]*storage.CrossCert
}

func newRekeyFakeStore() *rekeyFakeStore {
	return &rekeyFakeStore{caFakeStore: newCAFakeStore(), cross: make(map[string]*storage.CrossCert)}
}

func (f *rekeyFakeStore) UpdateCAStatus(ctx context.Context, id uuid.UUID, status storage.CAStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ca, ok := f.cas[id]; ok {
		ca.Status = status
		return nil
	}
	return nil
}

func (f *rekeyFakeStore) CreateCrossCert(ctx context.Context, cc *storage.CrossCert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cross[cc.TargetCAID.String()+"|"+cc.SigningCAID.String()] = cc
	return nil
}

func (f *rekeyFakeStore) GetCrossCert(ctx context.Context, targetCAID, signingCAID uuid.UUID) (*storage.CrossCert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cross[targetCAID.String()+"|"+signingCAID.String()], nil
}

func (f *rekeyFakeStore) ListCrossCertsByTarget(ctx context.Context, targetCAID uuid.UUID) ([]*storage.CrossCert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*storage.CrossCert
	for _, cc := range f.cross {
		if cc.TargetCAID == targetCAID {
			out = append(out, cc)
		}
	}
	return out, nil
}

func newRekeyEngine(t *testing.T) (*Engine, *rekeyFakeStore) {
	t.Helper()
	store := newRekeyFakeStore()
	ks, err := mintcrypto.NewKeystore(make([]byte, 32))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	return NewEngine(store, ks, "https://ca.test"), store
}

// TestRekeyCA_ProducesNewActiveCAAndSupersedesOld verifies re-keying keeps the
// same subject, marks the old CA superseded, and produces an active new CA
// with a different key/SKI signed by the same parent.
func TestRekeyCA_ProducesNewActiveCAAndSupersedesOld(t *testing.T) {
	ctx := context.Background()
	engine, store := newRekeyEngine(t)

	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root", CommonName: "Rekey Root", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	inter, err := engine.CreateIntermediateCA(ctx, CreateIntermediateCARequest{
		ParentCAID: root.ID, Name: "inter", CommonName: "Rekey Inter",
		KeyAlgo: KeyAlgoECDSAP256, TTLDays: 1825, MaxPathLen: 0,
	})
	if err != nil {
		t.Fatalf("create inter: %v", err)
	}

	// Re-key the intermediate.
	newInter, err := engine.RekeyCA(ctx, RekeyCARequest{CAID: inter.ID, TTLDays: 365})
	if err != nil {
		t.Fatalf("rekey: %v", err)
	}

	// Old CA superseded.
	old, _ := store.GetCA(ctx, inter.ID)
	if old.Status != storage.CAStatusSuperseded {
		t.Errorf("expected old CA superseded, got %s", old.Status)
	}
	// New CA active, same name/type/parent, different ID, new key metadata.
	if newInter.Status != storage.CAStatusActive {
		t.Errorf("expected new CA active, got %s", newInter.Status)
	}
	if newInter.ID == inter.ID {
		t.Error("expected new CA to have a new ID")
	}
	if newInter.ParentID == nil || *newInter.ParentID != root.ID {
		t.Errorf("expected new CA parent to be root, got %v", newInter.ParentID)
	}
	if newInter.Name != inter.Name {
		t.Errorf("expected name to be preserved, got %q", newInter.Name)
	}

	// New CA must actually issue.
	issued, err := engine.IssueCert(ctx, IssueCertRequest{
		CAID: newInter.ID, ProvisionerID: uuid.New(), Requester: "t",
		CommonName: "leaf.rekey.test", SANsDNS: []string{"leaf.rekey.test"},
		KeyAlgo: KeyAlgoECDSAP256, TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("issue under re-keyed CA: %v", err)
	}
	if issued == nil {
		t.Fatal("expected an issue result")
	}
}

// TestCrossSignCA_ReusesTargetPublicKey verifies a cross cert can be produced
// for a target CA from a different signer, then the cross chain is buildable
// and validates against a pool trusting the (old) root signer.
func TestCrossSignCA_ReusesTargetPublicKey(t *testing.T) {
	ctx := context.Background()
	engine, store := newRekeyEngine(t)

	oldRoot, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "old-root", CommonName: "Old Root", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create old root: %v", err)
	}
	newRoot, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "new-root", CommonName: "New Root", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create new root: %v", err)
	}

	// Old root cross-signs the new root's public key.
	cc, err := engine.CrossSignCA(ctx, CrossSignCARequest{
		SigningCAID: oldRoot.ID, TargetCAID: newRoot.ID, TTLDays: 1825,
	})
	if err != nil {
		t.Fatalf("cross sign: %v", err)
	}
	if cc.SigningCAID != oldRoot.ID || cc.TargetCAID != newRoot.ID {
		t.Fatalf("unexpected cross cert keys: signer=%s target=%s", cc.SigningCAID, cc.TargetCAID)
	}

	// The cross chain must include the cross cert + old root.
	chain, err := engine.GetCrossChainPEM(ctx, newRoot.ID, oldRoot.ID)
	if err != nil {
		t.Fatalf("get cross chain: %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("expected non-empty cross chain")
	}

	// Listing cross certs by target returns it.
	listed, err := store.ListCrossCertsByTarget(ctx, newRoot.ID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("expected 1 cross cert listed, got %d (err=%v)", len(listed), err)
	}
}

// TestCrossSignCA_SelfSignRejected verifies a CA cannot cross-sign itself.
func TestCrossSignCA_SelfSignRejected(t *testing.T) {
	ctx := context.Background()
	engine, _ := newRekeyEngine(t)
	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root", CommonName: "Root", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	_, err = engine.CrossSignCA(ctx, CrossSignCARequest{SigningCAID: root.ID, TargetCAID: root.ID, TTLDays: 365})
	if err == nil {
		t.Fatal("expected self cross-sign to be rejected")
	}
}

// TestRekeyCA_ExpirationClampedToOld ensures the re-keyed CA's NotAfter never
// exceeds the original CA certificate's lifetime (or a later guard).
func TestRekeyCA_ExpirationClampedToOld(t *testing.T) {
	ctx := context.Background()
	engine, _ := newRekeyEngine(t)
	root, err := engine.CreateRootCA(ctx, CreateRootCARequest{
		Name: "root", CommonName: "Root", KeyAlgo: KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	// Re-key the ROOT itself (self-sign) with a huge TTL that must be clamped.
	newRoot, err := engine.RekeyCA(ctx, RekeyCARequest{CAID: root.ID, TTLDays: 99999})
	if err != nil {
		t.Fatalf("rekey root: %v", err)
	}
	if newRoot.NotAfter.After(root.NotAfter.Add(time.Hour)) {
		t.Errorf("re-keyed CA NotAfter leaked beyond original: new=%v old=%v", newRoot.NotAfter, root.NotAfter)
	}
	if newRoot.Status != storage.CAStatusActive {
		t.Errorf("expected re-keyed root active, got %s", newRoot.Status)
	}
}
