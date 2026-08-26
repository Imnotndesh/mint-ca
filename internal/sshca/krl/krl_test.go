package krl

import (
	"bytes"
	"context"
	"testing"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func TestEncode_RoundTripSerials(t *testing.T) {
	now := time.Now().UTC()
	revoked := []*storage.SSHCertificate{
		{Serial: 42}, {Serial: 7}, {Serial: 100000},
	}
	data, err := encode(3, now, revoked)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.HasPrefix(data, []byte(krlMagic)) {
		t.Fatal("missing SSHKRL magic")
	}
	// magic(8)+format(4)+version(8)+generated(8)+flags(4)+reserved(4)+comment(4) = 40
	if len(data) < 40 {
		t.Fatalf("encoded KRL too short: %d bytes", len(data))
	}
	// certificate section must be present since we have revocations
	if data[40] != sectCertificat {
		t.Errorf("expected certificate section marker, got %x", data[40])
	}
}

func TestEncode_EmptyRevocationsStillValid(t *testing.T) {
	data, err := encode(1, time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.HasPrefix(data, []byte(krlMagic)) {
		t.Fatal("missing magic on empty KRL")
	}
	// no certificate section appended when nothing revoked
	if len(data) != 40 {
		t.Errorf("expected exactly header-only 40 bytes, got %d", len(data))
	}
}

func TestManager_GenerateAndGetKRL_VersionIncrements(t *testing.T) {
	ctx := context.Background()
	store := newKRLFakeStore()
	ca := &storage.SSHCertificateAuthority{ID: uuid.New(), Name: "krl-test", Status: storage.CAStatusActive}
	_ = store.CreateSSHCA(ctx, ca)

	mgr := NewManager(store)
	if err := mgr.GenerateKRL(ctx, ca.ID, time.Hour); err != nil {
		t.Fatalf("GenerateKRL 1: %v", err)
	}
	first, err := store.GetSSHKRL(ctx, ca.ID)
	if err != nil || first == nil {
		t.Fatalf("load first KRL: %v", err)
	}
	if first.KRLVersion != 1 {
		t.Errorf("expected version 1, got %d", first.KRLVersion)
	}

	if err := mgr.GenerateKRL(ctx, ca.ID, time.Hour); err != nil {
		t.Fatalf("GenerateKRL 2: %v", err)
	}
	second, _ := store.GetSSHKRL(ctx, ca.ID)
	if second.KRLVersion != 2 {
		t.Errorf("expected version 2, got %d", second.KRLVersion)
	}
}

func TestManager_RevokeAndRefresh_IncludesSerial(t *testing.T) {
	ctx := context.Background()
	store := newKRLFakeStore()
	ca := &storage.SSHCertificateAuthority{ID: uuid.New(), Name: "krl-revoke", Status: storage.CAStatusActive}
	_ = store.CreateSSHCA(ctx, ca)

	cert := &storage.SSHCertificate{ID: uuid.New(), CAID: ca.ID, Serial: 555, Status: storage.SSHCertStatusActive}
	_ = store.CreateSSHCertificate(ctx, cert)

	mgr := NewManager(store)
	if err := mgr.RevokeAndRefresh(ctx, cert.ID); err != nil {
		t.Fatalf("RevokeAndRefresh: %v", err)
	}

	got, err := store.GetSSHCertificate(ctx, cert.ID)
	if err != nil || got.Status != storage.SSHCertStatusRevoked {
		t.Fatalf("expected cert revoked, got %+v err=%v", got, err)
	}

	krlData, err := mgr.GetKRL(ctx, ca.ID)
	if err != nil {
		t.Fatalf("GetKRL: %v", err)
	}
	if !bytes.Contains(krlData, []byte{0, 0, 0, 0, 0, 0, 2, 43}) { // 555 as u64 BE
		t.Error("expected serial 555 encoded in KRL body")
	}
}
