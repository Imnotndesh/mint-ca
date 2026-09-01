package krl

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
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
	// no sections appended when nothing revoked (header is 40 bytes)
	if len(data) != 40 {
		t.Errorf("expected exactly header-only 40 bytes, got %d", len(data))
	}
}

// TestEncode_EmitsKeyAndFingerprintSections verifies that revoking a
// certificate also revokes its underlying plain key: an EXPLICIT_KEY section
// (raw blob) and a FINGERPRINT_SHA256 section (sorted hashes) are emitted
// after the certificate serial section.
func TestEncode_EmitsKeyAndFingerprintSections(t *testing.T) {
	// Generate two real keys so we can inspect their raw blobs and SHA256.
	_, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key A: %v", err)
	}
	signerA, err := ssh.NewSignerFromSigner(privA)
	if err != nil {
		t.Fatalf("wrap A: %v", err)
	}
	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key B: %v", err)
	}
	signerB, err := ssh.NewSignerFromSigner(privB)
	if err != nil {
		t.Fatalf("wrap B: %v", err)
	}

	blobA := signerA.PublicKey().Marshal()
	blobB := signerB.PublicKey().Marshal()
	if bytes.Equal(blobA, blobB) {
		t.Fatal("test keys unexpectedly identical")
	}

	data, err := encode(1, time.Now().UTC(), []*storage.SSHCertificate{
		{Serial: 1, PublicKey: string(ssh.MarshalAuthorizedKey(signerA.PublicKey()))},
		{Serial: 2, PublicKey: string(ssh.MarshalAuthorizedKey(signerB.PublicKey()))},
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Parse into sections: iterate type byte + u32-length string body.
	secs, err := parseSectionsForTest(data)
	if err != nil {
		t.Fatalf("parse sections: %v", err)
	}

	// Certificate section must be present (type 1).
	if _, ok := secs[sectCertificat]; !ok {
		t.Error("missing certificate section")
	}

	// EXPLICIT_KEY (2) must contain both raw key blobs.
	explicit, ok := secs[sectExplicitKey]
	if !ok {
		t.Fatal("missing explicit-key section")
	}
	foundBlobs := readStringList(explicit)
	if !containsBlob(foundBlobs, blobA) || !containsBlob(foundBlobs, blobB) {
		t.Errorf("explicit key section missing a key blob (got %d blobs)", len(foundBlobs))
	}

	// FINGERPRINT_SHA256 (5) must contain both 32-byte hashes.
	hashes, ok := secs[sectFpSHA256]
	if !ok {
		t.Fatal("missing SHA256 fingerprint section")
	}
	lenList := readStringList(hashes)
	if len(lenList) != 2 {
		t.Fatalf("expected 2 SHA256 fingerprint hashes, got %d", len(lenList))
	}
	wantA := sha256.Sum256(blobA)
	wantB := sha256.Sum256(blobB)
	for _, h := range lenList {
		if len(h) != sha256.Size {
			t.Errorf("SHA256 hash wrong length %d", len(h))
		}
		if bytes.Equal(h, wantA[:]) || bytes.Equal(h, wantB[:]) {
			continue
		}
		t.Errorf("SHA256 fingerprint list contains unexpected hash %v", h)
	}
}

// parseSectionsForTest walks the KRL body after the 40-byte header and returns
// each section's body keyed by section type.
func parseSectionsForTest(data []byte) (map[byte][]byte, error) {
	out := map[byte][]byte{}
	if len(data) < 40 {
		return out, nil
	}
	body := data[40:]
	for len(body) > 0 {
		typ := body[0]
		body = body[1:]
		if len(body) < 4 {
			return nil, &krlErr{"truncated section length"}
		}
		slen := int(binary.BigEndian.Uint32(body[:4]))
		body = body[4:]
		if len(body) < slen {
			return nil, &krlErr{"truncated section body"}
		}
		out[typ] = body[:slen]
		body = body[slen:]
	}
	return out, nil
}

// readStringList decodes a body of length-prefixed strings.
func readStringList(body []byte) [][]byte {
	var out [][]byte
	for len(body) >= 4 {
		n := int(binary.BigEndian.Uint32(body[:4]))
		body = body[4:]
		if n > len(body) {
			return out
		}
		out = append(out, body[:n])
		body = body[n:]
	}
	return out
}

func containsBlob(list [][]byte, want []byte) bool {
	for _, b := range list {
		if bytes.Equal(b, want) {
			return true
		}
	}
	return false
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
