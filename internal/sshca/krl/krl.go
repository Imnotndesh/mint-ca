// Package krl implements OpenSSH Key Revocation Lists (PROTOCOL.krl).
// Unsigned mode only: transport trust (HTTPS) is the security boundary,
// matching how mint-ca already serves x509 CRLs/OCSP.
//
// Signed KRL sections are deliberately NOT implemented. PROTOCOL.krl defines a
// KRL_SECTION_SIGNATURE (0x04) section, but OpenSSH removed all support for it
// in 9.4 (2023): the signing/verifing code was never completed, and modern
// OpenSSH ignores (and previously refused) KRLs containing signature sections.
// The upstream spec instead suggests SSHSIG (`ssh-keygen -Y sign`) as a
// detached-signature mechanism, but sshd(8) does NOT verify such signatures
// when it loads a KRL for the RevokedKeys directive — it hashes the issuing CA
// key and checks it against the KRL body directly. Since mint-ca serves KRLs
// over HTTPS (the /pki/sshca/{caID}/krl TLS endpoint), clients already receive
// them over a channel providing integrity protection, which PROTOCOL.krl
// describes as the case where "signature sections are optional ... by trusted
// means". A signed section would therefore add bytes that no consumer verifies,
// at risk of breaking OpenSSH >= 9.4 clients.
package krl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// KRL section types (OpenSSH PROTOCOL.krl).
const (
	krlMagic        = "SSHKRL\x00\x00" // 8 bytes: "SSHKRL" + 2 NUL padding
	krlFormatVers   = uint32(1)
	sectCertificat  = byte(1) // KRL_SECTION_CERTIFICATES
	sectExplicitKey = byte(2) // KRL_SECTION_EXPLICIT_KEY
	sectFpSHA1      = byte(3) // KRL_SECTION_FINGERPRINT_SHA1
	sectFpSHA256    = byte(5) // KRL_SECTION_FINGERPRINT_SHA256
	certSectSerial  = byte(2) // KRL_CERT_SECTION_SERIAL_LIST
)

// Manager generates and caches KRLs for SSH CAs, mirroring
// revocation.CRLManager's shape and lazy-regen semantics.
type Manager struct {
	store storage.Store
}

func NewManager(store storage.Store) *Manager {
	return &Manager{store: store}
}

// RevokeAndRefresh revokes the cert and immediately regenerates the KRL,
// closing the gap where SSHCAHandler.revokeCert flipped status with no
// revocation-list artifact for clients to consume.
func (m *Manager) RevokeAndRefresh(ctx context.Context, certID uuid.UUID) error {
	if err := m.store.RevokeSSHCertificate(ctx, certID); err != nil {
		return fmt.Errorf("krl: RevokeAndRefresh: revoke: %w", err)
	}
	cert, err := m.store.GetSSHCertificate(ctx, certID)
	if err != nil || cert == nil {
		return fmt.Errorf("krl: RevokeAndRefresh: reload cert: %w", err)
	}
	if err := m.GenerateKRL(ctx, cert.CAID, defaultKRLValidity); err != nil {
		return fmt.Errorf("krl: RevokeAndRefresh: regenerate: %w", err)
	}
	return nil
}

const defaultKRLValidity = 24 * time.Hour

// GenerateKRL builds a fresh KRL for caID and upserts it into ssh_krl_cache.
func (m *Manager) GenerateKRL(ctx context.Context, caID uuid.UUID, validFor time.Duration) error {
	if validFor <= 0 {
		validFor = defaultKRLValidity
	}
	ca, err := m.store.GetSSHCA(ctx, caID)
	if err != nil {
		return fmt.Errorf("krl: GenerateKRL: load CA: %w", err)
	}
	if ca == nil {
		return fmt.Errorf("krl: GenerateKRL: SSH CA %s not found", caID)
	}

	revoked, err := m.store.ListRevokedSSHCertificatesByCA(ctx, caID)
	if err != nil {
		return fmt.Errorf("krl: GenerateKRL: list revoked: %w", err)
	}

	now := time.Now().UTC()
	nextUpdate := now.Add(validFor)

	prev, err := m.store.GetSSHKRL(ctx, caID)
	if err != nil {
		return fmt.Errorf("krl: GenerateKRL: load previous: %w", err)
	}
	version := uint64(1)
	if prev != nil {
		version = prev.KRLVersion + 1
	}

	data, err := encode(version, now, revoked)
	if err != nil {
		return fmt.Errorf("krl: GenerateKRL: encode: %w", err)
	}

	entry := &storage.SSHKRLCache{
		ID:         uuid.New(),
		CAID:       caID,
		KRLData:    data,
		KRLVersion: version,
		ThisUpdate: now,
		NextUpdate: nextUpdate,
	}
	if err := m.store.UpsertSSHKRL(ctx, entry); err != nil {
		return fmt.Errorf("krl: GenerateKRL: upsert cache: %w", err)
	}
	return nil
}

// GetKRL returns the binary KRL for caID, regenerating if missing/expired.
func (m *Manager) GetKRL(ctx context.Context, caID uuid.UUID) ([]byte, error) {
	cached, err := m.store.GetSSHKRL(ctx, caID)
	if err != nil {
		return nil, fmt.Errorf("krl: GetKRL: load cache: %w", err)
	}
	if cached == nil || time.Now().UTC().After(cached.NextUpdate) {
		if err := m.GenerateKRL(ctx, caID, defaultKRLValidity); err != nil {
			return nil, fmt.Errorf("krl: GetKRL: regenerate: %w", err)
		}
		cached, err = m.store.GetSSHKRL(ctx, caID)
		if err != nil || cached == nil {
			return nil, fmt.Errorf("krl: GetKRL: load after regenerate: %w", err)
		}
	}
	return cached.KRLData, nil
}

// RefreshAll regenerates KRLs for every active SSH CA (background ticker).
func (m *Manager) RefreshAll(ctx context.Context, validity time.Duration) error {
	cas, err := m.store.ListSSHCAs(ctx)
	if err != nil {
		return fmt.Errorf("krl: RefreshAll: list CAs: %w", err)
	}
	var lastErr error
	for _, ca := range cas {
		if ca.Status != storage.CAStatusActive {
			continue
		}
		if err := m.GenerateKRL(ctx, ca.ID, validity); err != nil {
			lastErr = fmt.Errorf("krl: RefreshAll: CA %q: %w", ca.Name, err)
		}
	}
	return lastErr
}

// ---- binary encoding (PROTOCOL.krl, unsigned) ----
//
// Layout:
//
//	magic(8) | format_version(u32) | krl_version(u64) | generated_date(u64)
//	| flags(u32=0) | reserved_len(u32=0) | comment_len(u32=0)
//	then repeated sections: type(1) | length(u32) | body
//
// Certificate section body: ca_key_len(u32=0, omitted — unsigned mode has
// no embedded CA pubkey) is NOT included; we go straight to cert subsections:
//
//	subsect_type(1)=2 (SERIAL_LIST) | length(u32) | reserved(u64=0) | serial(u64)...
func encode(version uint64, generated time.Time, revoked []*storage.SSHCertificate) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(krlMagic)

	writeU32(&buf, krlFormatVers)
	writeU64(&buf, version)
	writeU64(&buf, uint64(generated.Unix()))
	writeU32(&buf, 0) // flags
	writeU32(&buf, 0) // reserved section length
	writeU32(&buf, 0) // comment length (no comment)

	if len(revoked) > 0 {
		var certSect bytes.Buffer
		var serials bytes.Buffer
		writeU64(&serials, 0) // reserved
		for _, c := range revoked {
			writeU64(&serials, c.Serial)
		}
		certSect.WriteByte(certSectSerial)
		writeU32(&certSect, uint32(serials.Len()))
		certSect.Write(serials.Bytes())

		buf.WriteByte(sectCertificat)
		writeU32(&buf, uint32(certSect.Len()))
		buf.Write(certSect.Bytes())
	}

	// Revoke the revoked certificates' underlying PLAIN keys too, so a raw key
	// is rejected even without its certificate. Two sections are emitted:
	//   KRL_SECTION_EXPLICIT_KEY        — the raw public key blobs
	//   KRL_SECTION_FINGERPRINT_SHA256  — SHA256 hash of each key blob
	keys, err := plainKeyBlobs(revoked)
	if err != nil {
		return nil, err
	}
	if err := writeStringListSection(&buf, sectExplicitKey, keys); err != nil {
		return nil, err
	}

	hashes := make([][]byte, 0, len(keys))
	for _, k := range keys {
		sum := sha256.Sum256(k)
		hashes = append(hashes, sum[:])
	}
	// OpenSSH requires fingerprint hashes in ascending numeric (big-endian) order.
	sort.Slice(hashes, func(i, j int) bool { return bytes.Compare(hashes[i], hashes[j]) < 0 })
	if err := writeStringListSection(&buf, sectFpSHA256, hashes); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// plainKeyBlobs extracts, for each revoked certificate, the raw wire-format
// blob of its plain (signed) public key. The stored PublicKey field is an
// OpenSSH authorized_keys line; we re-parse it to recover the raw blob.
func plainKeyBlobs(revoked []*storage.SSHCertificate) ([][]byte, error) {
	seen := make(map[string]bool)
	var out [][]byte
	for _, c := range revoked {
		if c.PublicKey == "" {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.PublicKey))
		if err != nil {
			continue // skip unparseable; serial-based revocation still applies
		}
		blob := pub.Marshal()
		if seen[string(blob)] {
			continue
		}
		seen[string(blob)] = true
		out = append(out, blob)
	}
	return out, nil
}

// writeStringListSection writes a KRL section (type byte + u32 length prefixed
// string body) whose body is a sequence of length-prefixed strings, per the
// PROTOCOL.krl explicit-key / fingerprint section layout. Writes nothing when
// items is empty.
func writeStringListSection(buf *bytes.Buffer, sectionType byte, items [][]byte) error {
	if len(items) == 0 {
		return nil
	}
	var body bytes.Buffer
	for _, it := range items {
		writeU32(&body, uint32(len(it)))
		body.Write(it)
	}
	buf.WriteByte(sectionType)
	writeU32(buf, uint32(body.Len()))
	buf.Write(body.Bytes())
	return nil
}

func writeU32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

func writeU64(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}
