// Package krl implements OpenSSH Key Revocation Lists (PROTOCOL.krl).
// Unsigned mode only: transport trust (HTTPS) is the security boundary,
// matching how mint-ca already serves x509 CRLs/OCSP.
package krl

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

const (
	krlMagic       = "SSHKRL\x00\x00" // 8 bytes: "SSHKRL" + 2 NUL padding
	krlFormatVers  = uint32(1)
	sectCertificat = byte(1) // KRL_SECTION_CERTIFICATES
	certSectSerial = byte(2) // KRL_CERT_SECTION_SERIAL_LIST
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
//   magic(8) | format_version(u32) | krl_version(u64) | generated_date(u64)
//   | flags(u32=0) | reserved_len(u32=0) | comment_len(u32=0)
//   then repeated sections: type(1) | length(u32) | body
//
// Certificate section body: ca_key_len(u32=0, omitted — unsigned mode has
// no embedded CA pubkey) is NOT included; we go straight to cert subsections:
//   subsect_type(1)=2 (SERIAL_LIST) | length(u32) | reserved(u64=0) | serial(u64)...
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

	return buf.Bytes(), nil
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
