package sshca

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// RekeyCARequest configures a key rotation (re-key) of an SSH CA.
type RekeyCARequest struct {
	// CAID is the active SSH CA row to rotate the key for.
	CAID uuid.UUID
	// KeyAlgo optionally selects a new signing algorithm for the rotated key.
	// Empty keeps the existing CA's algorithm.
	KeyAlgo KeyAlgo
}

func (r RekeyCARequest) validate() error {
	if r.CAID == uuid.Nil {
		return errors.New("sshca: RekeyCARequest: CAID is required")
	}
	return nil
}

// CrossSignCARequest configures creating a parallel SSH CA row that shares the
// target's existing key under the same logical identity. OpenSSH authenticates
// a certificate by its signing key's public key, so a parallel CA row lets an
// operator publish the same CA identity under a new physical ID (and, for key
// rotation, keep the old key trusted while a new key is rotated in). Regenerating
// the key is intentionally out of scope here — that is RekeyCA.
type CrossSignCARequest struct {
	// TargetCAID is the existing SSH CA whose key and logical identity the new
	// row shares.
	TargetCAID uuid.UUID
}

func (r CrossSignCARequest) validate() error {
	if r.TargetCAID == uuid.Nil {
		return errors.New("sshca: CrossSignCARequest: TargetCAID is required")
	}
	return nil
}

// ResolveActiveCA returns the active SSH CA row for a logical CA identity.
// If a row's LogicalCAID is nil it is treated as its own logical root (pre-
// existing rows). Superseded rows are never returned as the active identity.
func (e *Engine) ResolveActiveCA(ctx context.Context, logicalCAID uuid.UUID) (*storage.SSHCertificateAuthority, error) {
	record, err := e.store.GetSSHCA(ctx, logicalCAID)
	if err != nil {
		return nil, fmt.Errorf("sshca: ResolveActiveCA: load: %w", err)
	}
	if record == nil {
		// A logical id may point at a row that predates logical ids; also try a
		// scan for a row whose LogicalCAID matches the requested id.
		return e.resolveLogicalCAID(ctx, logicalCAID)
	}
	if record.Status == storage.CAStatusActive {
		return record, nil
	}
	// Row is non-active: chase its logical identity to the active descendant.
	if record.LogicalCAID != nil {
		if active, err := e.resolveLogicalCAID(ctx, *record.LogicalCAID); err != nil {
			return nil, err
		} else if active != nil {
			return active, nil
		}
	}
	return nil, fmt.Errorf("sshca: ResolveActiveCA: no active CA for logical id %s", logicalCAID)
}

// resolveLogicalCAID scans all SSH CAs for the row carrying the requested
// logical id. Of the active rows it prefers the primary (ParentID == nil, i.e.
// the logical root) so a cross-signed parallel row does not hijack resolution;
// otherwise it returns the Chronologically-first active row.
func (e *Engine) resolveLogicalCAID(ctx context.Context, logicalCAID uuid.UUID) (*storage.SSHCertificateAuthority, error) {
	cas, err := e.store.ListSSHCAs(ctx)
	if err != nil {
		return nil, fmt.Errorf("sshca: resolve: list: %w", err)
	}
	var primary *storage.SSHCertificateAuthority
	var fallback *storage.SSHCertificateAuthority
	for _, ca := range cas {
		if ca.Status != storage.CAStatusActive {
			continue
		}
		left := ca.LogicalCAID != nil && *ca.LogicalCAID == logicalCAID
		right := ca.LogicalCAID == nil && ca.ID == logicalCAID
		if !left && !right {
			continue
		}
		if ca.ParentID == nil && primary == nil {
			primary = ca
		}
		if fallback == nil {
			fallback = ca
		}
	}
	if primary != nil {
		return primary, nil
	}
	return fallback, nil
}

// RekeyCA rotates an SSH CA's signing key: it generates a fresh keypair, creates
// a new active CA row under the same logical identity, and supersedes the old
// row so it no longer signs new certificates (already-issued certs remain valid
// while the old public key is still trusted by clients).
func (e *Engine) RekeyCA(ctx context.Context, req RekeyCARequest) (*storage.SSHCertificateAuthority, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	return e.establishNewCA(ctx, req.CAID, req.KeyAlgo, true /*regenerate*/, true /*supersedeOld*/)
}

// CrossSignCA creates a parallel active SSH CA row sharing the target's key and
// logical identity without superseding the target. Both rows remain active, so
// clients trusting either physical CA id continue to work. This is the SSH
// analogue of cross-signing: a second row vouching for the same CA key.
func (e *Engine) CrossSignCA(ctx context.Context, req CrossSignCARequest) (*storage.SSHCertificateAuthority, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	return e.establishNewCA(ctx, req.TargetCAID, "", false /*regenerate*/, false /*supersedeOld*/)
}

// sshCAStatusUpdater is the minimal surface needed to mark an SSH CA row
// superseded during key rotation. Kept out of the broad storage.Store interface
// so fake stores in other packages don't need to implement it.
type sshCAStatusUpdater interface {
	UpdateSSHCAStatus(ctx context.Context, id uuid.UUID, status storage.CAStatus) error
}

// establishNewCA is the generic key-rotation primitive shared by RekeyCA and
// CrossSignCA. It creates a new SSH CA row under the target's logical identity,
// optionally regenerating the key and optionally superseding the target.
func (e *Engine) establishNewCA(
	ctx context.Context,
	targetCAID uuid.UUID,
	keyAlgo KeyAlgo,
	regenerate bool,
	supersedeOld bool,
) (*storage.SSHCertificateAuthority, error) {
	target, err := e.store.GetSSHCA(ctx, targetCAID)
	if err != nil {
		return nil, fmt.Errorf("sshca: establishNewCA: load target: %w", err)
	}
	if target == nil {
		return nil, fmt.Errorf("sshca: establishNewCA: SSH CA %s not found", targetCAID)
	}
	if target.Status != storage.CAStatusActive {
		return nil, fmt.Errorf("sshca: establishNewCA: SSH CA %q is not active (status: %s)", target.Name, target.Status)
	}

	logicalID := target.LogicalCAID
	if logicalID == nil {
		logicalID = &target.ID
	}

	var newKeyEnc []byte
	var newPublicKey string
	var newKeyAlgo storage.SSHKeyAlgo

	if regenerate {
		algo := keyAlgo
		if algo == "" {
			algo = DefaultKeyAlgo
		}
		if !algo.Valid() {
			return nil, fmt.Errorf("sshca: establishNewCA: unsupported KeyAlgo %q", algo)
		}
		signer, keyPEM, err := generateSSHKey(algo)
		if err != nil {
			return nil, fmt.Errorf("sshca: establishNewCA: generate key: %w", err)
		}
		sshSigner, err := ssh.NewSignerFromSigner(signer)
		if err != nil {
			return nil, fmt.Errorf("sshca: establishNewCA: wrap signer: %w", err)
		}
		enc, err := e.keystore.EncryptPEM(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("sshca: establishNewCA: encrypt key: %w", err)
		}
		newKeyEnc = enc
		newKeyAlgo = algo.storageAlgo()
		newPublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshSigner.PublicKey())))
	} else {
		// Cross-sign: reuse the target's exact encrypted key bytes.
		newKeyEnc = target.KeyEnc
		newKeyAlgo = target.KeyAlgo
		newPublicKey = target.PublicKey
	}

	newCA := &storage.SSHCertificateAuthority{
		ID:          uuid.New(),
		Name:        target.Name,     // re-keyed CA keeps the operator-facing name
		TenantID:    target.TenantID, // inherit tenant across re-key/cross-sign
		KeyAlgo:     newKeyAlgo,
		PublicKey:   newPublicKey,
		KeyEnc:      newKeyEnc,
		Status:      storage.CAStatusActive,
		LogicalCAID: logicalID,
		ParentID:    &target.ID,
		CreatedAt:   time.Now().UTC(),
	}
	if err := e.store.CreateSSHCA(ctx, newCA); err != nil {
		return nil, fmt.Errorf("sshca: establishNewCA: create: %w", err)
	}

	if supersedeOld {
		updater, ok := e.store.(sshCAStatusUpdater)
		if !ok {
			return nil, fmt.Errorf("sshca: establishNewCA: store cannot supersede SSH CA status")
		}
		if err := updater.UpdateSSHCAStatus(ctx, target.ID, storage.CAStatusSuperseded); err != nil {
			return nil, fmt.Errorf("sshca: establishNewCA: supersede old: %w", err)
		}
	}
	return newCA, nil
}
