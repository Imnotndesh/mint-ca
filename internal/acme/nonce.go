package acme

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	// DefaultNonceTTL is how long a nonce remains valid before it is rejected.
	// RFC 8555 does not mandate a specific value; 1 hour is a common choice.
	DefaultNonceTTL = 1 * time.Hour

	// nonce byte length — 16 bytes = 32 hex characters = 128 bits of entropy.
	nonceBytes = 16
)

// NonceStore is the database interface required by the nonce manager.
// These methods are added to the main storage.Store interface.
type NonceStore interface {
	// CreateNonce inserts a new nonce with the given expiry.
	CreateNonce(ctx context.Context, nonce string, expiresAt time.Time) error

	// ConsumeNonce atomically checks that the nonce exists and has not expired,
	// then deletes it. Returns (true, nil) if valid, (false, nil) if unknown or
	// expired, or (false, err) on a database error.
	ConsumeNonce(ctx context.Context, nonce string) (bool, error)

	// PruneExpiredNonces deletes all nonces past their expiry. Called on a
	// background ticker — callers should not block on the result.
	PruneExpiredNonces(ctx context.Context) error
}

// NonceManager issues and validates ACME replay nonces.
type NonceManager struct {
	store NonceStore
	ttl   time.Duration
}

// NewNonceManager constructs a NonceManager. If ttl is zero, DefaultNonceTTL
// is used.
func NewNonceManager(store NonceStore, ttl time.Duration) *NonceManager {
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	return &NonceManager{store: store, ttl: ttl}
}

// Issue generates a fresh nonce, persists it to the database, and returns the
// hex-encoded string to embed in a Replay-Nonce HTTP response header.
func (m *NonceManager) Issue(ctx context.Context) (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("nonce: generate random bytes: %w", err)
	}
	nonce := hex.EncodeToString(b)
	expiresAt := time.Now().UTC().Add(m.ttl)
	if err := m.store.CreateNonce(ctx, nonce, expiresAt); err != nil {
		return "", fmt.Errorf("nonce: persist: %w", err)
	}
	return nonce, nil
}

// Consume validates and atomically burns a nonce. Returns a *Problem if the
// nonce is missing, expired, or on a DB error so the caller can write a
// proper ACME error response immediately.
func (m *NonceManager) Consume(ctx context.Context, nonce string) *Problem {
	if nonce == "" {
		return ErrBadNonceProblem("missing nonce in JWS protected header")
	}
	ok, err := m.store.ConsumeNonce(ctx, nonce)
	if err != nil {
		return ErrServerInternalProblem("nonce validation failed: " + err.Error())
	}
	if !ok {
		return ErrBadNonceProblem("nonce is invalid or has already been used")
	}
	return nil
}
