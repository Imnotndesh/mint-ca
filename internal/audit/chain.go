// Package audit implements tamper-evidence for the audit log: each entry's
// hash is derived from its own fields plus the previous entry's hash, forming
// a hash chain (genesis entry chains from the empty string). Deleting,
// editing, or reordering any entry breaks the chain from that point forward,
// which VerifyChain detects. This package has no dependency on internal/storage
// so it can be used from the storage backends (which write the chain) and from
// the API layer (which verifies it) without an import cycle.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// GenesisPrevHash is the prev_hash value of the first entry in the chain.
const GenesisPrevHash = ""

// Entry is the subset of an audit log record that feeds the hash chain.
// PrevHash and EntryHash are the recorded values being verified — they are
// not inputs to the hash computation itself.
type Entry struct {
	ID        string
	EventType string
	Actor     string
	CAID      string
	CertID    string
	Payload   string // canonical JSON, as stored
	IPAddress string
	CreatedAt time.Time
	PrevHash  string
	EntryHash string
}

// ComputeHash derives the entry hash for e given the previous entry's hash.
func ComputeHash(prevHash string, e Entry) string {
	data := strings.Join([]string{
		prevHash,
		e.ID,
		e.EventType,
		e.Actor,
		e.CAID,
		e.CertID,
		e.Payload,
		e.IPAddress,
		e.CreatedAt.UTC().Format(time.RFC3339Nano),
	}, "|")
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// VerifyChain checks entries (given oldest-first, i.e. insertion order)
// against their recorded PrevHash/EntryHash. It returns the index of the
// first entry whose recorded hash doesn't match what the chain implies, or -1
// if every entry checks out from genesis.
func VerifyChain(entries []Entry) int {
	prev := GenesisPrevHash
	for i, e := range entries {
		if e.PrevHash != prev {
			return i
		}
		if e.EntryHash != ComputeHash(prev, e) {
			return i
		}
		prev = e.EntryHash
	}
	return -1
}
