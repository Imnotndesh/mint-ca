package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// MerkleTree is an RFC 6962 (Certificate Transparency)-style Merkle tree
// over a sequence of leaves — here, the EntryHash of successive audit log
// entries in chain order. It gives mint-ca a public commitment (the root
// hash) and per-entry inclusion proofs: "prove this specific entry was
// recorded, without needing the whole log" — the same trust model CT uses
// for certificate issuance logs, layered on top of the tamper-evident hash
// chain in chain.go.
//
// Leaf and internal node hashes are domain-separated (0x00 / 0x01 prefixes)
// exactly as RFC 6962 §2.1 specifies, which prevents a second-preimage attack
// where an internal node's hash is presented as a leaf.
type MerkleTree struct {
	leaves [][]byte // RFC 6962 leaf hashes, in entry order
}

const (
	leafHashPrefix = 0x00
	nodeHashPrefix = 0x01
)

func leafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafHashPrefix})
	h.Write(data)
	return h.Sum(nil)
}

func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodeHashPrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// NewMerkleTree builds a tree over entryHashes (hex-encoded AuditLog.EntryHash
// values), in the same oldest-first order VerifyChain expects.
func NewMerkleTree(entryHashes []string) (*MerkleTree, error) {
	leaves := make([][]byte, len(entryHashes))
	for i, h := range entryHashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("audit: decode entry hash at index %d: %w", i, err)
		}
		leaves[i] = leafHash(b)
	}
	return &MerkleTree{leaves: leaves}, nil
}

// Size returns the number of leaves in the tree.
func (t *MerkleTree) Size() int { return len(t.leaves) }

// RootHash computes the Merkle Tree Hash (hex-encoded), per RFC 6962 §2.1.
// The empty tree's root is defined as sha256() of no input.
func (t *MerkleTree) RootHash() string {
	return hex.EncodeToString(subtreeHash(t.leaves))
}

// subtreeHash computes MTH(leaves) recursively per RFC 6962 §2.1: split at
// the largest power of two less than n, hash each half, combine.
func subtreeHash(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		sum := sha256.Sum256(nil)
		return sum[:]
	}
	if n == 1 {
		return leaves[0]
	}
	k := largestPowerOfTwoLessThan(n)
	left := subtreeHash(leaves[:k])
	right := subtreeHash(leaves[k:])
	return nodeHash(left, right)
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less
// than n (RFC 6962's split point k, for n > 1).
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// InclusionProof returns the audit path proving the leaf at index i is
// included in the tree: hex-encoded sibling hashes ordered leaf-to-root, per
// RFC 6962 §2.1.1.
func (t *MerkleTree) InclusionProof(i int) ([]string, error) {
	if i < 0 || i >= len(t.leaves) {
		return nil, fmt.Errorf("audit: index %d out of range [0,%d)", i, len(t.leaves))
	}
	path := auditPath(t.leaves, i)
	out := make([]string, len(path))
	for j, p := range path {
		out[j] = hex.EncodeToString(p)
	}
	return out, nil
}

// auditPath computes PATH(i, leaves) per RFC 6962 §2.1.1, recursively.
func auditPath(leaves [][]byte, i int) [][]byte {
	n := len(leaves)
	if n <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if i < k {
		return append(auditPath(leaves[:k], i), subtreeHash(leaves[k:]))
	}
	return append(auditPath(leaves[k:], i-k), subtreeHash(leaves[:k]))
}

// VerifyInclusion checks that the audit log entry with hex-encoded entryHash
// at index, in a tree of size total leaves, produces rootHashHex via proofHex
// (hex-encoded siblings, leaf-to-root, as returned by InclusionProof).
func VerifyInclusion(entryHash string, index, size int, proofHex []string, rootHashHex string) (bool, error) {
	if index < 0 || index >= size {
		return false, fmt.Errorf("audit: index %d out of range [0,%d)", index, size)
	}
	leafBytes, err := hex.DecodeString(entryHash)
	if err != nil {
		return false, fmt.Errorf("audit: decode entry hash: %w", err)
	}
	proof := make([][]byte, len(proofHex))
	for i, p := range proofHex {
		b, err := hex.DecodeString(p)
		if err != nil {
			return false, fmt.Errorf("audit: decode proof element %d: %w", i, err)
		}
		proof[i] = b
	}
	cursor := 0
	computed, err := verifyPath(leafHash(leafBytes), index, size, proof, &cursor)
	if err != nil {
		return false, err
	}
	if cursor != len(proof) {
		return false, fmt.Errorf("audit: proof has unused trailing elements")
	}
	want, err := hex.DecodeString(rootHashHex)
	if err != nil {
		return false, fmt.Errorf("audit: decode root hash: %w", err)
	}
	return hex.EncodeToString(computed) == hex.EncodeToString(want), nil
}

// verifyPath reconstructs the root by mirroring auditPath's exact recursion
// structure, consuming proof elements in the same left-to-right order they
// were appended when the proof was generated.
func verifyPath(leaf []byte, index, n int, proof [][]byte, cursor *int) ([]byte, error) {
	if n <= 1 {
		return leaf, nil
	}
	k := largestPowerOfTwoLessThan(n)
	if index < k {
		left, err := verifyPath(leaf, index, k, proof, cursor)
		if err != nil {
			return nil, err
		}
		if *cursor >= len(proof) {
			return nil, fmt.Errorf("audit: proof too short")
		}
		right := proof[*cursor]
		*cursor++
		return nodeHash(left, right), nil
	}
	right, err := verifyPath(leaf, index-k, n-k, proof, cursor)
	if err != nil {
		return nil, err
	}
	if *cursor >= len(proof) {
		return nil, fmt.Errorf("audit: proof too short")
	}
	left := proof[*cursor]
	*cursor++
	return nodeHash(left, right), nil
}
