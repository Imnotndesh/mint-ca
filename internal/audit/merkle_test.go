package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func hashesFor(n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("entry-%d", i)))
		out[i] = hex.EncodeToString(sum[:])
	}
	return out
}

func TestMerkleTree_EmptyRoot(t *testing.T) {
	tree, err := NewMerkleTree(nil)
	if err != nil {
		t.Fatalf("NewMerkleTree: %v", err)
	}
	want := hex.EncodeToString(func() []byte { s := sha256.Sum256(nil); return s[:] }())
	if tree.RootHash() != want {
		t.Errorf("empty root = %s, want %s", tree.RootHash(), want)
	}
}

func TestMerkleTree_SingleLeaf_RootIsLeafHash(t *testing.T) {
	hashes := hashesFor(1)
	tree, err := NewMerkleTree(hashes)
	if err != nil {
		t.Fatalf("NewMerkleTree: %v", err)
	}
	b, _ := hex.DecodeString(hashes[0])
	want := hex.EncodeToString(leafHash(b))
	if tree.RootHash() != want {
		t.Errorf("single-leaf root = %s, want %s", tree.RootHash(), want)
	}
}

func TestMerkleTree_InclusionProof_RoundTrip(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 16, 17, 33} {
		n := n
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			hashes := hashesFor(n)
			tree, err := NewMerkleTree(hashes)
			if err != nil {
				t.Fatalf("NewMerkleTree: %v", err)
			}
			root := tree.RootHash()
			for i := 0; i < n; i++ {
				proof, err := tree.InclusionProof(i)
				if err != nil {
					t.Fatalf("InclusionProof(%d): %v", i, err)
				}
				ok, err := VerifyInclusion(hashes[i], i, n, proof, root)
				if err != nil {
					t.Fatalf("VerifyInclusion(%d): %v", i, err)
				}
				if !ok {
					t.Errorf("VerifyInclusion(%d) = false, want true (n=%d)", i, n)
				}
			}
		})
	}
}

func TestMerkleTree_InclusionProof_DetectsTamperedLeaf(t *testing.T) {
	hashes := hashesFor(8)
	tree, err := NewMerkleTree(hashes)
	if err != nil {
		t.Fatalf("NewMerkleTree: %v", err)
	}
	root := tree.RootHash()
	proof, err := tree.InclusionProof(3)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	tamperedHash := hashesFor(1)[0] // a different, unrelated hash
	ok, err := VerifyInclusion(tamperedHash, 3, 8, proof, root)
	if err != nil {
		t.Fatalf("VerifyInclusion: %v", err)
	}
	if ok {
		t.Error("expected verification to fail for a tampered leaf hash")
	}
}

func TestMerkleTree_InclusionProof_DetectsTamperedRoot(t *testing.T) {
	hashes := hashesFor(8)
	tree, err := NewMerkleTree(hashes)
	if err != nil {
		t.Fatalf("NewMerkleTree: %v", err)
	}
	proof, err := tree.InclusionProof(3)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	wrongRoot := hashesFor(1)[0]
	ok, err := VerifyInclusion(hashes[3], 3, 8, proof, wrongRoot)
	if err != nil {
		t.Fatalf("VerifyInclusion: %v", err)
	}
	if ok {
		t.Error("expected verification to fail against the wrong root")
	}
}

func TestMerkleTree_InclusionProof_IndexOutOfRange(t *testing.T) {
	tree, err := NewMerkleTree(hashesFor(3))
	if err != nil {
		t.Fatalf("NewMerkleTree: %v", err)
	}
	if _, err := tree.InclusionProof(3); err == nil {
		t.Error("expected an out-of-range error")
	}
	if _, err := tree.InclusionProof(-1); err == nil {
		t.Error("expected an out-of-range error")
	}
}

func TestMerkleTree_RootChangesWithLeafOrder(t *testing.T) {
	a, _ := NewMerkleTree([]string{hashesFor(2)[0], hashesFor(2)[1]})
	b, _ := NewMerkleTree([]string{hashesFor(2)[1], hashesFor(2)[0]})
	if a.RootHash() == b.RootHash() {
		t.Error("expected reordering leaves to change the root hash")
	}
}
