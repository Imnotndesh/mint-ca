package audit

import (
	"testing"
	"time"
)

func mkEntry(id string, t time.Time) Entry {
	return Entry{ID: id, EventType: "POST /api/v1/certs/issue", Actor: "key1", Payload: "{}", CreatedAt: t}
}

func chainEntries(n int) []Entry {
	entries := make([]Entry, n)
	prev := GenesisPrevHash
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		e := mkEntry(string(rune('a'+i)), base.Add(time.Duration(i)*time.Minute))
		e.PrevHash = prev
		e.EntryHash = ComputeHash(prev, e)
		entries[i] = e
		prev = e.EntryHash
	}
	return entries
}

func TestVerifyChain_IntactChain(t *testing.T) {
	entries := chainEntries(5)
	if broken := VerifyChain(entries); broken != -1 {
		t.Errorf("VerifyChain = %d, want -1 (intact)", broken)
	}
}

func TestVerifyChain_DetectsTamperedPayload(t *testing.T) {
	entries := chainEntries(5)
	entries[2].Payload = `{"tampered":true}`
	if broken := VerifyChain(entries); broken != 2 {
		t.Errorf("VerifyChain = %d, want 2", broken)
	}
}

func TestVerifyChain_DetectsDeletedEntry(t *testing.T) {
	entries := chainEntries(5)
	entries = append(entries[:2], entries[3:]...) // delete index 2
	if broken := VerifyChain(entries); broken != 2 {
		t.Errorf("VerifyChain = %d, want 2 (chain break at the gap)", broken)
	}
}

func TestVerifyChain_DetectsReorderedEntries(t *testing.T) {
	entries := chainEntries(5)
	entries[1], entries[2] = entries[2], entries[1]
	if broken := VerifyChain(entries); broken != 1 {
		t.Errorf("VerifyChain = %d, want 1", broken)
	}
}

func TestVerifyChain_EmptyIsIntact(t *testing.T) {
	if broken := VerifyChain(nil); broken != -1 {
		t.Errorf("VerifyChain(nil) = %d, want -1", broken)
	}
}

func TestComputeHash_Deterministic(t *testing.T) {
	e := mkEntry("x", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	h1 := ComputeHash("prev", e)
	h2 := ComputeHash("prev", e)
	if h1 != h2 {
		t.Error("ComputeHash is not deterministic")
	}
	if h3 := ComputeHash("different-prev", e); h3 == h1 {
		t.Error("expected different prevHash to produce different entry hash")
	}
}
