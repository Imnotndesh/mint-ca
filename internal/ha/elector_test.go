package ha

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeLeadershipStore struct {
	mu       sync.Mutex
	winner   string // node ID that should win the next campaign; "" = no one
	err      error
	attempts int
}

func (f *fakeLeadershipStore) TryAcquireLeadership(ctx context.Context, nodeID string, lease time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.err != nil {
		return false, f.err
	}
	return nodeID == f.winner, nil
}

func (f *fakeLeadershipStore) CurrentLeader(ctx context.Context) (string, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.winner, time.Now().Add(time.Minute), nil
}

func TestElector_SingleNodeMode_AlwaysLeader(t *testing.T) {
	e := NewElector(nil, "node-1", time.Second, time.Second)
	if !e.IsLeader() {
		t.Fatal("expected single-node mode (nil store) to always be leader")
	}
	// Run must be a no-op and return promptly.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := e.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !e.IsLeader() {
		t.Fatal("expected to remain leader after Run returns")
	}
}

func TestElector_WinsCampaign_BecomesLeader(t *testing.T) {
	store := &fakeLeadershipStore{winner: "node-1"}
	e := NewElector(store, "node-1", time.Second, time.Second)
	if e.IsLeader() {
		t.Fatal("expected not to be leader before any campaign")
	}
	e.campaign(context.Background())
	if !e.IsLeader() {
		t.Fatal("expected to become leader after winning the campaign")
	}
}

func TestElector_LosesCampaign_StaysStandby(t *testing.T) {
	store := &fakeLeadershipStore{winner: "node-2"}
	e := NewElector(store, "node-1", time.Second, time.Second)
	e.campaign(context.Background())
	if e.IsLeader() {
		t.Fatal("expected to remain standby when another node holds the lease")
	}
}

func TestElector_LeaderLosesLease_BecomesStandby(t *testing.T) {
	store := &fakeLeadershipStore{winner: "node-1"}
	e := NewElector(store, "node-1", time.Second, time.Second)
	e.campaign(context.Background())
	if !e.IsLeader() {
		t.Fatal("expected to win the first campaign")
	}

	store.mu.Lock()
	store.winner = "node-2" // another node took over
	store.mu.Unlock()
	e.campaign(context.Background())
	if e.IsLeader() {
		t.Fatal("expected to lose leadership once another node wins")
	}
}

func TestElector_StoreError_StepsDown(t *testing.T) {
	store := &fakeLeadershipStore{winner: "node-1"}
	e := NewElector(store, "node-1", time.Second, time.Second)
	e.campaign(context.Background())
	if !e.IsLeader() {
		t.Fatal("expected to win the first campaign")
	}

	store.mu.Lock()
	store.err = errors.New("db unavailable")
	store.mu.Unlock()
	e.campaign(context.Background())
	if e.IsLeader() {
		t.Fatal("expected a campaign error to step down out of caution")
	}
}

func TestElector_Run_CampaignsOnInterval(t *testing.T) {
	store := &fakeLeadershipStore{winner: "node-1"}
	e := NewElector(store, "node-1", time.Second, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Millisecond)
	defer cancel()
	_ = e.Run(ctx)

	store.mu.Lock()
	attempts := store.attempts
	store.mu.Unlock()
	if attempts < 3 {
		t.Errorf("expected several campaign attempts over the run, got %d", attempts)
	}
	if !e.IsLeader() {
		t.Error("expected to be leader after a successful run")
	}
}
