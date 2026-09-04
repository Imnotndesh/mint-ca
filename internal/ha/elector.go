// Package ha implements active-passive leader election for mint-ca so
// multiple server processes can share one Postgres database with only one
// node accepting writes at a time. A standby that loses its DB connection or
// stalls simply stops renewing its lease, and the next node to campaign takes
// over — no separate coordination service (etcd/Raft) required.
package ha

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// LeadershipStore is the storage surface a Postgres-backed deployment
// provides for leader election (see storage.postgresStore). Other backends
// (sqlite) don't implement it, in which case Elector runs in single-node
// mode and is always the leader — correct for sqlite, since it's a single-
// process, single-file store anyway.
type LeadershipStore interface {
	// TryAcquireLeadership attempts to become (or remain) leader for lease.
	// It succeeds if no other node currently holds an unexpired lease, or if
	// nodeID already holds it (lease renewal).
	TryAcquireLeadership(ctx context.Context, nodeID string, lease time.Duration) (bool, error)
	// CurrentLeader returns the node ID currently holding the lease (which
	// may be expired) and when that lease expires.
	CurrentLeader(ctx context.Context) (nodeID string, expiresAt time.Time, err error)
}

// Elector campaigns for leadership on an interval and exposes the current
// state via IsLeader. In active-passive HA, only the leader should serve
// mutating API traffic and run write-side background workers; standbys wait,
// ready to take over the moment the lease lapses.
//
// Elector implements workers.Worker so it can be added to the standard
// worker group like any other background job.
type Elector struct {
	store    LeadershipStore // nil => single-node mode, always leader
	nodeID   string
	lease    time.Duration
	interval time.Duration
	leader   atomic.Bool
}

// NewElector builds an Elector. A nil store puts it in single-node mode: it
// is always the leader and Run is a no-op (correct for the sqlite backend,
// which is inherently single-process).
func NewElector(store LeadershipStore, nodeID string, lease, interval time.Duration) *Elector {
	e := &Elector{store: store, nodeID: nodeID, lease: lease, interval: interval}
	if store == nil {
		e.leader.Store(true)
	}
	return e
}

// IsLeader reports whether this node currently holds the lease.
func (e *Elector) IsLeader() bool { return e.leader.Load() }

// NodeID returns this node's identity in the leader-election lock.
func (e *Elector) NodeID() string { return e.nodeID }

// Name implements workers.Worker.
func (e *Elector) Name() string { return "ha-leader-election" }

// Run implements workers.Worker: campaigns immediately, then on Elector's
// interval, until ctx is cancelled. A no-op in single-node mode.
func (e *Elector) Run(ctx context.Context) error {
	if e.store == nil {
		return nil
	}
	e.campaign(ctx)
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			e.campaign(ctx)
		}
	}
}

func (e *Elector) campaign(ctx context.Context) {
	campaignCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	won, err := e.store.TryAcquireLeadership(campaignCtx, e.nodeID, e.lease)
	if err != nil {
		slog.Warn("ha: leadership campaign failed", "node_id", e.nodeID, "err", err)
		e.leader.Store(false)
		return
	}
	wasLeader := e.leader.Swap(won)
	if won && !wasLeader {
		slog.Info("ha: acquired leadership", "node_id", e.nodeID)
	} else if !won && wasLeader {
		slog.Warn("ha: lost leadership", "node_id", e.nodeID)
	}
}
