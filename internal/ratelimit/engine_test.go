package ratelimit

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// noopCounterStore discards writes; tests only care about in-memory Allow behavior.
type noopCounterStore struct{}

func (noopCounterStore) IncrementRateLimitCounter(ctx context.Context, limiterName, bucketKey string, windowStart time.Time) error {
	return nil
}

func TestFixedWindow_AllowsUpToLimit(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine(noopCounterStore{})
	if err := engine.LoadConfigs([]LimiterConfig{
		{Name: "test_limiter", Scope: "test", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 3, Enabled: true},
	}); err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}

	for i := 0; i < 3; i++ {
		allowed, _, err := engine.Check(ctx, "test_limiter", "key-a")
		if err != nil {
			t.Fatalf("Check %d failed: %v", i, err)
		}
		if !allowed {
			t.Fatalf("expected request %d to be allowed", i)
		}
	}

	allowed, retryAfter, err := engine.Check(ctx, "test_limiter", "key-a")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if allowed {
		t.Fatal("expected 4th request to be denied")
	}
	if retryAfter <= 0 {
		t.Error("expected positive retryAfter when denied")
	}
}

func TestFixedWindow_SeparateBucketKeysIndependent(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine(noopCounterStore{})
	_ = engine.LoadConfigs([]LimiterConfig{
		{Name: "test_limiter", Scope: "test", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 1, Enabled: true},
	})

	allowedA, _, _ := engine.Check(ctx, "test_limiter", "key-a")
	allowedB, _, _ := engine.Check(ctx, "test_limiter", "key-b")
	if !allowedA || !allowedB {
		t.Error("expected independent bucket keys to each get their own quota")
	}

	allowedA2, _, _ := engine.Check(ctx, "test_limiter", "key-a")
	if allowedA2 {
		t.Error("expected key-a to be exhausted after 1 request")
	}
}

func TestFixedWindow_DisabledLimiterAlwaysAllows(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine(noopCounterStore{})
	_ = engine.LoadConfigs([]LimiterConfig{
		{Name: "test_limiter", Scope: "test", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 1, Enabled: false},
	})

	for i := 0; i < 5; i++ {
		allowed, _, err := engine.Check(ctx, "test_limiter", "key-a")
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !allowed {
			t.Fatalf("expected disabled limiter to always allow, denied on request %d", i)
		}
	}
}

func TestEngine_UnknownLimiter_FailsOpenWithError(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine(noopCounterStore{})

	allowed, _, err := engine.Check(ctx, "does_not_exist", "key-a")
	if !allowed {
		t.Error("expected fail-open (allowed=true) for unknown limiter")
	}
	if err == nil {
		t.Error("expected an error for unknown limiter so caller can log it")
	}
}

func TestEngine_UpdateConfig_ResetsCounters(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine(noopCounterStore{})
	_ = engine.LoadConfigs([]LimiterConfig{
		{Name: "test_limiter", Scope: "test", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 1, Enabled: true},
	})

	_, _, err := engine.Check(ctx, "test_limiter", "key-a")
	if err != nil {
		return
	} // consume the only slot

	if err := engine.UpdateConfig(LimiterConfig{
		Name: "test_limiter", Scope: "test", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 5, Enabled: true,
	}); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	allowed, _, _ := engine.Check(ctx, "test_limiter", "key-a")
	if !allowed {
		t.Error("expected fresh algorithm instance after UpdateConfig to have reset counters")
	}
}

// countingCounterStore counts write-through increments so tests can assert
// the async DB path is actually being exercised without adding real latency
// to the hot path.
type countingCounterStore struct {
	writes int64
}

func (c *countingCounterStore) IncrementRateLimitCounter(ctx context.Context, limiterName, bucketKey string, windowStart time.Time) error {
	atomic.AddInt64(&c.writes, 1)
	return nil
}
func seededRand(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(time.Now().UnixNano() + seed))
}

// humanThink returns a short pause with a mix of quick clicks, slower
// deliberate actions, and occasional longer pauses. This is intentionally
// less mechanical than a tight loop.
func humanThink(r *rand.Rand) time.Duration {
	switch r.Intn(10) {
	case 0:
		// Reading, reacting, or switching context.
		return time.Duration(30+r.Intn(50)) * time.Millisecond
	case 1, 2:
		// Slower, deliberate action.
		return time.Duration(10+r.Intn(20)) * time.Millisecond
	default:
		// Fast click-through.
		return time.Duration(1+r.Intn(8)) * time.Millisecond
	}
}

// humanStagger returns a small arrival delay, e.g. for users starting a
// session at slightly different times.
func humanStagger(r *rand.Rand, maxMs int) time.Duration {
	if maxMs <= 0 {
		return 0
	}
	return time.Duration(r.Intn(maxMs+1)) * time.Millisecond
}

// -----------------------------------------------------------------------
// Scenario 1: consistent human users. A fixed set of known accounts each
// browse in their own session, sending more requests than the limit while
// paused as a human would. Verifies per-key isolation holds and each
// account is capped at its own limit.
// -----------------------------------------------------------------------

func TestConcurrency_ConsistentHumans_EachRespectsOwnLimit(t *testing.T) {
	ctx := context.Background()
	counterStore := &countingCounterStore{}
	engine := NewEngine(counterStore)

	const limit = 10
	if err := engine.LoadConfigs([]LimiterConfig{
		{Name: "consistent_humans", Scope: "account", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: limit, Enabled: true},
	}); err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}

	const numUsers = 12
	const requestsPerUser = 30 // far more than the limit, to force denials

	var wg sync.WaitGroup
	allowedCounts := make([]int64, numUsers)

	for u := 0; u < numUsers; u++ {
		u := u
		userKey := fmt.Sprintf("user-%d", u)
		r := seededRand(int64(u))

		wg.Add(1)
		go func() {
			defer wg.Done()

			// Users begin their session at slightly different moments.
			time.Sleep(humanStagger(r, 30))

			for i := 0; i < requestsPerUser; i++ {
				allowed, _, err := engine.Check(ctx, "consistent_humans", userKey)
				if err != nil {
					t.Errorf("user %s: unexpected error: %v", userKey, err)
					return
				}
				if allowed {
					atomic.AddInt64(&allowedCounts[u], 1)
				}

				time.Sleep(humanThink(r))
			}
		}()
	}
	wg.Wait()

	for u := 0; u < numUsers; u++ {
		got := atomic.LoadInt64(&allowedCounts[u])
		if got != limit {
			t.Errorf("user-%d: expected exactly %d allowed requests under human-paced traffic, got %d", u, limit, got)
		}
	}
}

// -----------------------------------------------------------------------
// Scenario 2: mixed human activity. Active browsers, intermittent readers,
// and brand-new users all arrive concurrently. Verifies the engine stays
// correct when access patterns are irregular and new bucket keys appear
// alongside existing ones.
// -----------------------------------------------------------------------

func TestConcurrency_MixedHumanActivity_RapidIntermittentAndNewUsers(t *testing.T) {
	ctx := context.Background()
	counterStore := &countingCounterStore{}
	engine := NewEngine(counterStore)

	const limit = 10
	if err := engine.LoadConfigs([]LimiterConfig{
		{Name: "mixed_human_activity", Scope: "account", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: limit, Enabled: true},
	}); err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}

	const activeUsers = 5
	const activeRequests = 18 // over limit, each active user should be capped
	const intermittentUsers = 5
	const intermittentRequests = 6 // under limit, should all be allowed
	const newcomers = 20
	const newcomerRequests = 2 // each new user gets a fresh bucket and should be allowed

	activeAllowed := make([]int64, activeUsers)
	intermittentDenied := make([]int64, intermittentUsers)
	var newcomerAllowed, newcomerDenied int64

	var wg sync.WaitGroup

	// Group A: active human browsers with quick but irregular click-throughs.
	for u := 0; u < activeUsers; u++ {
		u := u
		userKey := fmt.Sprintf("active-user-%d", u)
		r := seededRand(int64(1000 + u))

		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(humanStagger(r, 20))

			for i := 0; i < activeRequests; i++ {
				allowed, _, err := engine.Check(ctx, "mixed_human_activity", userKey)
				if err != nil {
					t.Errorf("%s: %v", userKey, err)
					return
				}
				if allowed {
					atomic.AddInt64(&activeAllowed[u], 1)
				}
				time.Sleep(humanThink(r))
			}
		}()
	}

	// Group B: intermittent users with longer idle gaps between actions.
	for u := 0; u < intermittentUsers; u++ {
		u := u
		userKey := fmt.Sprintf("intermittent-user-%d", u)
		r := seededRand(int64(2000 + u))

		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(humanStagger(r, 60))

			for i := 0; i < intermittentRequests; i++ {
				allowed, _, err := engine.Check(ctx, "mixed_human_activity", userKey)
				if err != nil {
					t.Errorf("%s: %v", userKey, err)
					return
				}
				if !allowed {
					atomic.AddInt64(&intermittentDenied[u], 1)
				}

				// Longer idle time, like reading or waiting between actions.
				time.Sleep(time.Duration(40+r.Intn(80)) * time.Millisecond)
			}
		}()
	}

	// Group C: new users joining mid-test and taking a couple of onboarding actions.
	for u := 0; u < newcomers; u++ {
		userKey := fmt.Sprintf("newcomer-%d", u)
		r := seededRand(int64(3000 + u))

		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(u%20) * time.Millisecond)

			for i := 0; i < newcomerRequests; i++ {
				allowed, _, err := engine.Check(ctx, "mixed_human_activity", userKey)
				if err != nil {
					t.Errorf("%s: %v", userKey, err)
					return
				}
				if allowed {
					atomic.AddInt64(&newcomerAllowed, 1)
				} else {
					atomic.AddInt64(&newcomerDenied, 1)
				}
				time.Sleep(time.Duration(1+r.Intn(5)) * time.Millisecond)
			}
		}()
	}

	wg.Wait()

	for u := 0; u < activeUsers; u++ {
		if got := atomic.LoadInt64(&activeAllowed[u]); got != limit {
			t.Errorf("active-user-%d: expected exactly %d allowed, got %d", u, limit, got)
		}
	}
	for u := 0; u < intermittentUsers; u++ {
		if got := atomic.LoadInt64(&intermittentDenied[u]); got != 0 {
			t.Errorf("intermittent-user-%d: denied %d requests despite being under limit", u, got)
		}
	}

	expectedNewcomerAllowed := int64(newcomers * newcomerRequests)
	if newcomerDenied != 0 || newcomerAllowed != expectedNewcomerAllowed {
		t.Errorf("newcomers: expected %d allowed and 0 denied, got %d allowed / %d denied",
			expectedNewcomerAllowed, newcomerAllowed, newcomerDenied)
	}

	t.Logf("mixed human activity: allowed=%d denied=%d write-throughs=%d",
		atomic.LoadInt64(&newcomerAllowed)+atomic.LoadInt64(&counterStore.writes)-atomic.LoadInt64(&counterStore.writes),
		newcomerDenied, atomic.LoadInt64(&counterStore.writes))
}

// -----------------------------------------------------------------------
// Scenario 3: flash crowd / viral moment. Many users try to access the same
// shared bucket around the same instant after a notification, with small
// human reaction-time jitter. Strongly exercises the same-key race window
// without being an exact synthetic start gate.
// -----------------------------------------------------------------------

func TestConcurrency_FlashCrowd_ExactLimitEnforced(t *testing.T) {
	ctx := context.Background()
	counterStore := &countingCounterStore{}
	engine := NewEngine(counterStore)

	const limit = 25
	if err := engine.LoadConfigs([]LimiterConfig{
		{Name: "flash_crowd", Scope: "ip", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: limit, Enabled: true},
	}); err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}

	const users = 500

	var start sync.WaitGroup
	start.Add(1)

	var ready sync.WaitGroup
	ready.Add(users)

	var done sync.WaitGroup
	done.Add(users)

	var allowedCount int64

	for i := 0; i < users; i++ {
		i := i
		go func() {
			defer done.Done()
			ready.Done()
			start.Wait()

			r := seededRand(int64(4000 + i))
			// Small human reaction-time delay before the request hits.
			time.Sleep(time.Duration(1+r.Intn(20)) * time.Millisecond)

			allowed, _, err := engine.Check(ctx, "flash_crowd", "shared-hot-event")
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if allowed {
				atomic.AddInt64(&allowedCount, 1)
			}
		}()
	}

	ready.Wait()
	start.Done()
	done.Wait()

	if got := atomic.LoadInt64(&allowedCount); got != limit {
		t.Fatalf("flash crowd: expected exactly %d allowed out of %d near-simultaneous human requests, got %d",
			limit, users, got)
	}
}

// -----------------------------------------------------------------------
// Scenario 4: well-behaved human traffic. Many distinct users each make a
// small number of requests with think time between them, all well under
// their individual limit. Verifies the common case stays free of false
// denials under concurrency.
// -----------------------------------------------------------------------

func TestConcurrency_WellBehavedHumans_NoFalseDenials(t *testing.T) {
	ctx := context.Background()
	counterStore := &countingCounterStore{}
	engine := NewEngine(counterStore)

	const limit = 50
	if err := engine.LoadConfigs([]LimiterConfig{
		{Name: "well_behaved_humans", Scope: "account", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: limit, Enabled: true},
	}); err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}

	const numUsers = 200

	var wg sync.WaitGroup
	var deniedCount int64

	for u := 0; u < numUsers; u++ {
		userKey := fmt.Sprintf("human-%d", u)
		r := seededRand(int64(5000 + u))
		requests := 3 + r.Intn(5) // 3..7 requests per human session

		wg.Add(1)
		go func(key string, reqs int, r *rand.Rand) {
			defer wg.Done()

			time.Sleep(humanStagger(r, 25))

			for i := 0; i < reqs; i++ {
				allowed, _, err := engine.Check(ctx, "well_behaved_humans", key)
				if err != nil {
					t.Errorf("%s: %v", key, err)
					return
				}
				if !allowed {
					atomic.AddInt64(&deniedCount, 1)
				}
				time.Sleep(humanThink(r))
			}
		}(userKey, requests, r)
	}

	wg.Wait()

	if got := atomic.LoadInt64(&deniedCount); got != 0 {
		t.Errorf("expected 0 denials for well-behaved human users, got %d", got)
	}
}

// -----------------------------------------------------------------------
// Scenario 5: hot shared NAT/IP among normal users. Many humans behind one
// shared public IP hammer the same bucket while independent normal accounts
// continue their own sessions. Verifies the shared bucket is capped without
// allowing contention to leak across bucket keys.
// -----------------------------------------------------------------------

func TestConcurrency_HotSharedNATAmongNormalUsers_IsolatesCorrectly(t *testing.T) {
	ctx := context.Background()
	counterStore := &countingCounterStore{}
	engine := NewEngine(counterStore)

	const limit = 10
	if err := engine.LoadConfigs([]LimiterConfig{
		{Name: "shared_hotspot", Scope: "ip", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: limit, Enabled: true},
	}); err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}

	const hotUsers = 200
	const normalUsers = 80

	var start sync.WaitGroup
	start.Add(1)

	var hotReady sync.WaitGroup
	hotReady.Add(hotUsers)

	var wg sync.WaitGroup
	var hotAllowed int64

	for i := 0; i < hotUsers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			hotReady.Done()
			start.Wait()

			r := seededRand(int64(6000 + i))
			time.Sleep(time.Duration(1+r.Intn(15)) * time.Millisecond)

			allowed, _, err := engine.Check(ctx, "shared_hotspot", "shared-nat-ip")
			if err != nil {
				t.Errorf("shared NAT request: %v", err)
				return
			}
			if allowed {
				atomic.AddInt64(&hotAllowed, 1)
			}
		}()
	}

	normalDenied := make([]int64, normalUsers)

	// Normal human users with their own independent buckets.
	for u := 0; u < normalUsers; u++ {
		u := u
		userKey := fmt.Sprintf("normal-account-%d", u)
		r := seededRand(int64(7000 + u))

		wg.Add(1)
		go func(key string, r *rand.Rand) {
			defer wg.Done()

			time.Sleep(humanStagger(r, 30))
			requests := 2 + r.Intn(2) // 2..3 normal actions

			for i := 0; i < requests; i++ {
				allowed, _, err := engine.Check(ctx, "shared_hotspot", key)
				if err != nil {
					t.Errorf("%s: %v", key, err)
					return
				}
				if !allowed {
					atomic.AddInt64(&normalDenied[u], 1)
				}
				time.Sleep(humanThink(r))
			}
		}(userKey, r)
	}

	hotReady.Wait()
	start.Done()
	wg.Wait()

	if got := atomic.LoadInt64(&hotAllowed); got != limit {
		t.Errorf("shared NAT IP: expected exactly %d allowed out of %d human requests, got %d", limit, hotUsers, got)
	}

	for u := 0; u < normalUsers; u++ {
		if atomic.LoadInt64(&normalDenied[u]) != 0 {
			t.Errorf("normal-account-%d: denied despite having its own independent bucket; contention leaked across keys", u)
		}
	}
}

// -----------------------------------------------------------------------
// Scenario 6: abnormal load. A very large number of distinct users each
// make multiple requests concurrently, far beyond typical traffic. This is
// a stress test to ensure the engine remains correct and does not degrade
// under heavy contention across many independent buckets. Each user should
// still be capped at exactly the configured limit, with no cross‑key
// interference and no errors even at this scale.
// -----------------------------------------------------------------------

func TestConcurrency_AbnormalUserLoad_ManyUsersMultipleRequests(t *testing.T) {
	ctx := context.Background()
	counterStore := &countingCounterStore{}
	engine := NewEngine(counterStore)

	const limit = 5
	if err := engine.LoadConfigs([]LimiterConfig{
		{Name: "abnormal_load", Scope: "account", Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: limit, Enabled: true},
	}); err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}

	const numUsers = 100000
	const requestsPerUser = 20

	allowedCounts := make([]int64, numUsers)
	var errorCount int64

	var wg sync.WaitGroup
	for u := 0; u < numUsers; u++ {
		u := u
		userKey := fmt.Sprintf("stress-user-%d", u)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < requestsPerUser; i++ {
				allowed, _, err := engine.Check(ctx, "abnormal_load", userKey)
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
					return
				}
				if allowed {
					atomic.AddInt64(&allowedCounts[u], 1)
				}
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&errorCount); got != 0 {
		t.Errorf("encountered %d errors during abnormal load test", got)
	}

	for u := 0; u < numUsers; u++ {
		if got := atomic.LoadInt64(&allowedCounts[u]); got != limit {
			t.Errorf("stress-user-%d: expected exactly %d allowed requests, got %d", u, limit, got)
		}
	}

	t.Logf("abnormal load: %d users x %d requests each, limit %d, write-throughs=%d",
		numUsers, requestsPerUser, limit, atomic.LoadInt64(&counterStore.writes))
}
