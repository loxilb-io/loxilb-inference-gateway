package loxinet

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
)

// TestSetKvConnectedIfLiveHonorsCancel pins the guard itself: a write on a live
// ctx lands, a write on a cancelled ctx is dropped. The cancelled case is the
// whole point — teardown has already called ClearKvEpSeries by then, so a write
// would resurrect the deleted child as a permanent ghost.
func TestSetKvConnectedIfLiveHonorsCancel(t *testing.T) {
	const svc = "990301"

	prom.ClearKvEpSeries(svc, "0")
	t.Cleanup(func() { prom.ClearKvEpSeries(svc, "0") })

	live, cancel := context.WithCancel(context.Background())
	setKvConnectedIfLive(live, svc, "0", 1)
	if got := prom.KvSubscriberSeriesCount(svc); got != 1 {
		t.Fatalf("live ctx: %d series for service %s, want 1 (the write must land)", got, svc)
	}

	// Teardown order: cancel, then the series is deleted, then the goroutine's
	// deferred write fires. That last write must be a no-op.
	cancel()
	prom.ClearKvEpSeries(svc, "0")
	setKvConnectedIfLive(live, svc, "0", 0)
	if got := prom.KvSubscriberSeriesCount(svc); got != 0 {
		t.Fatalf("cancelled ctx: %d series for service %s survived teardown, want 0 "+
			"(a resurrected connected=0 child reds out the KV subscribers panel forever)", got, svc)
	}
}

// TestKvSubscriberTeardownLeavesNoSeries reproduces the production teardown
// order under contention: N subscriber goroutines each writing the liveness
// gauge in a tight loop while KvSubscriberStopAll cancels them and reaps the
// series. Before the guard this leaked on essentially every run (measured 15/15
// on the live testbed); with it, zero children may remain.
//
// Run with -race -count=50 to actually exercise the interleaving.
func TestKvSubscriberTeardownLeavesNoSeries(t *testing.T) {
	const serviceID uint32 = 990302
	const nEps = 4
	svcLabel := fmt.Sprintf("%d", serviceID)

	svc := newKvServiceState(serviceID)
	svc.algo = "sha256_cbor"

	// Leak hygiene: EVERY exit path (including a t.Fatalf before StopAll) must
	// cancel the writers and wait them out, or they outlive the iteration with
	// LIVE contexts and legitimately resurrect the cleared series — which then
	// fails every later -count iteration with "N survived" (a cascade first
	// seen under -race, where the slower warm-up tripped the vacuous-guard
	// Fatalf and orphaned that iteration's writers).
	var wg sync.WaitGroup
	var cancels []context.CancelFunc
	t.Cleanup(func() {
		for _, c := range cancels {
			c()
		}
		wg.Wait()
	})

	for ep := 0; ep < nEps; ep++ {
		epIdx := ep
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		svc.inventories[epIdx] = newKvInventory()
		svc.cancelFns[kvEpRankKey{epIdx: epIdx, rank: 0}] = cancel

		epLabel := fmt.Sprintf("%d", epIdx)
		// Stand-in for runKvSubscriberLoopRank: mark connected, churn the gauge
		// AND the reconnect/recv-error counters the way a reconnecting
		// subscriber does, and zero the gauge on exit. The counters share the
		// same resurrect-after-delete hazard as the gauge, so they must churn
		// here too or the test would under-constrain the fix.
		wg.Add(1)
		go func() {
			defer wg.Done()
			setKvConnectedIfLive(ctx, svcLabel, epLabel, 1)
			defer setKvConnectedIfLive(ctx, svcLabel, epLabel, 0)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				setKvConnectedIfLive(ctx, svcLabel, epLabel, 1)
				incKvReconnectIfLive(ctx, svcLabel, epLabel)
				incKvRecvErrorIfLive(ctx, svcLabel, epLabel)
			}
		}()
	}

	kvServicesMu.Lock()
	kvServices[serviceID] = svc
	kvServicesMu.Unlock()
	t.Cleanup(func() {
		kvServicesMu.Lock()
		delete(kvServices, serviceID)
		kvServicesMu.Unlock()
		for ep := 0; ep < nEps; ep++ {
			prom.ClearKvEpSeries(svcLabel, fmt.Sprintf("%d", ep))
		}
	})

	// Let the writers get going so the teardown genuinely races them. Poll
	// rather than a fixed sleep: under -race, goroutine startup is slow enough
	// that a 5ms sleep intermittently saw only 3/4 writers up.
	deadline := time.Now().Add(2 * time.Second)
	for prom.KvSubscriberSeriesCount(svcLabel) != nEps && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := prom.KvSubscriberSeriesCount(svcLabel); got != nEps {
		t.Fatalf("pre-teardown: %d series, want %d — writers never started, test would pass vacuously", got, nEps)
	}

	KvSubscriberStopAll(serviceID)
	wg.Wait()

	// Every writer has now exited, including its deferred write. Nothing may
	// have come back.
	if got := prom.KvSubscriberSeriesCount(svcLabel); got != 0 {
		t.Fatalf("post-teardown: %d kv_subscriber_connected series for service %s survived, want 0", got, svcLabel)
	}
	if got := prom.KvEpCounterSeriesCount(svcLabel); got != 0 {
		t.Fatalf("post-teardown: %d reconnect/recv-error counter series for service %s survived, want 0 "+
			"(unguarded Inc() after ClearKvEpSeries resurrects the child)", got, svcLabel)
	}
}
