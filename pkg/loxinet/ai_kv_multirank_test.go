// SPDX-License-Identifier: Apache 2.0
// Copyright (c) 2026 NetLOX Inc

// ai_kv_multirank_test.go — multi-DP-rank subscriber tests
// (SGL-03).
//
// Covers the event-source half of SGL-03 landed :
//
//   - Multi-rank union merge: N rank goroutines feed ONE shared per-EP
//     inventory; disjoint BlockStored sets union with no sawtooth under
// interleaved publish (warning sign).
// - gap-with-no-replay: a seq gap with replay==nil is no longer
//     silently ignored — kvResyncDecision runs (small resume ⇒ KEEP, large
//     forward jump ⇒ ClearAll) with the structured decision= marker the
// CICD scenario anchors on.
//   - Rank-isolated resync: a rank reconnect KEEPs/CLEARs on ITS OWN seq
//     state — another rank's interleaved stream can never poison the
//     decision.
//   - Teardown-clean: KvSubscriberStopAll after a 3-rank start exits every
//     rank goroutine and empties the registry; KvSubscriberStop(epIdx)
//     cancels ALL rank entries of that EP only.
//   - AllBlocksCleared union semantics: a Cleared event from ANY rank clears
//     the WHOLE shared EP inventory with the structured rank-naming marker
//     (Open Q3 over-clear tradeoff).
//
// NOTE: pkg/loxinet is a CGO package — these tests are AUTHORED here
// and validated on a remote GPU testbed via the
// kv_ssh spine:
//
//	go test ./pkg/loxinet/ -run 'TestKvMultiRank|TestKvReconnect|TestKvResync|TestKvSingleRole' -count=1
//
// darwin-local verification is structural only (gofmt + grep).
//
// The scripted-double machinery (recvStep/kvFrames/kvBlockStoredBatch/
// kvBlockRemovedBatch/errTestRecvDone/seedLoopService) is EXTENDED from
// ai_kv_reconnect_resync_test.go — that file stays byte-identical.
// chanKvSub adds the channel-driven double the interleave cases need: the
// script-walking fakeKvSub cannot coordinate ordering ACROSS concurrent rank
// loops, while a channel feed lets the test enforce a deterministic
// cross-rank interleave and wait for each message's effect before the next.

package loxinet

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
)

// ---------- wire-frame helper (extends the reconnect-test builders) ----------

// kvAllClearedBatch encodes a KVEventBatch carrying one AllBlocksCleared event:
//
//	[ts: float, events: [["AllBlocksCleared"]], dp_rank: nil]
func kvAllClearedBatch(t *testing.T) []byte {
	t.Helper()
	return kvMsgpackBatch(t, []interface{}{"AllBlocksCleared"})
}

// kvMsgpackBatch marshals one event array into the 3-field KVEventBatch shape.
func kvMsgpackBatch(t *testing.T, event []interface{}) []byte {
	t.Helper()
	batch := []interface{}{
		0.0,
		[]interface{}{event},
		nil,
	}
	b, err := msgpack.Marshal(batch)
	if err != nil {
		t.Fatalf("msgpack marshal batch: %v", err)
	}
	return b
}

// ---------- channel-driven KvEventSource double ----------

// chanKvSub is a channel-fed KvEventSource: RecvMultipart blocks on the feed
// channel (or ctx cancel), so a test can interleave messages ACROSS concurrent
// rank loops deterministically — feed one step, wait for its observable effect
// on the shared inventory, then feed the next (possibly to another rank).
// Connect always succeeds and counts invocations (rebuild proof), matching the
// fakeKvSub contract.
type chanKvSub struct {
	ctx      context.Context
	ch       chan recvStep
	connects atomic.Int32
}

func newChanKvSub(ctx context.Context) *chanKvSub {
	return &chanKvSub{ctx: ctx, ch: make(chan recvStep)}
}

func (c *chanKvSub) Connect(string) error {
	c.connects.Add(1)
	return nil
}

func (c *chanKvSub) Close() error { return nil }

func (c *chanKvSub) RecvMultipart() ([][]byte, error) {
	select {
	case <-c.ctx.Done():
		// Unblock on teardown: the loop's error path honors ctx.Done and exits.
		return nil, errTestRecvDone
	case step := <-c.ch:
		if step.err != nil {
			return nil, step.err
		}
		return step.frames, nil
	}
}

// feed delivers one step to the loop, failing the test if the loop never
// consumes it (wedge guard).
func (c *chanKvSub) feed(t *testing.T, step recvStep) {
	t.Helper()
	select {
	case c.ch <- step:
	case <-time.After(10 * time.Second):
		t.Fatalf("chanKvSub.feed: rank loop did not consume the step within timeout")
	}
}

// startRankLoop launches runKvSubscriberLoopRank for one (epIdx, rank) and
// returns its done channel (closed when the goroutine exits — the leak-free
// teardown observable).
func startRankLoop(ctx context.Context, svc *kvServiceState, epIdx int, rank uint16, sub KvEventSource) chan struct{} {
	done := make(chan struct{})
	go func() {
		// replay=nil mirrors production (: no replay client).
		runKvSubscriberLoopRank(ctx, epIdx, rank, svc, sub, nil, "inproc://multirank")
		close(done)
	}()
	return done
}

// kvWaitFor polls cond until true or fails the test after a bounded wait —
// the effect-synchronization primitive between feed steps.
func kvWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// ---------- structured-marker capture (logrus hook) ----------

// kvLogCapture records log messages so the tests can assert the EXACT
// structured markers CICD scenario greps (decision=KEEP|CLEAR,
// "clearing shared inventory") — the TK7 anti-pattern fix demands the marker
// itself be pinned, not just the inventory side effect.
type kvLogCapture struct {
	mu      sync.Mutex
	entries []string
}

func (c *kvLogCapture) Levels() []log.Level { return log.AllLevels }

func (c *kvLogCapture) Fire(e *log.Entry) error {
	c.mu.Lock()
	c.entries = append(c.entries, e.Message)
	c.mu.Unlock()
	return nil
}

func (c *kvLogCapture) contains(sub string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.entries {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// installKvLogCapture adds a capture hook on the global logrus logger and
// returns (capture, restore). restore reinstates the prior hook set — logrus
// has no RemoveHook, so it rebuilds the level→hooks map without ours and swaps
// it in atomically via ReplaceHooks (which locks internally).
func installKvLogCapture() (*kvLogCapture, func()) {
	std := log.StandardLogger()
	capt := &kvLogCapture{}
	std.AddHook(capt)
	return capt, func() {
		old := std.ReplaceHooks(make(log.LevelHooks))
		kept := make(log.LevelHooks)
		for lvl, hooks := range old {
			for _, h := range hooks {
				if h != log.Hook(capt) {
					kept[lvl] = append(kept[lvl], h)
				}
			}
		}
		std.ReplaceHooks(kept)
	}
}

// ---------- 1. multi-rank union merge (ROADMAP criterion 3) ----------

// TestKvMultiRankUnionMerge drives 3 concurrent rank loops (ranks 0/1/2 of ONE
// EP) publishing disjoint BlockStored sets in a deterministic cross-rank
// interleave. The shared inventory must converge to the exact union with NO
// sawtooth (size never decreases — a decrease means rank interleave triggered
// a spurious CLEAR, warning sign). Each rank runs its own seq
// space (widely separated bases) — per-rank seq state must make the bases
// invisible to one another.
func TestKvMultiRankUnionMerge(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	const (
		serviceID = uint32(990501)
		epIdx     = 0
		nRanks    = 3
		nRounds   = 3
	)
	svc := seedLoopService(t, serviceID, epIdx, nil, -1)
	inv := KvGetInventory(serviceID, epIdx)
	if inv == nil {
		t.Fatalf("KvGetInventory(%d, %d) returned nil", serviceID, epIdx)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Per-rank seq bases: widely separated so a SHARED seq detector would see
	// every cross-rank hop as a huge forward gap (or a backwards reset) and
	// CLEAR — the regression this test has teeth against.
	seqBase := []int64{10, 100_000, 9_000_000}

	subs := make([]*chanKvSub, nRanks)
	dones := make([]chan struct{}, nRanks)
	for rank := 0; rank < nRanks; rank++ {
		subs[rank] = newChanKvSub(ctx)
		dones[rank] = startRankLoop(ctx, svc, epIdx, uint16(rank), subs[rank])
	}

	var allHashes []uint64
	prevSize := 0
	// Interleave: round-robin across ranks, one message each per round, and
	// wait for every message's blocks to land before feeding the next rank.
	for round := 0; round < nRounds; round++ {
		for rank := 0; rank < nRanks; rank++ {
			h0 := uint64(0x9905_0000 + rank*0x100 + round*2)
			hashes := []uint64{h0, h0 + 1} // disjoint across (rank, round)
			allHashes = append(allHashes, hashes...)
			seq := seqBase[rank] + int64(round)
			subs[rank].feed(t, recvStep{frames: kvFrames(seq, kvBlockStoredBatch(t, hashes))})
			kvWaitFor(t, "blocks from rank/round to land", func() bool {
				return inv.MatchCount(hashes) == len(hashes)
			})
			size := inv.Size()
			if size < prevSize {
				t.Fatalf("sawtooth: inventory size decreased %d -> %d after rank %d round %d (spurious CLEAR under rank interleave —)",
					prevSize, size, rank, round)
			}
			prevSize = size
		}
	}

	// Union: every block from every rank present, size exactly the union.
	if mc := inv.MatchCount(allHashes); mc != len(allHashes) {
		t.Errorf("union merge: MatchCount(all)=%d, want %d (some rank's blocks were dropped)", mc, len(allHashes))
	}
	if got, want := inv.Size(), len(allHashes); got != want {
		t.Errorf("union merge: Size()=%d, want %d (disjoint sets must union exactly)", got, want)
	}

	cancel()
	for rank, done := range dones {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("rank %d loop did not exit after cancel", rank)
		}
	}
}

// ---------- 2. seq-gap invalidation (gap with replay==nil) ----------

// TestKvMultiRankSeqGapInvalidation pins fix: a seq gap
// on the live stream with NO replay client must run the conservative
// KEEP/CLEAR decision instead of falling through silently.
//   - large forward jump (> kvSeqResumeWindow) ⇒ ClearAll + decision=CLEAR
//
// marker (phantom-hash purge)
//   - small resume (within the window) ⇒ KEEP, inventory intact +
//     decision=KEEP marker
//
// Runs on rank 1 to prove path is rank-agnostic (not a rank-0-only
// back-compat artifact).
func TestKvMultiRankSeqGapInvalidation(t *testing.T) {
	const (
		serviceID = uint32(990502)
		epIdx     = 0
		rank      = uint16(1)
	)
	warm := []uint64{0xE1, 0xE2}  // landed before the gap
	fresh := []uint64{0xF1, 0xF2} // carried by the gap message itself

	cases := []struct {
		name       string
		firstSeq   int64 // seq of the warm message
		gapSeq     int64 // seq of the post-gap message
		wantSize   int
		wantMarker string
		wantWarm   int // MatchCount(warm) after the gap message
	}{
		{
			name:       "large_jump_CLEAR",
			firstSeq:   10,
			gapSeq:     10 + kvSeqResumeWindow + 5, // beyond the resume window ⇒ CLEAR
			wantSize:   len(fresh),
			wantMarker: "decision=CLEAR",
			wantWarm:   0,
		},
		{
			name:       "small_resume_KEEP",
			firstSeq:   10,
			gapSeq:     13, // gap of 2, within the window ⇒ KEEP
			wantSize:   len(warm) + len(fresh),
			wantMarker: "decision=KEEP",
			wantWarm:   len(warm),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			KvResetAll()
			defer KvResetAll()
			capture, restore := installKvLogCapture()
			defer restore()

			svc := seedLoopService(t, serviceID, epIdx, nil, -1)
			inv := KvGetInventory(serviceID, epIdx)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sub := newChanKvSub(ctx)
			done := startRankLoop(ctx, svc, epIdx, rank, sub)

			sub.feed(t, recvStep{frames: kvFrames(tc.firstSeq, kvBlockStoredBatch(t, warm))})
			kvWaitFor(t, "warm blocks to land", func() bool { return inv.MatchCount(warm) == len(warm) })

			sub.feed(t, recvStep{frames: kvFrames(tc.gapSeq, kvBlockStoredBatch(t, fresh))})
			kvWaitFor(t, "fresh blocks to land after the gap", func() bool {
				return inv.MatchCount(fresh) == len(fresh)
			})

			if got := inv.Size(); got != tc.wantSize {
				t.Errorf("after gap message: Size()=%d, want %d", got, tc.wantSize)
			}
			if mc := inv.MatchCount(warm); mc != tc.wantWarm {
				t.Errorf("after gap message: MatchCount(warm)=%d, want %d", mc, tc.wantWarm)
			}
			// The structured marker is CICD anchor — pin it exactly
			// (TK7: never a bare word; decision= is the field shape).
			kvWaitFor(t, "structured gap marker "+tc.wantMarker, func() bool {
				return capture.contains(tc.wantMarker)
			})

			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("rank loop did not exit after cancel")
			}
		})
	}
}

// ---------- 3. rank-isolated resync ----------

// TestKvMultiRankIsolatedResync interleaves a steady rank-0 publisher (high
// seq base) with a rank-1 blip+reconnect (low seq base). Rank 1's post-
// reconnect KEEP decision must key on rank 1's OWN lastSeq — under a shared
// seq detector, rank 0's interleaved high seq would make rank 1's resume look
// like a backwards reset and CLEAR the shared inventory (the spurious-clear
// regression this test has teeth against).
func TestKvMultiRankIsolatedResync(t *testing.T) {
	KvResetAll()
	defer KvResetAll()
	capture, restore := installKvLogCapture()
	defer restore()

	const (
		serviceID = uint32(990503)
		epIdx     = 0
	)
	a1 := []uint64{0xA11}
	a2 := []uint64{0xA22}
	y1 := []uint64{0xB11}
	y2 := []uint64{0xB22}

	svc := seedLoopService(t, serviceID, epIdx, nil, -1)
	inv := KvGetInventory(serviceID, epIdx)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub0 := newChanKvSub(ctx)
	sub1 := newChanKvSub(ctx)
	done0 := startRankLoop(ctx, svc, epIdx, 0, sub0)
	done1 := startRankLoop(ctx, svc, epIdx, 1, sub1)

	// rank 0 steady at a HIGH seq base…
	sub0.feed(t, recvStep{frames: kvFrames(1000, kvBlockStoredBatch(t, a1))})
	kvWaitFor(t, "rank0 a1", func() bool { return inv.MatchCount(a1) == 1 })
	// …rank 1 establishes its OWN low seq space…
	sub1.feed(t, recvStep{frames: kvFrames(50, kvBlockStoredBatch(t, y1))})
	kvWaitFor(t, "rank1 y1", func() bool { return inv.MatchCount(y1) == 1 })
	// …rank 0 keeps publishing between rank 1's messages (the interleave)…
	sub0.feed(t, recvStep{frames: kvFrames(1001, kvBlockStoredBatch(t, a2))})
	kvWaitFor(t, "rank0 a2", func() bool { return inv.MatchCount(a2) == 1 })
	// …rank 1 blips (recv error ⇒ rebuild ⇒ resyncPending)…
	sub1.feed(t, recvStep{err: errTestRecvDone})
	kvWaitFor(t, "rank1 rebuild (Connect)", func() bool { return sub1.connects.Load() >= 1 })
	// …and resumes at ITS OWN next seq ⇒ KEEP on rank-1 state.
	sub1.feed(t, recvStep{frames: kvFrames(51, kvBlockStoredBatch(t, y2))})
	kvWaitFor(t, "rank1 y2 after resync", func() bool { return inv.MatchCount(y2) == 1 })

	// No spurious clear: EVERYTHING from both ranks survives.
	all := []uint64{a1[0], a2[0], y1[0], y2[0]}
	if mc := inv.MatchCount(all); mc != len(all) {
		t.Errorf("rank interleave caused a spurious clear: MatchCount(all)=%d, want %d", mc, len(all))
	}
	if !capture.contains("rank 1 resync KEEP") {
		t.Errorf("rank 1 resync decision did not KEEP on its own seq state (marker 'rank 1 resync KEEP' absent)")
	}

	cancel()
	for i, done := range []chan struct{}{done0, done1} {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("rank %d loop did not exit after cancel", i)
		}
	}
}

// ---------- 4. teardown-clean (criterion 3) ----------

// TestKvMultiRankTeardownClean starts 3 REAL rank loops for one EP with their
// cancels registered under composite (epIdx, rank) keys, then proves
// KvSubscriberStopAll exits every rank goroutine (done channels close) and
// empties the registry. The per-EP KvSubscriberStop selectivity over the
// composite keys is pinned in a registry-seeded subtest (shape).
func TestKvMultiRankTeardownClean(t *testing.T) {
	t.Run("stopall_exits_all_rank_goroutines", func(t *testing.T) {
		KvResetAll()
		defer KvResetAll()

		const (
			serviceID = uint32(990504)
			epIdx     = 0
			nRanks    = 3
		)
		svc := newKvServiceState(serviceID)
		svc.algo = "sha256_cbor"
		svc.inventories[epIdx] = newKvInventory()
		kvServicesMu.Lock()
		kvServices[serviceID] = svc
		kvServicesMu.Unlock()

		dones := make([]chan struct{}, nRanks)
		for rank := 0; rank < nRanks; rank++ {
			ctx, cancel := context.WithCancel(context.Background())
			svc.mu.Lock()
			svc.cancelFns[kvEpRankKey{epIdx: epIdx, rank: uint16(rank)}] = cancel
			svc.mu.Unlock()
			dones[rank] = startRankLoop(ctx, svc, epIdx, uint16(rank), newChanKvSub(ctx))
		}
		// Registry before: 3 composite entries for the single EP.
		svc.mu.RLock()
		nBefore := len(svc.cancelFns)
		svc.mu.RUnlock()
		if nBefore != nRanks {
			t.Fatalf("before StopAll: %d cancelFns entries, want %d (one per rank)", nBefore, nRanks)
		}

		KvSubscriberStopAll(serviceID)

		// Every rank goroutine must EXIT (zero leaked goroutines —).
		for rank, done := range dones {
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatalf("rank %d goroutine leaked: still running after KvSubscriberStopAll", rank)
			}
		}
		// Registry after: service gone, detached state emptied.
		kvServicesMu.RLock()
		_, still := kvServices[serviceID]
		kvServicesMu.RUnlock()
		if still {
			t.Fatalf("service %d still present in kvServices registry after StopAll", serviceID)
		}
		svc.mu.RLock()
		nAfter := len(svc.cancelFns)
		svc.mu.RUnlock()
		if nAfter != 0 {
			t.Fatalf("after StopAll: %d cancelFns entries left, want 0", nAfter)
		}
	})

	t.Run("per_ep_stop_cancels_all_ranks_of_that_ep_only", func(t *testing.T) {
		KvResetAll()
		defer KvResetAll()

		const serviceID = uint32(990505)
		svc := newKvServiceState(serviceID)
		svc.algo = "sha256_cbor"
		cancelled := make(map[kvEpRankKey]int)
		var mu sync.Mutex
		seed := func(ep int, rank uint16) {
			key := kvEpRankKey{epIdx: ep, rank: rank}
			svc.cancelFns[key] = func() {
				mu.Lock()
				cancelled[key]++
				mu.Unlock()
			}
		}
		svc.inventories[0] = newKvInventory()
		svc.inventories[1] = newKvInventory()
		seed(0, 0)
		seed(0, 1)
		seed(0, 2)
		seed(1, 0)
		kvServicesMu.Lock()
		kvServices[serviceID] = svc
		kvServicesMu.Unlock()

		KvSubscriberStop(serviceID, 0)

		mu.Lock()
		defer mu.Unlock()
		for rank := uint16(0); rank < 3; rank++ {
			if n := cancelled[kvEpRankKey{epIdx: 0, rank: rank}]; n != 1 {
				t.Errorf("ep0 rank %d cancel invoked %d times, want exactly 1", rank, n)
			}
		}
		if n := cancelled[kvEpRankKey{epIdx: 1, rank: 0}]; n != 0 {
			t.Errorf("ep1 rank 0 cancel invoked %d times, want 0 (per-EP stop must not touch other EPs)", n)
		}
		svc.mu.RLock()
		defer svc.mu.RUnlock()
		if _, ok := svc.cancelFns[kvEpRankKey{epIdx: 1, rank: 0}]; !ok {
			t.Errorf("ep1 rank 0 entry removed by KvSubscriberStop(ep0)")
		}
		if len(svc.cancelFns) != 1 {
			t.Errorf("after Stop(ep0): %d cancelFns entries, want 1 (only ep1 rank0)", len(svc.cancelFns))
		}
		if _, ok := svc.inventories[0]; ok {
			t.Errorf("ep0 inventory still present after KvSubscriberStop")
		}
	})
}

// ---------- 5. AllBlocksCleared union semantics (Open Q3) ----------

// TestKvMultiRankAllBlocksClearedUnion pins the Open-Q3 resolution: an
// AllBlocksCleared from ANY rank clears the WHOLE shared EP inventory
// (over-clear — safe, loses warmth) and logs the structured marker naming the
// clearing rank ("clearing shared inventory" — CICD anchor).
func TestKvMultiRankAllBlocksClearedUnion(t *testing.T) {
	KvResetAll()
	defer KvResetAll()
	capture, restore := installKvLogCapture()
	defer restore()

	const (
		serviceID = uint32(990506)
		epIdx     = 0
		rank      = uint16(2)
	)
	// Blocks "owned" by other ranks, pre-seeded into the shared inventory.
	otherRanks := []uint64{0xAA1, 0xAA2, 0xAA3}
	svc := seedLoopService(t, serviceID, epIdx, otherRanks, -1)
	inv := KvGetInventory(serviceID, epIdx)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub := newChanKvSub(ctx)
	done := startRankLoop(ctx, svc, epIdx, rank, sub)

	// Rank 2 stores one block, then publishes AllBlocksCleared.
	sub.feed(t, recvStep{frames: kvFrames(5, kvBlockStoredBatch(t, []uint64{0xBB1}))})
	kvWaitFor(t, "rank2 block to land", func() bool { return inv.MatchCount([]uint64{0xBB1}) == 1 })
	sub.feed(t, recvStep{frames: kvFrames(6, kvAllClearedBatch(t))})
	kvWaitFor(t, "whole inventory cleared", func() bool { return inv.Size() == 0 })

	// The WHOLE union is gone — including the other ranks' blocks (over-clear).
	if mc := inv.MatchCount(otherRanks); mc != 0 {
		t.Errorf("AllBlocksCleared from rank 2 left other ranks' blocks: MatchCount=%d, want 0 (union clear, Open Q3)", mc)
	}
	// Structured marker names the clearing rank (anchor).
	kvWaitFor(t, "AllBlocksCleared shared-inventory marker", func() bool {
		return capture.contains("(rank 2) — clearing shared inventory")
	})

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("rank loop did not exit after cancel")
	}
}
