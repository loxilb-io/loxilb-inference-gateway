/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// ai_kv_reconnect_resync_test.go — reconnect/resync tests.
//
// Covers seq-reset KEEP/CLEAR resync that replaced the unconditional
// blind ClearAll on every reconnect (ai_kv_subscriber.go rebuildKvSubscriber +
// runKvSubscriberLoop). Two layers:
//
//   - TestKvResyncDecision: direct, exhaustive table over the factored decision
//     helper kvResyncDecision(seq, lastSeq) — the load-bearing branch logic.
//   - TestKvReconnectSeqReset / TestKvReconnectKeepConverge: integration-style
//     drives of the FULL runKvSubscriberLoop through a fake kvZmqSubscriber that
//     first errors (to trigger the rebuild) and then delivers a scripted first
//     post-reconnect message, asserting KvGetInventory Size after the decision.
//
// (no engine_id on the wire) is asserted by the structure here PLUS the
// Task-1 grep acceptance (grep -in engine_id matches only comments). There is no
// engine_id field to feed, so no test can parse one — the absence is the proof.
//
// runKvSubscriberLoop is driven
// with replay=nil exactly as production calls it; TestKvReconnectKeepConverge
// proves further BlockStored/BlockRemoved on the live stream converge the
// inventory with no replay client involved.
//
// Pure-Go, no CGO: builds frames and drives the loop in-process. No libzmq.

package loxinet

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// ---------- wire-frame helpers ----------

// kvBlockStoredBatch encodes a KVEventBatch carrying one BlockStored event with
// the given hashes, in the on-wire format decodeKVEventBatch expects:
//
//	[ts: float, events: [["BlockStored", [h0, h1, ...]]], dp_rank: nil]
func kvBlockStoredBatch(t *testing.T, hashes []uint64) []byte {
	t.Helper()
	ihashes := make([]interface{}, len(hashes))
	for i, h := range hashes {
		ihashes[i] = h
	}
	batch := []interface{}{
		0.0,
		[]interface{}{
			[]interface{}{"BlockStored", ihashes},
		},
		nil,
	}
	b, err := msgpack.Marshal(batch)
	if err != nil {
		t.Fatalf("msgpack marshal BlockStored batch: %v", err)
	}
	return b
}

// kvBlockRemovedBatch encodes a KVEventBatch carrying one BlockRemoved event.
func kvBlockRemovedBatch(t *testing.T, hashes []uint64) []byte {
	t.Helper()
	ihashes := make([]interface{}, len(hashes))
	for i, h := range hashes {
		ihashes[i] = h
	}
	batch := []interface{}{
		0.0,
		[]interface{}{
			[]interface{}{"BlockRemoved", ihashes},
		},
		nil,
	}
	b, err := msgpack.Marshal(batch)
	if err != nil {
		t.Fatalf("msgpack marshal BlockRemoved batch: %v", err)
	}
	return b
}

// kvFrames builds a 3-frame ZMQ multipart message: topic | 8-byte BE seq | payload.
func kvFrames(seq int64, payload []byte) [][]byte {
	seqFrame := make([]byte, 8)
	binary.BigEndian.PutUint64(seqFrame, uint64(seq))
	return [][]byte{[]byte("kv"), seqFrame, payload}
}

// ---------- fake kvZmqSubscriber ----------

// recvStep is one scripted RecvMultipart outcome. Exactly one of frames/err is
// meaningful: if err != nil the loop takes its recv-error/rebuild path; otherwise
// frames are delivered to the decode path. If cancel is true the step cancels the
// loop context (used on the terminal step so runKvSubscriberLoop exits cleanly).
type recvStep struct {
	frames [][]byte
	err    error
	cancel bool
}

// fakeKvSub is an in-process kvZmqSubscriber test double. RecvMultipart walks the
// scripted steps in order; Connect always succeeds (simulating a healthy
// reconnect). It records how many times Connect was called so tests can assert a
// rebuild actually happened.
type fakeKvSub struct {
	t        *testing.T
	steps    []recvStep
	idx      int
	cancel   context.CancelFunc
	connects int
}

func (f *fakeKvSub) Connect(string) error {
	f.connects++
	return nil
}

func (f *fakeKvSub) Close() error { return nil }

func (f *fakeKvSub) RecvMultipart() ([][]byte, error) {
	if f.idx >= len(f.steps) {
		// Script exhausted — cancel and return an error so the loop honors
		// ctx.Done on its error path and exits instead of spinning.
		if f.cancel != nil {
			f.cancel()
		}
		return nil, errTestRecvDone
	}
	step := f.steps[f.idx]
	f.idx++
	if step.cancel && f.cancel != nil {
		f.cancel()
	}
	if step.err != nil {
		return nil, step.err
	}
	return step.frames, nil
}

// errTestRecvDone is a sentinel recv error used to drive the rebuild path and to
// terminate the loop once the script is exhausted.
var errTestRecvDone = &testRecvErr{}

type testRecvErr struct{}

func (*testRecvErr) Error() string { return "test: recv done" }

// driveSubscriberLoop runs runKvSubscriberLoop against the fake until the script
// is exhausted (the fake cancels ctx). It returns once the loop exits, with a
// guard timeout so a logic bug cannot hang the suite.
func driveSubscriberLoop(t *testing.T, svc *kvServiceState, epIdx int, steps []recvStep) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := &fakeKvSub{t: t, steps: steps, cancel: cancel}

	done := make(chan struct{})
	// Resolved in the parent, as production does under svc.mu (#42).
	inv := svc.inventories[epIdx]
	serviceID := svc.serviceID
	go func() {
		// replay=nil mirrors the production call site exactly (: no replay client).
		runKvSubscriberLoop(ctx, epIdx, serviceID, inv, fake, nil, "inproc://test")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatal("runKvSubscriberLoop did not exit within timeout — possible wedge")
	}
	if fake.connects == 0 {
		t.Fatalf("expected at least one reconnect (Connect call) during the drive, got 0")
	}
}

// seedLoopService registers a kvServiceState with one inventory at epIdx,
// pre-seeded with hashes and with lastSeq stamped (so the post-reconnect
// kvResyncDecision has a baseline to compare against). Returns the service state.
func seedLoopService(t *testing.T, serviceID uint32, epIdx int, hashes []uint64, lastSeq int64) *kvServiceState {
	t.Helper()
	svc := newKvServiceState(serviceID)
	svc.algo = "sha256_cbor"
	inv := newKvInventory()
	svc.inventories[epIdx] = inv
	kvServicesMu.Lock()
	kvServices[serviceID] = svc
	kvServicesMu.Unlock()
	if len(hashes) > 0 {
		inv.AddBlocks(hashes)
	}
	inv.mu.Lock()
	inv.lastSeq = lastSeq
	inv.mu.Unlock()
	return svc
}

// ---------- TestKvResyncDecision (factored helper) ----------

func TestKvResyncDecision(t *testing.T) {
	cases := []struct {
		name    string
		seq     int64
		lastSeq int64
		keep    bool
	}{
		{"resume_exact", 100, 100, true},
		{"resume_within_window", 100 + kvSeqResumeWindow, 100, true},
		{"resume_small_forward", 105, 100, true},
		{"reset_to_zero", 0, 100, false},
		{"reset_to_low", 3, 100, false},
		{"seq_backwards", 99, 100, false},
		{"large_forward_jump", 100 + kvSeqResumeWindow + 1, 100, false},
		{"huge_forward_jump", 1_000_000, 100, false},
		{"no_prior_seq", 0, -1, false},
		{"no_prior_seq_high", 500, -1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := kvResyncDecision(tc.seq, tc.lastSeq)
			if got != tc.keep {
				t.Errorf("kvResyncDecision(seq=%d, lastSeq=%d) = %v (KEEP=%v), want KEEP=%v",
					tc.seq, tc.lastSeq, got, got, tc.keep)
			}
		})
	}
}

// ---------- TestKvReconnectSeqReset (integration) ----------

// TestKvReconnectSeqReset drives the full subscriber loop through a rebuild and a
// first post-reconnect message, asserting the warm inventory is KEPT or CLEARED
// per the seq-reset discriminator. The pre-blip inventory holds 3 warm hashes at
// lastSeq=100; the first post-reconnect message carries 2 new hashes.
func TestKvReconnectSeqReset(t *testing.T) {
	const (
		serviceID = uint32(7001)
		epIdx     = 0
		lastSeq   = int64(100)
	)
	warm := []uint64{0xA1, 0xA2, 0xA3} // 3 pre-blip blocks
	fresh := []uint64{0xB1, 0xB2}      // 2 blocks in the first post-reconnect message
	keepHashes := []uint64{0xA1, 0xB1} // a warm + a fresh hash, for MatchCount on KEEP

	cases := []struct {
		name     string
		firstSeq int64
		wantSize int // expected KvGetInventory Size after the first post-reconnect message
		wantKeep bool
	}{
		// KEEP: seq resumes near lastSeq → warm 3 survive + 2 fresh = 5.
		{"near_lastSeq_KEEP", lastSeq + 2, len(warm) + len(fresh), true},
		// CLEAR: seq reset to low → warm dropped, only the 2 fresh remain.
		{"low_seq_CLEAR", 1, len(fresh), false},
		// CLEAR: large forward jump → conservative clear, only the 2 fresh remain.
		{"large_jump_CLEAR", lastSeq + kvSeqResumeWindow + 50, len(fresh), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			KvResetAll()
			defer KvResetAll()

			svc := seedLoopService(t, serviceID, epIdx, warm, lastSeq)

			steps := []recvStep{
				// 1) recv error → triggers rebuild (Connect succeeds, lastSeq preserved).
				{err: errTestRecvDone},
				// 2) first post-reconnect message at the test seq, carrying fresh blocks.
				{frames: kvFrames(tc.firstSeq, kvBlockStoredBatch(t, fresh))},
				// 3) terminal step cancels ctx so the loop exits.
				{cancel: true},
			}
			driveSubscriberLoop(t, svc, epIdx, steps)

			inv := KvGetInventory(serviceID, epIdx)
			if inv == nil {
				t.Fatalf("KvGetInventory(%d, %d) returned nil", serviceID, epIdx)
			}
			if got := inv.Size(); got != tc.wantSize {
				t.Errorf("after first post-reconnect msg: Size()=%d, want %d (keep=%v)",
					got, tc.wantSize, tc.wantKeep)
			}
			if tc.wantKeep {
				// On KEEP, a warm hash AND a fresh hash must both be present.
				if mc := inv.MatchCount(keepHashes); mc != len(keepHashes) {
					t.Errorf("KEEP: MatchCount(warm+fresh)=%d, want %d (warm inventory should survive)",
						mc, len(keepHashes))
				}
			} else {
				// On CLEAR, none of the warm hashes survive; only fresh remain.
				if mc := inv.MatchCount(warm); mc != 0 {
					t.Errorf("CLEAR: MatchCount(warm)=%d, want 0 (stale inventory must be dropped)", mc)
				}
				if mc := inv.MatchCount(fresh); mc != len(fresh) {
					t.Errorf("CLEAR: MatchCount(fresh)=%d, want %d (this message's blocks applied after clear)",
						mc, len(fresh))
				}
			}
		})
	}
}

// ---------- TestKvReconnectKeepConverge (integration) ----------

// TestKvReconnectKeepConverge proves that after a KEEP decision the inventory
// continues to converge via the LIVE SUB stream (re-subscribe-and-converge) with
// no replay client: subsequent BlockStored/BlockRemoved on the stream mutate the
// inventory through the normal apply path (runKvSubscriberLoop drives replay=nil).
func TestKvReconnectKeepConverge(t *testing.T) {
	KvResetAll()
	defer KvResetAll()

	const (
		serviceID = uint32(7002)
		epIdx     = 0
		lastSeq   = int64(200)
	)
	warm := []uint64{0xC1, 0xC2, 0xC3} // 3 warm blocks survive the KEEP

	svc := seedLoopService(t, serviceID, epIdx, warm, lastSeq)

	steps := []recvStep{
		// 1) recv error → rebuild (lastSeq=200 preserved).
		{err: errTestRecvDone},
		// 2) first post-reconnect msg, seq just ahead of lastSeq → KEEP; adds 0xD1.
		{frames: kvFrames(lastSeq+1, kvBlockStoredBatch(t, []uint64{0xD1}))},
		// 3) live stream continues: store 0xD2, 0xD3.
		{frames: kvFrames(lastSeq+2, kvBlockStoredBatch(t, []uint64{0xD2, 0xD3}))},
		// 4) live stream removes one of the original warm blocks (0xC1).
		{frames: kvFrames(lastSeq+3, kvBlockRemovedBatch(t, []uint64{0xC1}))},
		// 5) terminal cancel.
		{cancel: true},
	}
	driveSubscriberLoop(t, svc, epIdx, steps)

	inv := KvGetInventory(serviceID, epIdx)
	if inv == nil {
		t.Fatalf("KvGetInventory(%d, %d) returned nil", serviceID, epIdx)
	}

	// Warm 3 (KEPT) - 1 removed (0xC1) + 3 new (0xD1,0xD2,0xD3) = 5.
	if got, want := inv.Size(), 5; got != want {
		t.Errorf("post-converge Size()=%d, want %d", got, want)
	}
	// 0xC1 was removed on the live stream → must be gone (converged, no replay).
	if mc := inv.MatchCount([]uint64{0xC1}); mc != 0 {
		t.Errorf("0xC1 should be removed via the live stream, MatchCount=%d want 0", mc)
	}
	// The surviving warm blocks + all newly-stored blocks must be present.
	present := []uint64{0xC2, 0xC3, 0xD1, 0xD2, 0xD3}
	if mc := inv.MatchCount(present); mc != len(present) {
		t.Errorf("converged set MatchCount=%d, want %d (live stream must converge with no replay)",
			mc, len(present))
	}
}
