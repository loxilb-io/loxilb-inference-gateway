/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package loxinet

import (
	"errors"
	"testing"
)

// fakeReplayRequester scripts a replay conversation: SendStartSeq records the
// requested start, RecvReplay serves the queued (seq, payload) pairs and then
// the done marker (or an injected error).
type fakeReplayRequester struct {
	startSeq  int64
	sendErr   error
	recvErr   error    // returned after the queued replies are exhausted
	replies   [][]byte // payloads served in order, seq = index
	nextReply int
	closed    bool
}

func (f *fakeReplayRequester) Connect(string) error { return nil }

func (f *fakeReplayRequester) SendStartSeq(seq int64) error {
	f.startSeq = seq
	return f.sendErr
}

func (f *fakeReplayRequester) RecvReplay() (int64, []byte, bool, error) {
	if f.nextReply < len(f.replies) {
		p := f.replies[f.nextReply]
		f.nextReply++
		return int64(f.nextReply), p, false, nil
	}
	if f.recvErr != nil {
		return 0, nil, false, f.recvErr
	}
	return -1, nil, true, nil
}

func (f *fakeReplayRequester) Close() error { f.closed = true; return nil }

// TestKvReplayEndpointDerivation pins the PUB→replay endpoint convention
// (fixed +1000 port offset, overridable, fail-closed on unparsable input).
func TestKvReplayEndpointDerivation(t *testing.T) {
	if got := kvReplayEndpoint("tcp://10.0.0.7:5557"); got != "tcp://10.0.0.7:6557" {
		t.Fatalf("default offset: got %q want tcp://10.0.0.7:6557", got)
	}
	t.Setenv("LLB_KV_REPLAY_PORT_OFFSET", "500")
	if got := kvReplayEndpoint("tcp://10.0.0.7:5557"); got != "tcp://10.0.0.7:6057" {
		t.Fatalf("override offset: got %q want tcp://10.0.0.7:6057", got)
	}
	t.Setenv("LLB_KV_REPLAY_PORT_OFFSET", "0")
	if got := kvReplayEndpoint("tcp://10.0.0.7:5557"); got != "" {
		t.Fatalf("offset 0 must disable replay, got %q", got)
	}
	t.Setenv("LLB_KV_REPLAY_PORT_OFFSET", "")
	if got := kvReplayEndpoint("garbage"); got != "" {
		t.Fatalf("unparsable address must disable replay, got %q", got)
	}
	if got := kvReplayEndpoint("tcp://10.0.0.7:65000"); got != "" {
		t.Fatalf("out-of-range derived port must disable replay, got %q", got)
	}
}

// TestKvReplayBackfillsInventory drives replayKvEvents with a scripted
// requester: the buffered history (stores then a removal) must land in the
// inventory exactly as if it had arrived on the live stream.
func TestKvReplayBackfillsInventory(t *testing.T) {
	inv := newKvInventory()
	f := &fakeReplayRequester{replies: [][]byte{
		kvBlockStoredBatch(t, []uint64{11, 22, 33}),
		kvBlockStoredBatch(t, []uint64{44}),
		kvBlockRemovedBatch(t, []uint64{22}),
	}}

	replayKvEvents(inv, f, 0, kvWireDecoderFunc(kvWireDecodeArrayV1))

	if f.startSeq != 0 {
		t.Fatalf("requested start seq = %d, want 0", f.startSeq)
	}
	if got := inv.Size(); got != 3 {
		t.Fatalf("inventory size after replay = %d, want 3 (11,33,44)", got)
	}
	if inv.MatchCount([]uint64{11, 33, 44}) != 3 {
		t.Fatalf("expected hashes 11,33,44 present after replay")
	}
	if inv.MatchCount([]uint64{22}) != 0 {
		t.Fatalf("hash 22 was removed in the replayed history but is present")
	}
}

// TestKvReplayFailOpen verifies both failure edges leave the subscriber
// usable: a failed replay request applies nothing, and a mid-stream recv
// error keeps what was already applied without panicking.
func TestKvReplayFailOpen(t *testing.T) {
	inv := newKvInventory()
	replayKvEvents(inv, &fakeReplayRequester{sendErr: errors.New("no listener")}, 0, kvWireDecoderFunc(kvWireDecodeArrayV1))
	if got := inv.Size(); got != 0 {
		t.Fatalf("failed request must apply nothing, inventory size = %d", got)
	}

	inv2 := newKvInventory()
	f := &fakeReplayRequester{
		replies: [][]byte{kvBlockStoredBatch(t, []uint64{7})},
		recvErr: errors.New("socket died mid-replay"),
	}
	replayKvEvents(inv2, f, 0, kvWireDecoderFunc(kvWireDecodeArrayV1))
	if got := inv2.Size(); got != 1 {
		t.Fatalf("partial replay must keep applied events, inventory size = %d", got)
	}
}
