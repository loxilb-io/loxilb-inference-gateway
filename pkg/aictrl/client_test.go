/*
 * Copyright (c) 2026 LoxiLB Authors
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

// In-process fake-controller harness over grpc/test/bufconn (W4 gate):
// scripted snapshots, recorded acks, recording sink, fake clock. All darwin
// CGO_ENABLED=0 — no fleet, no cgo.
package aictrl

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// ---------- fakes ----------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

type sinkUpdate struct {
	key    string
	idx    int
	packed uint32
}

type sinkMode struct {
	key  string
	mode uint8
}

type recordingSink struct {
	mu      sync.Mutex
	updates []sinkUpdate
	modes   []sinkMode
}

func (r *recordingSink) UpdateEp(key string, idx int, packed uint32) {
	r.mu.Lock()
	r.updates = append(r.updates, sinkUpdate{key, idx, packed})
	r.mu.Unlock()
}

func (r *recordingSink) SetMode(key string, mode uint8) {
	r.mu.Lock()
	r.modes = append(r.modes, sinkMode{key, mode})
	r.mu.Unlock()
}

func (r *recordingSink) counts() (updates, modes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.updates), len(r.modes)
}

func (r *recordingSink) modeWrites(mode uint8) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, m := range r.modes {
		if m.mode == mode {
			n++
		}
	}
	return n
}

func (r *recordingSink) lastPacked(idx int) (uint32, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.updates) - 1; i >= 0; i-- {
		if r.updates[i].idx == idx {
			return r.updates[i].packed, true
		}
	}
	return 0, false
}

// fakeCtrl serves scripted snapshot streams: each WatchSnapshots call
// consumes the next script channel from streams; closing a script kills that
// stream (stream-death simulation).
type fakeCtrl struct {
	UnimplementedAiCtrlServer
	streams   chan chan *Snapshot
	acks      chan *Ack
	ackUnimpl atomic.Bool
	ackCalls  atomic.Int64
}

func (f *fakeCtrl) WatchSnapshots(_ *WatchRequest, srv AiCtrl_WatchSnapshotsServer) error {
	script, ok := <-f.streams
	if !ok {
		return nil
	}
	for s := range script {
		if err := srv.Send(s); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeCtrl) AckSnapshot(_ context.Context, a *Ack) (*AckResponse, error) {
	f.ackCalls.Add(1)
	if f.ackUnimpl.Load() {
		return nil, status.Error(codes.Unimplemented, "ack not implemented")
	}
	f.acks <- a
	return &AckResponse{}, nil
}

// ---------- harness ----------

type harness struct {
	t     *testing.T
	clock *fakeClock
	sink  *recordingSink
	fake  *fakeCtrl
	sess  *Session

	mu          sync.Mutex
	modeChanges []Mode
	logs        []string
	unhealthy   map[int]bool
	overrides   map[int]int
}

func (h *harness) healthyFn(_ string, epIdx int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.unhealthy[epIdx]
}

func (h *harness) recordedModes() []Mode {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Mode, len(h.modeChanges))
	copy(out, h.modeChanges)
	return out
}

func (h *harness) logCount(substr string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, l := range h.logs {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	fake := &fakeCtrl{
		streams: make(chan chan *Snapshot, 8),
		acks:    make(chan *Ack, 32),
	}
	srv := grpc.NewServer()
	RegisterAiCtrlServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()

	h := &harness{
		t:         t,
		clock:     &fakeClock{t: tBase},
		sink:      &recordingSink{},
		fake:      fake,
		unhealthy: map[int]bool{},
		overrides: map[int]int{},
	}

	cfg := Config{
		Addr:        "bufnet",
		GatewayID:   "gw-test",
		DecayWindow: 30 * time.Second,
		Hysteresis:  5 * time.Second,
		AckTimeout:  2 * time.Second,
		JitterPct:   0, // deterministic tests; jitter covered by P3 config
		Now:         h.clock.Now,
		Dial: func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
			return grpc.DialContext(ctx, "bufnet",
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
					return lis.DialContext(ctx)
				}),
				grpc.WithTransportCredentials(insecure.NewCredentials()))
		},
		Sleep:  func(ctx context.Context, d time.Duration) {}, // compress backoff
		TickCh: make(chan time.Time),                          // never fires — tests drive tickOnce directly
		Known:  func() map[string][]uint32 { return testKnown() },
		Healthy: func(key string, epIdx int) bool {
			return h.healthyFn(key, epIdx)
		},
		OnModeChange: func(m Mode) {
			h.mu.Lock()
			h.modeChanges = append(h.modeChanges, m)
			h.mu.Unlock()
		},
		OnOverride: func(_ string, epIdx int) {
			h.mu.Lock()
			h.overrides[epIdx]++
			h.mu.Unlock()
		},
		Logf: func(format string, args ...interface{}) {
			h.mu.Lock()
			h.logs = append(h.logs, fmt.Sprintf(format, args...))
			h.mu.Unlock()
		},
	}
	h.sess = NewSession(cfg, h.sink)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = h.sess.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		close(fake.streams)
		srv.Stop()
		_ = lis.Close()
	})
	return h
}

// pushStream registers a new scripted stream and returns its send channel.
func (h *harness) pushStream() chan *Snapshot {
	script := make(chan *Snapshot, 8)
	h.fake.streams <- script
	return script
}

// waitAck waits for the next Ack recorded by the fake controller.
func (h *harness) waitAck() *Ack {
	h.t.Helper()
	select {
	case a := <-h.fake.acks:
		return a
	case <-time.After(5 * time.Second):
		h.t.Fatal("timed out waiting for Ack")
		return nil
	}
}

// waitFor polls cond until true or 5s real-time timeout.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// mkSnap builds a valid 3-EP snapshot (indices 0,1,4 of testKnown) with the
// given epoch/boot/deadline and prefill-EP-0 weight w0.
func mkSnap(epoch uint64, bootID string, deadline time.Time, w0 uint32) *Snapshot {
	return &Snapshot{
		Epoch:                   epoch,
		BootId:                  bootID,
		StalenessDeadlineUnixMs: uint64(deadline.UnixMilli()),
		MinApplierVersion:       1,
		Nonce:                   fmt.Sprintf("nonce-%d", epoch),
		Services: []*ServiceSnapshot{{
			ServiceKey: testSvcKey,
			Eps: []*EpEntry{
				{EpIdx: 0, EpAddr: "10.0.0.7:8100", Role: Role_ROLE_PREFILL, Weight: w0, State: EpState_EP_STATE_ACTIVE},
				{EpIdx: 1, EpAddr: "10.0.0.8:8100", Role: Role_ROLE_PREFILL, Weight: 100, State: EpState_EP_STATE_ACTIVE},
				{EpIdx: 4, EpAddr: "10.0.0.10:8200", Role: Role_ROLE_DECODE, Weight: 100, State: EpState_EP_STATE_ACTIVE},
			},
		}},
	}
}

func packedFor(state EpState, weight uint32) uint32 {
	return uint32(state)<<24 | weight
}

// ---------- (a) happy path ----------

func TestSessionHappyPathAck(t *testing.T) {
	h := newHarness(t)
	script := h.pushStream()

	script <- mkSnap(42, "boot-A", tBase.Add(30*time.Second), 80)

	ack := h.waitAck()
	if ack.GetStatus() != AckStatus_ACK_STATUS_APPLIED {
		t.Fatalf("ack status = %v, want APPLIED (detail: %s)", ack.GetStatus(), ack.GetErrorDetail())
	}
	if ack.GetEpoch() != 42 || ack.GetNonce() != "nonce-42" || ack.GetGatewayId() != "gw-test" {
		t.Fatalf("ack fields wrong: %+v", ack)
	}

	// Sink saw all three EP writes with the correct packed words (α=1 fresh).
	waitFor(t, "3 sink updates", func() bool { u, _ := h.sink.counts(); return u >= 3 })
	if p, ok := h.sink.lastPacked(0); !ok || p != packedFor(EpState_EP_STATE_ACTIVE, 80) {
		t.Fatalf("ep0 packed = %#x, want %#x", p, packedFor(EpState_EP_STATE_ACTIVE, 80))
	}
	if p, ok := h.sink.lastPacked(4); !ok || p != packedFor(EpState_EP_STATE_ACTIVE, 100) {
		t.Fatalf("ep4 packed = %#x, want %#x", p, packedFor(EpState_EP_STATE_ACTIVE, 100))
	}
	// Controller-live mode write (non-zero) for the service.
	if h.sink.modeWrites(1) < 1 {
		t.Fatal("no SetMode(1) write after apply")
	}
	// Apply announced Smart.
	waitFor(t, "Smart mode change", func() bool {
		ms := h.recordedModes()
		return len(ms) > 0 && ms[len(ms)-1] == ModeSmart
	})
}

// ---------- (b) replay ⇒ NACK + sink untouched ----------

func TestSessionReplayRejected(t *testing.T) {
	h := newHarness(t)
	script := h.pushStream()

	script <- mkSnap(42, "boot-A", tBase.Add(30*time.Second), 80)
	if a := h.waitAck(); a.GetStatus() != AckStatus_ACK_STATUS_APPLIED {
		t.Fatalf("setup ack: %+v", a)
	}
	waitFor(t, "initial updates", func() bool { u, _ := h.sink.counts(); return u >= 3 })
	u0, m0 := h.sink.counts()

	// Replay: same boot_id, LOWER epoch 41 after 42.
	script <- mkSnap(41, "boot-A", tBase.Add(30*time.Second), 10)

	ack := h.waitAck()
	if ack.GetStatus() != AckStatus_ACK_STATUS_REJECTED {
		t.Fatalf("replay ack status = %v, want REJECTED", ack.GetStatus())
	}
	if ack.GetEpoch() != 41 {
		t.Fatalf("replay ack epoch = %d, want 41", ack.GetEpoch())
	}
	// The typed validation message is plumbed into Ack.error_detail.
	if !strings.Contains(ack.GetErrorDetail(), "epoch replay on same boot_id") {
		t.Fatalf("error_detail missing replay reason: %q", ack.GetErrorDetail())
	}
	// Last-good kept: sink untouched by the rejected snapshot.
	if u1, m1 := h.sink.counts(); u1 != u0 || m1 != m0 {
		t.Fatalf("sink touched by rejected snapshot: updates %d→%d modes %d→%d", u0, u1, m0, m1)
	}
}

// ---------- (c) stream death ⇒ fake-clock decay ladder ----------

func TestSessionDecayLadder(t *testing.T) {
	h := newHarness(t)
	script := h.pushStream()

	deadline := tBase.Add(30 * time.Second)
	script <- mkSnap(42, "boot-A", deadline, 80)
	if a := h.waitAck(); a.GetStatus() != AckStatus_ACK_STATUS_APPLIED {
		t.Fatalf("setup ack: %+v", a)
	}
	waitFor(t, "initial updates", func() bool { u, _ := h.sink.counts(); return u >= 3 })

	// Stream death — the controller goes away.
	close(script)

	// Smart: before the deadline, full snapshot weight rewritten.
	h.clock.Set(tBase.Add(10 * time.Second))
	h.sess.tickOnce()
	if p, _ := h.sink.lastPacked(0); p != packedFor(EpState_EP_STATE_ACTIVE, 80) {
		t.Fatalf("Smart tick ep0 packed = %#x, want weight 80", p)
	}

	// Stale: mid-window (deadline+15s) ⇒ α=0.5 ⇒ w=80 → 90.
	h.clock.Set(deadline.Add(15 * time.Second))
	h.sess.tickOnce()
	if p, _ := h.sink.lastPacked(0); p != packedFor(EpState_EP_STATE_ACTIVE, 90) {
		t.Fatalf("Stale tick ep0 packed = %#x, want decayed weight 90", p)
	}

	// Autonomous: past window end ⇒ exactly ONE SetMode(0).
	h.clock.Set(deadline.Add(31 * time.Second))
	h.sess.tickOnce()
	if n := h.sink.modeWrites(0); n != 1 {
		t.Fatalf("SetMode(0) count = %d, want exactly 1", n)
	}
	uAuto, _ := h.sink.counts()

	// Further ticks: NO repeated mode-0 writes, NO further rewrites.
	h.clock.Set(deadline.Add(45 * time.Second))
	h.sess.tickOnce()
	h.clock.Set(deadline.Add(60 * time.Second))
	h.sess.tickOnce()
	if n := h.sink.modeWrites(0); n != 1 {
		t.Fatalf("repeated SetMode(0): count = %d, want exactly 1", n)
	}
	if u, _ := h.sink.counts(); u != uAuto {
		t.Fatalf("rewrites continued after Autonomous latch: %d → %d", uAuto, u)
	}

	// Ladder observed in order Smart → Stale → Autonomous.
	ms := h.recordedModes()
	if len(ms) < 3 || ms[len(ms)-3] != ModeSmart || ms[len(ms)-2] != ModeStale || ms[len(ms)-1] != ModeAutonomous {
		t.Fatalf("mode ladder wrong: %v", ms)
	}
}

// ---------- (d) controller return ⇒ re-convergence ----------

func TestSessionReconvergence(t *testing.T) {
	h := newHarness(t)
	script := h.pushStream()

	deadline := tBase.Add(30 * time.Second)
	script <- mkSnap(42, "boot-A", deadline, 80)
	if a := h.waitAck(); a.GetStatus() != AckStatus_ACK_STATUS_APPLIED {
		t.Fatalf("setup ack: %+v", a)
	}
	waitFor(t, "initial updates", func() bool { u, _ := h.sink.counts(); return u >= 3 })
	close(script) // stream death

	// Decay all the way to Autonomous.
	h.clock.Set(deadline.Add(31 * time.Second))
	h.sess.tickOnce()
	if n := h.sink.modeWrites(0); n != 1 {
		t.Fatalf("SetMode(0) count = %d, want 1", n)
	}

	// Controller returns: fresh epoch on a reconnected stream, deadline
	// relative to the CURRENT fake now.
	now := h.clock.Now()
	script2 := h.pushStream()
	script2 <- mkSnap(43, "boot-A", now.Add(30*time.Second), 60)

	ack := h.waitAck()
	if ack.GetStatus() != AckStatus_ACK_STATUS_APPLIED || ack.GetEpoch() != 43 {
		t.Fatalf("re-convergence ack: %+v (detail: %s)", ack, ack.GetErrorDetail())
	}
	// Fresh weight applied and controller-live mode re-written.
	waitFor(t, "fresh epoch-43 write", func() bool {
		p, ok := h.sink.lastPacked(0)
		return ok && p == packedFor(EpState_EP_STATE_ACTIVE, 60)
	})
	if h.sink.modeWrites(1) < 2 {
		t.Fatalf("SetMode(1) writes = %d, want >= 2 (initial + re-convergence)", h.sink.modeWrites(1))
	}
	// Mode back to Smart; rewrites resumed (autonomous latch cleared).
	waitFor(t, "Smart after re-convergence", func() bool {
		ms := h.recordedModes()
		return len(ms) > 0 && ms[len(ms)-1] == ModeSmart
	})
	u0, _ := h.sink.counts()
	h.clock.Set(now.Add(5 * time.Second))
	h.sess.tickOnce()
	if u1, _ := h.sink.counts(); u1 <= u0 {
		t.Fatal("1 Hz rewrite did not resume after fresh snapshot")
	}
}

// ---------- (e) unknown EP ⇒ REJECTED, sink untouched ----------

func TestSessionUnknownEpRejected(t *testing.T) {
	h := newHarness(t)
	script := h.pushStream()

	bad := mkSnap(7, "boot-A", tBase.Add(30*time.Second), 80)
	bad.Services[0].Eps[0].EpIdx = 99
	script <- bad

	ack := h.waitAck()
	if ack.GetStatus() != AckStatus_ACK_STATUS_REJECTED {
		t.Fatalf("unknown-EP ack status = %v, want REJECTED", ack.GetStatus())
	}
	if !strings.Contains(ack.GetErrorDetail(), "unknown ep_idx") {
		t.Fatalf("error_detail: %q", ack.GetErrorDetail())
	}
	if u, m := h.sink.counts(); u != 0 || m != 0 {
		t.Fatalf("sink touched by rejected snapshot: updates=%d modes=%d", u, m)
	}
}

// ---------- hysteresis: DIFFERENT-state transition inside the 5s window MUST pass (L-9) ----------

func TestSessionHysteresisStaleToSmartWithinWindow(t *testing.T) {
	h := newHarness(t)
	script := h.pushStream()

	deadline := tBase.Add(30 * time.Second)
	script <- mkSnap(1, "boot-A", deadline, 80)
	if a := h.waitAck(); a.GetStatus() != AckStatus_ACK_STATUS_APPLIED {
		t.Fatalf("setup ack: %+v", a)
	}
	waitFor(t, "Smart", func() bool {
		ms := h.recordedModes()
		return len(ms) > 0 && ms[len(ms)-1] == ModeSmart
	})

	// Enter Stale 1s past the deadline.
	h.clock.Set(deadline.Add(1 * time.Second))
	h.sess.tickOnce()
	waitFor(t, "Stale", func() bool {
		ms := h.recordedModes()
		return len(ms) > 0 && ms[len(ms)-1] == ModeStale
	})

	// Controller comes RIGHT back: 2s later (inside the 5s hysteresis
	// window) a fresh snapshot restores Smart. Different-state transition
	// within the window MUST pass (L-9 — blanket suppression would wedge
	// Stale→Smart recovery exactly like the xSync BACKUP→MASTER defect).
	h.clock.Set(deadline.Add(3 * time.Second))
	script <- mkSnap(2, "boot-A", deadline.Add(33*time.Second), 80)
	if a := h.waitAck(); a.GetStatus() != AckStatus_ACK_STATUS_APPLIED {
		t.Fatalf("recovery ack: %+v", a)
	}
	waitFor(t, "Stale→Smart within hysteresis window accepted", func() bool {
		ms := h.recordedModes()
		return len(ms) >= 2 && ms[len(ms)-2] == ModeStale && ms[len(ms)-1] == ModeSmart
	})
}

// ---------- override: local health wins during apply + rewrite ----------

func TestSessionLocalHealthOverride(t *testing.T) {
	h := newHarness(t)
	h.mu.Lock()
	h.unhealthy[0] = true // ep0 locally unhealthy (CB open / probe down)
	h.mu.Unlock()

	script := h.pushStream()
	script <- mkSnap(42, "boot-A", tBase.Add(30*time.Second), 100) // ACTIVE|100 — resurrection attempt
	if a := h.waitAck(); a.GetStatus() != AckStatus_ACK_STATUS_APPLIED {
		t.Fatalf("setup ack: %+v", a)
	}
	waitFor(t, "healthy EP writes", func() bool { u, _ := h.sink.counts(); return u >= 2 })

	// G4: ZERO writes for the unhealthy EP — the ACTIVE|100 snapshot cannot
	// resurrect it; the veto was counted.
	if _, ok := h.sink.lastPacked(0); ok {
		t.Fatal("sink write emitted for locally-unhealthy ep0 (G4 resurrection)")
	}
	h.mu.Lock()
	vetoed := h.overrides[0]
	h.mu.Unlock()
	if vetoed < 1 {
		t.Fatal("override event not counted for the vetoed EP")
	}
}

// ---------- Unimplemented Ack ⇒ capability-clear + warn-once ----------

func TestSessionAckUnimplementedDegrade(t *testing.T) {
	h := newHarness(t)
	h.fake.ackUnimpl.Store(true)

	script := h.pushStream()
	script <- mkSnap(1, "boot-A", tBase.Add(30*time.Second), 80)
	// Apply proceeds even though the ack degrades.
	waitFor(t, "epoch-1 applied", func() bool {
		p, ok := h.sink.lastPacked(0)
		return ok && p == packedFor(EpState_EP_STATE_ACTIVE, 80)
	})
	waitFor(t, "one ack attempt", func() bool { return h.fake.ackCalls.Load() == 1 })

	// Second snapshot: applied, but NO second ack attempt (capability cleared).
	script <- mkSnap(2, "boot-A", tBase.Add(30*time.Second), 70)
	waitFor(t, "epoch-2 applied", func() bool {
		p, ok := h.sink.lastPacked(0)
		return ok && p == packedFor(EpState_EP_STATE_ACTIVE, 70)
	})
	if n := h.fake.ackCalls.Load(); n != 1 {
		t.Fatalf("ack attempts after capability clear = %d, want 1", n)
	}
	// Warn-once: exactly one degrade log line.
	if n := h.logCount("Unimplemented"); n != 1 {
		t.Fatalf("Unimplemented warn count = %d, want exactly 1", n)
	}
}
