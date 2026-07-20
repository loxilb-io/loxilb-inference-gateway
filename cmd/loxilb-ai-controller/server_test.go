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

// Bufconn suite for the snapshot server — the mirror image
// of pkg/aictrl/client_test.go's fake-controller harness, from the server
// side. All darwin CGO_ENABLED=0: no fleet, no cgo.
package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/loxilb-io/loxilb/pkg/aictrl"
)

// serverHarness hosts one snapshotServer over bufconn and hands out clients.
type serverHarness struct {
	t   *testing.T
	srv *snapshotServer
	lis *bufconn.Listener

	mu   sync.Mutex
	logs []string
}

func newServerHarness(t *testing.T, sendTimeout time.Duration, watcherBuf int,
	srvOpts ...grpc.ServerOption) *serverHarness {

	t.Helper()
	h := &serverHarness{t: t}
	h.srv = newSnapshotServer(sendTimeout, watcherBuf, serverHooks{
		logf: func(format string, args ...interface{}) {
			h.mu.Lock()
			h.logs = append(h.logs, format)
			h.mu.Unlock()
		},
	})
	h.lis = bufconn.Listen(1 << 20)
	gs := grpc.NewServer(srvOpts...)
	aictrl.RegisterAiCtrlServer(gs, h.srv)
	go func() { _ = gs.Serve(h.lis) }()
	t.Cleanup(func() {
		gs.Stop()
		_ = h.lis.Close()
	})
	return h
}

// client dials a fresh bufconn client connection.
func (h *serverHarness) client(ctx context.Context, extra ...grpc.DialOption) aictrl.AiCtrlClient {
	h.t.Helper()
	opts := append([]grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return h.lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, extra...)
	//nolint:staticcheck // DialContext matches the pinned grpc v1.59 client_test precedent.
	conn, err := grpc.DialContext(ctx, "bufnet", opts...)
	if err != nil {
		h.t.Fatalf("bufconn dial: %v", err)
	}
	h.t.Cleanup(func() { _ = conn.Close() })
	return aictrl.NewAiCtrlClient(conn)
}

// waitForSrv polls cond until true or timeout.
func waitForSrv(t *testing.T, what string, cond func() bool) {
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

// testSnap builds a fleet-shaped snapshot; noncePad grows the payload so
// flow-control tests can fill a 64KB HTTP/2 window with few messages.
func testSnap(epoch uint64, noncePad int) *aictrl.Snapshot {
	return &aictrl.Snapshot{
		Epoch:                   epoch,
		BootId:                  "boot-S",
		StalenessDeadlineUnixMs: uint64(time.Now().Add(30 * time.Second).UnixMilli()),
		MinApplierVersion:       1,
		Nonce:                   "n-" + strings.Repeat("x", noncePad),
		Services: []*aictrl.ServiceSnapshot{{
			ServiceKey: "10.0.0.12:9003:tcp",
			Eps: []*aictrl.EpEntry{
				{EpIdx: 0, EpAddr: "10.0.0.7:8100", Role: aictrl.Role_ROLE_PREFILL, Weight: 100, State: aictrl.EpState_EP_STATE_ACTIVE},
				{EpIdx: 4, EpAddr: "10.0.0.10:8200", Role: aictrl.Role_ROLE_DECODE, Weight: 100, State: aictrl.EpState_EP_STATE_ACTIVE},
			},
		}},
	}
}

// recvOne reads a single snapshot with a deadline.
func recvOne(t *testing.T, stream aictrl.AiCtrl_WatchSnapshotsClient, what string) *aictrl.Snapshot {
	t.Helper()
	type res struct {
		s   *aictrl.Snapshot
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := stream.Recv()
		ch <- res{s, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("%s: Recv: %v", what, r.err)
		}
		return r.s
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: Recv timed out", what)
		return nil
	}
}

// ---------- late join gets the last SotW IMMEDIATELY ----------

func TestServerLateJoinImmediateSotW(t *testing.T) {
	h := newServerHarness(t, 0, 0)

	// Emission happens BEFORE any watcher exists.
	h.srv.Broadcast(testSnap(7, 0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := h.client(ctx).WatchSnapshots(ctx, &aictrl.WatchRequest{GatewayId: "gw-late"})
	if err != nil {
		t.Fatalf("WatchSnapshots: %v", err)
	}

	// First Recv is the last SotW — no new Broadcast needed.
	got := recvOne(t, stream, "late joiner")
	if got.GetEpoch() != 7 || got.GetBootId() != "boot-S" {
		t.Fatalf("late joiner got epoch=%d boot=%s, want 7/boot-S",
			got.GetEpoch(), got.GetBootId())
	}
}

// ---------- fan-out: every watcher receives a new emission ----------

func TestServerFanOutTwoWatchers(t *testing.T) {
	h := newServerHarness(t, 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s1, err := h.client(ctx).WatchSnapshots(ctx, &aictrl.WatchRequest{GatewayId: "gw-1"})
	if err != nil {
		t.Fatalf("watcher 1: %v", err)
	}
	s2, err := h.client(ctx).WatchSnapshots(ctx, &aictrl.WatchRequest{GatewayId: "gw-2"})
	if err != nil {
		t.Fatalf("watcher 2: %v", err)
	}
	waitForSrv(t, "2 registered watchers", func() bool { return h.srv.stats().Watchers == 2 })

	h.srv.Broadcast(testSnap(11, 0))

	for i, st := range []aictrl.AiCtrl_WatchSnapshotsClient{s1, s2} {
		got := recvOne(t, st, "fan-out watcher")
		if got.GetEpoch() != 11 {
			t.Fatalf("watcher %d got epoch %d, want 11", i+1, got.GetEpoch())
		}
	}

	// A second emission also reaches both (stream stays live).
	h.srv.Broadcast(testSnap(12, 0))
	for i, st := range []aictrl.AiCtrl_WatchSnapshotsClient{s1, s2} {
		got := recvOne(t, st, "fan-out watcher (2nd)")
		if got.GetEpoch() != 12 {
			t.Fatalf("watcher %d got epoch %d on 2nd emission, want 12", i+1, got.GetEpoch())
		}
	}
}

// ---------- stuck watcher: emission never blocks, healthy stays fast ----------

func TestServerStuckWatcherDoesNotBlockHealthy(t *testing.T) {
	const sendTimeout = 300 * time.Millisecond
	// Minimum HTTP/2 windows so a non-reading client's stream backpressures
	// once the 64KB window plus the transport's 64KB per-stream write quota
	// fill (~4 padded messages of 32KB nonce each).
	h := newServerHarness(t, sendTimeout, 2,
		grpc.InitialWindowSize(65536), grpc.InitialConnWindowSize(65536))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Stuck gateway: opens the stream and NEVER reads it. Its client conn
	// PINS the HTTP/2 windows (disables the client-side BDP auto-tuning that
	// would otherwise grow the window and absorb every send).
	stuckCli := h.client(ctx,
		grpc.WithInitialWindowSize(65536), grpc.WithInitialConnWindowSize(65536))
	if _, err := stuckCli.WatchSnapshots(ctx, &aictrl.WatchRequest{GatewayId: "gw-stuck"}); err != nil {
		t.Fatalf("stuck watcher: %v", err)
	}
	waitForSrv(t, "stuck watcher registered", func() bool { return h.srv.stats().Watchers == 1 })

	healthy, err := h.client(ctx).WatchSnapshots(ctx, &aictrl.WatchRequest{GatewayId: "gw-healthy"})
	if err != nil {
		t.Fatalf("healthy watcher: %v", err)
	}
	waitForSrv(t, "both watchers registered", func() bool { return h.srv.stats().Watchers == 2 })

	// Healthy consumer runs concurrently, recording the highest epoch seen.
	var mu sync.Mutex
	var lastSeen uint64
	go func() {
		for {
			s, err := healthy.Recv()
			if err != nil {
				return
			}
			mu.Lock()
			if s.GetEpoch() > lastSeen {
				lastSeen = s.GetEpoch()
			}
			mu.Unlock()
		}
	}()

	// Emit padded snapshots UNTIL the send timeout evicts the stuck watcher
	// (watchers back to 1). A fixed burst is not deterministic here: the
	// stuck stream backpressures only after the pinned 64KB HTTP/2 stream
	// window PLUS the transport's per-stream 64KB write quota are exhausted
	// (~4 padded messages), and the buf-2 drop-oldest channel means the pump
	// sees only a scheduling-dependent subset of any fixed burst. Emitting
	// until eviction makes the byte pressure deterministic while KEEPING the
	// core invariant: every Broadcast returns without blocking on the stuck
	// stream (per-call bound below).
	evictDeadline := time.Now().Add(8 * time.Second)
	var epoch uint64
	for h.srv.stats().Watchers != 1 {
		if time.Now().After(evictDeadline) {
			t.Fatal("timed out waiting for stuck watcher eviction")
		}
		epoch++
		start := time.Now()
		h.srv.Broadcast(testSnap(epoch, 32*1024))
		if elapsed := time.Since(start); elapsed >= sendTimeout {
			t.Fatalf("Broadcast took %s — emission blocked on the stuck watcher", elapsed)
		}
		time.Sleep(2 * time.Millisecond) // let the pumps drain the buf-2 channels
	}

	// Healthy watcher converges on the FINAL SotW well past any drops.
	final := epoch + 1
	h.srv.Broadcast(testSnap(final, 0))
	waitForSrv(t, "healthy watcher at final epoch", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return lastSeen == final
	})

	// Eviction was observed by the loop condition above; its overflow while
	// the blocked send waited out the timeout must be counted as drops.
	if d := h.srv.stats().Dropped["gw-stuck"]; d == 0 {
		t.Fatal("no drop-oldest recorded for the stuck gateway")
	}
	if d := h.srv.stats().Dropped["gw-healthy"]; d > 0 {
		// Healthy may legitimately drop under a fast burst (SotW supersedes);
		// it still converged on the final epoch above. Log, don't fail.
		t.Logf("healthy gateway dropped %d superseded snapshots (converged anyway)", d)
	}
}

// ---------- ack recording visible in stats ----------

func TestServerAckRecording(t *testing.T) {
	h := newServerHarness(t, 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := h.client(ctx)

	if _, err := cli.AckSnapshot(ctx, &aictrl.Ack{
		Epoch: 5, Nonce: "n-5", GatewayId: "gw-a",
		Status: aictrl.AckStatus_ACK_STATUS_APPLIED,
	}); err != nil {
		t.Fatalf("applied ack: %v", err)
	}
	if _, err := cli.AckSnapshot(ctx, &aictrl.Ack{
		Epoch: 6, Nonce: "n-6", GatewayId: "gw-b",
		Status:      aictrl.AckStatus_ACK_STATUS_REJECTED,
		ErrorDetail: "epoch replay on same boot_id",
	}); err != nil {
		t.Fatalf("rejected ack: %v", err)
	}

	st := h.srv.stats()
	if st.Applied["gw-a"] != 1 {
		t.Fatalf("applied[gw-a] = %d, want 1", st.Applied["gw-a"])
	}
	if st.Rejected["gw-b"] != 1 {
		t.Fatalf("rejected[gw-b] = %d, want 1", st.Rejected["gw-b"])
	}
	if len(st.Acks) != 2 {
		t.Fatalf("ack ring has %d records, want 2", len(st.Acks))
	}
	if st.Acks[0].Epoch != 5 || st.Acks[0].Status != aictrl.AckStatus_ACK_STATUS_APPLIED {
		t.Fatalf("ring[0] = %+v, want epoch-5 APPLIED", st.Acks[0])
	}
	if st.Acks[1].Epoch != 6 || st.Acks[1].Detail != "epoch replay on same boot_id" {
		t.Fatalf("ring[1] = %+v, want epoch-6 detail preserved", st.Acks[1])
	}

	// A REJECTED ack NEVER triggers a forced re-push: no broadcast happened,
	// so a fresh watcher sees NO immediate snapshot (last is nil) — the SotW
	// re-anchor (generator-side) is the only recovery path.
	stream, err := cli.WatchSnapshots(ctx, &aictrl.WatchRequest{GatewayId: "gw-b"})
	if err != nil {
		t.Fatalf("WatchSnapshots: %v", err)
	}
	got := make(chan struct{}, 1)
	go func() {
		if _, err := stream.Recv(); err == nil {
			got <- struct{}{}
		}
	}()
	select {
	case <-got:
		t.Fatal("rejected ack produced an unsolicited snapshot push")
	case <-time.After(300 * time.Millisecond):
		// expected: nothing pushed
	}
}
