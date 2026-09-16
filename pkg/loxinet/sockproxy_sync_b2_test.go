/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Sub-phase B: Rate-limiter HA tests for the coordinator
 * push goroutines + server handler + L-2 lock-discipline integration.
 *
 * Suite covers SPEC B1 (integration) + B2 (race-clean) + Rule-2-derived
 * cadence assertions:
 *
 *   TestRateLimiterServerHandlerRoutes — RateLimiterSync server handler
 *     correctly dispatches IsDelta=false → ImportState and IsDelta=true
 *     → ApplyGossipDelta on the coordinator's registered store.
 *   TestRateLimiterSendBatchChunking — 1200 entries split into 3 sequential
 *     RPCs of 500+500+200 per SPEC §Constraints (500/batch ceiling).
 *   TestRateLimiterCapDegrade — peer returns codes.Unimplemented for
 *     RateLimiterSync → capRateLimiterSync bit cleared, WARN-once,
 *     subsequent ticks skip the peer.
 *   TestRateLimiterPushCadenceAP — A-P mode produces ~5 ticks per second
 *     at 200ms cadence.
 *   TestRateLimiterPushCadenceAA — A-A mode produces 5-10 ticks per
 *     second in the 100-200ms jittered window.
 *   TestRateLimiterPushAbsoluteEvery10thAA — A-A every-10th push is a
 *     full snapshot (IsDelta=false) for drift insurance.
 *   TestRateLimiterPushL2Discipline — store.mu is NEVER held while
 *     gRPC Send is in flight (in-process verification, race-clean).
 */

package loxinet

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	rl "github.com/loxilb-io/loxilb/pkg/ratelimit"
)

// ---------- Mock server extensions for RateLimiterSync ----------

// mockRateLimiterServer is a focused mock that overrides RateLimiterSync
// for B2 tests. It records every batch received and (optionally) returns
// codes.Unimplemented to exercise the rolling-upgrade degrade path.
type mockRateLimiterServer struct {
	UnimplementedXSyncServer

	mu            sync.Mutex
	batches       []*RateLimiterBatch
	calls         atomic.Int32
	unimplemented bool
	// blockingCh, if non-nil, is sent to before responding — lets tests
	// observe the in-flight state.
	blockingCh chan struct{}
}

func (m *mockRateLimiterServer) RateLimiterSync(ctx context.Context, req *RateLimiterBatch) (*XSyncReply, error) {
	m.calls.Add(1)
	if m.unimplemented {
		return nil, status.Errorf(codes.Unimplemented, "method RateLimiterSync not implemented")
	}
	m.mu.Lock()
	// Deep-copy the batch so the caller can mutate freely.
	cp := &RateLimiterBatch{IsDelta: req.IsDelta, Entries: make([]*RateLimiterEntry, len(req.Entries))}
	for i, e := range req.Entries {
		cp.Entries[i] = proto.Clone(e).(*RateLimiterEntry)
	}
	m.batches = append(m.batches, cp)
	m.mu.Unlock()
	if m.blockingCh != nil {
		<-m.blockingCh
	}
	return &XSyncReply{Response: 0}, nil
}

// startMockRLServer brings up a bufconn-backed gRPC server hosting a
// mockRateLimiterServer and returns (client, cleanup). Mirrors the
// startMockServer helper in sockproxy_sync_test.go but registers our
// RateLimiterSync-focused mock.
func startMockRLServer(t *testing.T, m *mockRateLimiterServer) (XSyncClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	RegisterXSyncServer(srv, m)
	go func() { _ = srv.Serve(lis) }()

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())
	if err != nil {
		srv.Stop()
		t.Fatalf("failed to dial bufnet: %v", err)
	}
	cleanup := func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	}
	return NewXSyncClient(conn), cleanup
}

// ---------- Tests ----------

// TestRateLimiterServerHandlerRoutes verifies the xsync_server.go
// RateLimiterSync handler routes IsDelta=false → ImportState and
// IsDelta=true → ApplyGossipDelta on the coordinator's registered store.
func TestRateLimiterServerHandlerRoutes(t *testing.T) {
	t.Parallel()

	// Construct a coordinator with a fresh in-test RateLimiterStore.
	coord := newTestCoordinator(newMockApplier(0))
	store := rl.New()
	coord.SetRateLimiterStore(store)

	// Test 1: IsDelta=false → ImportState.
	// Build a batch with two tenants. After Apply, store.quotaMap should
	// have both, and ExportState should round-trip them.
	batch1 := &RateLimiterBatch{
		IsDelta: false,
		Entries: []*RateLimiterEntry{
			{KeyId: "t:srv-tenant-1", IsTenant: true, EpochStartTs: 100, TokensConsumed: 42},
			{KeyId: "t:srv-tenant-2", IsTenant: true, EpochStartTs: 100, TokensConsumed: 99},
		},
	}
	if err := coord.ApplyRateLimiterBatch("test-peer", batch1); err != nil {
		t.Fatalf("ApplyRateLimiterBatch (snapshot) failed: %v", err)
	}
	state := store.ExportState()
	got := map[string]int64{}
	for _, e := range state {
		if e.IsTenant {
			got[e.KeyID] = e.Consumed
		}
	}
	if got["t:srv-tenant-1"] != 42 || got["t:srv-tenant-2"] != 99 {
		t.Errorf("after snapshot import: expected t1=42, t2=99, got %+v", got)
	}

	// Test 2: IsDelta=true → ApplyGossipDelta; consumed=10 must NOT
	// retract local 42 (max-merge); consumed=200 advances local.
	batch2 := &RateLimiterBatch{
		IsDelta: true,
		Entries: []*RateLimiterEntry{
			{KeyId: "t:srv-tenant-1", IsTenant: true, EpochStartTs: 100, TokensConsumed: 10},
			{KeyId: "t:srv-tenant-2", IsTenant: true, EpochStartTs: 100, TokensConsumed: 200},
		},
	}
	if err := coord.ApplyRateLimiterBatch("test-peer", batch2); err != nil {
		t.Fatalf("ApplyRateLimiterBatch (delta) failed: %v", err)
	}
	state = store.ExportState()
	for _, e := range state {
		if e.KeyID == "t:srv-tenant-1" && e.Consumed != 42 {
			t.Errorf("max-merge: expected t1 STAYS at 42 (not retracted to 10), got %d", e.Consumed)
		}
		if e.KeyID == "t:srv-tenant-2" && e.Consumed != 200 {
			t.Errorf("max-merge: expected t2 advances 99→200, got %d", e.Consumed)
		}
	}
}

// TestRateLimiterApplyNilStore verifies the handler does not crash when
// no RateLimiterStore is registered yet (typical of early-boot before
// ai_gateway_dp.go has wired the global store).
func TestRateLimiterApplyNilStore(t *testing.T) {
	t.Parallel()
	coord := newTestCoordinator(newMockApplier(0))
	// Deliberately do NOT call SetRateLimiterStore.
	batch := &RateLimiterBatch{IsDelta: false, Entries: []*RateLimiterEntry{
		{KeyId: "t:no-store-tenant", IsTenant: true, EpochStartTs: 1, TokensConsumed: 1},
	}}
	if err := coord.ApplyRateLimiterBatch("test-peer", batch); err != nil {
		t.Errorf("ApplyRateLimiterBatch with no store should be nil-error (graceful), got %v", err)
	}
}

// TestRateLimiterSendBatchChunking verifies that 1200 entries are
// split into 3 sequential RateLimiterSync RPCs of 500+500+200 (the
// SPEC §Constraints 500-entry ceiling).
func TestRateLimiterSendBatchChunking(t *testing.T) {
	t.Parallel()
	srv := &mockRateLimiterServer{}
	client, cleanup := startMockRLServer(t, srv)
	defer cleanup()

	coord := newTestCoordinator(newMockApplier(0))
	peer := &DpPeer{Peer: net.ParseIP("127.0.0.1"), CapMask: 0xFFFFFFFF}

	entries := make([]rl.RateLimiterEntry, 1200)
	for i := 0; i < 1200; i++ {
		entries[i] = rl.RateLimiterEntry{
			KeyID:    "t:chunk-tenant-" + itoaT(i),
			IsTenant: true,
			Consumed: int64(i),
		}
	}

	if err := coord.sendRateLimiterBatch(peer, client, entries, false); err != nil {
		t.Fatalf("sendRateLimiterBatch returned error: %v", err)
	}

	got := srv.calls.Load()
	if got != 3 {
		t.Errorf("expected 3 chunked RPCs (sentinel + 1200 payload under the 500 ceiling), got %d", got)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.batches) != 3 {
		t.Fatalf("expected 3 batches recorded, got %d", len(srv.batches))
	}
	// EVERY chunk leads with the scope-version sentinel, INSIDE the 500-entry
	// RPC ceiling: each chunk is the sentinel + 499 payload entries, so no
	// call ever exceeds the SPEC bound. 1200 payload rows therefore chunk as
	// 499+499+202.
	//
	// This assertion previously required the opposite — "the sentinel must
	// lead the PUSH, not every chunk". That contract is not one the receiver
	// can honour: chunks are independent RPCs with no push identity, sequence
	// number or stream on the wire, so a chunk arriving without the sentinel
	// is indistinguishable from a push by a peer that pre-dates the ladder
	// scopes, and the receiver warned accordingly about its own up-to-date
	// sender. See TestChunkedPushDoesNotSelfReportAsOldPeer, which asserts
	// that consequence at the receiver.
	wantSizes := []int{500, 500, 203}
	for i, b := range srv.batches {
		if len(b.Entries) != wantSizes[i] {
			t.Errorf("batch %d: expected %d entries, got %d", i, wantSizes[i], len(b.Entries))
		}
	}
	for i, b := range srv.batches {
		if b.Entries[0].KeyId != rl.ScopeSentinelKeyID {
			t.Errorf("chunk %d must lead with the scope sentinel, got %q", i, b.Entries[0].KeyId)
		}
	}
}

// TestRateLimiterCapDegrade — peer returns codes.Unimplemented for
// RateLimiterSync; assert (a) sendRateLimiterBatch returns nil-err,
// (b) capRateLimiterSync bit cleared, (c) WARN-once.
func TestRateLimiterCapDegrade(t *testing.T) {
	t.Parallel()
	srv := &mockRateLimiterServer{unimplemented: true}
	client, cleanup := startMockRLServer(t, srv)
	defer cleanup()

	coord := newTestCoordinator(newMockApplier(0))
	peer := &DpPeer{Peer: net.ParseIP("127.0.0.2"), CapMask: 0xFFFFFFFF}

	entries := []rl.RateLimiterEntry{
		{KeyID: "t:degrade-tenant", IsTenant: true, Consumed: 5},
	}

	err := coord.sendRateLimiterBatch(peer, client, entries, false)
	if err != nil {
		t.Errorf("expected nil-err on Unimplemented (graceful degrade), got %v", err)
	}

	if peer.CapMask&capRateLimiterSync != 0 {
		t.Errorf("expected capRateLimiterSync cleared, CapMask=%032b", peer.CapMask)
	}

	// warnOnce should record exactly one (peer, RateLimiterSync) entry.
	count := 0
	coord.warnOnce.Range(func(_, _ interface{}) bool { count++; return true })
	if count != 1 {
		t.Errorf("expected exactly 1 warnOnce entry, got %d", count)
	}
}

// TestRateLimiterPushCadenceAP — drive 1 second under A-P mode; the
// push goroutine fires at 200ms cadence → expect ~5 ticks (tolerance ±2).
func TestRateLimiterPushCadenceAP(t *testing.T) {
	t.Parallel()
	srv := &mockRateLimiterServer{}
	client, cleanup := startMockRLServer(t, srv)
	defer cleanup()

	coord := newTestCoordinator(newMockApplier(0))
	coord.haMode.Store("AP")
	store := rl.New()
	// Seed at least one entry so ExportState returns non-empty (push
	// loop short-circuits on empty entries).
	store.AllowTokens("cadence-ap-tenant", 1, 1000000, 0)
	coord.SetRateLimiterStore(store)

	peer := &DpPeer{Peer: net.ParseIP("127.0.0.3"), CapMask: 0xFFFFFFFF}
	coord.StartRateLimiterPushLoop(peer, func() XSyncClient { return client })

	time.Sleep(1100 * time.Millisecond)
	close(coord.shutdownCh)
	coord.wg.Wait()

	got := srv.calls.Load()
	// Expected: 1100ms / 200ms = 5 (the first tick fires AFTER 200ms,
	// so at 1100ms we get up to 5 ticks). Allow ±2 for scheduler jitter.
	if got < 3 || got > 7 {
		t.Errorf("A-P cadence: expected ~5 ticks in 1s (200ms cadence), got %d", got)
	}
	// Every batch must be IsDelta=false (A-P = snapshots).
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for i, b := range srv.batches {
		if b.IsDelta {
			t.Errorf("A-P batch %d should be IsDelta=false (snapshot), got true", i)
		}
	}
}

// TestRateLimiterPushCadenceAA — drive 1 second under A-A mode; cadence
// is 100-200ms jittered → expect 5-10 ticks (tolerance one tick each
// side: 4-11). A driver goroutine continuously bumps the tenant's
// consumed counter so ExportDelta returns non-empty on every tick
// (the production push loop correctly skips empty deltas to save
// bandwidth; the test must therefore guarantee activity).
func TestRateLimiterPushCadenceAA(t *testing.T) {
	t.Parallel()
	srv := &mockRateLimiterServer{}
	client, cleanup := startMockRLServer(t, srv)
	defer cleanup()

	coord := newTestCoordinator(newMockApplier(0))
	coord.haMode.Store("AA")
	store := rl.New()
	store.AllowTokens("cadence-aa-tenant", 1, 1000000, 0)
	coord.SetRateLimiterStore(store)

	peer := &DpPeer{Peer: net.ParseIP("127.0.0.4"), CapMask: 0xFFFFFFFF}
	coord.StartRateLimiterPushLoop(peer, func() XSyncClient { return client })

	// Background driver: bump the tenant counter every 25ms so ExportDelta
	// always has something to report.
	driverStop := make(chan struct{})
	go func() {
		t := time.NewTicker(25 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-driverStop:
				return
			case <-t.C:
				store.AllowTokens("cadence-aa-tenant", 1, 1000000, 0)
			}
		}
	}()

	time.Sleep(1100 * time.Millisecond)
	close(driverStop)
	close(coord.shutdownCh)
	coord.wg.Wait()

	got := srv.calls.Load()
	if got < 4 || got > 12 {
		t.Errorf("A-A cadence: expected 5-10 ticks in 1s (100-200ms jittered), got %d", got)
	}
}

// TestRateLimiterPushAbsoluteEvery10thAA — in A-A mode, every 10th push
// should be a full snapshot (IsDelta=false) for drift insurance. We
// drive enough ticks for at least one absolute fallback (cadence ~150ms
// avg → 15 ticks in 2.5s, so at least 1 absolute at the 10th).
func TestRateLimiterPushAbsoluteEvery10thAA(t *testing.T) {
	t.Parallel()
	srv := &mockRateLimiterServer{}
	client, cleanup := startMockRLServer(t, srv)
	defer cleanup()

	coord := newTestCoordinator(newMockApplier(0))
	coord.haMode.Store("AA")
	store := rl.New()
	store.AllowTokens("absolute-tenant", 1, 1000000, 0)
	coord.SetRateLimiterStore(store)

	peer := &DpPeer{Peer: net.ParseIP("127.0.0.5"), CapMask: 0xFFFFFFFF}
	coord.StartRateLimiterPushLoop(peer, func() XSyncClient { return client })

	// Background driver: continuous activity so deltas remain non-empty
	// every tick (otherwise the push loop correctly short-circuits).
	driverStop := make(chan struct{})
	go func() {
		t := time.NewTicker(25 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-driverStop:
				return
			case <-t.C:
				store.AllowTokens("absolute-tenant", 1, 1000000, 0)
			}
		}
	}()

	// 2.5s at ~150ms average cadence → ~16 ticks → guarantees at least
	// 1 absolute snapshot at the 10th push.
	time.Sleep(2500 * time.Millisecond)
	close(driverStop)
	close(coord.shutdownCh)
	coord.wg.Wait()

	srv.mu.Lock()
	defer srv.mu.Unlock()
	absoluteCount := 0
	for _, b := range srv.batches {
		if !b.IsDelta {
			absoluteCount++
		}
	}
	if absoluteCount < 1 {
		t.Errorf("A-A every-10th absolute fallback: expected >=1 IsDelta=false batch in %d batches, got 0",
			len(srv.batches))
	}
	t.Logf("A-A absolute-fallback count: %d / %d batches", absoluteCount, len(srv.batches))
}

// TestRateLimiterPushL2Discipline integration-checks L-2 by driving the
// push loop while another goroutine concurrently calls CheckKey on the
// same store. The race detector + lack of deadlock confirms no lock is
// held across the gRPC Send. (The static grep gate in 70-B PLAN already
// proves the source-level property; this test is the dynamic
// confirmation under -race.)
func TestRateLimiterPushL2Discipline(t *testing.T) {
	t.Parallel()
	srv := &mockRateLimiterServer{}
	client, cleanup := startMockRLServer(t, srv)
	defer cleanup()

	coord := newTestCoordinator(newMockApplier(0))
	coord.haMode.Store("AP")
	store := rl.New()
	// Seed a few entries.
	for i := 0; i < 10; i++ {
		store.AllowTokens("l2-tenant-"+itoaT(i), 5, 1000000, 0)
	}
	coord.SetRateLimiterStore(store)

	peer := &DpPeer{Peer: net.ParseIP("127.0.0.6"), CapMask: 0xFFFFFFFF}
	coord.StartRateLimiterPushLoop(peer, func() XSyncClient { return client })

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 50 concurrent CheckKey + AllowTokens workers — must NEVER block
	// waiting for the push goroutine's lock (the L-2 invariant).
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					store.CheckKey("l2-key-"+itoaT(id%10), 1000, 1000)
					store.AllowTokens("l2-tenant-"+itoaT(id%10), 1, 1000000, 0)
				}
			}
		}(i)
	}

	time.Sleep(600 * time.Millisecond)
	close(stop)
	wg.Wait()
	close(coord.shutdownCh)
	coord.wg.Wait()

	// At least 1 push must have completed.
	if srv.calls.Load() < 1 {
		t.Errorf("expected at least 1 push to land, got %d", srv.calls.Load())
	}
}

// itoaT — small helper to avoid pulling strconv into this test file.
func itoaT(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// ---------- Scope-version sentinel: sender/receiver contract ----------

// warnRecorded reports whether the coordinator has latched the warn-once key
// for (peerKey, rpcName). warnOncePeerRPC stores exactly this key the first
// time it emits, so the map is a direct, non-vacuous oracle for "did this
// degrade warning fire, and about whom".
func warnRecorded(s *SockproxySync, peerKey, rpcName string) bool {
	_, ok := s.warnOnce.Load(peerKey + "/" + rpcName)
	return ok
}

// TestChunkedPushDoesNotSelfReportAsOldPeer — a push larger than the RPC
// ceiling must not make its own up-to-date sender look like a peer that
// pre-dates the ladder scopes.
//
// Every chunk is an INDEPENDENT RateLimiterSync RPC and the receiver scores
// each one on its own: there is no push identity, sequence number or stream on
// the wire, so a chunk that arrives without the sentinel is indistinguishable
// from a push by a v1 peer. "The sentinel leads the push" is therefore not a
// contract the receiver can honour — only "the sentinel leads every chunk" is.
//
// With the sentinel on the first chunk only, a 1200-entry push from a fully
// current node made that node's own peer log say it "pre-dates the
// per-user/per-key-TPM/keyless quota scopes" — inverting the single signal
// operators have for the unsupported mixed-version posture.
func TestChunkedPushDoesNotSelfReportAsOldPeer(t *testing.T) {
	t.Parallel()
	srv := &mockRateLimiterServer{}
	client, cleanup := startMockRLServer(t, srv)
	defer cleanup()

	sender := newTestCoordinator(newMockApplier(0))
	peer := &DpPeer{Peer: net.ParseIP("127.0.0.1"), CapMask: 0xFFFFFFFF}

	// Comfortably more than one chunk's worth.
	const n = 1200
	entries := make([]rl.RateLimiterEntry, n)
	for i := 0; i < n; i++ {
		entries[i] = rl.RateLimiterEntry{
			KeyID:    "t:chunk-tenant-" + itoaT(i),
			IsTenant: true,
			Consumed: int64(i),
		}
	}
	if err := sender.sendRateLimiterBatch(peer, client, entries, false); err != nil {
		t.Fatalf("sendRateLimiterBatch returned error: %v", err)
	}

	srv.mu.Lock()
	wire := make([]*RateLimiterBatch, len(srv.batches))
	copy(wire, srv.batches)
	srv.mu.Unlock()
	if len(wire) < 2 {
		t.Fatalf("test needs a multi-chunk push to be meaningful, got %d chunk(s)", len(wire))
	}

	// Every chunk must announce the vocabulary, because every chunk is scored
	// alone. This is the property the receiver's check actually depends on.
	for i, b := range wire {
		if len(b.Entries) == 0 || b.Entries[0].KeyId != rl.ScopeSentinelKeyID {
			got := "<empty>"
			if len(b.Entries) > 0 {
				got = b.Entries[0].KeyId
			}
			t.Errorf("chunk %d/%d does not lead with the scope sentinel (got %q); "+
				"the receiver scores each RPC alone and will read it as a v1 peer",
				i, len(wire), got)
		}
		if len(b.Entries) > rlPushBatchMax {
			t.Errorf("chunk %d carries %d entries, over the %d ceiling",
				i, len(b.Entries), rlPushBatchMax)
		}
	}

	// The end-to-end consequence, asserted at the receiver rather than inferred
	// from the wire: feed the captured chunks into a real receiving coordinator
	// and require that it never accuses this sender of being an old peer.
	recv := newTestCoordinator(newMockApplier(0))
	recv.SetRateLimiterStore(rl.New())
	const senderKey = "10.0.0.7:4041"
	for _, b := range wire {
		if err := recv.ApplyRateLimiterBatch(senderKey, b); err != nil {
			t.Fatalf("ApplyRateLimiterBatch: %v", err)
		}
	}
	if warnRecorded(recv, senderKey, "RateLimiterSync/scope-older") {
		t.Errorf("receiver reported an up-to-date sender as pre-dating the ladder scopes")
	}
}

// TestScopeVersionWarningsNameThePeerAndDoNotMask — the two scope-version
// warnings must be attributed to the peer they are about, and must not
// suppress one another.
//
// Both used to pass the literal "rl-scope-ver" where warnOncePeerRPC takes a
// peerKey. That made the warn-once key process-global, so across an entire
// fleet the message fired at most ONCE, logged peer=rl-scope-ver instead of an
// address, and let whichever of the two messages happened first silence the
// other permanently — including silencing a genuine old peer that joined later.
func TestScopeVersionWarningsNameThePeerAndDoNotMask(t *testing.T) {
	t.Parallel()
	recv := newTestCoordinator(newMockApplier(0))
	recv.SetRateLimiterStore(rl.New())

	const oldPeer = "10.0.0.8:4041"
	const newPeer = "10.0.0.9:4041"

	// A peer that pre-dates the ladder scopes: no sentinel at all.
	if err := recv.ApplyRateLimiterBatch(oldPeer, &RateLimiterBatch{
		Entries: []*RateLimiterEntry{{KeyId: "t:tenant-a", IsTenant: true}},
	}); err != nil {
		t.Fatalf("ApplyRateLimiterBatch(old): %v", err)
	}
	// A peer speaking a vocabulary NEWER than this build.
	if err := recv.ApplyRateLimiterBatch(newPeer, &RateLimiterBatch{
		Entries: []*RateLimiterEntry{
			{KeyId: "ver:99", IsTenant: true},
			{KeyId: "t:tenant-b", IsTenant: true},
		},
	}); err != nil {
		t.Fatalf("ApplyRateLimiterBatch(new): %v", err)
	}

	// Both must be recorded. Pre-fix only the first survived: the second hit
	// the same global key and was dropped as a duplicate.
	if !warnRecorded(recv, oldPeer, "RateLimiterSync/scope-older") {
		t.Errorf("no scope-older warning attributed to %s", oldPeer)
	}
	if !warnRecorded(recv, newPeer, "RateLimiterSync/scope-newer") {
		t.Errorf("no scope-newer warning attributed to %s (masked by the other message?)", newPeer)
	}
	// And the warning must not be filed under a literal tag.
	if warnRecorded(recv, "rl-scope-ver", "RateLimiterSync") {
		t.Errorf("warning filed under the literal \"rl-scope-ver\" instead of a peer address")
	}

	// A second old peer must still be reported: warn-once is per peer, not
	// per fleet. This is the case a process-global key loses outright.
	const otherOldPeer = "10.0.0.10:4041"
	if err := recv.ApplyRateLimiterBatch(otherOldPeer, &RateLimiterBatch{
		Entries: []*RateLimiterEntry{{KeyId: "t:tenant-c", IsTenant: true}},
	}); err != nil {
		t.Fatalf("ApplyRateLimiterBatch(old2): %v", err)
	}
	if !warnRecorded(recv, otherOldPeer, "RateLimiterSync/scope-older") {
		t.Errorf("a second old peer went unreported; warn-once must be per peer")
	}
}

// TestSnapshotImportDoesNotResetTheReceiversRpsBuckets — an absolute
// rate-limiter snapshot must not hand the receiving node's own per-key RPS
// buckets a fresh full burst.
//
// ImportState replaces the per-key entries map wholesale and rebuilds each
// limiter from the entry's (RPS, Burst). Those two fields have no slot in
// the wire message — RateLimiterEntry carries key_id, is_tenant,
// last_refill_ns, current_tokens, epoch_start_ts, tokens_consumed and
// exceeded, and rlGoEntryToProto never writes a rate or a burst. So every
// imported limiter arrives as rate.NewLimiter(0, 0), RateLimiterStore.check
// sees a config mismatch on the next call and mints a brand-new FULL bucket.
// The snapshot's per-key half therefore carries nothing the receiver can
// use, and the one thing it does is reset the receiver's live enforcement.
//
// The push is not a once-per-failover event: in A-A mode every tenth push
// is an absolute snapshot, so a serving node is re-zeroed on that cadence
// while it is admitting traffic against those very buckets.
//
// The two halves of the assertion are deliberate. The tenant-quota control
// proves the harness can see synced state arrive at all — without it a
// "bucket still denies" result could just as well mean the push never
// landed.
func TestSnapshotImportDoesNotResetTheReceiversRpsBuckets(t *testing.T) {
	t.Parallel()
	srv := &mockRateLimiterServer{}
	client, cleanup := startMockRLServer(t, srv)
	defer cleanup()

	// The sending node: one per-key bucket and one tenant driven deep into
	// quota debt (a full burst plus a 10% overrun — ~6s of drain, longer
	// than this test runs, so the debt cannot heal before the assertions).
	sendStore := rl.New()
	sendStore.CheckKey("shared-key", 1, 1)
	sendStore.AllowTokens("debt-tenant", 1000000, 1000000, 0)
	sendStore.AllowTokens("debt-tenant", 100000, 1000000, 0)

	sender := newTestCoordinator(newMockApplier(0))
	peer := &DpPeer{Peer: net.ParseIP("127.0.0.9"), CapMask: 0xFFFFFFFF}
	if err := sender.sendRateLimiterBatch(peer, client, sendStore.ExportState(), false); err != nil {
		t.Fatalf("sendRateLimiterBatch: %v", err)
	}

	srv.mu.Lock()
	wire := make([]*RateLimiterBatch, len(srv.batches))
	copy(wire, srv.batches)
	srv.mu.Unlock()
	if len(wire) == 0 {
		t.Fatalf("setup: no batch reached the wire")
	}

	// The receiving node is serving traffic of its own: it has charged the
	// same tenant once (which is what publishes the tenant's limit locally,
	// the denominator the debt check reads against) and has already spent
	// its own burst on the same key.
	recvStore := rl.New()
	recvStore.AllowTokens("debt-tenant", 1, 1000000, 0)
	if ok, _ := recvStore.CheckKey("shared-key", 1, 1); !ok {
		t.Fatalf("setup: the receiver's first request must be admitted")
	}
	if ok, _ := recvStore.CheckKey("shared-key", 1, 1); ok {
		t.Fatalf("setup: the receiver's burst must be spent before the push lands")
	}
	recv := newTestCoordinator(newMockApplier(0))
	recv.SetRateLimiterStore(recvStore)

	const senderKey = "10.0.0.9:4041"
	for _, b := range wire {
		if err := recv.ApplyRateLimiterBatch(senderKey, b); err != nil {
			t.Fatalf("ApplyRateLimiterBatch: %v", err)
		}
	}

	// Control: state really did cross the wire and land in this store.
	if !recvStore.IsTokenQuotaExceeded("debt-tenant") {
		t.Fatalf("control failed: the sender's tenant quota debt did not reach the receiver, " +
			"so the per-key result below proves nothing")
	}

	// Subject: the receiver's own spent bucket must still be spent.
	if ok, _ := recvStore.CheckKey("shared-key", 1, 1); ok {
		t.Errorf("a peer snapshot refilled the receiver's own per-key RPS bucket: " +
			"the request that was refused a moment ago is now admitted")
	}

	// And it is not a one-off: price what each further snapshot is worth to
	// a caller that keeps asking. Every admission here is one the local rate
	// limit had already refused.
	extra := 0
	for i := 0; i < 3; i++ {
		for _, b := range wire {
			if err := recv.ApplyRateLimiterBatch(senderKey, b); err != nil {
				t.Fatalf("ApplyRateLimiterBatch (replay %d): %v", i, err)
			}
		}
		if ok, _ := recvStore.CheckKey("shared-key", 1, 1); ok {
			extra++
		}
	}
	if extra != 0 {
		t.Errorf("%d of 3 replayed snapshots each bought the caller another admission "+
			"past a rate limit that had already refused it", extra)
	}
}

// TestRateLimiterPushDialsItsOwnPeer — the rate-limiter push loop must
// establish its own connection to a peer it has none for.
//
// The loop used to test clientFn() and skip when it came back nil, so the
// rate-limiter half of xsync ran only after something ELSE had dialled.
// Only two paths dial: the session-sync retry and key invalidation. A
// cluster whose traffic is L7 AI does neither, so quota state never
// replicated — and nothing said so, because the skip had no log, no
// counter, and left peer_up at the 0 the consumer loop writes at start.
//
// clientFn here returns nil until the connect hook has run, which is
// exactly the production shape: spClients is empty until connectFn stores
// a client in it.
func TestRateLimiterPushDialsItsOwnPeer(t *testing.T) {
	t.Parallel()
	srv := &mockRateLimiterServer{}
	client, cleanup := startMockRLServer(t, srv)
	defer cleanup()

	coord := newTestCoordinator(newMockApplier(0))
	coord.haMode.Store("AP")
	store := rl.New()
	// Seed one quota entry: ExportState must be non-empty or the loop
	// short-circuits before it ever looks for a client, and the test would
	// pass for the wrong reason.
	store.AllowTokens("dial-tenant", 1, 1000000, 0)
	coord.SetRateLimiterStore(store)

	var connects atomic.Int32
	var connected atomic.Bool
	coord.SetConnectFn(func(string) {
		connects.Add(1)
		connected.Store(true)
	})
	clientFn := func() XSyncClient {
		if connected.Load() {
			return client
		}
		return nil
	}

	peer := &DpPeer{Peer: net.ParseIP("127.0.0.11"), CapMask: 0xFFFFFFFF}
	coord.StartRateLimiterPushLoop(peer, clientFn)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && srv.calls.Load() == 0 {
		time.Sleep(50 * time.Millisecond)
	}
	close(coord.shutdownCh)
	coord.wg.Wait()

	if connects.Load() == 0 {
		t.Fatalf("the push loop never asked the connect hook to dial the peer")
	}
	if got := srv.calls.Load(); got == 0 {
		t.Errorf("no RateLimiterSync reached the peer after the loop dialled it (connects=%d)",
			connects.Load())
	}
}

// TestRateLimiterPushDialIsThrottled — a peer that cannot be dialled must
// not be re-dialled on every tick.
//
// The loop runs at 200ms in A-P and DialXSyncGRPC blocks for up to 2s on a
// TCP probe before it gives up, so an unthrottled retry turns an
// unreachable peer into a permanent connect storm. The bound is one
// attempt per rlDialRetryInterval.
func TestRateLimiterPushDialIsThrottled(t *testing.T) {
	t.Parallel()
	coord := newTestCoordinator(newMockApplier(0))
	coord.haMode.Store("AP")
	store := rl.New()
	store.AllowTokens("throttle-tenant", 1, 1000000, 0)
	coord.SetRateLimiterStore(store)

	var connects atomic.Int32
	coord.SetConnectFn(func(string) { connects.Add(1) })
	// Never connects: the peer is unreachable for the whole run.
	clientFn := func() XSyncClient { return nil }

	peer := &DpPeer{Peer: net.ParseIP("127.0.0.12"), CapMask: 0xFFFFFFFF}
	coord.StartRateLimiterPushLoop(peer, clientFn)

	const run = 2500 * time.Millisecond
	time.Sleep(run)
	close(coord.shutdownCh)
	coord.wg.Wait()

	ticks := int(run / rlPushIntervalAP)         // ~12
	maxDials := int(run/rlDialRetryInterval) + 2 // ~3, with slack for timing
	got := int(connects.Load())
	if got == 0 {
		t.Fatalf("the loop never dialled at all over %v; the throttle cannot be under test", run)
	}
	if got > maxDials {
		t.Errorf("dialled %d times in %v (%d ticks); the throttle allows at most %d",
			got, run, ticks, maxDials)
	}
}
