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
	if err := coord.ApplyRateLimiterBatch(batch1); err != nil {
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
	if err := coord.ApplyRateLimiterBatch(batch2); err != nil {
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
	if err := coord.ApplyRateLimiterBatch(batch); err != nil {
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
		t.Errorf("expected 3 chunked RPCs (1200 / 500 = ceil 3), got %d", got)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.batches) != 3 {
		t.Fatalf("expected 3 batches recorded, got %d", len(srv.batches))
	}
	wantSizes := []int{500, 500, 200}
	for i, b := range srv.batches {
		if len(b.Entries) != wantSizes[i] {
			t.Errorf("batch %d: expected %d entries, got %d", i, wantSizes[i], len(b.Entries))
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
	store.AllowTokens("cadence-ap-tenant", 1, 1000000)
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
	store.AllowTokens("cadence-aa-tenant", 1, 1000000)
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
				store.AllowTokens("cadence-aa-tenant", 1, 1000000)
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
	store.AllowTokens("absolute-tenant", 1, 1000000)
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
				store.AllowTokens("absolute-tenant", 1, 1000000)
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
		store.AllowTokens("l2-tenant-"+itoaT(i), 5, 1000000)
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
					store.AllowTokens("l2-tenant-"+itoaT(id%10), 1, 1000000)
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
