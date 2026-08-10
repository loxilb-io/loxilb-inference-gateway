/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * — Sockproxy HA State Sync. SPEC.md req: A1-A7, D1.
 *
 * Coordinator: drains the CGO event ring, batches outbound RPCs per peer,
 * subscribes to BFD state transitions, performs A-A conflict resolution
 * via the C-side proxy_sync_apply_session_entry() return code, handles
 * rolling-upgrade graceful degrade via per-peer capabilityMask + WARN-once.
 *
 * Singleton ring — DO NOT replicate per-service or per-EP.
 * SPEC §Constraints + RESEARCH Landmine L-13.
 */

package loxinet

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Mirror of proxy_sync_event_t in sockproxy_internal.h.
// MUST stay byte-for-byte compatible. MAX_CONV_ID_LEN = 128 (sockproxy.h:194).
#define MAX_CONV_ID_LEN 128

typedef struct proxy_sync_event {
    int      kind;
    char     service_key[64];
    char     conv_id[MAX_CONV_ID_LEN];
    int      prefill_ep_idx;
    int      decode_ep_idx;
    int      ep_idx;
    uint64_t created_ts;
    uint64_t last_access_ts;
    uint32_t request_count;
} proxy_sync_event_t;

// proxy_sync_apply_session_entry is defined in loxilb-ebpf/common/sockproxy_sync.c.
// Outcome codes:
//   0 = installed/remote_won, 1 = local_kept, 2 = tie_local_kept,
//   3 = health_reject (SPEC A5), -1 = error
extern int proxy_sync_apply_session_entry(const proxy_sync_event_t *ev);

// sockproxy_snapshot_all_sessions dumps all conv_map and pd_session_map
// entries across all services into a calloc'd proxy_sync_event_t array.
// Caller must free(*out_events). Returns 0 on success, -1 on failure.
extern int sockproxy_snapshot_all_sessions(proxy_sync_event_t **out_events, uint32_t *out_count);
*/
import "C"

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	tk "github.com/loxilb-io/loxilib"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	cmn "github.com/loxilb-io/loxilb/common"
	rl "github.com/loxilb-io/loxilb/pkg/ratelimit"
)

// proxySyncEventKind mirrors proxy_sync_event_kind_t in sockproxy_internal.h.
type proxySyncEventKind int32

const (
	syncSessionCreate proxySyncEventKind = 0
	syncSessionUpdate proxySyncEventKind = 1
	syncSessionDelete proxySyncEventKind = 2
	syncConvCreate    proxySyncEventKind = 3
	syncConvUpdate    proxySyncEventKind = 4
	syncConvDelete    proxySyncEventKind = 5
)

// Per-peer RPC-family capability bits stored in DpPeer.CapMask.
// graceful-degrade clears bits on codes.Unimplemented (SPEC D1).
const (
	capSessionSync       uint32 = 1 << 0
	capSessionBulkGet    uint32 = 1 << 1
	capRateLimiterSync   uint32 = 1 << 2
	capSockproxySnapshot uint32 = 1 << 3
)

// proxySyncEvent is the Go-local POD copy of proxy_sync_event_t from C.
// Copied byte-by-byte in llb_sockproxy_emit_sync_event and queued onto
// the singleton event ring. C-side buffer is invalid after the //export
// returns.
type proxySyncEvent struct {
	Kind         proxySyncEventKind
	ServiceKey   string
	ConvID       string
	PrefillEpIdx int32
	DecodeEpIdx  int32
	EpIdx        int32
	CreatedTs    uint64
	LastAccessTs uint64
	RequestCount uint32
}

// kindLabel maps a proxySyncEventKind to its Prometheus overflow-counter label.
// IN-01 + IN-04: previously returned a hardcoded "session" for every kind,
// collapsing the six event categories into one Grafana bucket. Now maps to
// a stable per-kind label so the dashboards can attribute overflow.
func (k proxySyncEventKind) kindLabel() string {
	switch k {
	case syncSessionCreate:
		return "session.create"
	case syncSessionUpdate:
		return "session.update"
	case syncSessionDelete:
		return "session.delete"
	case syncConvCreate:
		return "conv.create"
	case syncConvUpdate:
		return "conv.update"
	case syncConvDelete:
		return "conv.delete"
	default:
		return "session.unknown"
	}
}

// outboundQueueDepth caps the per-peer outbound batch queue.
// CONTEXT "Backpressure shape" pins this to 100 batches; on overflow we
// drop the OLDEST batch and increment outbound_batch overflow counter.
const outboundQueueDepth = 100

// pushTickInterval is the maximum time the drain goroutine will wait before
// flushing an in-progress batch even if it hasn't reached 256 entries.
// Matches SPEC §Req 3 "256 entries OR 100ms timer, whichever first".
const pushTickInterval = 100 * time.Millisecond

// pushBatchMax is the max session entries per SockproxySessionMod call.
const pushBatchMax = 256

// applyInterface decouples the C-side proxy_sync_apply_session_entry call
// from the coordinator so unit tests can inject a deterministic mock.
// Production: real CGO call. Tests: in-memory simulator that mirrors the
// SPEC A5/A6 semantics.
type applyInterface interface {
	Apply(ev proxySyncEvent) int
}

// realApply is the production implementation that crosses the CGO boundary.
type realApply struct{}

// Apply marshals a Go-side proxySyncEvent into a proxy_sync_event_t and
// invokes the C-side handler. Returns the outcome code (0..3 or -1).
func (realApply) Apply(ev proxySyncEvent) int {
	var c C.proxy_sync_event_t
	c.kind = C.int(ev.Kind)
	c.prefill_ep_idx = C.int(ev.PrefillEpIdx)
	c.decode_ep_idx = C.int(ev.DecodeEpIdx)
	c.ep_idx = C.int(ev.EpIdx)
	c.created_ts = C.uint64_t(ev.CreatedTs)
	c.last_access_ts = C.uint64_t(ev.LastAccessTs)
	c.request_count = C.uint32_t(ev.RequestCount)
	// service_key + conv_id are NUL-terminated char[]. strncpy guarantees
	// last-byte NUL because we pre-zero c (auto-init by Go struct alloc).
	// WR-05: C.CString allocates via malloc — we MUST C.free the result,
	// otherwise every Apply call leaks 64+128 bytes per CGO boundary
	// crossing (meaningful within hours at 256-entries/batch × HA traffic).
	if ev.ServiceKey != "" {
		cs := C.CString(ev.ServiceKey)
		C.strncpy(&c.service_key[0], cs, 63)
		C.free(unsafe.Pointer(cs))
	}
	if ev.ConvID != "" {
		cs := C.CString(ev.ConvID)
		C.strncpy(&c.conv_id[0], cs, 127)
		C.free(unsafe.Pointer(cs))
	}
	return int(C.proxy_sync_apply_session_entry(&c))
}

// SockproxySync is the singleton coordinator.
type SockproxySync struct {
	// Inbound event ring (10K cap, drop-oldest on overflow).
	eventCh chan proxySyncEvent

	// Per-peer outbound queues. Each peer drains its own queue serially —
	// single in-flight RPC per peer per RPC family (CONTEXT discretion).
	outboundQueues sync.Map // map[string]chan *SockproxySessionModReq

	// peers references the live DpPeer slice via the dpbroker.
	peersFn func() []DpPeer

	// applier is the C-side proxy_sync_apply_session_entry seam. Real builds
	// use realApply{}; tests inject a mock.
	applier applyInterface

	// warnOnce tracks "WARN once per (peer, RPC-family)" for SPEC D1.
	// Key shape: "peer.IP/RPCName". Value: ignored (presence == emitted).
	warnOnce sync.Map

	// haMode reflects the most recently observed BFD topology: "AP" or "AA".
	haMode atomic.Value // string

	// hysteresisCh is a 5-second debouncer for BFD state-transition events
	//. Multiple rapid OnStateChange calls collapse.
	lastHysteresisAt  atomic.Int64 // unix nanos of last accepted OnStateChange
	lastAcceptedState atomic.Value // string: last state that passed hysteresis (empty=none)

	// shutdownCh signals the drain + per-peer dispatchers to exit cleanly.
	shutdownCh chan struct{}

	// wg tracks coordinator goroutines for clean shutdown.
	wg sync.WaitGroup

	// shutdownOnce guards Stop.
	shutdownOnce sync.Once

	// startOnce guards the drainLoop
	// spawn inside Start(peersFn). The pre-70.1 Start advertised
	// "Idempotent" in its doc-comment but only the peersFn assignment
	// was idempotent — the goroutine spawn was not. Calling Start twice
	// (e.g., once via CGO lazy-init proxySyncInitOnce and once from
	// loxiNetInit) would spawn two drainLoops, both pulling from the
	// same eventCh and writing into the per-peer queues with double
	// frequency, which previously broke the TestSockproxySyncRollingUpgrade
	// goroutine-count tolerance. startOnce makes the spawn truly
	// idempotent.
	startOnce sync.Once

	// : peerConsumerStarted tracks which peer keys
	// already have a per-peer consumer goroutine running. Mirrors
	// rlPushLoopStarted; eager-spawn at Start time (RESEARCH
	// — lazy spawn would drop the very first batch before the dispatcher
	// schedules). Keyed by peer.IP.String.
	peerConsumerStarted sync.Map // map[string]struct{}

	// -B: rate-limiter HA. Handle to the shared RateLimiterStore
	// the per-peer push goroutines call ExportState/ExportDelta on.
	// nil-safe at start: the push loop sleeps until SetRateLimiterStore
	// is invoked (typically from ai_gateway_dp.go on first getGlobalRL).
	rlStore atomic.Pointer[rl.RateLimiterStore]

	// rlPrevSnapshot is the per-peer last-pushed-Consumed map for the
	// A-A gossip-delta path. Keyed first by peer.IP.String, then by
	// the RateLimiterEntry.KeyID (either "t:<id>" for the value or
	// "e:<id>" for the windowEpoch). RESEARCH §4 + 70-B Task B1
	// ExportDelta contract. mu-protected because per-peer goroutines
	// read/write concurrently when peer set changes.
	rlPrevSnapMu sync.Mutex
	rlPrevSnap   map[string]map[string]int64

	// rlPushCounter[peerKey] tracks pushes since the last absolute
	// snapshot fallback in A-A mode. Every 10th push, send a full
	// ExportState snapshot instead of a delta — drift insurance per
	// RESEARCH §4. Atomic-int per peer kept inside the map; the map
	// itself is mu-protected.
	rlPushCounter map[string]*int64

	// rlPushLoopStarted is set once per peer to avoid spawning duplicate
	// push goroutines on repeated SetRateLimiterStore + OnStateChange
	// invocations.
	rlPushLoopStarted sync.Map // map[string]struct{} keyed by peer.IP.String

	// WR-06: inboundDropMu serialises the drop-oldest-then-push pair in
	// sendNonBlockingDropOldest so the overflow counter accounts for
	// every dropped event under concurrent producers.
	inboundDropMu sync.Mutex

	// WR-02: per-peer drop-oldest mutexes for enqueueForPeer. Keyed by
	// peerKey. Created lazily; never deleted (peer set is small).
	peerDropMu sync.Map // map[string]*sync.Mutex

	// connectFn is injected by loxinet.go via SetConnectFn. When the
	// per-peer consumerLoop finds that clientFn returns nil (the gRPC
	// connection was never established or was reset), it calls connectFn
	// to trigger RPCConnect on the live mh.dp.Peers element. Without this
	// hook the consumer silently drops every batch forever because
	// DpWorkOnPeerOp creates peers with Client=nil and only DpXsyncRPC
	// (the CT-sync path) calls RPCConnect lazily — the sockproxy path
	// never went through DpXsyncRPC. Bug Fix.
	connectFn func(peerKey string)

	// spClients holds per-peer XSyncClient instances for the sockproxy
	// gRPC path. This is SEPARATE from DpPeer.Client, which is owned by
	// the CT-sync net/rpc path (netRPCClient). Bug Fix:
	// CT-sync sets pe.Client=*rpc.Client; the sockproxy clientFn was
	// querying peersFn.Client and failing the gRPCClient type assertion.
	// map[string]XSyncClient keyed by peer.Peer.String.
	spClients sync.Map
}

// proxySyncRing is the package-level singleton instance. Created lazily at
// first emit-event arrival.
var (
	proxySyncRing     *SockproxySync
	proxySyncRingOnce sync.Once
)

// proxySyncInitOnce constructs the singleton ring lazily.
func proxySyncInitOnce() *SockproxySync {
	proxySyncRingOnce.Do(func() {
		proxySyncRing = &SockproxySync{
			eventCh:       make(chan proxySyncEvent, 10000),
			shutdownCh:    make(chan struct{}),
			applier:       realApply{},
			rlPrevSnap:    make(map[string]map[string]int64),
			rlPushCounter: make(map[string]*int64),
		}
		proxySyncRing.haMode.Store("AP") // safe default
		tk.LogIt(tk.LogInfo, "[SOCKPROXY_SYNC] inbound ring initialised cap=10000\n")
	})
	return proxySyncRing
}

// NewSockproxySync returns the singleton coordinator. Tests may instead use
// newTestCoordinator to skip goroutine spawning.
func NewSockproxySync() *SockproxySync {
	return proxySyncInitOnce()
}

// Start spawns the coordinator goroutines. Idempotent in BOTH peersFn-set
// and drainLoop-spawn : the drainLoop
// goroutine is gated by startOnce so repeat Start calls cannot spawn a
// second drainer. The peersFn assignment is also idempotent — most-recent
// non-nil wins, mirroring SetRateLimiterStore's atomic-swap pattern.
//
// Per-peer consumer goroutines are eagerly spawned on every Start call
// for every peer returned by peersFn that does not already have one
// running. Repeat Start calls (e.g., after a
// peer-add) safely fan out to the newly-discovered peers without
// re-spawning consumers for existing peers (guard via peerConsumerStarted
// sync.Map).
//
// Pass nil peersFn to skip outbound dispatch (test mode).
func (s *SockproxySync) Start(peersFn func() []DpPeer) {
	if peersFn != nil {
		s.peersFn = peersFn
	}
	s.startOnce.Do(func() {
		s.wg.Add(1)
		go s.drainLoop()
	})
	// Eagerly spawn per-peer consumers for whichever peer set peersFn
	// reports at this instant. Idempotent across repeat Start calls
	// (peerConsumerStarted guards each peerKey). If peersFn is nil we
	// skip — test mode with no outbound dispatch.
	if s.peersFn != nil {
		s.spawnConsumersForKnownPeers()
	}
}

// SetConnectFn injects the RPCConnect hook. Called by loxinet.go after
// Start so the per-peer consumerLoop can trigger gRPC dial when it finds
// a nil client (DpWorkOnPeerOp creates peers with Client=nil; only
// DpXsyncRPC connects lazily on the CT-sync path — sockproxy never goes
// through that path). Bug Fix.
func (s *SockproxySync) SetConnectFn(fn func(peerKey string)) {
	s.connectFn = fn
}

// StoreGRPCClient caches a freshly-dialed XSyncClient for peerKey in
// spClients. Called by the connectFn injected from loxinet.go after a
// successful DialXSyncGRPC. Bug Fix.
func (s *SockproxySync) StoreGRPCClient(peerKey string, c XSyncClient) {
	s.spClients.Store(peerKey, c)
}

// spawnConsumersForKnownPeers iterates s.peersFn and for each peer that
// does not yet have a consumer goroutine, registers it in
// peerConsumerStarted and spawns s.consumerLoop. Safe to call repeatedly;
// repeat calls only spawn for newly-added peers (+
// RESEARCH eager-not-lazy).
func (s *SockproxySync) spawnConsumersForKnownPeers() {
	peers := s.peersFn()
	for i := range peers {
		// IMPORTANT: capture by index, not the loop variable — so the
		// consumer's `peer *DpPeer` (CapMask tracking) is stable for its
		// lifetime.
		pe := peers[i]
		peerKey := pe.Peer.String()
		if _, loaded := s.peerConsumerStarted.LoadOrStore(peerKey, struct{}{}); loaded {
			continue
		}
		// Build a clientFn that reads from spClients — the dedicated
		// sockproxy gRPC client map. This is separate from pe.Client
		// (owned by CT-sync net/rpc). Bug Fix: the previous
		// peersFn-based lookup was returning *rpc.Client (set by
		// CT-sync), which failed the gRPCClient type assertion → nil.
		clientFn := func() XSyncClient {
			if c, ok := s.spClients.Load(peerKey); ok && c != nil {
				return c.(XSyncClient)
			}
			return nil
		}
		s.wg.Add(1)
		peerCopy := pe
		go s.consumerLoop(&peerCopy, peerKey, clientFn)
		// GAP 2 fix: spawn RL push goroutine alongside session push.
		// SetRateLimiterStore is called once from ai_gateway_dp.go; the push
		// loop skips each tick until the store is registered (nil guard inside
		// rateLimiterPushLoop), so ordering is safe.
		s.StartRateLimiterPushLoop(&peerCopy, clientFn)
	}
}

// consumerLoop is the per-peer SockproxySessionMod dispatcher
// ). Drains the peer's outbound queue and issues sendOnce-wrapped
// gRPC calls with exponential-backoff retry semantics:
//
//   - 3 retries on transient gRPC error (initial attempt + 3 retries = 4
//     total RPC attempts)
//
// - backoff = min(100ms * 2^attempt, 5s)
//   - on retry exhaustion: drop the batch + increment
//     loxilb_sockproxy_sync_drop_total{reason="peer_unreachable"}
//   - codes.Unimplemented is handled by sendOnce (clears capSessionSync
//     bit + WARN-once); the consumer treats that as immediate success
//     and moves on (no retry storm)
//
// Lifetime: until s.shutdownCh closes. Stop blocks on wg.Wait until
// every spawned consumer exits — RESEARCH.
func (s *SockproxySync) consumerLoop(peer *DpPeer, peerKey string, clientFn func() XSyncClient) {
	defer s.wg.Done()

	q := s.peerQueue(peerKey)
	tk.LogIt(tk.LogInfo, "[SOCKPROXY_SYNC] consumerLoop start peer=%s\n", peerKey)

	for {
		// Outer select: wait for either a queued message or shutdown.
		select {
		case <-s.shutdownCh:
			tk.LogIt(tk.LogInfo, "[SOCKPROXY_SYNC] consumerLoop exit peer=%s\n", peerKey)
			return
		case msg := <-q:
			if msg == nil {
				continue
			}
			s.sendWithRetry(peer, peerKey, clientFn, msg)
		}
	}
}

// sendWithRetry encapsulates retry loop for a single batch.
// Separated from consumerLoop so the shutdown branch and the message
// branch can both share the retry shape without nested-select sprawl.
func (s *SockproxySync) sendWithRetry(peer *DpPeer, peerKey string, clientFn func() XSyncClient, msg *SockproxySessionModReq) {
	const maxRetries = 3
	const baseBackoff = 100 * time.Millisecond
	const maxBackoff = 5 * time.Second

	attempt := 0
	for {
		client := clientFn()
		if client == nil {
			// Peer not connected yet (pe.Client == nil before RPCConnect).
			// Bug Fix: trigger RPCConnect via the injected
			// connectFn so the next clientFn call sees the live Client.
			// Without this hook batches were silently dropped forever
			// because DpWorkOnPeerOp never calls RPCConnect.
			tk.LogIt(tk.LogWarning, "[XSYNC] peer=%s no gRPC client; triggering RPCConnect\n", peerKey)
			if s.connectFn != nil {
				s.connectFn(peerKey)
				client = clientFn() // re-check after connect attempt
			}
			if client == nil {
				tk.LogIt(tk.LogDebug, "[XSYNC] peer=%s still no client after RPCConnect; skipping batch (entries=%d)\n",
					peerKey, len(msg.Entries))
				return
			}
		}
		err, _ := s.sendOnce(peer, client, msg)
		if err == nil {
			tk.LogIt(tk.LogInfo, "[XSYNC_SEND] peer=%s entries=%d sent ok\n", peerKey, len(msg.Entries))
			return
		}
		// On error, decide whether to retry.
		if attempt >= maxRetries {
			s.spClients.Delete(peerKey) // stale conn; force reconnect on next batch
			tk.LogIt(tk.LogWarning, "[SOCKPROXY_SYNC] consumerLoop peer=%s dropping batch after %d retries: %v\n",
				peerKey, maxRetries, err)
			prom.SockproxySyncDropInc("peer_unreachable")
			return
		}
		attempt++
		// Exponential backoff: 100ms * 2^(attempt-1) capped at 5s.
		shift := attempt - 1
		if shift < 0 {
			shift = 0
		}
		backoff := baseBackoff << shift
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		select {
		case <-s.shutdownCh:
			// Shutdown during backoff — abandon the in-flight batch
			// (would have been dropped anyway after retries).
			return
		case <-time.After(backoff):
		}
	}
}

// clientFromPeer extracts the live XSyncClient from a DpPeer.Client
// (interface{} typed in dpbroker.go). The production gRPC implementation
// is xsync_client.go gRPCClient{xclient: XSyncClient}; tests inject the
// XSyncClient directly (no wrapper). This helper handles both cases.
func clientFromPeer(raw interface{}) XSyncClient {
	if raw == nil {
		return nil
	}
	// Test path: raw is already an XSyncClient.
	if c, ok := raw.(XSyncClient); ok {
		return c
	}
	// Production path: raw is a gRPCClient struct holding an XSyncClient.
	// Use a structural-typed accessor to avoid an import cycle reference
	// to the unexported gRPCClient.xclient field.
	if accessor, ok := raw.(interface{ XSyncClient() XSyncClient }); ok {
		return accessor.XSyncClient()
	}
	// Last-ditch: see if raw exposes the SockproxySessionMod method
	// directly (interface-typed peer Client). Behaves as an XSyncClient
	// for our purposes since SockproxySessionMod is the only RPC the
	// consumer issues.
	if c, ok := raw.(XSyncClient); ok {
		return c
	}
	return nil
}

// Stop signals graceful shutdown and waits for all coordinator goroutines.
// Safe to call multiple times.
func (s *SockproxySync) Stop() {
	s.shutdownOnce.Do(func() {
		close(s.shutdownCh)
	})
	s.wg.Wait()
}

// OnStateChange is the BFD state-transition hook called from cluster.go.
// Re-evaluates HA mode (A-P vs A-A) and on master-promotion triggers a
// chunked-pull bulk snapshot from the new master. Dispatcher in cluster.go
// MUST invoke via `go ...`.
//
// 5-second hysteresis: collapses rapid SAME-STATE flapping.
// Different-state transitions within the 5s window are legitimate role
// changes (e.g., keepalived initial-BACKUP at T=0 then promoted-MASTER at
// T=3s) and MUST pass through. The original implementation blanket-dropped
// every call within 5s of the last, which permanently suppressed legitimate
// BACKUP→MASTER transitions on bringup → MASTER never registered → emit
// drain loop saw BACKUP role → all events dropped → xSync silent on the
// wire even though transport + init were healthy. Defect #5 from Plan
// 70.3-03 live-triage: confirmed via tcpdump on port 22222 captured 0
// packets during a 30-session burst because s.peersFn was never invoked.
func (s *SockproxySync) OnStateChange(instance, state string) {
	now := time.Now().UnixNano()
	// WR-03: CAS-loop the hysteresis window so two near-simultaneous BFD
	// transitions cannot both pass the 5s gate and double-invoke the
	// master-promotion path. Plain Load+Store had a TOCTOU race where
	// both callers read the same stale 'last' and both proceeded.
	for {
		last := s.lastHysteresisAt.Load()
		if last != 0 && (now-last) < int64(5*time.Second) {
			lastState, _ := s.lastAcceptedState.Load().(string)
			if state == lastState {
				tk.LogIt(tk.LogDebug, "[SOCKPROXY_SYNC] OnStateChange suppressed by 5s hysteresis (same-state repeat: instance=%s state=%s)\n",
					instance, state)
				return
			}
			// Different state within window — legitimate transition; fall through.
		}
		if s.lastHysteresisAt.CompareAndSwap(last, now) {
			s.lastAcceptedState.Store(state)
			break
		}
		// Another goroutine advanced the timestamp under us — re-check
		// the window on the next iteration.
	}

	tk.LogIt(tk.LogInfo, "[SOCKPROXY_SYNC] OnStateChange instance=%s state=%s\n", instance, state)
	// Mode re-evaluation: more than one master ⇒ A-A, exactly one master ⇒ A-P.
	//
	// count cluster *instances* in MASTER state via ClusterMap, NOT
	// cluster nodes via NodeMap. NodeMap entries have no MASTER/BACKUP
	// field — they just enumerate the cluster's nodes — so the old loop
	// incremented nMaster for every entry (including BACKUP), flipping a
	// 2-node A-P deployment to "AA" forever and selecting the wrong
	// cadence in the rate-limiter push loop. ClusterMap is keyed by
	// instance and ClusterInstance.StateStr carries the live MASTER/BACKUP/
	// FAULT string from CIStateUpdate.
	if mh.has != nil {
		nMaster := 0
		mh.mtx.RLock()
		for _, ci := range mh.has.ClusterMap {
			if ci.StateStr == cmn.CIMasterStateString {
				nMaster++
			}
		}
		mh.mtx.RUnlock()
		if nMaster > 1 {
			s.haMode.Store("AA")
		} else {
			s.haMode.Store("AP")
		}
	}

	// fix: on MASTER promotion, re-run spawnConsumersForKnownPeers
	// to close the startup-order race documented in
	// sockproxy-prod-wiring/WIRING-PROBE.md. Start at boot runs BEFORE BFD
	// elects this node MASTER, so the role-gated peersFn returns nil and zero
	// per-peer consumer goroutines spawn. Without this hook the elected
	// MASTER drains its inbound ring into peerQueue but no consumer pushes
	// events out over the xsync gRPC channel.
	//
	// Idempotent: spawnConsumersForKnownPeers iterates peers and skips any
	// peerKey already present in peerConsumerStarted sync.Map (declared at
	// line 236, LoadOrStore guard at line 348). The 5-second hysteresis at
	// lines 44 above is the first defense layer against rapid repeat
	// invocations; peerConsumerStarted is the second.
	//
	// Test-mode contract preserved: Start with a nil peersFn (or a peersFn
	// that returns nil) followed by OnStateChange("MASTER") MUST NOT call
	// spawnConsumersForKnownPeers. The `s.peersFn != nil` guard enforces
	// this, mirroring the Start call site at lines 330-332.
	//
	// Lock safety: OnStateChange is dispatched in its own goroutine
	// (pkg/loxinet/cluster.go:549 via `go ...`). The mh.mtx.RLock above is
	// released at line 535 BEFORE this block runs. In production peersFn
	// (loxinet.go:553-583 closure) re-acquires mh.mtx.RLock + mh.dp.SyncMtx.
	// RLock — both read locks on different mutexes, neither held here. Safe.
	if state == cmn.CIMasterStateString && s.peersFn != nil {
		s.spawnConsumersForKnownPeers()
	}
}

// drainLoop pulls events from eventCh, batches up to pushBatchMax or
// pushTickInterval (whichever first), serialises into SockproxySessionModReq,
// and fans out to all peers via their outbound queues.
func (s *SockproxySync) drainLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(pushTickInterval)
	defer ticker.Stop()

	var batch []*SockproxySessionEntry

	flush := func() {
		if len(batch) == 0 {
			return
		}
		msg := &SockproxySessionModReq{Add: true, Entries: batch}
		numPeers := 0
		if s.peersFn != nil {
			peers := s.peersFn()
			numPeers = len(peers)
			for _, pe := range peers {
				s.enqueueForPeer(pe.Peer.String(), msg)
			}
		}
		tk.LogIt(tk.LogInfo, "[XSYNC_FLUSH] batch_size=%d peers=%d\n", len(batch), numPeers)
		batch = nil
	}

	for {
		select {
		case <-s.shutdownCh:
			flush()
			return
		case ev := <-s.eventCh:
			entry := s.eventToEntry(ev)
			if entry != nil {
				batch = append(batch, entry)
				if len(batch) >= pushBatchMax {
					flush()
				}
			}
		case <-ticker.C:
			flush()
		}
	}
}

// eventToEntry converts a Go-local proxySyncEvent into a wire-level
// SockproxySessionEntry for SockproxySessionMod batching.
func (s *SockproxySync) eventToEntry(ev proxySyncEvent) *SockproxySessionEntry {
	deleted := ev.Kind == syncSessionDelete || ev.Kind == syncConvDelete
	return &SockproxySessionEntry{
		ServiceKey:   ev.ServiceKey,
		ConvId:       ev.ConvID,
		PrefillEpIdx: ev.PrefillEpIdx,
		DecodeEpIdx:  ev.DecodeEpIdx,
		EpIdx:        ev.EpIdx,
		CreatedTs:    int64(ev.CreatedTs),
		LastAccessTs: int64(ev.LastAccessTs),
		RequestCount: ev.RequestCount,
		Deleted:      deleted,
	}
}

// enqueueForPeer pushes msg onto the per-peer outbound queue. Drop-oldest on
// overflow (CONTEXT "Backpressure shape").
//
// WR-02: serialise the drop-then-push pair under a per-peer mutex so every
// dropped batch increments the overflow counter exactly once. Without
// serialisation a concurrent producer could refill the channel between the
// receive and the second send, silently losing the new batch.
func (s *SockproxySync) enqueueForPeer(peerKey string, msg *SockproxySessionModReq) {
	q := s.peerQueue(peerKey)
	// Fast path: lock-free send.
	select {
	case q <- msg:
		return
	default:
	}
	// Slow path: queue full. Serialise drop + retry under per-peer mutex.
	mu := s.peerDropMutex(peerKey)
	mu.Lock()
	defer mu.Unlock()
	// Re-check under the lock — peer dispatcher may have drained.
	select {
	case q <- msg:
		return
	default:
	}
	select {
	case <-q:
		prom.SockproxySyncOverflowInc("outbound_batch")
	default:
		// Queue raced empty between our two non-blocking sends. Best-
		// effort push; if it still fails, count as overflow.
		select {
		case q <- msg:
		default:
			prom.SockproxySyncOverflowInc("outbound_batch")
		}
		return
	}
	select {
	case q <- msg:
	default:
		prom.SockproxySyncOverflowInc("outbound_batch")
	}
}

// peerDropMutex returns the per-peer drop-oldest serialisation mutex
// (creating on first reference). Used by enqueueForPeer to ensure the
// overflow counter accounts for every dropped batch.
func (s *SockproxySync) peerDropMutex(peerKey string) *sync.Mutex {
	if v, ok := s.peerDropMu.Load(peerKey); ok {
		return v.(*sync.Mutex)
	}
	mu := &sync.Mutex{}
	actual, _ := s.peerDropMu.LoadOrStore(peerKey, mu)
	return actual.(*sync.Mutex)
}

// peerQueue returns (creating on first reference) the outbound channel for
// peerKey. The channel is goroutine-fed; a per-peer dispatcher reads from it.
func (s *SockproxySync) peerQueue(peerKey string) chan *SockproxySessionModReq {
	if v, ok := s.outboundQueues.Load(peerKey); ok {
		return v.(chan *SockproxySessionModReq)
	}
	q := make(chan *SockproxySessionModReq, outboundQueueDepth)
	actual, loaded := s.outboundQueues.LoadOrStore(peerKey, q)
	if loaded {
		return actual.(chan *SockproxySessionModReq)
	}
	return q
}

// sendOnce attempts a single unary SockproxySessionMod RPC to peer.
// Returns (lastErr, cleared). cleared==true if the call hit codes.Unimplemented
// and we cleared the capSessionSync bit on the peer's CapMask.
func (s *SockproxySync) sendOnce(peer *DpPeer, client XSyncClient, msg *SockproxySessionModReq) (error, bool) {
	peerKey := peer.Peer.String()
	if peer.CapMask&capSessionSync == 0 {
		// Capability already cleared; pretend success to avoid retry storm.
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	prom.SockproxySyncInflightRpcInc(peerKey)
	start := time.Now()
	_, err := client.SockproxySessionMod(ctx, msg)
	prom.SockproxySyncPushLatencyObserve(peerKey, "SockproxySessionMod", time.Since(start).Seconds())
	prom.SockproxySyncInflightRpcDec(peerKey)

	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			// Clear capability + WARN once per (peer, RPC-family).
			atomic.AndUint32(&peer.CapMask, ^capSessionSync)
			s.warnOncePeerRPC(peerKey, "SockproxySessionMod",
				"peer returned Unimplemented; clearing capability bit and degrading gracefully")
			return nil, true
		}
		return err, false
	}
	return nil, false
}

// warnOncePeerRPC emits a single tk.LogWarning the first time the
// (peerKey, rpcName) tuple is seen. Subsequent occurrences are silent.
// SPEC D1 rolling-upgrade behaviour.
func (s *SockproxySync) warnOncePeerRPC(peerKey, rpcName, msg string) {
	key := peerKey + "/" + rpcName
	if _, loaded := s.warnOnce.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	tk.LogIt(tk.LogWarning, "[SOCKPROXY_SYNC] %s peer=%s rpc=%s: %s\n",
		"degrade", peerKey, rpcName, msg)
}

// ApplyOne is invoked by the gRPC server side (xsync_server.go) for each
// received SockproxySessionEntry. Returns the outcome code from the
// C-side proxy_sync_apply_session_entry call, with the conflict-resolution
// and health-reject metrics incremented appropriately.
func (s *SockproxySync) ApplyOne(e *SockproxySessionEntry) int {
	ev := proxySyncEvent{
		ServiceKey:   e.ServiceKey,
		ConvID:       e.ConvId,
		PrefillEpIdx: e.PrefillEpIdx,
		DecodeEpIdx:  e.DecodeEpIdx,
		EpIdx:        e.EpIdx,
		CreatedTs:    uint64(e.CreatedTs),
		LastAccessTs: uint64(e.LastAccessTs),
		RequestCount: e.RequestCount,
	}
	if e.Deleted {
		ev.Kind = syncSessionDelete
	} else {
		ev.Kind = syncSessionUpdate // CREATE vs UPDATE indistinguishable at receiver
	}
	outcome := s.applier.Apply(ev)
	tk.LogIt(tk.LogInfo, "[XSYNC_APPLY] svc=%s conv=%s ep_idx=%d prefill=%d decode=%d outcome=%d\n",
		e.ServiceKey, e.ConvId, e.EpIdx, e.PrefillEpIdx, e.DecodeEpIdx, outcome)
	switch outcome {
	case 0:
		prom.SockproxySyncConflictInc("remote_won")
	case 1:
		prom.SockproxySyncConflictInc("local_kept")
	case 2:
		prom.SockproxySyncConflictInc("tie_local_kept")
	case 3:
		prom.SockproxySyncHealthRejectInc("local_unhealthy")
	default:
		if outcome < 0 {
			// Outright apply failure (unknown service, malformed entry) —
			// previously invisible in every sync metric.
			prom.SockproxySyncApplyErrorInc()
		}
	}
	return outcome
}

// sendNonBlockingDropOldest queues ev onto eventCh, with drop-oldest semantics.
//
// WR-06: the drop-then-push pair must be serialised, otherwise a concurrent
// producer can refill the channel between the receive (drop oldest) and the
// retry send, causing the new event to be silently lost without an overflow
// increment. Hold inboundDropMu only on the slow path (channel was full); the
// fast path (initial non-blocking send succeeds) takes no lock.
func (s *SockproxySync) sendNonBlockingDropOldest(ev proxySyncEvent) {
	// Fast path: lock-free send.
	select {
	case s.eventCh <- ev:
		return
	default:
	}
	// Slow path: channel full. Serialise drop + retry so every dropped
	// event increments the overflow counter exactly once.
	s.inboundDropMu.Lock()
	defer s.inboundDropMu.Unlock()
	// Re-check under the lock — another goroutine may have drained.
	select {
	case s.eventCh <- ev:
		return
	default:
	}
	select {
	case <-s.eventCh:
		prom.SockproxySyncOverflowInc(ev.Kind.kindLabel())
	default:
		// Channel went from full to empty between our two non-blocking
		// sends without us draining it. Best-effort send; if it still
		// fails count it as overflow.
		select {
		case s.eventCh <- ev:
		default:
			prom.SockproxySyncOverflowInc(ev.Kind.kindLabel())
		}
		return
	}
	// We removed an element; retry send under the lock so no other
	// producer can refill before us.
	select {
	case s.eventCh <- ev:
	default:
		// Should not happen (we just drained), but count if it does.
		prom.SockproxySyncOverflowInc(ev.Kind.kindLabel())
	}
}

// PullSnapshot performs a chunked-pull snapshot from peer using the
// GetSockproxySnapshot RPC. Page size = 500 (SPEC §Constraints + planner
// reconciliation). Returns total entries applied, or an error on failure.
//
// Used by OnStateChange master-promotion path and by 70-L harness.
func (s *SockproxySync) PullSnapshot(ctx context.Context, client XSyncClient) (int, error) {
	applied := 0
	cursor := ""
	// WR-04 safeguard: cap iterations to prevent a buggy/malicious peer
	// from pinning the master-promotion goroutine in an infinite loop by
	// always returning a non-empty NextCursor. 1000 iters × 500 entries
	// per page = 500K entries, well above any realistic session count.
	const maxPullIterations = 1000
	for iter := 0; iter < maxPullIterations; iter++ {
		req := &SockproxyBulkReq{Cursor: cursor, PageSize: 500}
		reply, err := client.GetSockproxySnapshot(ctx, req)
		if err != nil {
			return applied, err
		}
		if reply == nil {
			// Defensive: protoc-generated stubs typically return non-nil
			// but a streaming-RPC migration could change that.
			break
		}
		for _, e := range reply.Sessions {
			// symmetric nil-check with xsync_server.go ApplyOne loop.
			// A malformed protobuf reply with a nil element must not panic
			// the master-promotion bulk-pull caller.
			if e == nil {
				continue
			}
			s.ApplyOne(e)
			applied++
		}
		cursor = reply.NextCursor
		if cursor == "" {
			break
		}
	}
	return applied, nil
}

// ---------- CGO export — invoked from C sockproxy after emit-after-unlock ----------

// llb_sockproxy_emit_sync_event is the C-callable CGO //export invoked from
// loxilb-ebpf/common/sockproxy_pd.c and sockproxy_ep.c after each state-
// changing mutation. Mirrors llb_ai_validate_key at ai_gateway_dp.go:14.
//
// Returns void: C-side producer NEVER blocks. Overflow drops oldest +
// increments loxilb_sockproxy_sync_overflow_total counter.
//
//export llb_sockproxy_emit_sync_event
func llb_sockproxy_emit_sync_event(ev *C.proxy_sync_event_t) {
	if ev == nil {
		return
	}
	s := proxySyncInitOnce()

	local := proxySyncEvent{
		Kind:         proxySyncEventKind(ev.kind),
		ServiceKey:   C.GoString(&ev.service_key[0]),
		ConvID:       C.GoString(&ev.conv_id[0]),
		PrefillEpIdx: int32(ev.prefill_ep_idx),
		DecodeEpIdx:  int32(ev.decode_ep_idx),
		EpIdx:        int32(ev.ep_idx),
		CreatedTs:    uint64(ev.created_ts),
		LastAccessTs: uint64(ev.last_access_ts),
		RequestCount: uint32(ev.request_count),
	}

	tk.LogIt(tk.LogInfo, "[XSYNC_EMIT] kind=%d svc=%s conv=%s ep_idx=%d prefill=%d decode=%d\n",
		int(local.Kind), local.ServiceKey, local.ConvID, local.EpIdx, local.PrefillEpIdx, local.DecodeEpIdx)

	s.sendNonBlockingDropOldest(local)
}

// ---------- Test helpers ----------

// newTestCoordinator returns a SockproxySync without spawning push goroutines
// and with a deterministic mock applier. Used only by sockproxy_sync_test.go.
// Mirrors the pkg/ratelimit/ratelimit_test.go:27-32 newTestStore pattern.
func newTestCoordinator(app applyInterface) *SockproxySync {
	s := &SockproxySync{
		eventCh:       make(chan proxySyncEvent, 10000),
		shutdownCh:    make(chan struct{}),
		applier:       app,
		rlPrevSnap:    make(map[string]map[string]int64),
		rlPushCounter: make(map[string]*int64),
	}
	s.haMode.Store("AP")
	return s
}

// ---------- -B: Rate-limiter HA push goroutines + handler ----------

// rlPushBatchMax caps the number of RateLimiterEntry per RateLimiterSync RPC.
// SPEC §Constraints: 500 entries per call (well under 4 MB protobuf ceiling).
const rlPushBatchMax = 500

// rlAbsoluteFallbackEvery controls how often the A-A gossip-delta path
// inserts a full absolute-snapshot push as drift insurance. Per RESEARCH
// §4: "every Nth push (e.g., every 10th = ~2s), send absolute full
// snapshot instead of delta. Insurance against drift from missed
// messages."
const rlAbsoluteFallbackEvery = 10

// rlPushIntervalAP is the A-P snapshot cadence per SPEC §Req 9.
const rlPushIntervalAP = 200 * time.Millisecond

// rlPushIntervalAAMin / rlPushIntervalAAMax bracket the jittered A-A
// gossip-delta cadence per SPEC §Req 9 ("100-200ms jittered").
const (
	rlPushIntervalAAMin = 100 * time.Millisecond
	rlPushIntervalAAMax = 200 * time.Millisecond
)

// SetRateLimiterStore registers the shared *ratelimit.RateLimiterStore
// handle with the coordinator. Safe to call multiple times — the most
// recent handle wins (atomic.Pointer swap). Typically invoked exactly
// once from ai_gateway_dp.go on first getGlobalRL.
//
// After registration, the per-peer push goroutines (spawned via
// StartRateLimiterPushLoop) will begin pulling state from the store on
// the configured cadence. Before registration, the push goroutines
// sleep on their ticker and skip publishing.
func (s *SockproxySync) SetRateLimiterStore(store *rl.RateLimiterStore) {
	s.rlStore.Store(store)
	tk.LogIt(tk.LogInfo, "[SOCKPROXY_SYNC] RateLimiterStore registered with coordinator\n")
}

// StartRateLimiterPushLoop spawns a per-peer goroutine that pushes
// rate-limiter state on the cadence dictated by the current HA mode.
// Idempotent per peer — repeated calls for the same peer key are no-ops
// (guarded by rlPushLoopStarted sync.Map).
//
// In A-P mode the master pushes a full snapshot every 200 ms. In A-A
// mode each node pushes a consumed-delta every 100-200 ms (uniform-
// random jitter to avoid synchronised peers). Every 10th push in A-A
// mode is upgraded to a full snapshot for drift insurance.
//
// The caller must provide a clientFn that returns the live XSyncClient
// for the peer at dispatch time — this defers gRPC connection
// resolution until each push, surviving connection resets without
// requiring re-Start.
func (s *SockproxySync) StartRateLimiterPushLoop(peer *DpPeer, clientFn func() XSyncClient) {
	if peer == nil || clientFn == nil {
		return
	}
	peerKey := peer.Peer.String()
	if _, loaded := s.rlPushLoopStarted.LoadOrStore(peerKey, struct{}{}); loaded {
		return // already running
	}
	s.wg.Add(1)
	go s.rateLimiterPushLoop(peer, peerKey, clientFn)
}

// rateLimiterPushLoop is the per-peer goroutine body. Selects between
// the A-P 200ms ticker and the A-A 100-200ms jittered timer based on
// the coordinator's current haMode at each tick. The timer/ticker is
// re-armed on every iteration to handle mode flips cleanly.
func (s *SockproxySync) rateLimiterPushLoop(peer *DpPeer, peerKey string, clientFn func() XSyncClient) {
	defer s.wg.Done()

	// Per-peer RNG seeded with peerKey hash + Unix nano. Avoids
	// synchronised jitter across peers if two coordinators start
	// simultaneously.
	rng := rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(hashStringForJitter(peerKey))))

	for {
		// Compute next-tick interval based on current HA mode.
		mode, _ := s.haMode.Load().(string)
		var interval time.Duration
		if mode == "AA" {
			interval = rlPushIntervalAAMin +
				time.Duration(rng.Int63n(int64(rlPushIntervalAAMax-rlPushIntervalAAMin+1)))
		} else {
			interval = rlPushIntervalAP
		}

		select {
		case <-s.shutdownCh:
			return
		case <-time.After(interval):
		}

		// Skip if no store registered yet.
		store := s.rlStore.Load()
		if store == nil {
			continue
		}

		// Skip if peer capability bit cleared.
		if atomic.LoadUint32(&peer.CapMask)&capRateLimiterSync == 0 {
			continue
		}

		client := clientFn()
		if client == nil {
			continue // peer disconnected; wait for next tick
		}

		// Decide push shape: snapshot (A-P, or every-10th in A-A) vs delta (A-A).
		mode2, _ := s.haMode.Load().(string)
		var (
			entries []rl.RateLimiterEntry
			isDelta bool
		)
		if mode2 == "AA" {
			ctr := s.getOrCreatePushCounter(peerKey)
			n := atomic.AddInt64(ctr, 1)
			if n%rlAbsoluteFallbackEvery == 0 {
				// Drift-insurance absolute snapshot.
				entries = store.ExportState()
				isDelta = false
			} else {
				prev := s.copyPrevSnapshot(peerKey)
				entries = store.ExportDelta(prev)
				isDelta = true
			}
		} else {
			// A-P: full snapshot every tick.
			entries = store.ExportState()
			isDelta = false
		}

		if len(entries) == 0 {
			continue
		}
		if err := s.sendRateLimiterBatch(peer, client, entries, isDelta); err != nil {
			tk.LogIt(tk.LogDebug, "[SOCKPROXY_SYNC] RateLimiterSync push to peer=%s failed: %v\n", peerKey, err)
		}
	}
}

// sendRateLimiterBatch chunks `entries` at rlPushBatchMax and dispatches
// them via sequential RateLimiterSync RPCs. On codes.Unimplemented the
// capRateLimiterSync bit is cleared and a single WARN logged.
//
// CRITICAL (integration): the entries slice was materialised
// by store.ExportState / store.ExportDelta — both of which release
// the RateLimiterStore mutex BEFORE returning. The gRPC Send below
// therefore runs with NO RateLimiterStore lock held. The grep gate in
// 70-B-PLAN verify step proves this property at the source level.
func (s *SockproxySync) sendRateLimiterBatch(peer *DpPeer, client XSyncClient,
	entries []rl.RateLimiterEntry, isDelta bool) error {

	peerKey := peer.Peer.String()
	for start := 0; start < len(entries); start += rlPushBatchMax {
		end := start + rlPushBatchMax
		if end > len(entries) {
			end = len(entries)
		}
		batch := entries[start:end]
		protoBatch := &RateLimiterBatch{
			IsDelta: isDelta,
			Entries: make([]*RateLimiterEntry, 0, len(batch)),
		}
		for i := range batch {
			protoBatch.Entries = append(protoBatch.Entries, rlGoEntryToProto(&batch[i]))
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		prom.SockproxySyncInflightRpcInc(peerKey)
		tStart := time.Now()
		_, err := client.RateLimiterSync(ctx, protoBatch)
		prom.SockproxySyncPushLatencyObserve(peerKey, "RateLimiterSync", time.Since(tStart).Seconds())
		prom.SockproxySyncInflightRpcDec(peerKey)
		cancel()

		if err != nil {
			if status.Code(err) == codes.Unimplemented {
				atomic.AndUint32(&peer.CapMask, ^capRateLimiterSync)
				s.warnOncePeerRPC(peerKey, "RateLimiterSync",
					"peer returned Unimplemented; clearing capRateLimiterSync bit and degrading gracefully")
				return nil
			}
			return err
		}
	}

	// On successful push (only when sending a delta), update the per-peer
	// prevSnapshot map so the next ExportDelta correctly identifies
	// "what has advanced since I last pushed to this peer".
	if isDelta {
		s.updatePrevSnapshot(peerKey, entries)
	}
	return nil
}

// ApplyRateLimiterBatch is invoked by the gRPC server (xsync_server.go)
// for each received RateLimiterBatch. Routes to ImportState (absolute
// snapshot) or ApplyGossipDelta (delta merge) based on the batch's
// IsDelta flag. Returns nil-store-error if no RateLimiterStore is
// registered yet (allows the wire path to be exercised by tests before
// the AI gateway is wired in production).
func (s *SockproxySync) ApplyRateLimiterBatch(m *RateLimiterBatch) error {
	store := s.rlStore.Load()
	if store == nil {
		// No store registered yet. Not a hard error — the wire path is
		// open but the receiver has nothing to install. Logged at DEBUG.
		tk.LogIt(tk.LogDebug, "[SOCKPROXY_SYNC] RateLimiterSync received delta=%v entries=%d but no RateLimiterStore registered yet\n",
			m.IsDelta, len(m.Entries))
		return nil
	}
	goEntries := make([]rl.RateLimiterEntry, 0, len(m.Entries))
	for _, e := range m.Entries {
		if e == nil {
			continue
		}
		// WR-01: ApplyGossipDelta silently no-ops non-tenant rows
		// (ratelimit_sync.go:323-331). Drop them at ingest to avoid
		// pointless alloc + GC pressure on hundreds-of-key delta batches.
		// Absolute (ImportState) snapshots still carry every row because
		// the receiver clears state before installing.
		if m.IsDelta && !e.IsTenant {
			continue
		}
		goEntries = append(goEntries, rlProtoEntryToGo(e))
	}
	if m.IsDelta {
		store.ApplyGossipDelta(goEntries)
	} else {
		store.ImportState(goEntries)
	}
	return nil
}

// rlGoEntryToProto converts a Go-side ratelimit.RateLimiterEntry into
// the wire-level proto message. The two share field semantics one-to-one
// (RESEARCH §4) — only the names differ slightly.
//
// Wire-shape mapping:
//
//	KeyID        → key_id
//	IsTenant     → is_tenant
//	WindowEpoch  → epoch_start_ts
//	Consumed     → tokens_consumed (unmodified — math.MinInt64 round-trips)
//	Exceeded → exceeded (explicit field 7, added by.1-03)
//	LastAccessNs → last_refill_ns (per-key only; reused for "last activity")
//
// The wire `current_tokens` (double, field 4) is currently unused — it was
// reserved for a future Phase-C-style live-bucket transfer. DO NOT
// repurpose field 4 (wire-incompat per proto3 field-number stability).
//
// The previous encoding rode Exceeded on the
// sign bit of tokens_consumed via a two's-complement negate-and-decrement
// sentinel. That hack corrupted Consumed == math.MinInt64 because the
// negate-and-decrement step overflowed int64, and any legitimate negative
// Consumed counter was misdecoded as Exceeded=true. The explicit `bool
// exceeded = 7;` field (xsync.proto, regen at 34aa4240) decouples sign
// from the flag and makes the round-trip lossless.
//
// Wire compatibility note: ships as a full-cluster cutover —
// -A peers (sign-bit decoder) will misinterpret
// payloads. See SUMMARY.md and 70.1-RESEARCH §.
func rlGoEntryToProto(e *rl.RateLimiterEntry) *RateLimiterEntry {
	return &RateLimiterEntry{
		KeyId:          e.KeyID,
		IsTenant:       e.IsTenant,
		LastRefillNs:   e.LastAccessNs,
		CurrentTokens:  0, // unused; reserved -- DO NOT repurpose (wire-incompat)
		EpochStartTs:   e.WindowEpoch,
		TokensConsumed: e.Consumed,
		Exceeded:       e.Exceeded,
	}
}

// rlProtoEntryToGo inverts rlGoEntryToProto. Reads the explicit `exceeded`
// field directly — no sign-bit gymnastics. See rlGoEntryToProto for the
// cutover rationale.
func rlProtoEntryToGo(p *RateLimiterEntry) rl.RateLimiterEntry {
	return rl.RateLimiterEntry{
		KeyID:        p.KeyId,
		IsTenant:     p.IsTenant,
		WindowEpoch:  p.EpochStartTs,
		Consumed:     p.TokensConsumed,
		Exceeded:     p.Exceeded,
		LastAccessNs: p.LastRefillNs,
	}
}

// getOrCreatePushCounter returns the *int64 push counter for peerKey,
// creating it lazily.
func (s *SockproxySync) getOrCreatePushCounter(peerKey string) *int64 {
	s.rlPrevSnapMu.Lock()
	defer s.rlPrevSnapMu.Unlock()
	if ctr, ok := s.rlPushCounter[peerKey]; ok {
		return ctr
	}
	ctr := new(int64)
	s.rlPushCounter[peerKey] = ctr
	return ctr
}

// copyPrevSnapshot returns a defensive copy of the per-peer prev-
// snapshot map suitable for passing into store.ExportDelta. A copy
// avoids holding rlPrevSnapMu across the Export call (which itself
// acquires the RateLimiterStore mutex briefly).
func (s *SockproxySync) copyPrevSnapshot(peerKey string) map[string]int64 {
	s.rlPrevSnapMu.Lock()
	defer s.rlPrevSnapMu.Unlock()
	src, ok := s.rlPrevSnap[peerKey]
	if !ok {
		return map[string]int64{}
	}
	cp := make(map[string]int64, len(src))
	for k, v := range src {
		cp[k] = v
	}
	return cp
}

// updatePrevSnapshot records the just-pushed Consumed + WindowEpoch
// values for peerKey, so the next ExportDelta call can correctly
// short-circuit tenants whose state has not advanced.
func (s *SockproxySync) updatePrevSnapshot(peerKey string, entries []rl.RateLimiterEntry) {
	s.rlPrevSnapMu.Lock()
	defer s.rlPrevSnapMu.Unlock()
	m, ok := s.rlPrevSnap[peerKey]
	if !ok {
		m = make(map[string]int64, len(entries))
		s.rlPrevSnap[peerKey] = m
	}
	for _, e := range entries {
		if !e.IsTenant {
			continue
		}
		m[e.KeyID] = e.Consumed
		// Strip "t:" prefix and prepend "e:" for the epoch sentinel key.
		tenantID := e.KeyID
		if len(tenantID) > 2 && tenantID[:2] == "t:" {
			tenantID = tenantID[2:]
		}
		m["e:"+tenantID] = e.WindowEpoch
	}
}

// hashStringForJitter is a tiny FNV-1a hash used only to seed the
// per-peer jitter RNG. NOT security-sensitive.
func hashStringForJitter(s string) uint32 {
	const (
		offset32 uint32 = 2166136261
		prime32  uint32 = 16777619
	)
	h := offset32
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}
