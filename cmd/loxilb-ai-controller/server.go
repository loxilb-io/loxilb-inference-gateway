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

// gRPC snapshot server : implements the frozen
// loxilb.aictrl.v1 AiCtrl service — WatchSnapshots SotW fan-out +
// AckSnapshot recording.
//
// Distribution invariants:
//
//   - LATE-JOIN CONVERGENCE: a new watcher immediately receives the LAST
//     emitted snapshot (SotW — reconnecting gateways converge instantly,
//     the sockproxy_sync.go periodic-full-sync precedent).
//   - EMISSION NEVER BLOCKS: Broadcast performs only non-blocking sends
//     into per-watcher buffered channels with drop-oldest; a gateway that
//     misses N snapshots re-converges on the next SotW by design (every
//     snapshot is the FULL state of the world, not a delta).
//   - STUCK WATCHERS ARE EVICTED: each stream Send runs under a
//     per-watcher timeout; a gateway that stops reading its stream is
//     unregistered after the timeout and re-converges when it redials.
//   - ACKS ARE TELEMETRY ONLY (RESEARCH Pattern 4): REJECTED
//     never triggers a forced re-push — the periodic identical-SotW
//     re-anchor covers recovery. Acks land in a ring buffer + counters
//     (wired to aictrl_acks_applied_total / aictrl_acks_rejected_total by
//     gateway label in metrics.go).
package main

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/loxilb-io/loxilb/pkg/aictrl"
)

const (
	// defaultSendTimeout bounds one stream Send: a watcher that cannot
	// absorb a snapshot within this window is evicted.
	defaultSendTimeout = 5 * time.Second
	// defaultWatcherBuf is the per-watcher snapshot channel depth. Small on
	// purpose: SotW snapshots supersede each other, so buffering more than
	// a few is pure staleness.
	defaultWatcherBuf = 4
	// ackRingSize bounds the recorded ack history.
	ackRingSize = 256

	// maxGatewayIDs caps the DISTINCT client-supplied gateway_id values
	// admitted into metric labels and per-gateway maps (F8: the gRPC surface
	// is unauthenticated until mTLS, so gateway_id arrives straight off the
	// wire); beyond the cap unseen IDs collapse to "other".
	maxGatewayIDs = 128
)

// gwIDSanitizeRe bounds the gateway_id alphabet for label/map safety.
var gwIDSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._\-:]`)

var (
	gwIDMu sync.Mutex
	gwIDs  = make(map[string]struct{}, maxGatewayIDs)
)

// boundGatewayID sanitises and bounds a client-supplied gateway_id before it
// reaches metric labels (aictrl_acks_*_total{gateway}, watcher-dropped) and
// the per-gateway counter maps. No eviction — an admitted ID keeps its label
// for process lifetime, so a gateway's series never flips mid-run.
func boundGatewayID(id string) string {
	id = gwIDSanitizeRe.ReplaceAllString(id, "_")
	if len(id) > 64 {
		id = id[:64]
	}
	if id == "" {
		return "unknown"
	}
	gwIDMu.Lock()
	defer gwIDMu.Unlock()
	if _, ok := gwIDs[id]; ok {
		return id
	}
	if len(gwIDs) >= maxGatewayIDs {
		return "other"
	}
	gwIDs[id] = struct{}{}
	return id
}

// serverHooks are optional observability callbacks. metrics.go wires them
// into the CTRL-05 promauto series (aictrl_watchers_connected,
// aictrl_acks_applied_total{gateway}, aictrl_acks_rejected_total{gateway},
// aictrl_watcher_dropped_snapshots_total{gateway}); tests inject recorders.
// All fields are nil-safe.
type serverHooks struct {
	ackApplied  func(gateway string)
	ackRejected func(gateway string)
	watchers    func(n int)
	dropped     func(gateway string)
	logf        func(format string, args ...interface{})
}

func (h serverHooks) log(format string, args ...interface{}) {
	if h.logf != nil {
		h.logf(format, args...)
	}
}

// ackRecord is one recorded AckSnapshot call.
type ackRecord struct {
	GatewayID string
	Epoch     uint64
	Status    aictrl.AckStatus
	Detail    string
	At        time.Time
}

// watcher is one connected WatchSnapshots stream.
type watcher struct {
	id      uint64
	gateway string
	ch      chan *aictrl.Snapshot
}

// snapshotServer implements aictrl.AiCtrlServer. Broadcast is driven by the
// single controller decision loop; WatchSnapshots/AckSnapshot are driven by
// gRPC handler goroutines.
type snapshotServer struct {
	aictrl.UnimplementedAiCtrlServer

	sendTimeout time.Duration
	watcherBuf  int
	hooks       serverHooks

	mu       sync.Mutex
	last     *aictrl.Snapshot
	watchers map[uint64]*watcher
	nextID   uint64
	dropped  map[string]uint64 // gateway -> dropped snapshot count

	ackMu    sync.Mutex
	acks     [ackRingSize]ackRecord
	ackNext  int
	ackCount int
	applied  map[string]uint64 // gateway -> APPLIED acks
	rejected map[string]uint64 // gateway -> REJECTED acks
}

// newSnapshotServer builds the server. Non-positive sendTimeout/watcherBuf
// fall back to the defaults.
func newSnapshotServer(sendTimeout time.Duration, watcherBuf int, hooks serverHooks) *snapshotServer {
	if sendTimeout <= 0 {
		sendTimeout = defaultSendTimeout
	}
	if watcherBuf <= 0 {
		watcherBuf = defaultWatcherBuf
	}
	return &snapshotServer{
		sendTimeout: sendTimeout,
		watcherBuf:  watcherBuf,
		hooks:       hooks,
		watchers:    map[uint64]*watcher{},
		dropped:     map[string]uint64{},
		applied:     map[string]uint64{},
		rejected:    map[string]uint64{},
	}
}

// Broadcast records snap as the current SotW and offers it to every
// connected watcher WITHOUT BLOCKING: full per-watcher buffers drop their
// OLDEST entry (counted) — one stuck gateway can never stall emission for
// the fleet.
func (s *snapshotServer) Broadcast(snap *aictrl.Snapshot) {
	s.mu.Lock()
	s.last = snap
	ws := make([]*watcher, 0, len(s.watchers))
	for _, w := range s.watchers {
		ws = append(ws, w)
	}
	s.mu.Unlock()

	for _, w := range ws {
		s.offer(w, snap)
	}
}

// offer performs the non-blocking buffered send with drop-oldest. Only the
// broadcast loop writes and only the watcher's handler reads, so the
// pop-retry loop terminates.
func (s *snapshotServer) offer(w *watcher, snap *aictrl.Snapshot) {
	for {
		select {
		case w.ch <- snap:
			return
		default:
		}
		// Buffer full: drop the OLDEST queued snapshot (superseded SotW)
		// and count it — the gateway re-converges on the next full SotW.
		select {
		case <-w.ch:
			s.mu.Lock()
			s.dropped[w.gateway]++
			s.mu.Unlock()
			if s.hooks.dropped != nil {
				s.hooks.dropped(w.gateway)
			}
		default:
		}
	}
}

// register adds a watcher and returns it together with the current SotW
// (captured under the SAME lock, so the immediate send + channel forwarding
// never miss an emission; duplicates are suppressed by epoch in the stream
// loop).
func (s *snapshotServer) register(gateway string) (*watcher, *aictrl.Snapshot) {
	s.mu.Lock()
	s.nextID++
	w := &watcher{
		id:      s.nextID,
		gateway: gateway,
		ch:      make(chan *aictrl.Snapshot, s.watcherBuf),
	}
	s.watchers[w.id] = w
	n := len(s.watchers)
	last := s.last
	s.mu.Unlock()
	if s.hooks.watchers != nil {
		s.hooks.watchers(n)
	}
	return w, last
}

func (s *snapshotServer) unregister(w *watcher) {
	s.mu.Lock()
	delete(s.watchers, w.id)
	n := len(s.watchers)
	s.mu.Unlock()
	if s.hooks.watchers != nil {
		s.hooks.watchers(n)
	}
}

// WatchSnapshots implements the server-stream: immediate last-SotW for late
// joiners, then every new Broadcast until the stream context ends or the
// watcher is evicted by the send timeout.
func (s *snapshotServer) WatchSnapshots(req *aictrl.WatchRequest,
	stream aictrl.AiCtrl_WatchSnapshotsServer) error {

	gw := boundGatewayID(req.GetGatewayId())
	w, last := s.register(gw)
	defer s.unregister(w)
	s.hooks.log("[AICTRL] watcher connected: gateway=%s", gw)

	// Track what was already sent so a Broadcast racing the registration
	// cannot produce a duplicate (same boot_id + epoch <= sent ⇒ skip).
	var sentBoot string
	var sentEpoch uint64

	if last != nil {
		if err := s.sendWithTimeout(stream, last); err != nil {
			s.hooks.log("[AICTRL] watcher %s dropped on initial SotW: %v", gw, err)
			return err
		}
		sentBoot, sentEpoch = last.GetBootId(), last.GetEpoch()
	}

	for {
		select {
		case <-stream.Context().Done():
			s.hooks.log("[AICTRL] watcher disconnected: gateway=%s", gw)
			return stream.Context().Err()
		case snap := <-w.ch:
			if snap.GetBootId() == sentBoot && snap.GetEpoch() <= sentEpoch {
				continue // already delivered (register/broadcast race)
			}
			if err := s.sendWithTimeout(stream, snap); err != nil {
				s.hooks.log("[AICTRL] watcher %s evicted: %v", gw, err)
				return err
			}
			sentBoot, sentEpoch = snap.GetBootId(), snap.GetEpoch()
		}
	}
}

// sendWithTimeout bounds one stream Send. On timeout the handler returns
// (unregistering the watcher); the in-flight Send unblocks with an error
// when gRPC tears the stream down, so the helper goroutine never leaks.
func (s *snapshotServer) sendWithTimeout(stream aictrl.AiCtrl_WatchSnapshotsServer,
	snap *aictrl.Snapshot) error {

	done := make(chan error, 1)
	go func() { done <- stream.Send(snap) }()
	t := time.NewTimer(s.sendTimeout)
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		return fmt.Errorf("send timeout after %s (stuck watcher)", s.sendTimeout)
	}
}

// AckSnapshot records the apply result — ring buffer + per-gateway counters
// (surfaced as aictrl_acks_applied_total / aictrl_acks_rejected_total).
// REJECTED is recorded, NEVER retried-with-force: the SotW re-anchor is the
// recovery path (RESEARCH Pattern 4).
func (s *snapshotServer) AckSnapshot(_ context.Context, a *aictrl.Ack) (*aictrl.AckResponse, error) {
	rec := ackRecord{
		GatewayID: boundGatewayID(a.GetGatewayId()),
		Epoch:     a.GetEpoch(),
		Status:    a.GetStatus(),
		Detail:    a.GetErrorDetail(),
		At:        time.Now(),
	}

	s.ackMu.Lock()
	s.acks[s.ackNext] = rec
	s.ackNext = (s.ackNext + 1) % ackRingSize
	if s.ackCount < ackRingSize {
		s.ackCount++
	}
	switch rec.Status {
	case aictrl.AckStatus_ACK_STATUS_APPLIED:
		s.applied[rec.GatewayID]++
	case aictrl.AckStatus_ACK_STATUS_REJECTED:
		s.rejected[rec.GatewayID]++
	}
	s.ackMu.Unlock()

	switch rec.Status {
	case aictrl.AckStatus_ACK_STATUS_APPLIED:
		if s.hooks.ackApplied != nil {
			s.hooks.ackApplied(rec.GatewayID)
		}
	case aictrl.AckStatus_ACK_STATUS_REJECTED:
		if s.hooks.ackRejected != nil {
			s.hooks.ackRejected(rec.GatewayID)
		}
		s.hooks.log("[AICTRL] ack REJECTED: gateway=%s epoch=%d detail=%q",
			rec.GatewayID, rec.Epoch, rec.Detail)
	}
	return &aictrl.AckResponse{}, nil
}

// serverStats is the test/introspection view of the server state.
type serverStats struct {
	Watchers int
	Dropped  map[string]uint64
	Applied  map[string]uint64
	Rejected map[string]uint64
	Acks     []ackRecord // oldest-first
}

func (s *snapshotServer) stats() serverStats {
	st := serverStats{
		Dropped:  map[string]uint64{},
		Applied:  map[string]uint64{},
		Rejected: map[string]uint64{},
	}
	s.mu.Lock()
	st.Watchers = len(s.watchers)
	for k, v := range s.dropped {
		st.Dropped[k] = v
	}
	s.mu.Unlock()

	s.ackMu.Lock()
	for k, v := range s.applied {
		st.Applied[k] = v
	}
	for k, v := range s.rejected {
		st.Rejected[k] = v
	}
	start := 0
	if s.ackCount == ackRingSize {
		start = s.ackNext
	}
	for i := 0; i < s.ackCount; i++ {
		st.Acks = append(st.Acks, s.acks[(start+i)%ackRingSize])
	}
	s.ackMu.Unlock()
	return st
}
