//go:build !doca

/*
 * Copyright (c) 2022 NetLOX Inc
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

package loxinet

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	tk "github.com/loxilb-io/loxilib"
	"golang.org/x/sync/singleflight"
)

// aclPending — stub mirror. Same shape as the doca-build twin
// in dpu_doca_bf2.go; the !doca build treats em as an opaque pointer and the
// matching DocaAcl*EntryAdd stubs return nil + errDocaNotAvailable — the
// state-machine tests assert pre-CGO behaviour (cancel-pending-on-Del, batch
// cap forces flush, lazy lifecycle 0↔n transitions) and inject a no-CGO
// flushAclPending path below that writes directly to the maps.
//
// correction: DOCA 2.9.4 BASIC pipes don't support per-entry masks —
// emMask is gone from the doca twin; the !doca stub mirrors that shape.
type aclPending struct {
	hash   string
	action byte
	em     unsafe.Pointer
	onDone chan error
}

// aclBatchCap mirrors dpu_doca_bf2.go.
const aclBatchCap = 128

// aclDebounceMs mirrors dpu_doca_bf2.go.
const aclDebounceMs = 50 * time.Millisecond

// docaOffloadEntry is the build-tag-agnostic shape used by the bookkeeping
// path under !doca. The real (DOCA-build) declaration in dpu_doca_bf2.go is
// the source of truth; this mirror exists so unit tests under !doca can
// inspect the Direction tag set by the paired-offload bookkeeper.
type docaOffloadEntry struct {
	pipe             unsafe.Pointer
	entry            unsafe.Pointer
	pipeKey          string
	pkey             []byte
	evicting         atomic.Uint32
	userCtx          uint64
	lbMark           int
	Direction        string         // prep: "forward" / "reply" / ""
	fwdPortID        uint16         // trace: DPDK forward-port ID at offload time
	pairedSteerEntry unsafe.Pointer // mirror of dpu_doca_bf2.go (B23-03)
	siblingKey       string         // mirror of dpu_doca_bf2.go : paired route fwd/rev flowKey
}

// DpDocaBf2 is a stub for non-DOCA builds. Pairing-related state is
// mirrored here so unit tests under !doca compile and exercise pairOrDispatch /
// gcPendingPairs / pairedLBFlowOffload via injectable seams.
type DpDocaBf2 struct {
	// fields — must mirror the DOCA-build struct for cross-build tests.
	bidirEnabled bool
	pendingPair  map[string]*pendingPair
	pairMu       sync.Mutex
	entries      map[string]*docaOffloadEntry

	// userCtx ↔ flowKey reverse map + monotonic allocator, mirrored
	// from the DOCA-build DpDocaBf2 so the !doca RouteFlowOffload / LBFlowRemove /
	// handleAgedEntry mirrors below can exercise the sibling-cascade teardown
	// contract (userCtx is how handleAgedEntry resolves an aged entry to a flow).
	nextUserCtx  atomic.Uint64
	userCtxToKey map[uint64]string

	// A1: 4-mutex split mirror (S1 stub-symmetry; production fields documented in dpu_doca_bf2.go).
	ctMtx     sync.Mutex
	fdbMtx    sync.Mutex
	userCtxMu sync.Mutex
	statsRWMu sync.RWMutex

	// B23-02: mirror of the DOCA-build struct so deferred-retry tests
	// (TestMarkDeferred / TestSweepDeferred*) can construct a DpDocaBf2 under
	// !doca and exercise markDeferred + sweepDeferred without CGO.
	deferredOffload sync.Map
	pairedOffloadFn func(fwd, rev *DpCtInfo, lbMark int) error

	// A3: mirror of the DOCA-build resolveSF field so unit tests
	// under !doca can construct DpDocaBf2 and exercise the singleflight
	// path via the !doca-build resolveFlowMACs stub (extended below to
	// match the production fast-path/slow-path behavior under test).
	resolveSF singleflight.Group

	// === : lazy DENY+ALLOW + debounce mirror ===
	// Symbols mirror the doca-build twin (dpu_doca_bf2.go) so unit tests under
	// `//go:build !doca` exercise the Go state machine without DOCA SDK. The
	// !doca flushAclPending writes directly into the maps without calling CGO.
	aclDenyEntries  map[string]*docaOffloadEntry
	aclAllowEntries map[string]*docaOffloadEntry
	aclPipesUp      bool
	aclLifecycleMu  sync.Mutex
	aclPendingAdd   []aclPending
	aclPendingDel   []string
	aclBatchMu      sync.Mutex
	aclBatchTimer   *time.Timer
}

// NewDpDocaBf2 returns nil on non-DOCA builds. Callers check for nil before use.
func NewDpDocaBf2() *DpDocaBf2 {
	return nil
}

// The methods below exist solely so the compiler can type-check code paths
// that reference *DpDocaBf2 (e.g., loxinet.go). They are never called because
// NewDpDocaBf2 returns nil and callers guard with if bf2 != nil.

func (d *DpDocaBf2) Bridge() *DocaBridge                          { return nil }
func (d *DpDocaBf2) Init(cfg DpuConfig) error                     { return ErrNotSupported }
func (d *DpDocaBf2) Shutdown() error                              { return ErrNotSupported }
func (d *DpDocaBf2) ShutdownCtx(_ context.Context) error          { return nil }
func (d *DpDocaBf2) Name() string                                 { return "doca-bf2-stub" }
func (d *DpDocaBf2) Capabilities() DpuCapabilities                { return DpuCapabilities{} }
func (d *DpDocaBf2) LBFlowOffload(ct *DpCtInfo, lbMark int) error { return ErrNotSupported }
func (d *DpDocaBf2) RouteAdd(w *RouteDpWorkQ) error               { return ErrNotSupported }
func (d *DpDocaBf2) RouteDel(w *RouteDpWorkQ) error               { return ErrNotSupported }
func (d *DpDocaBf2) FdbFlowOffload(fdb *FdbEnt) error             { return ErrNotSupported }
func (d *DpDocaBf2) FdbFlowRemove(fdb *FdbEnt) error              { return ErrNotSupported }

// FwRuleAdd / FwRuleDel — state-machine mirrors.
// Real bodies live below (after the seam declarations).
func (d *DpDocaBf2) NextHopAdd(w *NextHopDpWorkQ) error             { return ErrNotSupported }
func (d *DpDocaBf2) NextHopDel(w *NextHopDpWorkQ) error             { return ErrNotSupported }
func (d *DpDocaBf2) FlowStats(ct *DpCtInfo) (uint64, uint64, error) { return 0, 0, ErrNotSupported }
func (d *DpDocaBf2) PipeStats(name string) (uint32, error)          { return 0, ErrNotSupported }
func (d *DpDocaBf2) AllFlowStats() []FlowHwStats                    { return nil }
func (d *DpDocaBf2) AllFdbStats() []FdbHwStats                      { return nil }
func (d *DpDocaBf2) AllRouteStats() []RouteHwStats                  { return nil }
func (d *DpDocaBf2) AllAclStats() []AclHwStats                      { return nil }
func (d *DpDocaBf2) LBFlowOffloadWithPipeKind(ct *DpCtInfo, lbMark int) (pipeKind, error) {
	return pipeCT, ErrNotSupported
}
func (d *DpDocaBf2) MeterAdd(w *PolDpWorkQ) error    { return ErrNotSupported }
func (d *DpDocaBf2) MeterDel(w *PolDpWorkQ) error    { return ErrNotSupported }
func (d *DpDocaBf2) ActiveMeters() map[uint32]string { return nil }
func (d *DpDocaBf2) QueryMeterStats(meterID uint32) (DocaMeterStats, error) {
	return DocaMeterStats{}, ErrNotSupported
}
func (d *DpDocaBf2) EnqueueRetry(flowKey string, ct *DpCtInfo, isLB bool) bool { return false }

// hooks -- stubs for non-DOCA builds.
func (d *DpDocaBf2) RebuildRootAfterFdbChange() error { return ErrNotSupported }
func (d *DpDocaBf2) IsFdbMissWired() bool             { return false }

// CtRevTestDropAll is a no-op stub for non-DOCA builds (TEST-ONLY diagnostic).
func (d *DpDocaBf2) CtRevTestDropAll() error    { return ErrNotSupported }
func (d *DpDocaBf2) DocaRebuildRootPipe() error { return ErrNotSupported }

// resolveFlowMACs is the !doca-build placeholder for the DOCA-build resolver
// at dpu_doca_bf2.go. The production resolver walks netlink.NeighList and
// the ifindexToPort map, neither of which the !doca build tracks; tests that
// need controlled MAC/port output should override the resolveFlowMACsFn seam
// in dpu_doca_bf2_helpers.go (invariants).
//
// A4: the SelfIPCache.Has fast path is mirrored here so unit tests
// under !doca can validate the suppression contract (-05). When
// SelfIPCache.Has reports ip as loxilb-owned the function returns
// stubProxyPortMAC for both src and dst MAC and reports ok=true without
// emitting any log line. d.reversePortMap is zero-length under !doca so we
// cannot return d.reversePortMap[0]; instead use the package-level
// stubProxyPortMAC which tests can populate.
//
// A3: the singleflight wrap is preserved so the resolveSF.Do
// invariant ("identical key → one invocation") is exercised under !doca too.
// The slow-path body returns ok=false (no DPDK port data) — singleflight
// still collapses concurrent callers to a single inner-fn invocation.
func (d *DpDocaBf2) resolveFlowMACs(ip net.IP) (uint16, [6]byte, [6]byte, bool) {
	// A4: self-IP fast path. Mirrors the production logic
	// (tk.IPtonl key derivation kept in lockstep with self_ip_cache.go).
	if ip4 := ip.To4(); ip4 != nil {
		if SelfIPCache.Has(tk.IPtonl(ip4)) {
			return 0, stubProxyPortMAC, stubProxyPortMAC, true
		}
	}

	// A3: singleflight wrap. Production passes through neighListFn;
	// the !doca build has no neighListFn (no netlink slow path) so we just
	// run the stub body inside the Group to keep the collapse semantics
	// observable.
	type stubResult struct {
		port uint16
		dst  [6]byte
		src  [6]byte
		ok   bool
	}
	v, _, _ := d.resolveSF.Do(ip.String(), func() (interface{}, error) {
		// !doca has no DPDK ports — slow path is "always missing".
		// Tests that need a positive slow-path result should override
		// resolveFlowMACsFn (the seam).
		return stubResult{}, nil
	})
	r := v.(stubResult)
	return r.port, r.dst, r.src, r.ok
}

// stubProxyPortMAC is the MAC the !doca-build resolveFlowMACs returns for
// SelfIPCache hits. Tests populate it before exercising the fast path.
// Default is the zero MAC so test pollution is detectable.
var stubProxyPortMAC [6]byte

// === paired-offload test seams (!doca only) ===
//
// These package-level function vars let unit tests (dpu_doca_bf2_pending_pair_test.go)
// inject mock behavior for the two DOCA add calls and the rollback primitive
// without compiling against the DOCA toolchain. The DOCA build defines the same
// orchestration in pairedLBFlowOffload (in dpu_doca_bf2.go) using the real
// CGO functions directly — those are the production primitives, with no
// fn-var indirection on the hot path.
var (
	// docaEntryAddBasicFn is invoked once per direction by pairedLBFlowOffload
	// in the !doca build. It returns (entryHandle, pipeHandle, err); tests
	// override it to simulate add success/failure ordering.
	docaEntryAddBasicFn = func(ct *DpCtInfo, direction string, lbMark int) (unsafe.Pointer, unsafe.Pointer, error) {
		return nil, nil, ErrNotSupported
	}
	// docaEntryRemoveDirectFn is the rollback primitive for paired offload
	// (RESEARCH §Anti-Patterns line 374). Tests override to count calls.
	docaEntryRemoveDirectFn = DocaEntryRemoveDirect
	// docaEntryRemoveFn is wired ONLY so tests can detect anti-pattern misuse
	// (Blocker 1 invariant). Production code MUST NOT use it inside paired
	// rollback — the Direct primitive is required.
	docaEntryRemoveFn = DocaEntryRemove
)

// pairedLBFlowOffload programs forward+reply DOCA entries atomically
//
// !doca build: uses package-level fn-var seams so tests can inject mocks. The
// real DOCA-build implementation (dpu_doca_bf2.go) calls the C primitives
// directly with full param-build inherited from LBFlowOffload.
//
// P51-02: invokes buildPairedFlowParams for both directions BEFORE calling
// docaEntryAddBasicFn so unit tests reach the resolveFlowMACsFn / nextHopForFlow
// path and can assert invariants. On ARP miss after FIB fallback
// the function returns errFwdARPMiss / errReplyARPMiss without calling the
// add-entry seam (atomicity).
//
// Rollback primitive: docaEntryRemoveDirectFn per RESEARCH §Anti-Patterns line
// 374. The submit-routed DocaEntryRemove would self-deadlock when called
// from the worker pthread (Pattern 3).
func (d *DpDocaBf2) pairedLBFlowOffload(fwd, rev *DpCtInfo, lbMark int) error {
	if d == nil || fwd == nil || rev == nil {
		return ErrNotSupported
	}

	// P51-02: forward + reply param build runs the same MAC/port
	// resolution path as the DOCA build so tests exercise.
	if _, err := d.buildPairedFlowParams(fwd, fwd, true); err != nil {
		return err
	}
	if _, err := d.buildPairedFlowParams(rev, fwd, false); err != nil {
		return err
	}

	fwdEntry, fwdPipe, err := docaEntryAddBasicFn(fwd, "forward", lbMark)
	if err != nil {
		return err
	}

	revEntry, revPipe, err := docaEntryAddBasicFn(rev, "reply", lbMark)
	if err != nil {
		// Forward succeeded, reply failed: rollback via the Direct primitive.
		_ = docaEntryRemoveDirectFn(fwdPipe, fwdEntry)
		return err
	}

	// Both succeeded — bookkeep both entries with Direction tags.
	d.ctMtx.Lock()
	if d.entries == nil {
		d.entries = make(map[string]*docaOffloadEntry)
	}
	fwdKey := fwd.Key()
	revKey := rev.Key()
	d.entries[fwdKey] = &docaOffloadEntry{
		pipe:      fwdPipe,
		entry:     fwdEntry,
		pipeKey:   "ct",
		Direction: "forward",
		lbMark:    lbMark,
	}
	d.entries[revKey] = &docaOffloadEntry{
		pipe:      revPipe,
		entry:     revEntry,
		pipeKey:   "ct",
		Direction: "reply",
		lbMark:    lbMark,
	}
	d.ctMtx.Unlock()
	return nil
}

// === : !doca mirror of the route fwd/rev pair install + cascade ===
//
// The DOCA-build implementations in dpu_doca_bf2.go (RouteFlowOffload,
// LBFlowRemove, handleAgedEntry) are the SOURCE OF TRUTH. The mirrors below
// reproduce ONLY the testable control-flow contract — reverse 5-tuple
// synthesis, both-or-neither atomicity, siblingKey cross-link, and cascade
// teardown — through the package-level seams (docaGetCTFwdPipeFn,
// docaGetCTRevPipeFn, docaEntryAddBasicFn, docaEntryRemoveFn,
// docaEntryRemoveDirectFn, resolveFlowMACsFn). Production-only concerns
// (bridge nil-guard, circuit breaker, Prometheus metrics, offloadActive
// accounting, eBPF CT tombstone) are intentionally omitted — they are not
// part of the contract under test and have no !doca representation.
//
// Keep this block in lockstep with dpu_doca_bf2.go, exactly as the
// pairedLBFlowOffload mirror above is kept in lockstep with its DOCA-build
// twin. dpu_doca_bf2_perdirection_test.go is the regression net.

// allocUserCtx mirrors dpu_doca_bf2.go: monotonic id (0 reserved as the NULL
// sentinel in the C callback) registered in the userCtx→flowKey reverse map.
func (d *DpDocaBf2) allocUserCtx(flowKey string) uint64 {
	id := d.nextUserCtx.Add(1)
	d.userCtxMu.Lock()
	if d.userCtxToKey == nil {
		d.userCtxToKey = make(map[uint64]string)
	}
	d.userCtxToKey[id] = flowKey
	d.userCtxMu.Unlock()
	return id
}

func (d *DpDocaBf2) lookupUserCtx(id uint64) (string, bool) {
	d.userCtxMu.Lock()
	k, ok := d.userCtxToKey[id]
	d.userCtxMu.Unlock()
	return k, ok
}

func (d *DpDocaBf2) releaseUserCtx(id uint64) {
	d.userCtxMu.Lock()
	delete(d.userCtxToKey, id)
	d.userCtxMu.Unlock()
}

// RouteFlowOffload (!doca mirror) — installs a forward entry on g_ct_fwd_pipe
// and a reverse entry on g_ct_rev_pipe for a non-NAT routed flow, atomically
// (both-or-neither), cross-linked by siblingKey. Mirror of dpu_doca_bf2.go
// RouteFlowOffload.
func (d *DpDocaBf2) RouteFlowOffload(ct *DpCtInfo, rid int) error {
	if d == nil || ct == nil {
		return ErrNotSupported
	}
	if _, protoOk := protoNumForRouteOffload(ct.Proto); !protoOk {
		return nil
	}
	flowKey := ct.Key()

	d.ctMtx.Lock()
	defer d.ctMtx.Unlock()

	if d.entries == nil {
		d.entries = make(map[string]*docaOffloadEntry)
	}
	if _, exists := d.entries[flowKey]; exists {
		return nil // idempotent
	}

	fwdPipe := docaGetCTFwdPipeFn()
	if fwdPipe == nil {
		return fmt.Errorf("doca-bf2 RouteFlowOffload: ct fwd pipe not available")
	}

	// Reverse 5-tuple — swapped DpCtInfo, revCt.Key so the key stays in
	// lockstep with DpCtInfo.Key's format.
	revCt := *ct
	revCt.DIP, revCt.SIP = ct.SIP, ct.DIP
	revCt.Dport, revCt.Sport = ct.Sport, ct.Dport
	revFlowKey := revCt.Key()
	if revFlowKey == flowKey {
		revFlowKey = "" // degenerate self-flow — forward only, no sibling
	} else if _, exists := d.entries[revFlowKey]; exists {
		return nil // sibling already installed by a concurrent path
	}

	// MAC/port resolution via the shared seam — forward steers toward ct.DIP,
	// reverse toward ct.SIP. Atomic: BOTH must resolve before EITHER installs.
	_, _, _, ok := resolveFlowMACsFn(d, d.nextHopForFlow(ct.DIP))
	_, _, _, revOk := resolveFlowMACsFn(d, d.nextHopForFlow(ct.SIP))
	if !ok || (revFlowKey != "" && !revOk) {
		return nil // defer the whole flow to eBPF until the next CT scan retry
	}

	revPipe := docaGetCTRevPipeFn()
	if revFlowKey != "" && revPipe == nil {
		return fmt.Errorf("doca-bf2 RouteFlowOffload: ct rev pipe not available")
	}

	userCtx := d.allocUserCtx(flowKey)
	var revUserCtx uint64
	if revFlowKey != "" {
		revUserCtx = d.allocUserCtx(revFlowKey)
	}

	// Forward entry → g_ct_fwd_pipe.
	fwdEntry, _, err := docaEntryAddBasicFn(ct, "forward", rid)
	if err != nil {
		d.releaseUserCtx(userCtx)
		if revFlowKey != "" {
			d.releaseUserCtx(revUserCtx)
		}
		return fmt.Errorf("doca-bf2 RouteFlowOffload entry add failed: %w", err)
	}

	// Reverse entry → g_ct_rev_pipe. On failure roll back the forward entry via
	// the Direct primitive (same worker context as the DOCA build).
	var revEntry unsafe.Pointer
	if revFlowKey != "" {
		revEntry, _, err = docaEntryAddBasicFn(&revCt, "reply", rid)
		if err != nil {
			_ = docaEntryRemoveDirectFn(fwdPipe, fwdEntry)
			d.releaseUserCtx(userCtx)
			d.releaseUserCtx(revUserCtx)
			return fmt.Errorf("doca-bf2 RouteFlowOffload reverse entry add failed (rolled back): %w", err)
		}
	}

	// Bookkeeping — forward + reverse cross-linked by siblingKey.
	d.entries[flowKey] = &docaOffloadEntry{
		pipe:      fwdPipe,
		entry:     fwdEntry,
		pipeKey:   "route",
		pkey:      append([]byte(nil), ct.PKey...),
		userCtx:   userCtx,
		Direction: "forward",
	}
	if revFlowKey != "" {
		d.entries[flowKey].siblingKey = revFlowKey
		d.entries[revFlowKey] = &docaOffloadEntry{
			pipe:       revPipe,
			entry:      revEntry,
			pipeKey:    "route",
			pkey:       append([]byte(nil), ct.PKey...),
			userCtx:    revUserCtx,
			Direction:  "reply",
			siblingKey: flowKey,
		}
	}
	return nil
}

// LBFlowRemove (!doca mirror) — removes the entry for ct and, if it is one half
// of a non-NAT route pair (siblingKey set), cascades teardown to the sibling in
// the same ctMtx critical section. Mirror of dpu_doca_bf2.go LBFlowRemove —
// uses docaEntryRemoveFn (non-Direct), the eBPF-CT-expiry context.
func (d *DpDocaBf2) LBFlowRemove(ct *DpCtInfo) error {
	if d == nil || ct == nil {
		return ErrNotSupported
	}
	flowKey := ct.Key()

	d.ctMtx.Lock()
	defer d.ctMtx.Unlock()

	oe, exists := d.entries[flowKey]
	if !exists {
		return nil // not offloaded or already removed
	}
	if !oe.evicting.CompareAndSwap(0, 1) {
		// DOCA aging already evicting this entry — just drop the bookkeeping.
		delete(d.entries, flowKey)
		d.releaseUserCtx(oe.userCtx)
		return nil
	}
	_ = docaEntryRemoveFn(oe.pipe, oe.entry)
	delete(d.entries, flowKey)
	d.releaseUserCtx(oe.userCtx)

	// cascade teardown to the sibling (non-NAT route fwd/rev pair).
	// Inlined — no recursion; the sibling's evicting CAS guards a concurrent
	// handleAgedEntry.
	if oe.siblingKey != "" {
		if sib, ok := d.entries[oe.siblingKey]; ok && sib.evicting.CompareAndSwap(0, 1) {
			_ = docaEntryRemoveFn(sib.pipe, sib.entry)
			delete(d.entries, oe.siblingKey)
			d.releaseUserCtx(sib.userCtx)
		}
	}
	return nil
}

// handleAgedEntry (!doca mirror) — DOCA-aging eviction path. Captures the
// sibling under the lock and removes both DOCA entries with the Direct
// primitive (DOCA worker thread context). Mirror of dpu_doca_bf2.go
// handleAgedEntry.
func (d *DpDocaBf2) handleAgedEntry(userCtx uint64) {
	d.ctMtx.Lock()
	flowKey, found := d.lookupUserCtx(userCtx)
	if !found {
		d.ctMtx.Unlock()
		return
	}
	oe, exists := d.entries[flowKey]
	if !exists {
		d.releaseUserCtx(userCtx)
		d.ctMtx.Unlock()
		return
	}
	if !oe.evicting.CompareAndSwap(0, 1) {
		d.ctMtx.Unlock()
		return // LBFlowRemove is handling it
	}
	delete(d.entries, flowKey)
	d.releaseUserCtx(userCtx)
	pipe, entry := oe.pipe, oe.entry

	// capture the sibling under the lock so aging out one half of a
	// non-NAT route pair tears down both — g_ct_rev_pipe cannot leak.
	var sibPipe, sibEntry unsafe.Pointer
	var hasSib bool
	if oe.siblingKey != "" {
		if sib, ok := d.entries[oe.siblingKey]; ok && sib.evicting.CompareAndSwap(0, 1) {
			sibPipe, sibEntry, hasSib = sib.pipe, sib.entry, true
			delete(d.entries, oe.siblingKey)
			d.releaseUserCtx(sib.userCtx)
		}
	}
	d.ctMtx.Unlock()

	// DOCA removal outside the lock — Direct variant (DOCA worker thread).
	_ = docaEntryRemoveDirectFn(pipe, entry)
	if hasSib {
		_ = docaEntryRemoveDirectFn(sibPipe, sibEntry)
	}
}

// === — Go state-machine mirror (!doca) ===
//
// The !doca build mirrors the lazy DENY+ALLOW pipe lifecycle, the per-pipe
// debouncer, the entry maps, and the metric .Set / .Inc call sites so unit
// tests can exercise the Go logic on macOS / Linux CI without the DOCA SDK.
// CGO entry-add / del calls are replaced with map writes that ALWAYS succeed.

// prefixLen returns the number of contiguous 1-bits in a net.IPMask.
func prefixLen(mask net.IPMask) int {
	if len(mask) == 0 {
		return 32
	}
	ones, _ := mask.Size()
	return ones
}

// ruleHashFor — mirror.
func ruleHashFor(w *FwDpWorkQ) string {
	return fmt.Sprintf("src=%s/%d,dst=%s/%d,sp=%d,dp=%d,pref=%d,act=%d",
		w.SrcIP.IP.String(), prefixLen(w.SrcIP.Mask),
		w.DstIP.IP.String(), prefixLen(w.DstIP.Mask),
		w.L4SrcMin, w.L4DstMin, w.Pref, w.FwType)
}

// isPortOffloadable mirrors dpu_doca_bf2.go for the !doca build's
// FwRuleAdd defence-in-depth check.
func isPortOffloadable(min, max uint16) bool {
	if min == 0 && (max == 0 || max == 65535) {
		return true
	}
	return min == max
}

// ensureAclPipesUp — OPENING (no-CGO). Idempotent.
func (d *DpDocaBf2) ensureAclPipesUp() error {
	d.aclLifecycleMu.Lock()
	defer d.aclLifecycleMu.Unlock()
	if d.aclPipesUp {
		return nil
	}
	d.aclPipesUp = true
	return nil
}

// maybeTearDownAclPipes — CLOSING (no-CGO).
func (d *DpDocaBf2) maybeTearDownAclPipes() {
	d.aclLifecycleMu.Lock()
	defer d.aclLifecycleMu.Unlock()
	if !d.aclPipesUp {
		return
	}
	d.fdbMtx.Lock()
	empty := len(d.aclDenyEntries) == 0 && len(d.aclAllowEntries) == 0
	d.fdbMtx.Unlock()
	if !empty {
		return
	}
	d.aclPipesUp = false
}

// scheduleAclFlush — mirror.
func (d *DpDocaBf2) scheduleAclFlush() {
	d.aclBatchMu.Lock()
	defer d.aclBatchMu.Unlock()
	if d.aclBatchTimer != nil {
		d.aclBatchTimer.Stop()
	}
	d.aclBatchTimer = time.AfterFunc(aclDebounceMs, d.flushAclPending)
}

// flushAclPending — mirror (no-CGO). Each Add succeeds; map
// writes happen under fdbMtx; gauge updates use the shared docaAclHw*
// vars in dpu_metrics.go (build-tag-free).
func (d *DpDocaBf2) flushAclPending() {
	d.aclBatchMu.Lock()
	adds := d.aclPendingAdd
	dels := d.aclPendingDel
	d.aclPendingAdd = nil
	d.aclPendingDel = nil
	d.aclBatchMu.Unlock()

	if len(adds) == 0 && len(dels) == 0 {
		return
	}

	for _, p := range adds {
		// Free is a no-op under !doca (the alloc helpers in dpu_doca_cgo_stub.go
		// return a Go-owned 1-byte slice that GC cleans up). Calling Free keeps
		// behaviour identical to the doca-build for symmetry.
		if p.em != nil {
			DocaAclMatchFree(p.em)
		}
		d.fdbMtx.Lock()
		if d.aclDenyEntries == nil {
			d.aclDenyEntries = make(map[string]*docaOffloadEntry)
		}
		if d.aclAllowEntries == nil {
			d.aclAllowEntries = make(map[string]*docaOffloadEntry)
		}
		if p.action == 1 {
			d.aclAllowEntries[p.hash] = &docaOffloadEntry{pipeKey: "acl_allow"}
			docaAclHwOffloadRulesTotal.WithLabelValues("allow").Inc()
		} else {
			d.aclDenyEntries[p.hash] = &docaOffloadEntry{pipeKey: "acl_deny"}
			docaAclHwOffloadRulesTotal.WithLabelValues("deny").Inc()
		}
		d.fdbMtx.Unlock()
		if p.onDone != nil {
			p.onDone <- nil
			close(p.onDone)
		}
	}

	for _, hash := range dels {
		d.fdbMtx.Lock()
		if _, ok := d.aclDenyEntries[hash]; ok {
			delete(d.aclDenyEntries, hash)
			d.fdbMtx.Unlock()
			continue
		}
		if _, ok := d.aclAllowEntries[hash]; ok {
			delete(d.aclAllowEntries, hash)
		}
		d.fdbMtx.Unlock()
	}

	d.fdbMtx.Lock()
	denyCount := len(d.aclDenyEntries)
	allowCount := len(d.aclAllowEntries)
	d.fdbMtx.Unlock()
	docaAclHwDenyEntries.Set(float64(denyCount))
	docaAclHwAllowEntries.Set(float64(allowCount))

	if denyCount == 0 && allowCount == 0 {
		d.aclLifecycleMu.Lock()
		up := d.aclPipesUp
		d.aclLifecycleMu.Unlock()
		if up {
			go d.maybeTearDownAclPipes()
		}
	}
}

// FwRuleAdd — !doca mirror of the lazy state-machine. Same
// opt-IN gate, defence-in-depth checks, enqueue-and-block-on-done shape.
func (d *DpDocaBf2) FwRuleAdd(w *FwDpWorkQ) error {
	if d == nil {
		return ErrNotSupported
	}
	if !w.HwOffload {
		return nil
	}
	if w.SrcIP.IP.To4() == nil || w.DstIP.IP.To4() == nil {
		return fmt.Errorf("FwRuleAdd: HwOffload=true with IPv6 src/dst is not expressible")
	}
	if !isPortOffloadable(w.L4SrcMin, w.L4SrcMax) || !isPortOffloadable(w.L4DstMin, w.L4DstMax) {
		return fmt.Errorf("FwRuleAdd: HwOffload=true with port range is not expressible")
	}
	if w.Proto != 0 {
		return fmt.Errorf("FwRuleAdd: HwOffload=true with protocol-specific rule is not expressible")
	}

	hash := ruleHashFor(w)
	var action byte
	if w.FwType != DpFwDrop {
		action = 1
	}

	// !doca match-buffer alloc returns a Go-owned 1-byte slice address; opaque
	// to anyone except the matching CGO call (which is a stub).
	src4 := w.SrcIP.IP.To4()
	dst4 := w.DstIP.IP.To4()
	em := DocaAclMatchAllocIP4(
		binary.BigEndian.Uint32(src4), 0,
		binary.BigEndian.Uint32(dst4), 0,
		0, 0, 0, 0,
	)

	done := make(chan error, 1)
	p := aclPending{hash: hash, action: action, em: em, onDone: done}

	d.aclBatchMu.Lock()
	d.aclPendingAdd = append(d.aclPendingAdd, p)
	full := len(d.aclPendingAdd) >= aclBatchCap
	d.aclBatchMu.Unlock()

	if err := d.ensureAclPipesUp(); err != nil {
		d.aclBatchMu.Lock()
		for i := range d.aclPendingAdd {
			if d.aclPendingAdd[i].hash == hash {
				d.aclPendingAdd = append(d.aclPendingAdd[:i], d.aclPendingAdd[i+1:]...)
				break
			}
		}
		d.aclBatchMu.Unlock()
		DocaAclMatchFree(em)
		return err
	}

	if full {
		d.flushAclPending()
	} else {
		d.scheduleAclFlush()
	}

	return <-done
}

// FwRuleDel — !doca mirror. Cancel-pending-on-Del; non-blocking.
func (d *DpDocaBf2) FwRuleDel(w *FwDpWorkQ) error {
	if d == nil {
		return ErrNotSupported
	}
	if !w.HwOffload {
		return nil
	}
	hash := ruleHashFor(w)

	d.aclBatchMu.Lock()
	for i, p := range d.aclPendingAdd {
		if p.hash == hash {
			d.aclPendingAdd = append(d.aclPendingAdd[:i], d.aclPendingAdd[i+1:]...)
			d.aclBatchMu.Unlock()
			DocaAclMatchFree(p.em)
			if p.onDone != nil {
				close(p.onDone)
			}
			return nil
		}
	}
	d.aclPendingDel = append(d.aclPendingDel, hash)
	d.aclBatchMu.Unlock()

	d.scheduleAclFlush()
	return nil
}

// countEntriesForPipe — !doca stub mirror of the doca-tagged implementation
// in dpu_doca_bf2.go:172. The dpu_doca_bf2_perdirection_test.go test file
// has build tag !doca and references this symbol, so the no-doca build needs
// a definition. Behaviorally identical to the doca version.
//
// -A: pre-existing missing-symbol fixed under Rule 3 (blocking issue —
// without this stub the pkg/loxinet test binary won't compile on the no-doca
// build path, blocking 70-A's go test -race -run Sockproxy gate).
func countEntriesForPipe(entries map[string]*docaOffloadEntry, pipeKey string) int {
	count := 0
	for _, oe := range entries {
		if oe.pipeKey == pipeKey {
			count++
		}
	}
	return count
}
