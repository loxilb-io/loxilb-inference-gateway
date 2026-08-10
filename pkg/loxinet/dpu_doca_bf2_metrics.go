//go:build doca

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

/*
 * dpu_doca_bf2_metrics.go -- Wave 2 (Plan 65-02) Go CGO scaffold
 * extended by Wave 3 (Plan 65-03) with Prometheus metrics, chunked walker,
 * ReconcileCtStats, and OffloadState enum.
 *
 * Bridges the C-side wrappers in loxilb-ebpf/doca/loxilb_doca_metrics.c
 * to the Go control plane. Every SDK call serializes through
 * d.bridge.submit so DPDK worker-thread affinity (pkg/loxinet/dpu_doca_cgo.go
 * line 154 worker) is preserved.
 *
 * Scope discipline:
 *   - Plan 65-02 shipped the CGO scaffold + the ReconciledCounterResult type
 *     + the callback-registry primitives (RegisterDocaCollector /
 *     InvokeRegisteredDocaCollectors).
 *   - Plan 65-03 extended with Prometheus metric vars, ReconcileCtStats
 *     simplified-math implementation, OffloadState enum, and the production
 *     noteDocaCollectorPanic helper. (The chunked-walker pipe surface was
 *     later removed in the metrics audit, D3 — it never ran in production.)
 * - InvokeRegisteredDocaCollectors is wired into the existing 
 *     per-tick path at pkg/loxinet/dpu_metrics.go.
 *
 * amendment iter 2 (callback registry, NO goroutine spawn):
 *   - This file MUST NOT spawn a periodic-collection goroutine
 * (the anti-pattern wrapper is intentionally absent).
 *   - This file MUST NOT create a polling ticker on the DOCA hot path.
 *   - This file MUST NOT bare-spawn a collection goroutine.
 *   - The chunked walker (Plan 65-03) runs in the existing DOCA worker
 * thread context via d.bridge.submit; the per-tick context
 *     drives the cadence.
 *
 * correction guard:
 *   - This file MUST NOT consult the per-flow offload-active atomic
 *     (the field at pkg/loxinet/dpu_doca_bf2.go:317 continues to drive
 *     the existing docaOffloadActiveFlows gauge through the existing
 *     Add(+/-1) sites at dpu_doca_bf2.go:826,832,1220,1495,1574;
 * reconciliation ignores it and computes
 *     total = ebpf + doca directly).
 */

package loxinet

/*
#include <stdlib.h>
#include "../../loxilb-ebpf/doca/loxilb_doca_flow.h"
#cgo CFLAGS: -I./../../loxilb-ebpf/doca/
#cgo LDFLAGS: -L./../../loxilb-ebpf/doca/ -l:libloxilb_doca_flow.a
*/
import "C"

import (
	"fmt"
	"unsafe"

	tk "github.com/loxilb-io/loxilib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ----------------------------------------------------------------------
// Prometheus metric surface (loxilb_doca_* prefix)
//
// Canonical metric names: loxilb_doca_* for DOCA-specific metrics.
// The C-side symbol prefix llb_doca_* stays unchanged.
//
// The Phase-65 chunked-walker pipe surface (loxilb_doca_pipe_*,
// loxilb_lb_pkts/bytes_total, collector walk/sweep/poll gauges) was
// removed in the metrics audit (D3): UpdatePipeTotal never gained a
// production caller, so the walker never ran and the whole surface was
// permanently zero (and fwd_to replayed deltas onto a hardcoded static
// topology). The working per-pipe HW counters live in dpu_metrics.go
// (doca_pipe_hw_pkts/bytes_total via CollectHwOffloadStats).
// ----------------------------------------------------------------------

// llbDocaQueryAPILabelValues is the closed enum for the api dimension on the
// errors counter. Values: entry_query, batch_query, pipe_miss, panic.
var llbDocaQueryAPILabelValues = [...]string{"entry_query", "batch_query", "pipe_miss", "panic"}

// llbDocaQueryReasonLabelValues is the closed enum for the reason dimension.
// Values: hw_error, timeout, panic, other.
var llbDocaQueryReasonLabelValues = [...]string{"hw_error", "timeout", "panic", "other"}

var loxilbDocaCollectorQueryErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "loxilb_doca_collector_query_errors_total",
	Help: "DOCA counter-query errors partitioned by API (entry_query, batch_query, pipe_miss, panic) and reason (hw_error, timeout, panic, other). Incremented by ReconcileCtStats, QueryDocaEntries, and InvokeRegisteredDocaCollectors recover().",
}, []string{"api", "reason"})

// loxilbDocaEgressCountersAvailable — G2 outcome mirror.
// G2 PASS ratified across runs 4/5/6 per 65-STAGE2-RESULTS.md:
// EGRESS-domain SHARED counter RESOURCE binding works on bf2-arm DOCA 2.9.4.
// Set at post-pipe-init time in dpu_doca_bf2_init.go from d.EgressCountersAvailable.
var loxilbDocaEgressCountersAvailable = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "loxilb_doca_egress_counters_available",
	Help: "G2 outcome gauge: 1 when EGRESS-domain SHARED counter resources can be bound on this BF2 DOCA version. value=true child is 1 on bf2-arm DOCA 2.9.4 (constant per Stage-2 runs 4/5/6). P66/P67 depend on this gauge to confirm EGRESS availability before using the EGRESS_DISPATCH pipe.",
}, []string{"value"})

func init() {
	// Pre-instantiate all closed-enum children so rate queries have a t0
	// baseline from the first scrape (RESEARCH §Pattern 7; -05
	// discipline). Without pre-instantiation, panels show "no data" until the
	// first event fires — the empty-label-set problem for sparse metrics.

	// 4 api x 4 reason = 16 children for the errors counter.
	for _, api := range llbDocaQueryAPILabelValues {
		for _, reason := range llbDocaQueryReasonLabelValues {
			loxilbDocaCollectorQueryErrorsTotal.WithLabelValues(api, reason)
		}
	}

	// EGRESS flag pre-instantiation (both children; actual value set post-pipe-init
	// from d.EgressCountersAvailable in dpu_doca_bf2_init.go site).
	loxilbDocaEgressCountersAvailable.WithLabelValues("true")
	loxilbDocaEgressCountersAvailable.WithLabelValues("false")
}

// ----------------------------------------------------------------------
//  Type: ReconciledCounterResult
//  Plain-data Go mirror of llb_doca_counter_result_t.
// D-P65-05 reconciliation contract scaffold -- consumes
//  this type from the chunked walker and the lazy-on-read CT path.
// ----------------------------------------------------------------------

// ReconciledCounterResult is the Go-side mirror of the C
// llb_doca_counter_result_t plain-data struct. It carries packet and
// byte counts returned by any of counter-query wrappers
// (per-entry, batched-shared). will compose this with an
// eBPF-side delta to produce the reconciled flow counter (D-P65-05,
// lazy-on-read).
//
// Field order matches the C struct (total_pkts, total_bytes) for clarity
// at the CGO boundary; the bridge does a per-field copy rather than a
// memcpy so the Go field names can be more idiomatic.
type ReconciledCounterResult struct {
	Pkts  uint64
	Bytes uint64
}

// counterResultFromC converts a C.llb_doca_counter_result_t into the
// idiomatic Go shape. Kept as a tiny helper so the four call sites
// below stay focused on their per-method orchestration.
func counterResultFromC(c C.llb_doca_counter_result_t) ReconciledCounterResult {
	return ReconciledCounterResult{
		Pkts:  uint64(c.total_pkts),
		Bytes: uint64(c.total_bytes),
	}
}

// ----------------------------------------------------------------------
//  Section B: OffloadState enum + ReconciledStats struct
// ----------------------------------------------------------------------

// OffloadState describes the DOCA hardware offload state for a CT entry.
// three-valued enum: none, transitioning, hw.
type OffloadState string

const (
	// OffloadNone means the CT entry has no DOCA handle; running eBPF-only.
	OffloadNone OffloadState = "none"
	// OffloadTransitioning means the entry has a DOCA handle installed but
	// hw_pkts == 0 (handle present; hardware not yet forwarding).
	OffloadTransitioning OffloadState = "transitioning"
	// OffloadHw means the entry has a DOCA handle and hw_pkts > 0 (hardware
	// actively forwarding; fast-path engaged).
	OffloadHw OffloadState = "hw"
)

// ReconciledStats is the output of ReconcileCtStats (corrected,
// lazy-on-read). Carries the simplified total = ebpf + doca math
// as per MONOTONIC finding: no frozen-snapshot subtraction,
// no leak math, no saturating arithmetic.
//
// REST handler and loxicmd get ct -o wide consume this.
type ReconciledStats struct {
	Pkts         uint64       // total lifetime packets (ebpf + doca)
	Bytes        uint64       // total lifetime bytes (ebpf + doca)
	HwPkts       uint64       // DOCA hardware share only (0 if OffloadState != hw)
	HwBytes      uint64       // DOCA hardware bytes only
	OffloadState OffloadState // classification
}

// ----------------------------------------------------------------------
// Section C: callback registry — moved to dpu_doca_collector_registry.go
// (build-tag free; shared by doca and !doca builds). Only the
// noteDocaCollectorPanic recover helper stays here because it touches the
// doca-build Prometheus error counter.
// ----------------------------------------------------------------------

// noteDocaCollectorPanic is the production recover helper for the
// InvokeRegisteredDocaCollectors panic-isolation path. Bumps the
// loxilb_doca_collector_query_errors_total{api="batch_query",reason="panic"}
// counter and logs at warning level. Replaces placeholder.
//
// amendment guard: this function does NOT spawn a goroutine.
func noteDocaCollectorPanic(r interface{}) {
	loxilbDocaCollectorQueryErrorsTotal.WithLabelValues("batch_query", "panic").Inc()
	tk.LogIt(tk.LogWarning,
		"[doca-metrics] collector panic recovered: %v\n", r)
}

// ----------------------------------------------------------------------
//  Section D: CGO wrappers on *DpDocaBf2.
//
//  Every public method below routes its SDK call through
//  d.bridge.submit so DPDK-worker-thread affinity is preserved
//  (DocaBridge.submit at pkg/loxinet/dpu_doca_cgo.go:315).
//
//  Errors surface to callers. Methods MUST NOT panic; the C wrappers
//  return -1 on any SDK error and the Go side translates that into a
//  named error.
// ----------------------------------------------------------------------

// EntryQuery returns the cached counter pair for one BASIC pipe entry.
// Dispatches the C call C.llb_doca_entry_query_v2 onto the DOCA worker
// thread via d.bridge.submit. The opaque entry handle MUST have been
// returned by a prior llb_doca_entry_add_basic / llb_doca_acl_*entry_add
// or similar SDK-side pipe-entry add call.
//
// chunked walker calls this in a chunked loop bounded by
// polling-budget shape. REST debug endpoint calls
// this for operator on-demand per-entry queries.
//
// Honored decisions: D-P65-01 entry 1, D-P65-05 reconciliation contract.
func (d *DpDocaBf2) EntryQuery(entryHandle unsafe.Pointer) (ReconciledCounterResult, error) {
	var zero ReconciledCounterResult
	if d == nil || d.bridge == nil {
		return zero, fmt.Errorf("doca-bf2 EntryQuery: bridge not initialized")
	}
	if entryHandle == nil {
		return zero, fmt.Errorf("doca-bf2 EntryQuery: nil entry handle")
	}

	var c C.llb_doca_counter_result_t
	err := d.bridge.submit(func() error {
		rc := C.llb_doca_entry_query_v2(entryHandle, &c)
		if rc != 0 {
			return fmt.Errorf("llb_doca_entry_query_v2 failed: rc=%d", int(rc))
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	return counterResultFromC(c), nil
}

// BatchQuery returns the cached counter pairs for a batch of
// shared-resource IDs in a single SDK call. Dispatches
// C.llb_doca_counter_batch_query through d.bridge.submit.
//
// FUTURE-PROOF narrowing -- no production pipe references
// SHARED counters today; may declare a registration site
// without invoking the wrapper. The shape stays stable so a future
// protocol-pipe SHARED pool can plug in without API churn.
//
// Honored decisions: D-P65-01 entry 3 (forward-compat), D-P65-02
// (polling-budget API shape).
func (d *DpDocaBf2) BatchQuery(ids []uint32) ([]ReconciledCounterResult, error) {
	if d == nil || d.bridge == nil {
		return nil, fmt.Errorf("doca-bf2 BatchQuery: bridge not initialized")
	}
	n := uint32(len(ids))
	if n == 0 {
		return nil, nil
	}

	// Build a C uint32 array from the Go input. The slice is local
	// to this method; lifetime is bounded by the bridge.submit closure.
	cIDs := make([]C.uint32_t, n)
	for i, id := range ids {
		cIDs[i] = C.uint32_t(id)
	}
	cResults := make([]C.llb_doca_counter_result_t, n)

	err := d.bridge.submit(func() error {
		rc := C.llb_doca_counter_batch_query(
			(*C.uint32_t)(unsafe.Pointer(&cIDs[0])),
			(*C.llb_doca_counter_result_t)(unsafe.Pointer(&cResults[0])),
			C.uint32_t(n),
		)
		if rc != 0 {
			return fmt.Errorf("llb_doca_counter_batch_query failed: rc=%d", int(rc))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	results := make([]ReconciledCounterResult, n)
	for i := uint32(0); i < n; i++ {
		results[i] = counterResultFromC(cResults[i])
	}
	return results, nil
}

// AllocSharedCounter requests a fresh shared-counter ID from the C side
// monotonic allocator. scope_key is forwarded for forward-compat (Plan
// 65-05 lazy-recycle pool may consume it) but ignored in v6.0 first
// release. Honored decisions: lifecycle.
func (d *DpDocaBf2) AllocSharedCounter(scopeKey string) (uint32, error) {
	if d == nil || d.bridge == nil {
		return 0, fmt.Errorf("doca-bf2 AllocSharedCounter: bridge not initialized")
	}
	cKey := C.CString(scopeKey)
	defer C.free(unsafe.Pointer(cKey))

	var cID C.uint32_t
	err := d.bridge.submit(func() error {
		rc := C.llb_doca_alloc_shared_counter(cKey, &cID)
		if rc != 0 {
			return fmt.Errorf("llb_doca_alloc_shared_counter failed: rc=%d", int(rc))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return uint32(cID), nil
}

// FreeSharedCounter releases a shared-counter ID. v6.0 first release
// is a no-op on the C side (lazy recycle deferred to); the
// Go wrapper preserves the symmetrical alloc/free shape so production
// call sites stay clean. Honored decisions: lifecycle.
func (d *DpDocaBf2) FreeSharedCounter(id uint32) {
	if d == nil || d.bridge == nil {
		return
	}
	_ = d.bridge.submit(func() error {
		C.llb_doca_free_shared_counter(C.uint32_t(id))
		return nil
	})
}

// EgressCountersAvailable reports the cached G2 outcome.
// mirrors this into the loxilb_doca_egress_counters_available
// Prometheus gauge so operators can dashboard the availability
// alongside throughput. Honored decisions: G2 ratification, D-P65-01
// entry 3 context.
func (d *DpDocaBf2) EgressCountersAvailable() bool {
	if d == nil || d.bridge == nil {
		return false
	}
	var ret C.int
	_ = d.bridge.submit(func() error {
		ret = C.llb_doca_egress_counter_available()
		return nil
	})
	return ret == 1
}

// ----------------------------------------------------------------------
// Section E: ReconcileCtStats — simplified math + OffloadState
//
// CORRECTED (2026-05-16): eBPF CT counter is MONOTONIC from CT
//  creation through eviction. No reset path at HW offload. Therefore:
//    total_lifetime = current_ebpf + current_doca
//  No frozen-snapshot subtraction. No leak math. No saturating arithmetic.
//
//  lazy-on-read. MUST NOT propagate bridge errors to the GET handler.
//
//  entryQueryFn is the production function pointer defaulting to
//  (*DpDocaBf2).EntryQuery. Tests override this seam to inject a mock
//  without requiring a live DOCA bridge.
// ----------------------------------------------------------------------

// entryQueryFn is the unit-test seam for EntryQuery. Tests set this to a
// mock function; production code uses nil (which causes ReconcileCtStats
// to call d.EntryQuery directly). This field is package-level so both
// test and production code can access it without changing the public API.
//
// Unit-test affordance: set entryQueryFn = func(h unsafe.Pointer) (ReconciledCounterResult, error) { ... }
// in the test to bypass the DOCA bridge.
var entryQueryFn func(unsafe.Pointer) (ReconciledCounterResult, error)

// ReconcileCtStats implements simplified reconciliation for one CT
// entry. Looks up the DOCA entry handle from d.entries[ct.Key], queries
// the HW counter, and returns the simplified total = ebpf + doca.
//
// lazy-on-read contract: this function MUST NOT return an error.
// Bridge failures increment loxilb_doca_collector_query_errors_total
// {api="entry_query",reason="hw_error"} and treat HW count as zero —
// the caller (REST/CLI handler) sees a valid ReconciledStats with the
// eBPF portion only.
//
// correction guard: this function MUST NOT consult the per-flow
// offload-active atomic — no gating on it exists here.
func (d *DpDocaBf2) ReconcileCtStats(ct *DpCtInfo) ReconciledStats {
	if ct == nil {
		return ReconciledStats{OffloadState: OffloadNone}
	}

	// eBPF counter is MONOTONIC (corrected): read from DpCtInfo fields
	// set by convDPCt2GoObj at eBPF map read time (dpebpf_linux.go:2168-2169).
	// No eBPF system call is made here — we read the cached Go-side fields.
	ebpfPkts, ebpfBytes := readEbpfCT(ct)

	// Look up the DOCA entry handle from the in-process registry.
	// ctMtx guard: snapshot under lock, release before CGO (anti-deadlock
	// pattern).
	d.ctMtx.Lock()
	oe, exists := d.entries[ct.Key()]
	var entryHandle unsafe.Pointer
	if exists && oe != nil {
		entryHandle = oe.entry
	}
	d.ctMtx.Unlock()

	if !exists || entryHandle == nil {
		// No DOCA handle: eBPF-only path. OffloadNone.
		return ReconciledStats{
			Pkts:         ebpfPkts,
			Bytes:        ebpfBytes,
			HwPkts:       0,
			HwBytes:      0,
			OffloadState: OffloadNone,
		}
	}

	// Query the DOCA HW counter. Use the test seam if set, else real bridge.
	var hwRes ReconciledCounterResult
	var err error
	if entryQueryFn != nil {
		hwRes, err = entryQueryFn(entryHandle)
	} else {
		hwRes, err = d.EntryQuery(entryHandle)
	}

	if err != nil {
		// lazy-on-read MUST NOT fail the GET handler. Treat as zero.
		loxilbDocaCollectorQueryErrorsTotal.WithLabelValues("entry_query", "hw_error").Inc()
		hwRes = ReconciledCounterResult{}
	}

	state := classifyOffloadState(entryHandle, hwRes.Pkts)
	return ReconciledStats{
		Pkts:         ebpfPkts + hwRes.Pkts,
		Bytes:        ebpfBytes + hwRes.Bytes,
		HwPkts:       hwRes.Pkts,
		HwBytes:      hwRes.Bytes,
		OffloadState: state,
	}
}

// readEbpfCT reads the cached eBPF packet and byte counters from a DpCtInfo.
// The eBPF CT map is read periodically by the control plane and cached in
// ct.Packets / ct.Bytes (set at dpebpf_linux.go:2168-2169 via convDPCt2GoObj).
// NO eBPF system call is made here — we read the cached Go-side fields.
//
// corrected: the eBPF CT counter is MONOTONIC from CT creation through
// eviction; after HW offload installation, packets bypass eBPF naturally
// (counter stops incrementing). The cached value at any given read is the
// eBPF-side lifetime total.
//
// If future work needs per-tick delta tracking for the eBPF contribution,
// the delta can be computed at the call site without modifying this helper.
// TODO: if the field names change in DpCtInfo, update this helper accordingly.
// Search anchor: grep -n 'ct.Packets\|ct.Bytes\|PktCount' pkg/loxinet/dpebpf_linux.go
func readEbpfCT(ct *DpCtInfo) (pkts, bytes uint64) {
	return ct.Packets, ct.Bytes
}

// classifyOffloadState returns OffloadState for a DOCA entry.
// nil/zero handle → OffloadNone (caller already checks handle != nil before calling)
// handle + hwPkts == 0 → OffloadTransitioning (handle installed; HW not yet forwarding)
// handle + hwPkts > 0  → OffloadHw (HW fast-path active)
func classifyOffloadState(handle unsafe.Pointer, hwPkts uint64) OffloadState {
	if handle == nil {
		return OffloadNone
	}
	if hwPkts > 0 {
		return OffloadHw
	}
	return OffloadTransitioning
}

// ----------------------------------------------------------------------
//  Section F: (removed)
//
//  The Phase-65 chunked per-tick walker (CollectDocaCounters /
//  collectDocaCounters_pipe / pipeWalkState / UpdatePipeTotal) was
//  deleted in the metrics audit (D3): UpdatePipeTotal never gained a
//  production caller, so every walk early-returned on total==0 and the
//  loxilb_doca_pipe_* surface stayed permanently zero.
// ----------------------------------------------------------------------

// initDocaMetricsCollector sets the EGRESS gauge from
// d.EgressCountersAvailable at post-pipe-init time.
//
// Called from (*DpDocaBf2).Init at the end of pipe initialization. Must be
// called once per process lifetime (amendment: no goroutine spawn, no
// ticker, no wrapped collection goroutine for DOCA collection).
func initDocaMetricsCollector(d *DpDocaBf2) {
	// Set the EGRESS counters availability gauge from the cached G2 outcome.
	// G2 PASS ratified across runs 4/5/6 per 65-STAGE2-RESULTS.md; returns
	// constant 1 in v6.0 first release from EgressCountersAvailable.
	if d.EgressCountersAvailable() {
		loxilbDocaEgressCountersAvailable.WithLabelValues("true").Set(1)
		loxilbDocaEgressCountersAvailable.WithLabelValues("false").Set(0)
	} else {
		loxilbDocaEgressCountersAvailable.WithLabelValues("true").Set(0)
		loxilbDocaEgressCountersAvailable.WithLabelValues("false").Set(1)
	}
}

// DocaEntryRow is a package-internal result row for filtered query.
// The adapter in dpu_debug_adapter.go converts it to handler.DocaEntryDetail
// to avoid a circular import between pkg/loxinet and api/restapi/handler.
type DocaEntryRow struct {
	// EntryHandleHashed is the fnv64a hash of the raw pointer (guard).
	EntryHandleHashed string
	// FiveTuple is the flow key (sip:sport|dip:dport|proto).
	FiveTuple string
	// HwPkts is the current hardware packet count.
	HwPkts uint64
	// HwBytes is the current hardware byte count.
	HwBytes uint64
	// PipeKey identifies the DOCA pipe.
	PipeKey string
}

// QueryDocaEntries implements filtered per-entry detail query.
// Called by DpuManager via the dpuDebugProviderAdapter to serve
// GET /config/dpu/debug?pipe=...&svc=...&ep=...&limit=N.
//
// All input validation is done by the REST handler BEFORE this call.
// On per-entry bridge error: bumps query errors counter and continues.
// guard: no new goroutine or ticker; bridge.submit handles affinity.
func (d *DpDocaBf2) QueryDocaEntries(pipeName, svc, ep string, limit int) []DocaEntryRow {
	if d == nil {
		return nil
	}

	// Snapshot entries under ctMtx (brief lock, release before CGO).
	type entrySnap struct {
		key     string
		entry   unsafe.Pointer
		pipeKey string
	}
	var snaps []entrySnap

	d.ctMtx.Lock()
	for key, oe := range d.entries {
		if oe == nil || oe.entry == nil {
			continue
		}
		// Filter by pipeKey. ct_fwd_5tuple / ct_rev_5tuple both map to "ct".
		if pipeName != "" {
			match := false
			switch pipeName {
			case "ct_fwd_5tuple", "ct_rev_5tuple":
				match = oe.pipeKey == "ct"
			default:
				match = oe.pipeKey == pipeName
			}
			if !match {
				continue
			}
		}
		// Filter by svc / ep as substring of the flow key.
		if svc != "" && !stringsContains(key, svc) {
			continue
		}
		if ep != "" && !stringsContains(key, ep) {
			continue
		}
		snaps = append(snaps, entrySnap{key: key, entry: oe.entry, pipeKey: oe.pipeKey})
		if len(snaps) >= limit {
			break
		}
	}
	d.ctMtx.Unlock()

	results := make([]DocaEntryRow, 0, len(snaps))
	for _, snap := range snaps {
		res, err := d.EntryQuery(snap.entry)
		if err != nil {
			loxilbDocaCollectorQueryErrorsTotal.WithLabelValues("entry_query", "hw_error").Inc()
			continue
		}
		// hash raw pointer before serialization; never expose uintptr.
		handleHash := fmt.Sprintf("%016x", fnv64aUintptr(uintptr(unsafe.Pointer(snap.entry))))
		results = append(results, DocaEntryRow{
			EntryHandleHashed: handleHash,
			FiveTuple:         snap.key,
			HwPkts:            res.Pkts,
			HwBytes:           res.Bytes,
			PipeKey:           snap.pipeKey,
		})
	}
	return results
}

// stringsContains is a thin alias so the !doca stub can avoid importing strings.
func stringsContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && containsStr(s, sub))
}

// containsStr is a naive O(n*m) substring check that avoids the strings package
// import requirement in the stub build. For the small flow-key strings used in
// filter it is fast enough.
func containsStr(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// fnv64aUintptr computes the FNV-1a 64-bit hash of a uintptr value.
// Used to hash raw DOCA entry handles before JSON serialization (guard).
func fnv64aUintptr(v uintptr) uint64 {
	const offset64 = 14695981039346656037
	const prime64 = 1099511628211
	h := uint64(offset64)
	for i := 0; i < 8; i++ {
		h ^= uint64(v & 0xff)
		h *= prime64
		v >>= 8
	}
	return h
}
