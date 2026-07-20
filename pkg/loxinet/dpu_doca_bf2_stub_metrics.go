//go:build !doca

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
 * dpu_doca_bf2_stub_metrics.go -- !doca mirror of dpu_doca_bf2_metrics.go.
 *
 * Stub-mirror discipline (09 lesson): every public symbol
 * exported by the //go:build doca companion is mirrored here as a
 * no-op so the darwin / Linux-without-DOCA build path compiles
 * cleanly. operator runbook is the only path that exercises
 * the doca-build code on real BF2 silicon; until then, this stub is
 * the test-build authority.
 *
 * Mirror surface (kept in lockstep with dpu_doca_bf2_metrics.go):
 *   - ReconciledCounterResult struct (identical fields, Go-side only).
 *   - OffloadState enum + constants (OffloadNone, OffloadTransitioning, OffloadHw).
 * - ReconciledStats struct (5 fields per).
 *   - (*DpDocaBf2).EntryQuery -- returns zero + nil.
 *   - (*DpDocaBf2).BatchQuery -- returns nil + nil.
 *   - (*DpDocaBf2).AllocSharedCounter -- returns 0 + nil.
 *   - (*DpDocaBf2).FreeSharedCounter -- silent no-op.
 *   - (*DpDocaBf2).EgressCountersAvailable -- returns false.
 *   - (*DpDocaBf2).ReconcileCtStats -- returns ReconciledStats{OffloadState: OffloadNone}.
 *   - initDocaMetricsCollector -- silent no-op.
 *   - noteDocaCollectorPanic -- silent no-op.
 *
 * Constraints honored:
 *   - NO CGO import. The stub MUST be Go-only.
 *   - NO SDK references. The stub MUST NOT name any SDK symbol.
 * - amendment guard: no `safeGoroutineOperation`, no
 *     `time.NewTicker`, no `go ` spawn (trivially satisfied by being
 *     no-ops).
 * - correction guard: no consultation of the per-flow
 *     offload-active atomic (the stub has no access to that field
 *     anyway).
 * - : no `layer="combined"` label child (trivially satisfied).
 */

package loxinet

// ReconciledCounterResult mirrors the doca-build struct in
// dpu_doca_bf2_metrics.go so non-CGO callers in Plans 65-03/65-04
// (and any unit tests under //go:build !doca) compile against the
// same type identity.
//
// Field order matches the doca-build declaration verbatim.
type ReconciledCounterResult struct {
	Pkts  uint64
	Bytes uint64
}

// OffloadState describes the DOCA hardware offload state for a CT entry.
// three-valued enum. This stub declaration makes the type available
// to REST handler and loxicmd renderer on darwin/CI builds.
type OffloadState string

const (
	// OffloadNone mirrors the doca-build constant. CT entry has no DOCA handle.
	OffloadNone OffloadState = "none"
	// OffloadTransitioning mirrors the doca-build constant. Handle installed;
	// hardware not yet forwarding (hw_pkts == 0).
	OffloadTransitioning OffloadState = "transitioning"
	// OffloadHw mirrors the doca-build constant. Hardware actively forwarding.
	OffloadHw OffloadState = "hw"
)

// ReconciledStats mirrors the doca-build struct. REST handler
// and loxicmd get ct -o wide renderer consume this type on all
// build paths including darwin/CI.
type ReconciledStats struct {
	Pkts         uint64
	Bytes        uint64
	HwPkts       uint64
	HwBytes      uint64
	OffloadState OffloadState
}

// noteDocaCollectorPanic is the !doca-build mirror of the recover helper.
// The doca-build companion also bumps the Prometheus error counter; that
// counter only exists under the doca tag, so the stub just discards the
// event. The registry itself (RegisterDocaCollector /
// InvokeRegisteredDocaCollectors) is shared build-tag-free in
// dpu_doca_collector_registry.go.
func noteDocaCollectorPanic(r interface{}) {
	_ = r
}

// EntryQuery returns a zero-valued result + nil error on !doca builds.
// Honors D-P65-01 entry 1 surface so Plans 65-03/65-04 compile under
// the !doca build path.
func (d *DpDocaBf2) EntryQuery(entryHandle interface{}) (ReconciledCounterResult, error) {
	// Intentional no-op. The doca-build companion takes
	// unsafe.Pointer; using `interface{}` here lets the stub avoid
	// pulling in `unsafe` and lets test code pass any sentinel value.
	_ = entryHandle
	return ReconciledCounterResult{}, nil
}

// BatchQuery returns nil + nil on !doca builds. Honors D-P65-01
// entry 3 surface (forward-compat per).
func (d *DpDocaBf2) BatchQuery(ids []uint32) ([]ReconciledCounterResult, error) {
	_ = ids
	return nil, nil
}

// AllocSharedCounter returns 0 + nil on !doca builds. Honors
// lifecycle surface.
func (d *DpDocaBf2) AllocSharedCounter(scopeKey string) (uint32, error) {
	_ = scopeKey
	return 0, nil
}

// FreeSharedCounter is a no-op on !doca builds. Honors lifecycle
// surface.
func (d *DpDocaBf2) FreeSharedCounter(id uint32) {
	_ = id
}

// EgressCountersAvailable returns false on !doca builds. The
// doca-build companion returns the cached G2 outcome; without DOCA
// there is no EGRESS-domain counter pool to query, so false is the
// honest answer. mirror Prometheus gauge will read 0
// under the !doca build path. Honors G2 outcome accessor contract.
func (d *DpDocaBf2) EgressCountersAvailable() bool {
	return false
}

// ReconcileCtStats returns a zero-valued ReconciledStats with
// OffloadState=OffloadNone on !doca builds. The doca-build companion
// queries the DOCA bridge and computes total=ebpf+doca; without DOCA
// there is no bridge, so only the eBPF portion is returned as the
// total (and since we have no eBPF here in the stub, all fields are 0).
//
// REST handler calls this; it must compile on darwin/CI.
// Honors (lazy-on-read, never fails) and (no offloadActive).
func (d *DpDocaBf2) ReconcileCtStats(ct *DpCtInfo) ReconciledStats {
	// Stub: no DOCA bridge available. Return OffloadNone with zero hw counters.
	// The eBPF counters are in ct.Packets/ct.Bytes but we return zeros here
	// because the stub is not the authority for eBPF-only reads (those go
	// through the REST handler which reads ct directly).
	_ = ct
	return ReconciledStats{OffloadState: OffloadNone}
}

// initDocaMetricsCollector is the !doca-build no-op mirror. The
// doca-build companion sets the EGRESS gauge from the cached G2 outcome;
// that action is not possible without DOCA linkage.
func initDocaMetricsCollector(d *DpDocaBf2) {
	_ = d
}

// DocaEntryRow mirrors the doca-build struct in dpu_doca_bf2_metrics.go.
// Exposed so the dpuDebugProviderAdapter in dpu_debug_adapter.go compiles
// on the !doca path and the REST handler tests can construct synthetic rows.
type DocaEntryRow struct {
	EntryHandleHashed string
	FiveTuple         string
	HwPkts            uint64
	HwBytes           uint64
	PipeKey           string
}

// QueryDocaEntries is the !doca-build no-op mirror. The doca-build companion
// walks the entry registry and calls EntryQuery per entry; without DOCA there
// is no entry registry so this returns nil. The REST handler handles nil as
// an empty result set.
func (d *DpDocaBf2) QueryDocaEntries(pipeName, svc, ep string, limit int) []DocaEntryRow {
	_ = pipeName
	_ = svc
	_ = ep
	_ = limit
	return nil
}

// stringsContains is the !doca-build mirror — avoids importing the strings
// package in the stub file; returns true iff s contains sub.
func stringsContains(s, sub string) bool {
	return len(sub) == 0 || containsStr(s, sub)
}

// containsStr is the !doca-build naive substring check mirror.
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

// fnv64aUintptr is the !doca-build mirror for test compilation.
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
