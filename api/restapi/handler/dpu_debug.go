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

package handler

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"
	"strconv"
	"strings"

	tk "github.com/loxilb-io/loxilib"
)

// FlowHwStatsEntry is a per-flow hardware counter entry in the debug response.
type FlowHwStatsEntry struct {
	FlowKey string `json:"flow_key"`
	PipeKey string `json:"pipe_key"`
	HwBytes uint64 `json:"hw_bytes"`
	HwPkts  uint64 `json:"hw_pkts"`
}

// FdbHwStatsEntry is a per-FDB-entry hardware counter row in the debug response.
// P49-R1. Plain-data fields only (threat — no raw DOCA handle leak in JSON).
// Mirrors pkg/loxinet.FdbHwStats shape; package-separated to avoid a handler→loxinet import cycle.
type FdbHwStatsEntry struct {
	Mac     string `json:"mac"`
	Port    uint16 `json:"port"`
	HwBytes uint64 `json:"hw_bytes"`
	HwPkts  uint64 `json:"hw_pkts"`
}

// RouteHwStatsEntry is a per-route hardware counter row in the debug response.
// (full FIB-seeded LPM pipe) is POSTPONED to v7.1 — this slice will be
// empty ([]) on v7.0 until the LPM pipe ships. Routed flows landed by the
// CT-path (06 RouteFlowOffload) appear in `flows[]` with pipe_key="route".
type RouteHwStatsEntry struct {
	Dst        string `json:"dst"`
	NextHopMac string `json:"next_hop_mac"`
	Port       uint16 `json:"port"`
	HwBytes    uint64 `json:"hw_bytes"`
	HwPkts     uint64 `json:"hw_pkts"`
}

// AclHwStatsEntry is a per-ACL-rule hardware counter row in the debug response.
type AclHwStatsEntry struct {
	RuleID  uint32 `json:"rule_id"`
	Action  string `json:"action"`
	HwBytes uint64 `json:"hw_bytes"`
	HwPkts  uint64 `json:"hw_pkts"`
}

// DpuDebugResponse is the GET response for /netlox/v1/config/dpu/debug.
type DpuDebugResponse struct {
	Enabled bool `json:"enabled"`

	// Legacy scalars (+). Preserved EXACTLY for backward-compat with
	// the 5 CICD consumers inventoried in 49-RESEARCH.md §Schema Backward-Compat:
	// cicd/dpu-l4-lb/validation.sh, cicd/dpu-failover/validation.sh,
	// cicd/dpu-combined/validation.sh, cicd/dpu-nat-modes/validation.sh,
	// cicd/bf2-perf/common_bf2.sh — all parse these as integers.
	OffloadSuccess uint64 `json:"offload_success"`
	OffloadFailure uint64 `json:"offload_failure"`
	OffloadActive  int64  `json:"offload_active"`

	// P49-R1: per-pipe breakdown. Always populated (5 keys:
	// ct, udp_ct, route, fdb, acl). The *ActiveByPipe map additionally
	// contains a synthetic "total" key equal to OffloadActive (scalar).
	OffloadSuccessByPipe map[string]uint64 `json:"offload_success_by_pipe"`
	OffloadFailureByPipe map[string]uint64 `json:"offload_failure_by_pipe"`
	OffloadActiveByPipe  map[string]int64  `json:"offload_active_by_pipe"`

	Plugins []string           `json:"plugins"`
	Flows   []FlowHwStatsEntry `json:"flows,omitempty"`

	// P49-R1: per-pipe-family entry arrays. Always present as JSON
	// arrays (never null) — handler normalizes nil slices to []T{} before writing.
	// NO `omitempty` — consumers expect the key to always exist.
	FdbEntries   []FdbHwStatsEntry   `json:"fdb_entries"`
	RouteEntries []RouteHwStatsEntry `json:"route_entries"`
	AclEntries   []AclHwStatsEntry   `json:"acl_entries"`

	// CircuitBreakerOpen mirrors docaCircuitBreakerStateGauge for consumers that
	// read /dpu/debug instead of /metrics. True iff any registered plugin reports
	// its offload circuit breaker as tripped. Observability gap fix for the
	// Scenario C (degraded-path) benchmark: CICD test scripts could not
	// previously detect CB state since /metrics is not always enabled.
	CircuitBreakerOpen bool `json:"circuit_breaker_open"`

	// per-DOCA-entry detail (optional; only present when
	// ?pipe=...&svc=...&ep=...&limit=N query params are supplied).
	// omitempty so legacy parsers see no new field on the aggregate-only path.
	// Hard cap: limit ≤ 2000 per G3 ratification (65-STAGE2-RESULTS.md:
	// 2000 × 660ns p99 = 1.32ms, 757× under the 1.0s gate).
	// R-11-C escape hatch: for workloads with 100K+ offloaded flows the
	// per-entry reconciliation cost is ~7ms per 1K flows; sustained
	// high-frequency polling above 10K flows is not supported (/ R-11-C
	// caching deferred past).
	DocaEntryDetails []DocaEntryDetail `json:"doca_entry_details,omitempty"`
}

// DpuDebugAction is the POST request body for /netlox/v1/config/dpu/debug.
//
// Supported actions:
//   - {"action":"unregister","plugin":"<name>"}      Unload a DPU plugin.
//   - {"action":"cb_force","mode":"open"|"close"}    Test-only: pin the DOCA
//     circuit breaker into the given state so Scenario C benchmarks can
//     deterministically drive the eBPF fallback path without racing DOCA init.
type DpuDebugAction struct {
	Action string `json:"action"`           // "unregister" | "cb_force"
	Plugin string `json:"plugin,omitempty"` // for action=="unregister"
	Mode   string `json:"mode,omitempty"`   // for action=="cb_force": "open" | "close"
}

// DocaEntryDetail is the per-DOCA-entry detail record returned by the
// filtered query (GET /config/dpu/debug?pipe=&svc=&ep=&limit=N).
// entry handles are hashed (fnv64a) before serialization — raw
// pointers are NEVER exposed in JSON.
type DocaEntryDetail struct {
	// EntryHandleHashed is the fnv64a hash of the raw DOCA entry handle
	// (uintptr). Used for log correlation only — not a capability token.
	EntryHandleHashed string `json:"entry_handle_hashed"`
	// FiveTuple is the flow 5-tuple string for human readability.
	FiveTuple string `json:"5_tuple"`
	// HwPkts is the current hardware packet count for this entry.
	HwPkts uint64 `json:"hw_pkts"`
	// HwBytes is the current hardware byte count for this entry.
	HwBytes uint64 `json:"hw_bytes"`
	// AgeMsEstimate is a placeholder for age_ms (currently 0; age-query
	// is a separate API not used). Exposed so
	// runbook can wire it when available.
	AgeMsEstimate uint64 `json:"age_ms"`
	// PipeKey identifies which DOCA pipe this entry belongs to.
	PipeKey string `json:"pipe_key"`
}

// DocaQueryFilter holds the parsed query parameters.
// Used as the argument to DpuDebugProvider.QueryDocaEntries.
type DocaQueryFilter struct {
	Pipe  string // pipe name from the closed allow-list
	Svc   string // service name (empty = all)
	Ep    string // endpoint addr:port (empty = all)
	Limit int    // clamped to [1, 2000]
}

// dpuDebugAllowedPipes is the closed allow-list for the ?pipe= parameter.
// validated; any value not in this set returns HTTP 400.
var dpuDebugAllowedPipes = map[string]bool{
	"rss":                true,
	"to_kernel":          true,
	"egress_dispatch":    true,
	"ct_fwd_5tuple":      true,
	"ct_rev_5tuple":      true,
	"root_l3l4_dispatch": true,
	"fdb_l2":             true,
	"deny":               true,
	"allow":              true,
}

// dpuDebugDefaultLimit is the default per-request entry limit.
const dpuDebugDefaultLimit = 200

// dpuDebugMaxLimit is the hard cap per G3 ratification:
// 2000 × 660ns p99 = 1.32ms, 757× under the 1.0s gate.
const dpuDebugMaxLimit = 2000

// fnv64aHash returns the FNV-1a 64-bit hash of the input as a hex string.
// Used to hash raw entry handles before JSON serialization (guard).
func fnv64aHash(v uint64) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strconv.FormatUint(v, 10)))
	return fmt.Sprintf("%016x", h.Sum64())
}

// CtFlowRef contains the 5-tuple + identity fields needed to locate a CT entry
// in the DOCA entry registry for lazy-on-read reconciliation.
// All fields are plain Go types so the handler package never imports loxinet
// types (circular-import guard).
type CtFlowRef struct {
	// SipStr / DipStr are the string forms of source/destination IP.
	SipStr string
	DipStr string
	// Sport / Dport are the layer-4 source/destination ports.
	Sport uint16
	Dport uint16
	// Proto is the IP protocol string (e.g. "tcp", "udp", "icmp").
	Proto string
	// IdentStr is the raw ident field from cmn.CtInfo (format "idtype:ident").
	// The adapter parses this back to uint32 IdType + Ident for key construction.
	IdentStr string
	// EbpfPkts / EbpfBytes are the eBPF CT counters at the time of the GET.
	// The reconciled total = EbpfPkts + hwPkts (corrected: MONOTONIC eBPF counter).
	EbpfPkts  uint64
	EbpfBytes uint64
}

// DpuDebugProvider abstracts DpuManager access to avoid circular imports.
// Implemented by pkg/loxinet and registered via SetDpuDebugProvider.
type DpuDebugProvider interface {
	IsEnabled() bool
	OffloadStats() (success, failure uint64, active int64)
	PluginNames() []string
	Unregister(name string)
	AllFlowHwStats() []FlowHwStatsEntry

	// P49-R1 additions.
	OffloadStatsByPipe() (successByPipe map[string]uint64, failureByPipe map[string]uint64, activeByPipe map[string]int64)
	AllFdbHwStats() []FdbHwStatsEntry
	AllRouteHwStats() []RouteHwStatsEntry
	AllAclHwStats() []AclHwStatsEntry

	// CB observability + test hook. Returns false when no plugin implements a
	// circuit breaker (e.g. pure eBPF build). CircuitBreakerForce is a no-op in
	// that case as well (returns nil).
	CircuitBreakerOpen() bool
	CircuitBreakerForce(mode string) error

	// per-DOCA-entry filtered query.
	// Returns up to filter.Limit DocaEntryDetail records filtered by
	// (pipe, svc, ep). Dispatches each query via the bridge.submit
	// serialization path (DPDK worker affinity). On !doca builds the
	// stub returns nil, nil. On per-entry bridge errors, the error counter
	// is bumped and the entry is skipped (partial results are returned).
	QueryDocaEntries(filter DocaQueryFilter) ([]DocaEntryDetail, error)

	// lazy-on-read CT reconciliation.
	// Looks up the DOCA entry handle for the given CT flow (identified by
	// ref's 5-tuple + ident), queries the HW counter, and returns the
	// OffloadState string ("none"|"transitioning"|"hw") plus the HW
	// packet and byte counts. On !doca builds the stub returns ("none", 0, 0).
	// contract: MUST NOT return an error — bridge failures treat HW
	// count as zero and return OffloadNone.
	ReconcileCtFlowStats(ref CtFlowRef) (offloadState string, hwPkts, hwBytes uint64)
}

var dpuDebugProvider DpuDebugProvider

// SetDpuDebugProvider registers the DpuManager as the debug provider.
// Called from pkg/loxinet during initialization.
func SetDpuDebugProvider(p DpuDebugProvider) {
	dpuDebugProvider = p
}

// HandleDpuDebug dispatches DPU debug requests by HTTP method.
func HandleDpuDebug(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dpuDebugGet(w, r)
	case http.MethodPost:
		dpuDebugPost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func dpuDebugGet(w http.ResponseWriter, r *http.Request) {
	tk.LogIt(tk.LogTrace, "api: DPU Debug GET called by IP: %s\n", r.RemoteAddr)

	// --- : parse query params FIRST (all input validation before
	// any CGO crossing per RESEARCH §Security Domain V5). ---
	q := r.URL.Query()
	pipeParam := q.Get("pipe")
	svcParam := q.Get("svc")
	epParam := q.Get("ep")
	limitParam := q.Get("limit")

	// if no params are present, dispatch the existing aggregate
	// handler unchanged (backward-compat with CICD consumers that parse the
	// existing integer fields and expect no new keys).
	d07Requested := pipeParam != "" || svcParam != "" || epParam != "" || limitParam != ""

	if d07Requested {
		// --- input validation (ALL done before any CGO crossing) ---

		// Validate pipe against the closed allow-list.
		if pipeParam != "" && !dpuDebugAllowedPipes[pipeParam] {
			allowed := strings.Join([]string{
				"rss", "to_kernel", "egress_dispatch",
				"ct_fwd_5tuple", "ct_rev_5tuple", "root_l3l4_dispatch",
				"fdb_l2", "deny", "allow",
			}, "|")
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("invalid pipe; allowed: %s", allowed),
			})
			return
		}

		// Validate ep if present: must be addr:port with port in [1, 65535].
		if epParam != "" {
			lastColon := strings.LastIndex(epParam, ":")
			if lastColon < 0 {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error": "invalid ep: must be addr:port (e.g. 10.0.0.5:80)",
				})
				return
			}
			portStr := epParam[lastColon+1:]
			portNum, err := strconv.Atoi(portStr)
			if err != nil || portNum < 1 || portNum > 65535 {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error": fmt.Sprintf("invalid ep: port %q out of range [1, 65535]", portStr),
				})
				return
			}
		}

		// Parse and clamp limit: default 200, hard cap 2000 (G3 ratification).
		limit := dpuDebugDefaultLimit
		if limitParam != "" {
			parsed, err := strconv.Atoi(limitParam)
			if err == nil && parsed > 0 {
				limit = parsed
			}
		}
		if limit < 1 {
			limit = dpuDebugDefaultLimit
		}
		if limit > dpuDebugMaxLimit {
			limit = dpuDebugMaxLimit
		}

		// All input validated. Now dispatch filtered query.
		dpuDebugGetFiltered(w, r, DocaQueryFilter{
			Pipe:  pipeParam,
			Svc:   svcParam,
			Ep:    epParam,
			Limit: limit,
		})
		return
	}

	// --- : no-param aggregate path (existing behavior unchanged) ---

	// ?flows=1 opts-in to per-entry DOCA hw-stat enumeration.
	// By default (no ?flows=1) these calls are skipped because AllFlowStats/AllFdbStats
	// iterate every DOCA CT/FDB entry and read HW counters — at high CPS (hundreds of
	// active CT entries) this takes seconds and blocks the REST endpoint under load.
	// The aggregate counters (offload_active_by_pipe, offload_success_by_pipe, …) are
	// still returned from atomics, which are always O(1).
	includeFlows := q.Get("flows") == "1"

	if dpuDebugProvider == nil {
		// Manager not registered — return the disabled-shape response.
		// Even in the disabled path, new array fields MUST emit as [] not null
		// (CICD consumers iterate them with d.get('fdb_entries', [])).
		writeJSON(w, http.StatusOK, DpuDebugResponse{
			Enabled:              false,
			Plugins:              []string{},
			OffloadSuccessByPipe: map[string]uint64{},
			OffloadFailureByPipe: map[string]uint64{},
			OffloadActiveByPipe:  map[string]int64{},
			FdbEntries:           []FdbHwStatsEntry{},
			RouteEntries:         []RouteHwStatsEntry{},
			AclEntries:           []AclHwStatsEntry{},
			CircuitBreakerOpen:   false,
		})
		return
	}

	success, failure, active := dpuDebugProvider.OffloadStats()
	successByPipe, failureByPipe, activeByPipe := dpuDebugProvider.OffloadStatsByPipe()

	// Expensive DOCA hw-stat enumeration: only when explicitly requested.
	var flows []FlowHwStatsEntry
	var fdbEntries []FdbHwStatsEntry
	var routeEntries []RouteHwStatsEntry
	var aclEntries []AclHwStatsEntry
	if includeFlows {
		flows = dpuDebugProvider.AllFlowHwStats()
		fdbEntries = dpuDebugProvider.AllFdbHwStats()
		routeEntries = dpuDebugProvider.AllRouteHwStats()
		aclEntries = dpuDebugProvider.AllAclHwStats()
	}

	resp := DpuDebugResponse{
		Enabled:              dpuDebugProvider.IsEnabled(),
		OffloadSuccess:       success,
		OffloadFailure:       failure,
		OffloadActive:        active,
		OffloadSuccessByPipe: successByPipe,
		OffloadFailureByPipe: failureByPipe,
		OffloadActiveByPipe:  activeByPipe,
		Plugins:              dpuDebugProvider.PluginNames(),
		Flows:                flows,
		FdbEntries:           fdbEntries,
		RouteEntries:         routeEntries,
		AclEntries:           aclEntries,
		CircuitBreakerOpen:   dpuDebugProvider.CircuitBreakerOpen(),
	}

	// Normalize nil slices / maps to empty collections so JSON emits [] / {} never null.
	// Matches the existing resp.Plugins normalization below.
	if resp.Plugins == nil {
		resp.Plugins = []string{}
	}
	if resp.OffloadSuccessByPipe == nil {
		resp.OffloadSuccessByPipe = map[string]uint64{}
	}
	if resp.OffloadFailureByPipe == nil {
		resp.OffloadFailureByPipe = map[string]uint64{}
	}
	if resp.OffloadActiveByPipe == nil {
		resp.OffloadActiveByPipe = map[string]int64{}
	}
	if resp.FdbEntries == nil {
		resp.FdbEntries = []FdbHwStatsEntry{}
	}
	if resp.RouteEntries == nil {
		// P48 postponed -- this slice is expected to be empty on v7.0.
		resp.RouteEntries = []RouteHwStatsEntry{}
	}
	if resp.AclEntries == nil {
		resp.AclEntries = []AclHwStatsEntry{}
	}

	writeJSON(w, http.StatusOK, resp)
}

// dpuDebugGetFiltered handles filtered per-entry detail path.
// All input validation is done by the caller (dpuDebugGet) BEFORE this call.
// This function dispatches QueryDocaEntries, assembles the aggregate + detail
// response, and returns. On per-entry bridge errors the entry is skipped
// (partial results are returned with the loxilb_doca_collector_query_errors_total
// counter bumped inside QueryDocaEntries).
func dpuDebugGetFiltered(w http.ResponseWriter, r *http.Request, filter DocaQueryFilter) {
	if dpuDebugProvider == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "DPU manager not initialized",
		})
		return
	}

	// Collect the aggregate shape (same as) for the response envelope.
	success, failure, active := dpuDebugProvider.OffloadStats()
	successByPipe, failureByPipe, activeByPipe := dpuDebugProvider.OffloadStatsByPipe()

	// per-entry filtered query dispatched through bridge.submit.
	entries, err := dpuDebugProvider.QueryDocaEntries(filter)
	if err != nil {
		// Hard query failure (provider not available, bridge down).
		// Return the aggregate shape + empty entry list with a warning header.
		tk.LogIt(tk.LogWarning, "api: DPU Debug query error: %v\n", err)
	}

	resp := DpuDebugResponse{
		Enabled:              dpuDebugProvider.IsEnabled(),
		OffloadSuccess:       success,
		OffloadFailure:       failure,
		OffloadActive:        active,
		OffloadSuccessByPipe: successByPipe,
		OffloadFailureByPipe: failureByPipe,
		OffloadActiveByPipe:  activeByPipe,
		Plugins:              dpuDebugProvider.PluginNames(),
		// the filtered entry detail. omitempty handles the nil case.
		DocaEntryDetails: entries,
		// FdbEntries / RouteEntries / AclEntries are expensive; skip on the
		// filtered path (is detail-on-demand, not bulk-all).
		FdbEntries:         []FdbHwStatsEntry{},
		RouteEntries:       []RouteHwStatsEntry{},
		AclEntries:         []AclHwStatsEntry{},
		CircuitBreakerOpen: dpuDebugProvider.CircuitBreakerOpen(),
	}

	if resp.Plugins == nil {
		resp.Plugins = []string{}
	}
	if resp.OffloadSuccessByPipe == nil {
		resp.OffloadSuccessByPipe = map[string]uint64{}
	}
	if resp.OffloadFailureByPipe == nil {
		resp.OffloadFailureByPipe = map[string]uint64{}
	}
	if resp.OffloadActiveByPipe == nil {
		resp.OffloadActiveByPipe = map[string]int64{}
	}

	writeJSON(w, http.StatusOK, resp)
}

func dpuDebugPost(w http.ResponseWriter, r *http.Request) {
	tk.LogIt(tk.LogTrace, "api: DPU Debug POST called by IP: %s\n", r.RemoteAddr)

	if dpuDebugProvider == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "DPU manager not initialized"})
		return
	}

	var action DpuDebugAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if action.Action == "unregister" && action.Plugin != "" {
		dpuDebugProvider.Unregister(action.Plugin)
		tk.LogIt(tk.LogInfo, "[DPU-DEBUG] unregister triggered for plugin: %s\n", action.Plugin)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	if action.Action == "cb_force" {
		if action.Mode != "open" && action.Mode != "close" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cb_force requires mode=open|close"})
			return
		}
		if err := dpuDebugProvider.CircuitBreakerForce(action.Mode); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		tk.LogIt(tk.LogWarning, "[DPU-DEBUG] circuit breaker force-%s via debug endpoint (remote=%s)\n", action.Mode, r.RemoteAddr)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":               "ok",
			"circuit_breaker_open": dpuDebugProvider.CircuitBreakerOpen(),
		})
		return
	}

	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported action or missing required field"})
}
