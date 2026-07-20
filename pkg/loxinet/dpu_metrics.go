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
	"fmt"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// DOCA offload Prometheus metrics.
// Registration is gated (metrics audit D5): the metric variables are created
// at package init but only registered with the default Prometheus registry by
// registerDpuMetrics(), called from DpuManager.Register when a DPU plugin
// actually attaches. Non-DOCA builds/deployments get a clean /metrics with no
// permanently-zero doca_* series.
var (
	docaOffloadActiveFlows = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "doca_offload_active_flows",
		Help: "Current number of flows offloaded to DOCA hardware",
	})
	docaCircuitBreakerStateGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "doca_circuit_breaker_state",
		Help: "DOCA circuit breaker state (0=closed, 1=open)",
	})
	docaOffloadAttemptsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "doca_offload_attempts_total",
		Help: "Total DOCA offload attempts",
	})
	docaOffloadFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "doca_offload_failures_total",
		Help: "Total DOCA offload failures",
	})

	// Aging observability metrics
	docaStaleEntriesEvicted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "doca_stale_entries_evicted_total",
		Help: "Total number of DOCA CT entries evicted by native aging",
	})
	docaCtPipeUtilization = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "doca_ct_pipe_utilization",
		Help: "DOCA CT pipe utilization ratio (Go-tracked entries / capacity). Measures Go-side tracking map, not hardware pipe state directly. May briefly diverge from HW during eviction cleanup.",
	}, []string{"pipe"})
	docaAgingCycleDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "doca_aging_cycle_duration_seconds",
		Help:    "Duration of DOCA aging poll cycles",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
	})

	// QoS meter Prometheus metrics
	docaMeterPacketsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "doca_meter_packets_total",
		Help: "Total packets processed by DOCA shared meter",
	}, []string{"meter_id", "name"})
	docaMeterBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "doca_meter_bytes_total",
		Help: "Total bytes processed by DOCA shared meter",
	}, []string{"meter_id", "name"})
	docaMeterOffloadActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "doca_meter_offload_active",
		Help: "Whether a DOCA shared meter is currently active (1=active, 0=inactive)",
	}, []string{"meter_id", "name"})
	docaMeterPoolExhaustedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "doca_meter_pool_exhausted_total",
		Help: "Total meter add attempts rejected because meter ID exceeds DOCA shared meter limit (64 slots)",
	})
)

// docaDefaultTCPPipeCapacityAggregate (Option A) is the
// denominator for the doca_ct_pipe_utilization{pipe="tcp"} gauge.
// It SUMS the two per-direction CT pipes (g_ct_pipe + g_ct_rev_pipe), each
// sized at g_ct_pipe_capacity*2 = 16384, total = 32768.
// countEntriesForPipe(bf2.entries, "ct") aggregates forward+reply entries
// because keeps pipeKey="ct" for both directions; only the
// denominator changes vs. the pre- single-pipe model.
const docaDefaultTCPPipeCapacityAggregate = 32768

// ---------------------------------------------------------------------------
// P49-R2 — per-pipe HW counter surface.
// Labels: fixed 5-value pipe enum. Cardinality bounded per 49-RESEARCH.md
// §Prometheus Label Cardinality Analysis.
// ---------------------------------------------------------------------------

// docaPipeHwPktsTotal: cumulative-increments counter, per-pipe hw_pkts sum across all entries.
// Updated by CollectHwOffloadStats from a DELTA of aggregated cumulative totals per 10s tick.
// NEVER Add(cumulative) -- UpdateMeterStats now follows the same delta
// discipline (C-4 fix); Adding a cumulative every tick grows quadratically.
//
// extended with `direction` label dimension. Allowed values:
// "forward" / "reply" for paired LB-flow CT entries (programmed by
// pairedLBFlowOffload), and "" for legacy LBFlowOffload, route, fdb, and acl
// entries that are not direction-paired. Cardinality is bounded:
// 5 pipes x 3 directions = 15 children per metric.
var docaPipeHwPktsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "doca_pipe_hw_pkts_total",
	Help: "Total packets processed in DOCA hardware per pipe family per direction (delta-tracked across 10s collection cycles).",
}, []string{"pipe", "direction"})

var docaPipeHwBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "doca_pipe_hw_bytes_total",
	Help: "Total bytes processed in DOCA hardware per pipe family per direction (delta-tracked across 10s collection cycles).",
}, []string{"pipe", "direction"})

// docaFdbEntriesActive: gauge of currently-offloaded FDB entries per egress port.
// port label cardinality bounded by DPDK repr count (~6).
var docaFdbEntriesActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "doca_fdb_entries_active",
	Help: "Current number of FDB entries offloaded to DOCA hardware, grouped by egress port.",
}, []string{"port"})

// docaRouteEntriesActive: gauge of currently-offloaded route entries (scalar; no label — P48 postponed to v7.1).
var docaRouteEntriesActive = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "doca_route_entries_active",
	Help: "Current number of route entries offloaded to DOCA hardware. Empty (0) on v7.0 until FIB-seeded LPM ships in v7.1.",
})

// docaAclEntriesActive: gauge of currently-offloaded ACL rules.
var docaAclEntriesActive = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "doca_acl_entries_active",
	Help: "Current number of ACL rules offloaded to DOCA hardware.",
})

// ---------------------------------------------------------------------------
// HwOffload=true ACL rule visibility (lazy DENY+ALLOW).
// Per-pipe gauges report current map sizes after every successful flush.
// The rules_total counter increments on every successful Add by action label.
// All three are pre-instantiated at init so rate panels have a t0
// sample from first scrape rather than "no data" until the first event.
// ---------------------------------------------------------------------------

// docaAclHwDenyEntries — gauge of current DOCA DENY_PIPE entries.
var docaAclHwDenyEntries = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "loxilb_acl_hw_deny_entries",
	Help: "Current count of DOCA HW DENY_PIPE entries.",
})

// docaAclHwAllowEntries — gauge of current DOCA ALLOW_PIPE entries.
var docaAclHwAllowEntries = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "loxilb_acl_hw_allow_entries",
	Help: "Current count of DOCA HW ALLOW_PIPE entries.",
})

// docaAclHwOffloadRulesTotal — cumulative counter of LoxiLB FW rules installed
// with HwOffload=true, by action label. Cardinality 2:
// {action="deny"} (FWD_DROP on DENY pipe) and {action="allow"} (FWD_PIPE on
// ALLOW pipe). Pre-instantiated in init below.
var docaAclHwOffloadRulesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "loxilb_acl_hw_offload_rules_total",
	Help: "Total LoxiLB FW rules installed with HwOffload=true, by action.",
}, []string{"action"})

// deferredRetryResultLabelValues is the closed enum for the
// docaOffloadDeferredRetryTotal counter (B23-02).
// Cardinality: 4 children, well within -05 budget.
var deferredRetryResultLabelValues = [...]string{"queued", "ok", "failed", "gave_up"}

// docaOffloadDeferredRetryTotal: deferred-retry queue events emitted by
// markDeferred (queued) and sweepDeferred (ok / failed / gave_up).
//
// Closed-enum + pre-instantiation discipline (05 / S2): the
// init loop in dpu_metrics.go pre-instantiates all 4 children so
// rate(doca_offload_deferred_retry_total{result="X"}[5m]) has a t0
// sample from first scrape rather than "no data".
var docaOffloadDeferredRetryTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "doca_offload_deferred_retry_total",
	Help: "DOCA offload deferred-retry queue events (B23-02). Labels: result ∈ {queued, ok, failed, gave_up}.",
}, []string{"result"})

// ---------------------------------------------------------------------------
// A2 — per-pipe-per-reason install-error counter.
// Cardinality: 7 pipe values × 6 reason values = 42 children, all
// pre-instantiated at init for rate t0 (05 discipline).
// ---------------------------------------------------------------------------

// docaInstallErrorsPipeLabelValues is the closed enum for the `pipe` label
// on docaOffloadInstallErrorsTotal. Distinct from pipeLabelValues because A2
// adds two error-only sites (ct_rev / egress_steer) that are not in the HW
// counter dimensions but ARE in the install-failure dimensions.
var docaInstallErrorsPipeLabelValues = [...]string{"ct", "ct_rev", "udp_ct", "route", "fdb", "acl", "egress_steer"}

// docaInstallErrorsReasonLabelValues is the closed enum for the `reason`
// label on docaOffloadInstallErrorsTotal. Mapped from DOCA error codes /
// Go error strings via docaErrorReason in dpu_doca_cgo.go.
var docaInstallErrorsReasonLabelValues = [...]string{"invalid_input", "capacity_full", "null_return", "timeout", "hw_busy", "paired_steer_failed"}

// docaOffloadInstallErrorsTotal: per-pipe-per-reason DOCA offload-install
// failure counter (A2). Incremented at every llb_doca_*_add call
// site failure branch in dpu_doca_bf2.go via docaErrorReason(err) mapping.
//
// The P2 atomic-rollback path (pairedLBFlowOffload forward-fail / reply-fail)
// uses the explicit reason="paired_steer_failed" so operators can
// distinguish paired-egress-steer cascade failures from per-pipe install
// errors that happen at the original add site.
var docaOffloadInstallErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "doca_offload_install_errors_total",
	Help: "DOCA offload-install errors partitioned by pipe and root-cause reason (A2). Cardinality: 7 pipe × 6 reason = 42 series, pre-instantiated at init.",
}, []string{"pipe", "reason"})

// ---------------------------------------------------------------------------
// Kernel-bridge byte gauge.
// GAUGE not counter: sysfs rx_bytes/tx_bytes resets when a bridge is recreated;
// gauge Set semantics correctly tolerate non-monotonic values.
// Named loxilb_ (not doca_): the data is pure-kernel sysfs, not DOCA HW.
// ---------------------------------------------------------------------------
var kernelBridgeBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "loxilb_kernel_bridge_bytes",
	Help: "Cumulative kernel-side RX+TX bytes for each Linux bridge (/sys/class/net/<br>/statistics). Stays flat when DOCA ASIC carries all bridge traffic — proves HW offload engagement.",
}, []string{"bridge"})

// pipeLabelValues is the ONLY permitted set of `pipe` label values.
// Any deviation (typo, new-pipe-without-enum-bump) fails TestPipeMetricsCardinality.
// Order must match pkg/loxinet/dpu_manager.go pipeKindNames.
var pipeLabelValues = [...]string{"ct", "udp_ct", "route", "fdb", "acl"}

// directionLabelValues is the closed set of permitted `direction` label values
// . "" is a first-class value for legacy / route / FDB / ACL
// entries that are not direction-paired. Cardinality bound = 3.
var directionLabelValues = [...]string{"forward", "reply", ""}

// lastPipePktsByDir / lastPipeBytesByDir track the last-seen cumulative total
// keyed by composite "pipe|direction". CollectHwOffloadStats
// computes delta = current - last, Adds delta, then stores current.
// Package-level because CollectHwOffloadStats is called from a single goroutine
// (PolTicker); no locking needed. If a future caller runs this from a different
// goroutine, wrap in sync.Mutex.
var (
	lastPipePktsByDir  = map[string]uint64{}
	lastPipeBytesByDir = map[string]uint64{}
)

// lastMeterPkts / lastMeterBytes track the last-seen cumulative totals per
// DOCA shared meter, keyed by composite "meter_id|name" — the same identity
// as the docaMeterPacketsTotal / docaMeterBytesTotal label children.
// UpdateMeterStats computes delta = current - last, Adds delta, then stores
// current (C-4 fix). Package-level because UpdateMeterStats is called from a
// single goroutine (PolTicker via CollectMeterStats); no locking needed. If a
// future caller runs this from a different goroutine, wrap in sync.Mutex.
var (
	lastMeterPkts  = map[string]uint64{}
	lastMeterBytes = map[string]uint64{}
)

// lastFdbPorts remembers the FDB egress ports seen on the previous
// CollectHwOffloadStats tick so vanished ports can be Set(0) instead of
// keeping their stale last value. Single-goroutine (PolTicker), no locking.
var lastFdbPorts = map[uint16]bool{}

func init() {
	// Pre-instantiate all 5 pipe x 3 direction = 15 label children so rate
	// has a t0 sample (49-RESEARCH.md §Pre-instantiation discipline). Grafana
	// panels that graph rate(doca_pipe_hw_pkts_total[5m]) show a flat line
	// from first scrape rather than "no data" until the first non-zero traffic
	// event. The empty-string direction child is required so legacy /
	// route / FDB / ACL counters keep their flat-line baseline.
	for _, p := range pipeLabelValues {
		for _, dir := range []string{"forward", "reply", ""} {
			docaPipeHwPktsTotal.WithLabelValues(p, dir)
			docaPipeHwBytesTotal.WithLabelValues(p, dir)
		}
	}

	// B23-02 / : pre-instantiate all 4 children of the
	// deferred-retry counter (queued, ok, failed, gave_up) so Grafana panels
	// that graph rate(doca_offload_deferred_retry_total{result="X"}[5m]) start
	// from a flat-line baseline rather than "no data" until the first event.
	for _, r := range deferredRetryResultLabelValues {
		docaOffloadDeferredRetryTotal.WithLabelValues(r)
	}

	// A2: pre-instantiate all 7 pipe × 6 reason = 42
	// children of the install-errors counter so rate(...{pipe=X,reason=Y}[5m])
	// has a t0 sample from first scrape rather than "no data".
	for _, p := range docaInstallErrorsPipeLabelValues {
		for _, r := range docaInstallErrorsReasonLabelValues {
			docaOffloadInstallErrorsTotal.WithLabelValues(p, r)
		}
	}

	// pre-instantiate both children of the rule-visibility
	// counter so Grafana panels that graph
	// rate(loxilb_acl_hw_offload_rules_total{action="X"}[5m]) start from a
	// flat-line baseline rather than "no data" until the first event.
	docaAclHwOffloadRulesTotal.WithLabelValues("deny")
	docaAclHwOffloadRulesTotal.WithLabelValues("allow")
}

// registerDpuMetricsOnce guards registerDpuMetrics against double
// registration (Register can be called for more than one plugin).
var registerDpuMetricsOnce sync.Once

// registerDpuMetrics registers the DPU/DOCA metric families with the default
// Prometheus registry. Called from DpuManager.Register when a DPU plugin
// attaches (metrics audit D5): deployments without DOCA hardware never expose
// these series. Tests that gather the default registry must call this first.
func registerDpuMetrics() {
	registerDpuMetricsOnce.Do(func() {
		prometheus.MustRegister(
			docaOffloadActiveFlows,
			docaCircuitBreakerStateGauge,
			docaOffloadAttemptsTotal,
			docaOffloadFailuresTotal,
			docaStaleEntriesEvicted,
			docaCtPipeUtilization,
			docaAgingCycleDuration,
			docaMeterPacketsTotal,
			docaMeterBytesTotal,
			docaMeterOffloadActive,
			docaMeterPoolExhaustedTotal,
			docaPipeHwPktsTotal,
			docaPipeHwBytesTotal,
			docaFdbEntriesActive,
			docaRouteEntriesActive,
			docaAclEntriesActive,
			docaAclHwDenyEntries,
			docaAclHwAllowEntries,
			docaAclHwOffloadRulesTotal,
			docaOffloadDeferredRetryTotal,
			docaOffloadInstallErrorsTotal,
			kernelBridgeBytes,
		)
	})
}

// UpdateMeterStats updates Prometheus counters for a DOCA shared meter.
// Called from PolTicker (via CollectMeterStats) when MeterOffload is active.
//
// Delta discipline (C-4 fix): totalPkts / totalBytes are CUMULATIVE lifetime
// totals from the DOCA shared-meter query (loxilb_doca_flow.h meter stats),
// NOT per-tick increments. We track the last-seen cumulative per meter and
// Add only the delta — the same pattern as CollectHwOffloadStats below.
// The previous Add(cumulative)-every-tick made the counter grow
// quadratically: after N ticks it read ~N/2x reality.
//
// If the delta would be negative (C-side meter reset / restart shrank the
// cumulative), we skip the Add (prometheus.Counter.Add panics on negative)
// and re-prime the baseline from the fresh cumulative.
func UpdateMeterStats(meterID uint32, name string, totalPkts, totalBytes uint64) {
	id := fmt.Sprintf("%d", meterID)
	key := id + "|" + name
	if totalPkts >= lastMeterPkts[key] {
		if d := totalPkts - lastMeterPkts[key]; d > 0 {
			docaMeterPacketsTotal.WithLabelValues(id, name).Add(float64(d))
		}
	}
	lastMeterPkts[key] = totalPkts
	if totalBytes >= lastMeterBytes[key] {
		if d := totalBytes - lastMeterBytes[key]; d > 0 {
			docaMeterBytesTotal.WithLabelValues(id, name).Add(float64(d))
		}
	}
	lastMeterBytes[key] = totalBytes
}

// SetMeterOffloadActive sets the active gauge for a meter.
func SetMeterOffloadActive(meterID uint32, name string, active bool) {
	id := fmt.Sprintf("%d", meterID)
	if active {
		docaMeterOffloadActive.WithLabelValues(id, name).Set(1)
	} else {
		docaMeterOffloadActive.WithLabelValues(id, name).Set(0)
	}
}

// CollectHwOffloadStats is the 10s-tick collector per-pipe counters.
// Called from the same PolTicker loop as CollectMeterStats.
//
// Delta discipline: the per-entry stats returned by plugin AllFlowStats /
// AllFdbStats / AllRouteStats / AllAclStats are CUMULATIVE totals since start.
// We sum across entries per pipe family, track the last-seen aggregate, and
// call counter.Add(delta). NEVER counter.Add(cumulative) — that was the
// historical UpdateMeterStats bug (49-RESEARCH.md line 262, fixed in C-4:
// UpdateMeterStats above now uses the same delta discipline).
//
// If the delta would be negative (cumulative shrunk because entries were
// deleted between ticks), we Add 0 to avoid the prometheus client panic on
// negative Add. This is an explicit defense: even though the delta equation
// won't overflow (we check current >= last), we also skip on strict inequality.
func (m *DpuManager) CollectHwOffloadStats() {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	// Aggregate current cumulative totals per (pipe, direction) tuple from plugin
	// queries. Composite map key = pipe + "|" + direction so the
	// existing scalar-keyed delta-tracking shape is preserved.
	pktsNow := map[string]uint64{}
	bytesNow := map[string]uint64{}
	for _, v := range pipeLabelValues {
		for _, dir := range directionLabelValues {
			key := v + "|" + dir
			pktsNow[key] = 0
			bytesNow[key] = 0
		}
	}

	// CT / UDP CT come from AllFlowStats — PipeKey attributes each row,
	// and Direction splits forward/reply for paired LB-flow CT
	// entries. Direction is "" for legacy LBFlowOffload, fdb, and acl
	// entries — the empty-string child holds those legacy buckets.
	//
	// FDB / Route / ACL come from the multi-pipe providers. Route rows are
	// OWNED by AllRouteStats: the BF2 plugin reports the same d.entries rows
	// tagged pipeKey=="route" through BOTH AllFlowStats and AllRouteStats, so
	// summing both into the same bucket doubled the cumulative aggregate — and
	// a doubled cumulative produces a doubled per-tick delta, over-counting
	// doca_pipe_hw_pkts_total{pipe="route"} exactly 2x (H-25 fix: route rows
	// are skipped in the AllFlowStats loop below). These multi-pipe sources are
	// NOT direction-paired and therefore always land on the direction="" child.
	for _, p := range m.plugins {
		if fsp, ok := p.(flowStatsProvider); ok {
			for _, fs := range fsp.AllFlowStats() {
				// fs.PipeKey is one of ct / udp_ct / route. Unknown keys silently
				// skipped — TestPipeMetricsCardinality asserts the allowed set.
				// fs.Direction is one of "forward" / "reply" / "". Per
				// the empty-string is a first-class direction value used by
				// legacy / non-paired entries; do NOT derive it from heuristics.
				//
				// H-25: route rows are counted from AllRouteStats below —
				// counting them here too would double the aggregate (and the
				// resulting per-tick delta) for pipe="route".
				if fs.PipeKey == "route" {
					continue
				}
				key := fs.PipeKey + "|" + fs.Direction
				if _, known := pktsNow[key]; !known {
					continue
				}
				pktsNow[key] += fs.HwPkts
				bytesNow[key] += fs.HwBytes
			}
		}
		if msp, ok := p.(multiPipeStatsProvider); ok {
			for _, s := range msp.AllFdbStats() {
				pktsNow["fdb|"] += s.HwPkts
				bytesNow["fdb|"] += s.HwBytes
			}
			for _, s := range msp.AllRouteStats() {
				pktsNow["route|"] += s.HwPkts
				bytesNow["route|"] += s.HwBytes
			}
			for _, s := range msp.AllAclStats() {
				pktsNow["acl|"] += s.HwPkts
				bytesNow["acl|"] += s.HwBytes
			}
		}
	}

	// Apply deltas per (pipe, direction). Guard against negative (cumulative
	// shrunk — rare, only on pipe rebuild or entry removal;
	// prometheus.Counter.Add panics on negative).
	for compositeKey, current := range pktsNow {
		pipe := compositeKey
		dir := ""
		if idx := strings.IndexByte(compositeKey, '|'); idx >= 0 {
			pipe = compositeKey[:idx]
			dir = compositeKey[idx+1:]
		}
		if current >= lastPipePktsByDir[compositeKey] {
			if d := current - lastPipePktsByDir[compositeKey]; d > 0 {
				docaPipeHwPktsTotal.WithLabelValues(pipe, dir).Add(float64(d))
			}
		}
		lastPipePktsByDir[compositeKey] = current
	}
	for compositeKey, current := range bytesNow {
		pipe := compositeKey
		dir := ""
		if idx := strings.IndexByte(compositeKey, '|'); idx >= 0 {
			pipe = compositeKey[:idx]
			dir = compositeKey[idx+1:]
		}
		if current >= lastPipeBytesByDir[compositeKey] {
			if d := current - lastPipeBytesByDir[compositeKey]; d > 0 {
				docaPipeHwBytesTotal.WithLabelValues(pipe, dir).Add(float64(d))
			}
		}
		lastPipeBytesByDir[compositeKey] = current
	}

	// Update the Active gauges from OffloadStatsByPipe.
	_, _, activeByPipe := m.OffloadStatsByPipe()
	docaRouteEntriesActive.Set(float64(activeByPipe["route"]))
	docaAclEntriesActive.Set(float64(activeByPipe["acl"]))

	// Per-port FDB active gauge: bucket AllFdbStats by port and Set the fresh
	// per-port count each tick. Ports seen on a previous tick but absent now
	// are explicitly Set to 0 (Gauge children are not auto-reaped by
	// prometheus, so a vanished port would otherwise keep its last value
	// forever).
	fdbByPort := map[uint16]int{}
	for _, p := range m.plugins {
		if msp, ok := p.(multiPipeStatsProvider); ok {
			for _, s := range msp.AllFdbStats() {
				fdbByPort[s.Port]++
			}
		}
	}
	for port := range lastFdbPorts {
		if _, still := fdbByPort[port]; !still {
			docaFdbEntriesActive.WithLabelValues(fmt.Sprintf("%d", port)).Set(0)
			delete(lastFdbPorts, port)
		}
	}
	for port, count := range fdbByPort {
		docaFdbEntriesActive.WithLabelValues(fmt.Sprintf("%d", port)).Set(float64(count))
		lastFdbPorts[port] = true
	}

	// amendment iter 2: invoke registered DOCA collector callbacks.
	// Per-callback defer recover inside InvokeRegisteredDocaCollectors provides
	// panic isolation. NO new goroutine, NO new ticker — the existing per-tick
	// path is the canonical 10s drive cycle.
	InvokeRegisteredDocaCollectors()
}
