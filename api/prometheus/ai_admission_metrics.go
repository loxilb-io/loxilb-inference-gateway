/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

package prometheus

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stddef.h>
#include <stdint.h>

// Twin declaration of proxy_fc_svc_stat_t. CANONICAL definition lives in
// loxilb-ebpf/common/sockproxy_metrics.h; a weak stub for CGO-only builds
// (go test, no sockproxy object) lives in proxy_metrics_stub.c. All THREE
// must move in lockstep, same commit; the offsets are pinned by the asserts
// after the struct, in all three.
//
// Role index 0 = normal, 1 = prefill, 2 = decode; reason index follows the
// gate's enum fc_reason. Cap on pools reported per call; lockstep with
// PROXY_FC_STAT_MAX in sockproxy_metrics.h.
#define PROXY_FC_STAT_MAX 256
#define PROXY_FC_ROLES 3
#define PROXY_FC_REASONS 14
#define PROXY_FC_POOL_LEN 64
#define PROXY_FC_QWAIT_BUCKETS 8
#define PROXY_FC_LIMITS 8
#define PROXY_FC_ADAPT_LIMITS 3
#define PROXY_FC_BAND_LIMITS 9
#define PROXY_FC_BANDS 3
#define PROXY_FC_BAND_OUTCOMES 5

typedef struct proxy_fc_svc_stat {
    uint32_t xip;
    uint16_t xport;
    uint8_t  protocol;
    uint8_t  mode;
    uint32_t max_outstanding;
    uint32_t ep_cap[PROXY_FC_ROLES];
    uint32_t inflight;
    uint32_t ep_inflight[PROXY_FC_ROLES];
    uint64_t decisions[PROXY_FC_REASONS];
    char     pool[PROXY_FC_POOL_LEN];
    uint32_t queued;
    uint32_t max_queue_depth;
    uint32_t max_queue_wait_ms;
    uint32_t pad;
    uint64_t qwait_bucket[PROXY_FC_QWAIT_BUCKETS];
    uint64_t qwait_sum_ms;
    uint64_t qwait_count;
    uint32_t telemetry_stale_ms;
    uint8_t  src[PROXY_FC_LIMITS];
    uint32_t pad2;
    uint32_t effective_max_outstanding;
    uint32_t warmup_ms;
    uint32_t ttft_target_ms;
    uint8_t  adaptive;
    uint8_t  adapt_state;
    uint8_t  adapt_reason;
    uint8_t  src_adapt[PROXY_FC_ADAPT_LIMITS];
    uint16_t warming_eps;
    uint64_t adapt_down;
    uint64_t adapt_up;
    uint32_t tenants_active;
    uint8_t  tenant_share_pct;
    uint8_t  src_tenant;
    uint8_t  expose_headers;
    uint8_t  src_expose;
    uint32_t tenant_slots;
    uint32_t band_inflight[PROXY_FC_BANDS];
    uint32_t band_queued[PROXY_FC_BANDS];
    uint32_t band_wait_ms[PROXY_FC_BANDS];
    uint8_t  wake_policy;
    uint8_t  shed_queue;
    uint8_t  tenant_wake;
    uint8_t  llmd_headers;
    uint8_t  band_weight[PROXY_FC_BANDS];
    uint8_t  band_min_share_pct[PROXY_FC_BANDS];
    uint8_t  band_queue_pct[PROXY_FC_BANDS];
    uint8_t  bands;
    uint8_t  src_band[PROXY_FC_BAND_LIMITS];
    uint8_t  band_fallback;
    uint8_t  wake_policy_cfg;
    uint8_t  shed_queue_cfg;
    uint8_t  tenant_wake_cfg;
    uint8_t  critical_reserve_pct; uint8_t  band_pad[4];
    uint64_t band_outcome[PROXY_FC_BANDS][PROXY_FC_BAND_OUTCOMES];
} proxy_fc_svc_stat_t;
// Pinned to the layout in sockproxy_metrics.h.
_Static_assert(sizeof(proxy_fc_svc_stat_t) == 568, "proxy_fc_svc_stat_t size");
_Static_assert(offsetof(proxy_fc_svc_stat_t, decisions) == 40, "decisions offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, pool) == 152, "pool offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, queued) == 216, "queued offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, qwait_bucket) == 232, "qwait_bucket offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, qwait_count) == 304, "qwait_count offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, telemetry_stale_ms) == 312, "telemetry_stale_ms offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, src) == 316, "src offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, effective_max_outstanding) == 328, "effective_max_outstanding offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, adaptive) == 340, "adaptive offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, warming_eps) == 346, "warming_eps offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, adapt_down) == 352, "adapt_down offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, tenants_active) == 368, "tenants_active offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, tenant_slots) == 376, "tenant_slots offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, band_inflight) == 380, "band_inflight offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, wake_policy) == 416, "wake_policy offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, src_band) == 430, "src_band offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, band_fallback) == 439, "band_fallback offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, band_outcome) == 448, "band_outcome offset");

extern int proxy_get_fc_stats(proxy_fc_svc_stat_t *out, int max);
extern uint64_t proxy_get_fc_anomaly(int kind);
*/
import "C"

import (
	"fmt"
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// ============================================================================
// AI ADMISSION GATE (capacity) METRICS - per service, per model pool
// ============================================================================
// The capacity gate keeps its state on the pool (loxilb-ebpf/common/
// sockproxy_fc.h): the units in flight at the service and at each endpoint
// per role, the ceilings in force, and one counter per decision the gate
// took. Without this file none of that leaves the process, and an operator
// reading a 429 storm cannot tell a ceiling set too low from a backend that
// stopped answering.
//
// Collection follows the shaper's idiom in qos_shaper_metrics.go: the 10s
// RunSockproxyMetrics cycle refreshes a Go-side store (writer) and the
// collector emits ConstMetrics from it on scrape (reader). The C call walks
// the service list under the proxy read lock, off the scrape path.
//
// The bounded queue rides on the same row: the requests waiting for a unit,
// the depth and wait window in force, and a histogram of how long the
// resumed ones waited, so an operator can tell a queue that absorbs bursts
// from one that only delays the 429.
//
// Every model pool of an AI-gateway service gets a row whatever the gate's
// mode. A pool with the gate off reports mode 0 and zeros, so the mode
// series answers "is this pool gated" without a second source of truth, and
// the gauges read 0 rather than being absent. Counters are exported raw: a
// pool that is deleted and re-created starts from zero, which Prometheus
// already reads as a counter reset.
// ============================================================================

// Role label values, indexed as the C arrays are; "service" is the pool-wide
// unit that every inference request holds once however many legs it opens,
// "queue" is the bound on the requests waiting for one.
var admissionRoleLabels = [3]string{"normal", "prefill", "decode"}

const (
	admissionRoleService = "service"
	admissionRoleQueue   = "queue"
)

// Decision reasons, indexed as the gate's enum fc_reason. The wire vocabulary
// is closed: a reason the gate does not have cannot appear here.
var admissionReasonLabels = [14]string{
	"admitted",
	"capacity_shed",
	"no_healthy_capacity",
	"observe_would_shed",
	"bypass_non_inference",
	"queued",
	"queue_full",
	"queue_timeout",
	"cancelled",
	"drained",
	"observe_would_queue",
	"draining",
	"tenant_share",
	"shed",
}

// Queue wait histogram upper bounds in seconds, one per C bucket
// (fc_qwait_bounds_ms in sockproxy_fc.c: 10, 50, 100, 250, 500, 1000, 2500,
// 5000 ms). The C side counts each wait in its first bucket whose bound it
// does not exceed; Prometheus wants cumulative counts, so Collect sums them.
var admissionQwaitBoundsSeconds = [8]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

// Adaptive ceiling states and reasons, indexed as the gate's enum
// fc_adapt_state and enum fc_adapt_reason.
var admissionAdaptStateLabels = [4]string{"off", "open", "tightened", "frozen"}
var admissionAdaptReasonLabels = [5]string{"none", "queued", "ttft", "clear", "stale"}

// Anomaly kinds, indexed as the gate's enum fc_anomaly.
var admissionAnomalyLabels = [5]string{"underflow", "unknown_permit", "tenant_table_full", "h2_deny_headers", "expose_head_overflow"}

// admissionSample is one pool's gate state, converted to Go types and label
// strings.
type admissionSample struct {
	service string
	pool    string

	mode           float64
	maxOutstanding float64
	inflight       float64
	epCap          [3]float64
	epInflight     [3]float64
	decisions      [14]float64

	queued       float64
	queueDepth   float64
	qwaitBuckets [8]uint64
	qwaitSumMs   uint64
	qwaitCount   uint64

	effectiveLimit float64
	adaptState     uint8
	adaptReason    uint8
	adaptMoves     [2]float64 // down, up
	warmingEps     float64

	tenantsActive float64
	tenantSlots   float64

	// Per band index (cmn.FcBand*) and outcome, as the gate's enum
	// fc_band_outcome; the series are in ai_fc_band_metrics.go.
	bandOutcome [3][5]float64
}

// admissionStore is the state shared between the collection loop (writer)
// and admissionCollector.Collect (reader, on scrape). Replaced wholesale
// each cycle so a deleted pool's series stop being emitted instead of
// freezing at their last value. The anomaly counters are process-wide and
// ride along in the same publish.
var (
	admissionStoreMutex sync.Mutex
	admissionStore      []admissionSample
	admissionAnomalies  [5]float64
)

var admissionPoolLabels = []string{"service", "pool"}
var admissionRoleLabelNames = []string{"service", "pool", "role"}
var admissionReasonLabelNames = []string{"service", "pool", "reason"}
var admissionAnomalyLabelNames = []string{"kind"}
var admissionStateLabelNames = []string{"service", "pool", "state"}
var admissionAdaptReasonLabelNames = []string{"service", "pool", "reason"}
var admissionDirectionLabelNames = []string{"service", "pool", "direction"}
var admissionTenantSlotsLabelNames = []string{"service", "kind"}

var (
	admissionModeDesc = prometheus.NewDesc(
		"loxilb_ai_admission_mode",
		"Capacity gate mode on the pool: 0 off (dispatch path unchanged), 1 observe (decisions counted, everything admitted), 2 enforce (over a ceiling is refused). Present for every model pool of an AI-gateway service.",
		admissionPoolLabels, nil,
	)
	admissionInflightDesc = prometheus.NewDesc(
		"loxilb_ai_admission_inflight",
		"Capacity units held right now. role=\"service\" is the pool-wide count, one per executing inference request; the other roles sum the endpoint units held across the pool's endpoints for that role. Zero with the gate off.",
		admissionRoleLabelNames, nil,
	)
	admissionLimitDesc = prometheus.NewDesc(
		"loxilb_ai_admission_limit",
		"Ceiling in force for the role: role=\"service\" is the pool-wide bound on executing requests, role=\"queue\" is the bound on requests waiting for a unit (0: over a ceiling is refused at once), the other roles are the per-endpoint bound for that role. 0 means unlimited at that level.",
		admissionRoleLabelNames, nil,
	)
	admissionQueuedDesc = prometheus.NewDesc(
		"loxilb_ai_admission_queued",
		"Inference requests parked on the pool right now, waiting for a capacity unit. Zero with no queue depth configured.",
		admissionPoolLabels, nil,
	)
	admissionQueueWaitDesc = prometheus.NewDesc(
		"loxilb_ai_admission_queue_wait_seconds",
		"Time a request waited in the pool's queue: one sample per park, taken when the park ends (admitted, expired, shed by eviction or cancelled) and measured from its first park, so a woken request that goes back to its place is one wait, not two. A request drained from the queue is not sampled.",
		admissionPoolLabels, nil,
	)
	admissionDecisionsDesc = prometheus.NewDesc(
		"loxilb_ai_admission_decisions_total",
		"Gate decisions per pool and reason: admitted, capacity_shed (429), no_healthy_capacity (503), observe_would_shed (admitted in observe mode where enforce would have refused, counted at each ceiling that would have refused it), bypass_non_inference (not an inference request, no unit taken), queued (parked to wait for a unit, once per park: a woken request that goes back to its place is the same park), queue_full (429, the queue at its depth), queue_timeout (504, waited the whole window), cancelled (the client left while waiting), drained (the pool or the process stopped taking work while it waited), observe_would_queue (admitted in observe mode where enforce would have parked it), draining (503, the process is draining for maintenance), tenant_share (429, the tenant holds its share of the ceiling or of the queue), shed (429 admission_shed, a sheddable request refused at a ceiling or evicted from the queue by band policy).",
		admissionReasonLabelNames, nil,
	)
	admissionEffectiveLimitDesc = prometheus.NewDesc(
		"loxilb_ai_admission_effective_limit",
		"The pool-wide ceiling in force right now: the adaptive one while the pool adapts (at most the configured loxilb_ai_admission_limit{role=\"service\"}), else the configured one. 0 means unlimited.",
		admissionPoolLabels, nil,
	)
	admissionAdaptStateDesc = prometheus.NewDesc(
		"loxilb_ai_admission_adapt_state",
		"Where the adaptive ceiling stands, 1 for the current state and 0 for the others: off (not adaptive, or no ceiling), open (at the configured ceiling), tightened (below it, following fresh backpressure signals), frozen (below it with no fresh signal: held, never widened on stale telemetry).",
		admissionStateLabelNames, nil,
	)
	admissionAdaptReasonDesc = prometheus.NewDesc(
		"loxilb_ai_admission_adapt_reason",
		"Why the adaptive ceiling last moved or holds, 1 for the current reason: queued (an endpoint reported waiting requests), ttft (an endpoint's time to first token is over the target), clear (fresh signals without backpressure: widened), stale (no fresh signal: held), none.",
		admissionAdaptReasonLabelNames, nil,
	)
	admissionAdaptMovesDesc = prometheus.NewDesc(
		"loxilb_ai_admission_adapt_moves_total",
		"Steps of the adaptive ceiling: direction=\"down\" to four fifths on fresh backpressure, direction=\"up\" by one on a fresh clear second.",
		admissionDirectionLabelNames, nil,
	)
	admissionWarmingDesc = prometheus.NewDesc(
		"loxilb_ai_admission_warming_endpoints",
		"Endpoints of the pool inside their warm-up window, their ceilings ramping from a quarter to all of it after a return to service.",
		admissionPoolLabels, nil,
	)
	admissionTenantsDesc = prometheus.NewDesc(
		"loxilb_ai_admission_tenants_active",
		"Tenants holding a capacity unit or waiting on the pool right now, counted while the pool holds tenants to a share (fc_tenant_max_share_pct); zero otherwise. Requests without a tenant count as one.",
		admissionPoolLabels, nil,
	)
	admissionTenantSlotsDesc = prometheus.NewDesc(
		"loxilb_ai_fc_tenant_slots",
		"The tenant table of the capacity gate, per service: kind=\"max\" is how many tenants a model pool tracks by name at once (LLB_FC_TENANT_SLOTS, fixed when the pool is created), kind=\"used\" is how many hold a unit or wait right now on the service's fullest pool. used above max means tenants past the table are sharing one budget. used is zero while no pool of the service holds tenants to a share.",
		admissionTenantSlotsLabelNames, nil,
	)
	admissionAnomaliesDesc = prometheus.NewDesc(
		"loxilb_ai_admission_anomalies_total",
		"Accounting anomalies in the capacity gate, process-wide: underflow (a release found its counter at zero), unknown_permit (an executing permit with no pool), tenant_table_full (a request whose tenant found the pool's tenant table full and shared the last slot with the other tenants past it), h2_deny_headers (an HTTP/2 refusal had more headers than its frame holds; the stream was reset instead) and expose_head_overflow (an HTTP/1.1 response head arrived in pieces and grew past 16 KiB before it ended; it was relayed as it came, without the admission headers). underflow, unknown_permit and h2_deny_headers are defects; tenant_table_full means more tenants than the table holds are active on one pool; expose_head_overflow means a backend sends response heads larger than the gateway assembles.",
		admissionAnomalyLabelNames, nil,
	)
)

// admissionCollector emits the gate series from admissionStore on scrape.
// With no AI-gateway service configured the store is empty and only the
// anomaly counters are emitted.
type admissionCollector struct{}

// Describe implements prometheus.Collector.
func (admissionCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- admissionModeDesc
	ch <- admissionInflightDesc
	ch <- admissionLimitDesc
	ch <- admissionQueuedDesc
	ch <- admissionQueueWaitDesc
	ch <- admissionDecisionsDesc
	ch <- admissionEffectiveLimitDesc
	ch <- admissionAdaptStateDesc
	ch <- admissionAdaptReasonDesc
	ch <- admissionAdaptMovesDesc
	ch <- admissionWarmingDesc
	ch <- admissionTenantsDesc
	ch <- admissionTenantSlotsDesc
	ch <- admissionAnomaliesDesc
}

// Collect implements prometheus.Collector.
func (admissionCollector) Collect(ch chan<- prometheus.Metric) {
	admissionStoreMutex.Lock()
	samples := admissionStore
	anomalies := admissionAnomalies
	admissionStoreMutex.Unlock()

	for _, s := range samples {
		ch <- prometheus.MustNewConstMetric(admissionModeDesc, prometheus.GaugeValue, s.mode, s.service, s.pool)
		ch <- prometheus.MustNewConstMetric(admissionInflightDesc, prometheus.GaugeValue, s.inflight, s.service, s.pool, admissionRoleService)
		ch <- prometheus.MustNewConstMetric(admissionLimitDesc, prometheus.GaugeValue, s.maxOutstanding, s.service, s.pool, admissionRoleService)
		for r, role := range admissionRoleLabels {
			ch <- prometheus.MustNewConstMetric(admissionInflightDesc, prometheus.GaugeValue, s.epInflight[r], s.service, s.pool, role)
			ch <- prometheus.MustNewConstMetric(admissionLimitDesc, prometheus.GaugeValue, s.epCap[r], s.service, s.pool, role)
		}
		ch <- prometheus.MustNewConstMetric(admissionLimitDesc, prometheus.GaugeValue, s.queueDepth, s.service, s.pool, admissionRoleQueue)
		ch <- prometheus.MustNewConstMetric(admissionQueuedDesc, prometheus.GaugeValue, s.queued, s.service, s.pool)
		qwCount, qwBuckets := admissionQwaitHistogram(s.qwaitBuckets, s.qwaitCount)
		ch <- prometheus.MustNewConstHistogram(admissionQueueWaitDesc, qwCount, float64(s.qwaitSumMs)/1000,
			qwBuckets, s.service, s.pool)
		for d, reason := range admissionReasonLabels {
			ch <- prometheus.MustNewConstMetric(admissionDecisionsDesc, prometheus.CounterValue, s.decisions[d], s.service, s.pool, reason)
		}
		ch <- prometheus.MustNewConstMetric(admissionEffectiveLimitDesc, prometheus.GaugeValue, s.effectiveLimit, s.service, s.pool)
		for i, st := range admissionAdaptStateLabels {
			ch <- prometheus.MustNewConstMetric(admissionAdaptStateDesc, prometheus.GaugeValue, admissionOneHot(int(s.adaptState) == i), s.service, s.pool, st)
		}
		for i, r := range admissionAdaptReasonLabels {
			ch <- prometheus.MustNewConstMetric(admissionAdaptReasonDesc, prometheus.GaugeValue, admissionOneHot(int(s.adaptReason) == i), s.service, s.pool, r)
		}
		ch <- prometheus.MustNewConstMetric(admissionAdaptMovesDesc, prometheus.CounterValue, s.adaptMoves[0], s.service, s.pool, "down")
		ch <- prometheus.MustNewConstMetric(admissionAdaptMovesDesc, prometheus.CounterValue, s.adaptMoves[1], s.service, s.pool, "up")
		ch <- prometheus.MustNewConstMetric(admissionWarmingDesc, prometheus.GaugeValue, s.warmingEps, s.service, s.pool)
		ch <- prometheus.MustNewConstMetric(admissionTenantsDesc, prometheus.GaugeValue, s.tenantsActive, s.service, s.pool)
	}
	for _, t := range admissionTenantSlotsByService(samples) {
		ch <- prometheus.MustNewConstMetric(admissionTenantSlotsDesc, prometheus.GaugeValue, t.used, t.service, "used")
		ch <- prometheus.MustNewConstMetric(admissionTenantSlotsDesc, prometheus.GaugeValue, t.max, t.service, "max")
	}
	for k, kind := range admissionAnomalyLabels {
		ch <- prometheus.MustNewConstMetric(admissionAnomaliesDesc, prometheus.CounterValue, anomalies[k], kind)
	}
}

// init registers the gate collector once with the default registry (the
// same registry the promauto metrics use).
func init() {
	datapathRegisterer{}.MustRegister(admissionCollector{})
}

// admissionServiceTenantSlots is one service's tenant-table reading.
type admissionServiceTenantSlots struct {
	service string
	used    float64
	max     float64
}

// admissionTenantSlotsByService folds the pools of each service into one
// reading, in the order the services first appear: the table size, and the
// tenants on the pool that has the most. A service's pools are sized alike,
// and it is the fullest one that reaches the table's end first. Pure Go.
func admissionTenantSlotsByService(samples []admissionSample) []admissionServiceTenantSlots {
	out := make([]admissionServiceTenantSlots, 0, len(samples))
	at := make(map[string]int, len(samples))
	for _, s := range samples {
		i, seen := at[s.service]
		if !seen {
			i = len(out)
			at[s.service] = i
			out = append(out, admissionServiceTenantSlots{service: s.service})
		}
		if s.tenantsActive > out[i].used {
			out[i].used = s.tenantsActive
		}
		if s.tenantSlots > out[i].max {
			out[i].max = s.tenantSlots
		}
	}
	return out
}

// admissionOneHot is a state-set member's value. Pure Go.
func admissionOneHot(on bool) float64 {
	if on {
		return 1
	}
	return 0
}

// admissionQwaitCumulative turns the C side's per-bucket counts into the
// cumulative form a Prometheus histogram carries, keyed by the bucket's upper
// bound in seconds. Pure Go.
func admissionQwaitCumulative(buckets [8]uint64) map[float64]uint64 {
	out := make(map[float64]uint64, len(buckets))
	var acc uint64
	for i, n := range buckets {
		acc += n
		out[admissionQwaitBoundsSeconds[i]] = acc
	}
	return out
}

// admissionQwaitHistogram is the histogram a scrape emits: the cumulative
// buckets and a count no smaller than the last of them. The C side adds a
// wait to its bucket before its count and the snapshot reads them without a
// lock, so a scrape can land between the two; a count below a bucket would
// be a histogram that is not monotonic. Pure Go.
func admissionQwaitHistogram(buckets [8]uint64, count uint64) (uint64, map[float64]uint64) {
	cum := admissionQwaitCumulative(buckets)
	if top := cum[admissionQwaitBoundsSeconds[len(admissionQwaitBoundsSeconds)-1]]; count < top {
		count = top
	}
	return count, cum
}

// admissionServiceLabel renders the service identity the audit trail and the
// admission gate already use: "VIP:port". Pure Go.
func admissionServiceLabel(xip uint32, xport uint16) string {
	return fmt.Sprintf("%s:%d", qosVipString(xip), xport)
}

// admissionPoolLabel bounds the pool key for use as a label. The key is the
// pool's "host|path" or "host" as configured; sanitizeLabel keeps the
// character set closed and the length bounded, and an empty key (a service
// with one anonymous pool) reads as "-" so it is legible in a query. Pure Go.
func admissionPoolLabel(key string) string {
	p := sanitizeLabel(key)
	if p == "" {
		p = "-"
	}
	return p
}

// sortAdmissionSamples orders the store deterministically (service, pool)
// so the exposition output is stable between scrapes. Pure Go.
func sortAdmissionSamples(samples []admissionSample) {
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].service != samples[j].service {
			return samples[i].service < samples[j].service
		}
		return samples[i].pool < samples[j].pool
	})
}

// dedupeAdmissionSamples drops every sample after the first per (service,
// pool) label pair. Distinct pool keys can sanitize to the same label; two
// samples on one label set would fail the whole scrape with a duplicate
// series error, so the first wins -- the rule the other collectors follow.
// Expects a sorted input. Pure Go.
func dedupeAdmissionSamples(samples []admissionSample) []admissionSample {
	out := samples[:0]
	for i, s := range samples {
		if i > 0 && s.service == samples[i-1].service && s.pool == samples[i-1].pool {
			continue
		}
		out = append(out, s)
	}
	return out
}

// refreshAdmissionStore pulls the per-pool gate state from the sockproxy and
// republishes the store. Called once per RunSockproxyMetrics cycle.
func refreshAdmissionStore() {
	var raw [C.PROXY_FC_STAT_MAX]C.proxy_fc_svc_stat_t

	n := int(C.proxy_get_fc_stats(&raw[0], C.int(len(raw))))
	if n < 0 {
		n = 0
	}
	if n > len(raw) {
		n = len(raw)
	}

	samples := make([]admissionSample, 0, n)
	for i := 0; i < n; i++ {
		st := raw[i]
		s := admissionSample{
			service:        admissionServiceLabel(uint32(st.xip), uint16(st.xport)),
			pool:           admissionPoolLabel(C.GoString(&st.pool[0])),
			mode:           float64(st.mode),
			maxOutstanding: float64(st.max_outstanding),
			inflight:       float64(st.inflight),
		}
		for r := 0; r < len(admissionRoleLabels); r++ {
			s.epCap[r] = float64(st.ep_cap[r])
			s.epInflight[r] = float64(st.ep_inflight[r])
		}
		for d := 0; d < len(admissionReasonLabels); d++ {
			s.decisions[d] = float64(st.decisions[d])
		}
		s.queued = float64(st.queued)
		s.queueDepth = float64(st.max_queue_depth)
		for b := 0; b < len(s.qwaitBuckets); b++ {
			s.qwaitBuckets[b] = uint64(st.qwait_bucket[b])
		}
		s.qwaitSumMs = uint64(st.qwait_sum_ms)
		s.qwaitCount = uint64(st.qwait_count)
		s.effectiveLimit = float64(st.effective_max_outstanding)
		s.adaptState = uint8(st.adapt_state)
		s.adaptReason = uint8(st.adapt_reason)
		s.adaptMoves[0] = float64(st.adapt_down)
		s.adaptMoves[1] = float64(st.adapt_up)
		s.warmingEps = float64(st.warming_eps)
		s.tenantsActive = float64(st.tenants_active)
		s.tenantSlots = float64(st.tenant_slots)
		for b := 0; b < len(s.bandOutcome); b++ {
			for o := 0; o < len(s.bandOutcome[b]); o++ {
				s.bandOutcome[b][o] = float64(st.band_outcome[b][o])
			}
		}
		samples = append(samples, s)
	}
	sortAdmissionSamples(samples)
	samples = dedupeAdmissionSamples(samples)

	var anomalies [5]float64
	for k := range admissionAnomalyLabels {
		anomalies[k] = float64(C.proxy_get_fc_anomaly(C.int(k)))
	}

	admissionStoreMutex.Lock()
	admissionStore = samples
	admissionAnomalies = anomalies
	admissionStoreMutex.Unlock()
}
