package prometheus

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>

// Forward declaration - actual definition in sockproxy.c
typedef struct proxy_metrics_snapshot {
    // Gauges (point-in-time counts)
    uint64_t active_connections;
    uint64_t active_ssl_connections;
    uint64_t cache_backpressure_active;
    uint64_t conversation_sessions;
    uint64_t h2_sessions;

    // Counters (cumulative atomics)
    uint64_t cache_high_water_events;
    uint64_t conversation_hits;
    uint64_t conversation_misses;
    uint64_t h2_total_streams;
    uint64_t chunked_responses;
    uint64_t cache_drain_partial;
    uint64_t peer_eof_graceful;
    uint64_t conversation_ttl_expired;

    // L7 Metrics: HTTP Response Counters
    uint64_t http_responses_total;
    uint64_t http_status_2xx;
    uint64_t http_status_3xx;
    uint64_t http_status_4xx;
    uint64_t http_status_5xx;

    // L7 Metrics: TTFB Latency Histogram (C-side buckets)
    uint64_t latency_bucket[12];
    uint64_t latency_sum_us;
    uint64_t latency_count;

    // Histograms (samples - future use)
    uint64_t cache_size_samples[100];
    uint32_t cache_size_sample_count;

    // CHWBL (optional)
    float chwbl_load_imbalance_ratio;

    // P/D Buffer: kv_transfer_params overflow counter
    uint64_t pd_kv_params_overflow;

    // P/D Production Hardening gauges
    uint64_t pd_sessions_active;
    uint64_t pd_trie_nodes;
    uint64_t pd_cb_flips;
    uint64_t pd_fallback_to_normal;

    // KV Tier 1.5 routing diagnostics (per-guard miss + fallthrough)
    uint64_t pd_kv_t15_miss_mode_off;
    uint64_t pd_kv_t15_miss_warmup;
    uint64_t pd_kv_t15_miss_text_empty;
    uint64_t pd_kv_t15_miss_model_empty;
    uint64_t pd_kv_t15_miss_tokenize;
    uint64_t pd_kv_t15_miss_hashes;
    uint64_t pd_kv_t15_miss_no_worker;
    uint64_t pd_kv_t15_miss_excluded;
    uint64_t pd_kv_t15_fallthrough_total;

    // CB proactive heal + per-EP admission layer
    // counters. TAIL-APPEND ONLY — twin-declared in
    // loxilb-ebpf/common/sockproxy_metrics.h; keep BOTH in lockstep, same commit.
    uint64_t pd_cb_proactive_heal;
    uint64_t pd_admission_shed;
    uint64_t pd_admission_queued;
} proxy_metrics_snapshot_t;

// C function from sockproxy.c
extern proxy_metrics_snapshot_t proxy_get_metrics(void);
*/
import "C"

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

// ============================================================================
// SOCKPROXY METRICS - Following LoxiLB promauto Pattern
// ============================================================================
// Pattern: promauto.NewGauge/Counter (auto-registers, no manual registration)
// Collection: Periodic updates via RunSockproxyMetrics goroutine
// Delta Calculation: For cumulative C atomics (same as security metrics)
// ============================================================================

var (
	// ========================================================================
	// TIER 1 METRICS - Critical AI/LLM Metrics (10s collection)
	// ========================================================================

	// Metric #1: Cache Backpressure Ratio
	proxyCacheBackpressureRatio = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "loxilb_proxy_cache_backpressure_ratio",
			Help: "Ratio of connections with active cache backpressure (0.0-1.0). High values indicate sustained cache pressure.",
		},
	)

	// Metric #2: Session Affinity Hits / Misses (Counters)
	// Raw counters instead of a lifetime hit-rate ratio: the windowed rate is
	// derivable in PromQL, e.g.
	// rate(loxilb_proxy_conversation_hits_total[5m]) /
	//   (rate(loxilb_proxy_conversation_hits_total[5m]) + rate(loxilb_proxy_conversation_misses_total[5m]))
	proxyConversationHitsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_conversation_hits_total",
			Help: "Total conversation mapping lookups that hit an existing session affinity entry.",
		},
	)
	proxyConversationMissesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_conversation_misses_total",
			Help: "Total conversation mapping lookups that missed (no session affinity entry).",
		},
	)

	// Metric #5: Cache High Water Events (Counter)
	proxyCacheHighWaterEventsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_cache_high_water_events_total",
			Help: "Total cache backpressure activations. Monotonic counter tracking adaptive backpressure triggers.",
		},
	)

	// ========================================================================
	// TIER 2 METRICS - Important Observability (30s collection)
	// ========================================================================

	// Metric #6: Active Connections
	proxyActiveConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "loxilb_proxy_active_connections",
			Help: "Current number of active proxy connections (all types).",
		},
	)

	// Metric #7: Active SSL Connections
	proxyActiveSslConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "loxilb_proxy_active_ssl_connections",
			Help: "Current number of active SSL/TLS connections.",
		},
	)

	// Metric #8: Conversation Sessions
	proxyConversationSessions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "loxilb_proxy_conversation_sessions",
			Help: "Current number of active conversation mappings (session affinity state).",
		},
	)

	// Metric #9: Chunked Responses Total (Counter - cumulative)
	proxyChunkedResponsesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_chunked_responses_total",
			Help: "Total number of chunked transfer encoding responses detected. Indicates streaming AI workloads.",
		},
	)

	// Metric #10: HTTP/2 Sessions (Counter)
	// The C side (sockproxy_h2.c) only ever increments h2_sessions — sessions
	// are never decremented on teardown — so the value is lifetime sessions
	// created, not currently-active sessions. Declared as a counter until the
	// C side gains teardown accounting (metrics audit D4, deferred).
	proxyHttp2SessionsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_http2_sessions_total",
			Help: "Total HTTP/2 sessions created.",
		},
	)

	// ========================================================================
	// TIER 3 METRICS - Operational Debugging (2m collection)
	// ========================================================================

	// Metric #11: Cache Drain Partial Events (Counter)
	proxyCacheDrainPartialTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_cache_drain_partial_total",
			Help: "Total partial cache drain events (EAGAIN/EWOULDBLOCK during flush). Indicates socket flow control.",
		},
	)

	// Metric #12: Graceful Close with Cache Drain (Counter)
	proxyGracefulCloseTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_graceful_close_total",
			Help: "Total graceful connection closes with pending cache drain. Tracks proper shutdown preventing data loss.",
		},
	)

	// Metric #13: Conversation TTL Expirations (Counter)
	proxyConversationTtlExpiredTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_conversation_ttl_expired_total",
			Help: "Total conversation mappings expired due to TTL timeout. Helps tune session affinity TTL settings.",
		},
	)

	// ========================================================================
	// L7 METRICS - HTTP RPS, Status Codes, TTFB Latency
	// ========================================================================

	// Metric #14: HTTP Responses Total (Counter - for RPS via rate)
	proxyHttpResponsesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_http_responses_total",
			Help: "Total HTTP responses processed. Use rate() for RPS calculation.",
		},
	)

	// Metric #15: HTTP Responses by Status Class (CounterVec)
	proxyHttpResponsesByStatus = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_http_responses_by_status_total",
			Help: "Total HTTP responses by status code class (2xx, 3xx, 4xx, 5xx).",
		},
		[]string{"status_class"},
	)

	// Metric #16: HTTP TTFB Latency (Histogram - seconds)
	// NOT a promauto histogram: the C side already maintains a cumulative
	// le-bucket histogram (record_latency_sample in sockproxy_metrics.c), so
	// it is exposed verbatim via ttfbCollector (a custom prometheus.Collector
	// emitting a ConstHistogram) instead of replaying per-sample Observe
	// calls. See the TTFB section below the metric declarations.

	// ========================================================================
	// P/D METRICS - Buffer Hardening
	// ========================================================================

	// Metric #17: P/D KV Params Buffer Overflow (Counter)
	proxyPdKvParamsOverflowTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_pd_kv_params_overflow_total",
			Help: "Total kv_transfer_params extraction buffer overflow events. Alert on sustained non-zero rate.",
		},
	)

	// ========================================================================
	// P/D PRODUCTION HARDENING METRICS
	// ========================================================================

	// Metric #18: P/D Sessions Active (Gauge)
	pdSessionsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "loxilb_pd_sessions_active",
			Help: "Number of active P/D disaggregation sessions.",
		},
	)

	// Metric #19: P/D Trie Nodes (Gauge)
	pdTrieNodes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "loxilb_pd_trie_nodes",
			Help: "Number of prefix trie nodes for P/D routing.",
		},
	)

	// Metric #20: P/D Circuit Breaker Flips (Counter)
	pdCbFlipsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_pd_cb_flips_total",
			Help: "Total circuit breaker state transitions (CLOSED->OPEN, HALF_OPEN->OPEN, HALF_OPEN->CLOSED, OPEN->HALF_OPEN).",
		},
	)

	// Metric #21: P/D Fallback to Normal (Counter)
	pdFallbackToNormalTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_pd_fallback_to_normal_total",
			Help: "Total requests that fell back from P/D to normal inference mode due to unhealthy prefill/decode EPs.",
		},
	)

	// Metric #22: KV Blocks per Endpoint (Gauge)
	// Populated by ai_kv_subscriber.go when KV routing is active. Joinable to
	// an endpoint address via loxilb_pd_ep_info on (service, ep_idx).
	pdKvBlocks = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "loxilb_pd_kv_blocks",
			Help: "KV cache blocks currently stored per endpoint.",
		},
		[]string{"service", "ep_idx"},
	)

	// Metric #23: KV Tier-1.5 Cache Hit Routing (Counter)
	// Incremented by ai_kv_subscriber.go llb_ai_kv_best_worker when a prefill
	// EP with matching KV blocks is selected (Tier 1.5 cache-hit routing fires).
	// This is the primary proof-of-correctness observable for TK17/TK21.
	pdKvTier15HitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_pd_kv_tier15_hits_total",
			Help: "Total Tier-1.5 KV cache-hit routing decisions (prompt routed to EP with matching KV blocks).",
		},
		[]string{"ep_idx"},
	)

	// Metric #23b: P/D endpoint identity mapping (info metric).
	// The KV per-EP series (tier15_hits/spills, kv_subscriber_connected, kv_blocks)
	// are keyed by the opaque integer ep_idx, which an operator cannot map to a
	// physical endpoint. This info metric records ep_idx -> endpoint IP so those
	// series can be joined to an address:
	//   loxilb_pd_kv_tier15_hits_total * on(ep_idx) group_left(ep) loxilb_pd_ep_info
	// Set at KvSubscriberStart for EVERY prefill EP — so an ep_idx that has not yet
	// emitted a (lazy) tier15_hits series is still discoverable. Value is always 1.
	pdEpInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "loxilb_pd_ep_info",
			Help: "P/D endpoint identity: maps ep_idx (the label on the KV per-EP metrics) to the endpoint IP. Value is always 1.",
		},
		[]string{"service", "ep_idx", "ep"},
	)

	// ========================================================================
	// KV Tier 1.5 routing diagnostics
	// ========================================================================
	// These counters surface *why* Tier 1.5 routing is (or is not) firing so
	// operators can pinpoint the specific guard in pd_kv_exact_select that
	// short-circuits routing in production. Populated from snapshot deltas in
	// plan 42-02 (storage allocated here in plan 42-01).

	// Metric #24: Tier 1.5 per-guard miss reasons (CounterVec)
	pdKvT15MissReasonTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "loxilb",
			Subsystem: "pd_kv",
			Name:      "tier15_miss_reason_total",
			Help:      "Total Tier-1.5 KV-exact routing misses by guard reason (mode_off,warmup,text_empty,model_empty,tokenize,hashes,no_worker,excluded).",
		},
		[]string{"reason"},
	)

	// Metric #25: Tier 1.5 fallthrough (Counter)
	pdKvT15FallthroughTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "loxilb",
			Subsystem: "pd_kv",
			Name:      "tier15_fallthrough_total",
			Help:      "Total requests that skipped Tier 1.5 KV-exact routing entirely and fell through to Tier 2 (round-robin / next-tier).",
		},
	)

	// ========================================================================
	// KV subscriber liveness (observability for vLLM EP restart recovery)
	// ========================================================================
	// Surfaces the ZMQ SUB socket state per (service, ep) so operators can
	// detect silent subscriber disconnects. Populated from ai_kv_subscriber.go.

	// KV subscriber connection gauge (1 = connected, 0 = disconnected/rebuilding).
	kvSubscriberConnected = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "loxilb_kv_subscriber_connected",
			Help: "ZMQ KV subscriber connection state per endpoint (1=connected, 0=disconnected/rebuilding).",
		},
		[]string{"service", "ep"},
	)

	// Reconnect counter — increments each time the subscriber rebuilds its SUB
	// socket after detecting a dead connection. A non-zero rate indicates EP
	// churn (vLLM restarts) and is the primary signal that recovery is working.
	kvSubscriberReconnectTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_kv_subscriber_reconnect_total",
			Help: "Total ZMQ KV subscriber socket rebuilds (increments on every successful reconnect after a dead-socket detection).",
		},
		[]string{"service", "ep"},
	)

	// Recv-error counter — increments on every RecvMultipart error before the
	// subscriber decides whether to rebuild. Useful for detecting flaky links
	// vs. outright EP crashes.
	kvSubscriberRecvErrorTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_kv_subscriber_recv_error_total",
			Help: "Total ZMQ KV subscriber recv errors (includes transient errors before rebuild threshold is crossed).",
		},
		[]string{"service", "ep"},
	)

	// Cap-hit eviction counter — increments by the number of blocks
	// evicted whenever an EP's kvInventory exceeds the per-EP kvMaxBlocks cap.
	// Authoritative "publisher misbehaving" signal: nonzero ⇒ a publisher is
	// emitting BlockStored without matching BlockRemoved. Event-driven
	// (incremented at the eviction site in ai_kv_subscriber.go AddBlocks),
	// never lossy. Mirrors the loxilb_kv_subscriber_* name family (plain name,
	// {service, ep} labels) — NOT the namespaced pd_kv family.
	kvInvCapEvictionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_kv_inv_cap_evictions_total",
			Help: "Total KV inventory blocks evicted due to the per-EP kvMaxBlocks cap. Nonzero is the authoritative publisher-misbehaving signal (BlockStored without matching BlockRemoved).",
		},
		[]string{"service", "ep"},
	)

	// KV Tier-1.5 capacity-bounded-load spill counter. Incremented
	// by ai_kv_subscriber.go llb_ai_kv_best_worker when the UNIFIED prefix-CHWBL +
	// capacity-weighted-bounded-load mode spills past the highest-overlap
	// (affinity-preferred) EP because that EP is at/over its capacity-weighted cap
	// cap_i = ceil((1+ε)·total_load·capacity_i/Σcapacity). A nonzero value is the
	// authoritative C4 cap-enforcement signal — it proves the load/capacity term
	// fired and the selector did NOT herd to the affinity winner. Sibling of
	// pd_kv_tier15_hits_total; OFF entirely when the unified mode is disabled.
	kvTier15SpillsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_pd_kv_tier15_spills_total",
			Help: "Total Tier-1.5 unified-mode spills past the affinity-preferred EP because it exceeded its capacity-weighted bounded-load cap (C4 cap enforcement).",
		},
		[]string{"ep_idx"},
	)

	// Tier-1.5 zero-hit watchdog counter. Incremented by
	// ai_kv_subscriber.go kvZeroHitWatchdog on EVERY lookup at-or-past the
	// LOXILB_KV_ZERO_HIT_N (default 50) consecutive-zero-hit threshold for a
	// service whose ELIGIBLE inventory is non-empty. Nonzero ⇒ that service's
	// inventories never match live traffic — the authoritative silent
	// kvBlockSize≠page-size / hash-algo parity-failure signal (the [KV_ZEROHIT]
	// WARN fires once per transition edge, shape; this counter carries
	// the volume). Per-service labeling ({service_id} = the rule number) keeps
	// the two-VIP coexistence scenario attributable per arm.
	kvZeroHitWatchdogTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_pd_kv_zero_hit_watchdog_total",
			Help: "Total KV-exact lookups at-or-past the consecutive-zero-hit watchdog threshold against a non-empty inventory. Nonzero is the authoritative silent hash-parity-failure signal (kvBlockSize/page-size mismatch or hash-algo drift).",
		},
		[]string{"service_id"},
	)

	// ========================================================================
	// P/D admission + CB proactive-heal export
	// ========================================================================
	// Makes C-side counters Prometheus-visible (export-first, P11)
	// so operators observe admission/heal behavior via /metrics deltas, never
	// docker-log grep. These belong to the PER-EP admission layer (:
	// LLB_PD_MAX_INFLIGHT_PER_EP cap + LLB_PD_QUEUE_DEPTH_PER_EP FIFO) — a
	// DIFFERENT mechanism from global valve
	// (pd_admission_total_inflight/pd_admission_total_blocked, sockproxy.h).

	// Metric #26: P/D per-EP admission sheds (Counter)
	pdAdmissionShedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_pd_admission_shed_total",
			Help: "Total requests shed (retriable 429) by the per-EP admission layer : every healthy prefill EP at the in-flight cap with no parked-FIFO room. Distinct from global total-inflight valve.",
		},
	)

	// Metric #27: P/D per-EP admission parks (Counter)
	pdAdmissionQueuedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_pd_admission_queued_total",
			Help: "Total requests PARKED (held, not shed) on a per-EP FIFO by the per-EP admission layer (hold-don't-drop). Distinct from global total-inflight valve.",
		},
	)

	// Metric #28: P/D circuit-breaker proactive heals (Counter)
	pdCbProactiveHealTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_pd_cb_proactive_heal_total",
			Help: "Total circuit-breaker OPEN->HALF_OPEN transitions driven proactively by the 1Hz health pass (self-heal) without organic traffic. Sibling of loxilb_pd_cb_flips_total (which counts ALL CB state transitions).",
		},
	)
)

// pdKvT15MissReasonLabels enumerates the canonical guard reasons used by the
// Tier 1.5 miss-reason CounterVec. Keep aligned with the pd_kv_t15_miss_*
// atomic fields in proxy_global_stats_t (sockproxy.h) and the snapshot
// struct (sockproxy_metrics.h). Used by the CGO consumer below and by
// TestKvTier15MissCountersRegistered.
var pdKvT15MissReasonLabels = []string{
	"mode_off",
	"warmup",
	"text_empty",
	"model_empty",
	"tokenize",
	"hashes",
	"no_worker",
	"excluded",
}

// init pre-creates every reason child so the CounterVec appears in
// prometheus.DefaultGatherer output immediately after package init (before any
// increment). This guarantees downstream dashboards see every reason series
// and lets TestKvTier15MissCountersRegistered verify registration via Gather.
func init() {
	for _, reason := range pdKvT15MissReasonLabels {
		pdKvT15MissReasonTotal.WithLabelValues(reason)
	}
}

// ============================================================================
// TTFB Histogram - Custom ConstHistogram Collector (Metric #16)
// ============================================================================
// The C side keeps a CUMULATIVE le-bucket histogram: record_latency_sample
// (loxilb-ebpf/common/sockproxy_metrics.c) increments EVERY bucket whose
// upper bound >= sample, so latency_bucket[i] is already "count of samples
// <= bound[i]" — exactly Prometheus le-bucket semantics. Instead of
// reconstructing per-sample Observe calls from snapshot deltas (which
// livelocked on uint64 underflow when a torn C-side read made bucket[i+1] <
// bucket[i], and mis-attributed every sample to its bucket upper bound), the
// cumulative state is stored here and emitted as a ConstHistogram on scrape.
// latency_sum_us gives the exact _sum (converted to seconds).
// ============================================================================

// ttfbBucketBounds are the histogram upper bounds in SECONDS. Must match
// latency_bucket_bounds_us (microseconds) in
// loxilb-ebpf/common/sockproxy_metrics.c.
var ttfbBucketBounds = [12]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}

// ttfbSnapshot is the sanitized cumulative TTFB histogram state taken from a
// C-side proxy_metrics_snapshot_t.
type ttfbSnapshot struct {
	buckets [12]uint64 // cumulative counts keyed by ttfbBucketBounds index
	count   uint64     // total samples (includes samples above the last bound)
	sumSecs float64    // cumulative sum of all samples, in seconds
}

// ttfbStore is the mutex-guarded state shared between the 10s collection
// loop (writer) and ttfbCollector.Collect (reader, on scrape).
var (
	ttfbStoreMutex sync.Mutex
	ttfbStore      ttfbSnapshot
)

// sanitizeTtfbSnapshot absorbs torn reads inside one C snapshot: the 12
// bucket atomics are loaded one-by-one while the hot path increments them,
// so a later bucket can be read smaller than an earlier one. Clamp the
// cumulative sequence non-decreasing (cum[i] = max(cum[i], cum[i-1])) and
// clamp count to at least the highest bucket. Pure Go — unit tested without
// CGO in sockproxy_metrics_test.go.
func sanitizeTtfbSnapshot(raw ttfbSnapshot) ttfbSnapshot {
	s := raw
	for i := 1; i < len(s.buckets); i++ {
		if s.buckets[i] < s.buckets[i-1] {
			s.buckets[i] = s.buckets[i-1]
		}
	}
	if s.count < s.buckets[len(s.buckets)-1] {
		s.count = s.buckets[len(s.buckets)-1]
	}
	return s
}

// mergeTtfbSnapshot maintains monotonicity ACROSS snapshots: element-wise
// max of the previously exposed state and the new (sanitized) snapshot, so a
// torn read can never make the exposed histogram go backwards (Prometheus
// would misread that as a counter reset). Exception: a drastically lower
// count (< half of previous) is treated as a genuine C-side reset (process
// restart) and the new state replaces the old wholesale. Both inputs must be
// sanitized; element-wise max of two non-decreasing sequences stays
// non-decreasing. Pure Go — unit tested without CGO.
func mergeTtfbSnapshot(prev, next ttfbSnapshot) ttfbSnapshot {
	if next.count < prev.count/2 {
		return next
	}
	merged := next
	for i := range merged.buckets {
		if prev.buckets[i] > merged.buckets[i] {
			merged.buckets[i] = prev.buckets[i]
		}
	}
	if prev.count > merged.count {
		merged.count = prev.count
	}
	if prev.sumSecs > merged.sumSecs {
		merged.sumSecs = prev.sumSecs
	}
	return merged
}

// updateTtfbStore sanitizes+merges a raw snapshot into ttfbStore. Called
// once per collection cycle by RunSockproxyMetrics.
func updateTtfbStore(raw ttfbSnapshot) {
	next := sanitizeTtfbSnapshot(raw)
	ttfbStoreMutex.Lock()
	ttfbStore = mergeTtfbSnapshot(ttfbStore, next)
	ttfbStoreMutex.Unlock()
}

// ttfbDesc keeps the exact metric identity of the former promauto histogram.
var ttfbDesc = prometheus.NewDesc(
	"loxilb_proxy_http_ttfb_seconds",
	"HTTP Time-To-First-Byte latency in seconds.",
	nil, nil,
)

// ttfbCollector emits loxilb_proxy_http_ttfb_seconds as a ConstHistogram straight
// from ttfbStore on every scrape. Before the first snapshot it emits a
// zero-valued histogram (count=0), which is standard for an idle histogram.
type ttfbCollector struct{}

// Describe implements prometheus.Collector.
func (ttfbCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- ttfbDesc
}

// Collect implements prometheus.Collector.
func (ttfbCollector) Collect(ch chan<- prometheus.Metric) {
	ttfbStoreMutex.Lock()
	s := ttfbStore
	ttfbStoreMutex.Unlock()

	buckets := make(map[float64]uint64, len(ttfbBucketBounds))
	for i, ub := range ttfbBucketBounds {
		buckets[ub] = s.buckets[i]
	}
	ch <- prometheus.MustNewConstHistogram(ttfbDesc, s.count, s.sumSecs, buckets)
}

// init registers the TTFB collector once with the default registry (same
// registry the promauto metrics above use).
func init() {
	prometheus.MustRegister(ttfbCollector{})
}

// ============================================================================
// Previous State for Delta Calculation (Cumulative C Atomics)
// ============================================================================
// Pattern: Same as prevSecurityStats in prometheus.go
// Purpose: Calculate deltas from cumulative eBPF/C atomic counters
// ============================================================================

var prevSockproxyMetrics C.proxy_metrics_snapshot_t

// ============================================================================
// Helper Calculation Functions
// ============================================================================

// calculateBackpressureRatio computes ratio of connections with active backpressure
func calculateBackpressureRatio(metrics C.proxy_metrics_snapshot_t) float64 {
	total := float64(metrics.active_connections)
	if total == 0 {
		return 0.0
	}
	return float64(metrics.cache_backpressure_active) / total
}

// ============================================================================
// RunSockproxyMetrics - Periodic Collection Goroutine
// ============================================================================
// Pattern: Follows RunSecurityRateStats from prometheus.go (lines 2521-2600)
// Purpose: Collect metrics from C, calculate deltas, update Prometheus gauges/counters
// Interval: PrometheusDefaultPeriod (10 seconds)
// ============================================================================

// RunSockproxyMetrics collects sockproxy metrics for AI/LLM workloads
// This function MUST be in sockproxy_metrics.go (not prometheus.go) because:
// - CGO's 'C' package is file-scoped (only accessible in file with 'import "C"')
// - C.proxy_metrics_snapshot_t type only exists in this file
func RunSockproxyMetrics(ctx context.Context) {
	safeGoroutineOperation(func(ctx context.Context) error {
		// 1. Fetch current metrics from C
		current := C.proxy_get_metrics()

		// 2. Update GAUGES (point-in-time values)
		proxyCacheBackpressureRatio.Set(calculateBackpressureRatio(current))
		proxyActiveConnections.Set(float64(current.active_connections))
		proxyActiveSslConnections.Set(float64(current.active_ssl_connections))
		proxyConversationSessions.Set(float64(current.conversation_sessions))

		// 3. Update COUNTERS (delta from cumulative C atomics with overflow protection)
		if current.conversation_hits >= prevSockproxyMetrics.conversation_hits {
			delta := current.conversation_hits - prevSockproxyMetrics.conversation_hits
			proxyConversationHitsTotal.Add(float64(delta))
		}

		if current.conversation_misses >= prevSockproxyMetrics.conversation_misses {
			delta := current.conversation_misses - prevSockproxyMetrics.conversation_misses
			proxyConversationMissesTotal.Add(float64(delta))
		}

		if current.h2_sessions >= prevSockproxyMetrics.h2_sessions {
			delta := current.h2_sessions - prevSockproxyMetrics.h2_sessions
			proxyHttp2SessionsTotal.Add(float64(delta))
		}

		if current.cache_high_water_events >= prevSockproxyMetrics.cache_high_water_events {
			delta := current.cache_high_water_events - prevSockproxyMetrics.cache_high_water_events
			proxyCacheHighWaterEventsTotal.Add(float64(delta))
		}

		if current.chunked_responses >= prevSockproxyMetrics.chunked_responses {
			delta := current.chunked_responses - prevSockproxyMetrics.chunked_responses
			proxyChunkedResponsesTotal.Add(float64(delta))
		}

		if current.cache_drain_partial >= prevSockproxyMetrics.cache_drain_partial {
			delta := current.cache_drain_partial - prevSockproxyMetrics.cache_drain_partial
			proxyCacheDrainPartialTotal.Add(float64(delta))
		}

		if current.peer_eof_graceful >= prevSockproxyMetrics.peer_eof_graceful {
			delta := current.peer_eof_graceful - prevSockproxyMetrics.peer_eof_graceful
			proxyGracefulCloseTotal.Add(float64(delta))
		}

		if current.conversation_ttl_expired >= prevSockproxyMetrics.conversation_ttl_expired {
			delta := current.conversation_ttl_expired - prevSockproxyMetrics.conversation_ttl_expired
			proxyConversationTtlExpiredTotal.Add(float64(delta))
		}

		// 3b. Update L7 METRICS (HTTP RPS, Status Codes, TTFB Histogram)
		if current.http_responses_total >= prevSockproxyMetrics.http_responses_total {
			delta := current.http_responses_total - prevSockproxyMetrics.http_responses_total
			proxyHttpResponsesTotal.Add(float64(delta))
		}

		// Status code class deltas
		if current.http_status_2xx >= prevSockproxyMetrics.http_status_2xx {
			delta := current.http_status_2xx - prevSockproxyMetrics.http_status_2xx
			proxyHttpResponsesByStatus.WithLabelValues("2xx").Add(float64(delta))
		}
		if current.http_status_3xx >= prevSockproxyMetrics.http_status_3xx {
			delta := current.http_status_3xx - prevSockproxyMetrics.http_status_3xx
			proxyHttpResponsesByStatus.WithLabelValues("3xx").Add(float64(delta))
		}
		if current.http_status_4xx >= prevSockproxyMetrics.http_status_4xx {
			delta := current.http_status_4xx - prevSockproxyMetrics.http_status_4xx
			proxyHttpResponsesByStatus.WithLabelValues("4xx").Add(float64(delta))
		}
		if current.http_status_5xx >= prevSockproxyMetrics.http_status_5xx {
			delta := current.http_status_5xx - prevSockproxyMetrics.http_status_5xx
			proxyHttpResponsesByStatus.WithLabelValues("5xx").Add(float64(delta))
		}

		// TTFB Histogram: store the cumulative C-side state for ttfbCollector.
		// C buckets are already cumulative le counts (bucket[i] = samples <=
		// bound[i]) and latency_sum_us is the exact cumulative sum, so no
		// per-sample Observe reconstruction is needed — sanitize/merge in
		// updateTtfbStore absorbs torn reads and the collector emits a
		// ConstHistogram on scrape.
		var ttfbRaw ttfbSnapshot
		for i := 0; i < len(ttfbRaw.buckets); i++ {
			ttfbRaw.buckets[i] = uint64(current.latency_bucket[i])
		}
		ttfbRaw.count = uint64(current.latency_count)
		ttfbRaw.sumSecs = float64(current.latency_sum_us) / 1e6
		updateTtfbStore(ttfbRaw)

		// 3c. P/D buffer overflow counter
		if current.pd_kv_params_overflow >= prevSockproxyMetrics.pd_kv_params_overflow {
			delta := current.pd_kv_params_overflow - prevSockproxyMetrics.pd_kv_params_overflow
			proxyPdKvParamsOverflowTotal.Add(float64(delta))
		}

		// 3d. P/D Production Hardening metrics
		pdSessionsActive.Set(float64(current.pd_sessions_active))
		pdTrieNodes.Set(float64(current.pd_trie_nodes))

		if current.pd_cb_flips >= prevSockproxyMetrics.pd_cb_flips {
			delta := current.pd_cb_flips - prevSockproxyMetrics.pd_cb_flips
			pdCbFlipsTotal.Add(float64(delta))
		}
		if current.pd_fallback_to_normal >= prevSockproxyMetrics.pd_fallback_to_normal {
			delta := current.pd_fallback_to_normal - prevSockproxyMetrics.pd_fallback_to_normal
			pdFallbackToNormalTotal.Add(float64(delta))
		}

		// 3e. : KV Tier 1.5 routing diagnostics (per-guard miss + fallthrough)
		// Delta pattern matches existing counters; fields populate in plan 42-02.
		t15MissCurrent := [8]C.uint64_t{
			current.pd_kv_t15_miss_mode_off,
			current.pd_kv_t15_miss_warmup,
			current.pd_kv_t15_miss_text_empty,
			current.pd_kv_t15_miss_model_empty,
			current.pd_kv_t15_miss_tokenize,
			current.pd_kv_t15_miss_hashes,
			current.pd_kv_t15_miss_no_worker,
			current.pd_kv_t15_miss_excluded,
		}
		t15MissPrev := [8]C.uint64_t{
			prevSockproxyMetrics.pd_kv_t15_miss_mode_off,
			prevSockproxyMetrics.pd_kv_t15_miss_warmup,
			prevSockproxyMetrics.pd_kv_t15_miss_text_empty,
			prevSockproxyMetrics.pd_kv_t15_miss_model_empty,
			prevSockproxyMetrics.pd_kv_t15_miss_tokenize,
			prevSockproxyMetrics.pd_kv_t15_miss_hashes,
			prevSockproxyMetrics.pd_kv_t15_miss_no_worker,
			prevSockproxyMetrics.pd_kv_t15_miss_excluded,
		}
		for i, reason := range pdKvT15MissReasonLabels {
			if t15MissCurrent[i] >= t15MissPrev[i] {
				delta := t15MissCurrent[i] - t15MissPrev[i]
				pdKvT15MissReasonTotal.WithLabelValues(reason).Add(float64(delta))
			}
		}
		if current.pd_kv_t15_fallthrough_total >= prevSockproxyMetrics.pd_kv_t15_fallthrough_total {
			delta := current.pd_kv_t15_fallthrough_total - prevSockproxyMetrics.pd_kv_t15_fallthrough_total
			pdKvT15FallthroughTotal.Add(float64(delta))
		}

		// 3f. : per-EP admission layer + CB proactive-heal counters.
		// Delta pattern matches cache_high_water_events (monotonic >= guard).
		if current.pd_admission_shed >= prevSockproxyMetrics.pd_admission_shed {
			delta := current.pd_admission_shed - prevSockproxyMetrics.pd_admission_shed
			pdAdmissionShedTotal.Add(float64(delta))
		}
		if current.pd_admission_queued >= prevSockproxyMetrics.pd_admission_queued {
			delta := current.pd_admission_queued - prevSockproxyMetrics.pd_admission_queued
			pdAdmissionQueuedTotal.Add(float64(delta))
		}
		if current.pd_cb_proactive_heal >= prevSockproxyMetrics.pd_cb_proactive_heal {
			delta := current.pd_cb_proactive_heal - prevSockproxyMetrics.pd_cb_proactive_heal
			pdCbProactiveHealTotal.Add(float64(delta))
		}

		// 4. Save state for next cycle
		prevSockproxyMetrics = current

		// 5. Sleep and loop (security pattern)
		time.Sleep(PrometheusDefaultPeriod) // 10 seconds
		return nil
	}, "sockproxy_metrics", ctx)
}

// SetKvBlocksGauge updates the loxilb_pd_kv_blocks gauge for one endpoint.
// Called from pkg/loxinet/ai_kv_subscriber.go to bridge KV inventory sizes.
func SetKvBlocksGauge(service, epIdx string, count float64) {
	pdKvBlocks.WithLabelValues(service, epIdx).Set(count)
}

// IncKvTier15HitCounter increments the pd_kv_tier15_hits_total counter for a given EP index.
// Called from pkg/loxinet/ai_kv_subscriber.go llb_ai_kv_best_worker on every Tier-1.5 routing hit.
func IncKvTier15HitCounter(epIdx string) {
	pdKvTier15HitsTotal.WithLabelValues(epIdx).Inc()
}

// IncKvTier15SpillCounter increments the pd_kv_tier15_spills_total counter
// (C4) for the EP that the unified mode SPILLED TO. Called from
// llb_ai_kv_best_worker when the capacity-weighted bounded-load cap forces the
// selector off the highest-overlap EP. Nonzero ⇒ cap enforcement fired.
func IncKvTier15SpillCounter(epIdx string) {
	kvTier15SpillsTotal.WithLabelValues(epIdx).Inc()
}

// SetKvEpInfo records the ep_idx->IP identity for a P/D endpoint (info metric).
// Called from KvSubscriberStart, where the endpoint IP is known, for EVERY EP —
// so an ep_idx that has not yet emitted a (lazy) tier15_hits series is still
// discoverable. Value is always 1.
func SetKvEpInfo(service, epIdx, ep string) {
	pdEpInfo.WithLabelValues(service, epIdx, ep).Set(1)
}

// ClearKvEpInfo removes the identity series for an EP when its subscriber stops,
// so a decommissioned ep_idx does not linger as a stale mapping. Matches on
// (service, ep_idx) so the caller need not know the IP at stop time.
func ClearKvEpInfo(service, epIdx string) {
	pdEpInfo.DeletePartialMatch(prometheus.Labels{"service": service, "ep_idx": epIdx})
}

// ClearKvEpSeries removes ALL per-EP KV series for a decommissioned endpoint
// (series lifecycle, metrics audit): the blocks gauge, subscriber liveness /
// reconnect / recv-error / cap-eviction series, the Tier-1.5 hit/spill
// counters, and the ep_idx->IP identity mapping. Stale children otherwise
// linger on /metrics forever (a connected=0 ghost, a frozen blocks count).
//
// Caveat: the tier15 hit/spill counters are keyed by ep_idx ONLY (no service
// label) — when two services share an ep_idx the deletion resets the shared
// child; Prometheus rate() treats the reset like any counter restart.
func ClearKvEpSeries(service, epIdx string) {
	pdKvBlocks.DeleteLabelValues(service, epIdx)
	kvSubscriberConnected.DeleteLabelValues(service, epIdx)
	kvSubscriberReconnectTotal.DeleteLabelValues(service, epIdx)
	kvSubscriberRecvErrorTotal.DeleteLabelValues(service, epIdx)
	kvInvCapEvictionsTotal.DeleteLabelValues(service, epIdx)
	pdKvTier15HitsTotal.DeleteLabelValues(epIdx)
	kvTier15SpillsTotal.DeleteLabelValues(epIdx)
	ClearKvEpInfo(service, epIdx)
}

// ClearKvServiceSeries removes service-scoped KV series (the zero-hit
// watchdog counter) when a whole service is torn down.
func ClearKvServiceSeries(serviceID string) {
	kvZeroHitWatchdogTotal.DeleteLabelValues(serviceID)
}

// KvTier15SpillValue returns the current spill-counter value for epIdx.
// Test-only getter (mirrors KvInventoryCapHitValue) — reads via dto.Metric.Write
// to keep prometheus/testutil out of the loxinet import graph.
func KvTier15SpillValue(epIdx string) float64 {
	c := kvTier15SpillsTotal.WithLabelValues(epIdx)
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		return 0
	}
	if m.Counter == nil || m.Counter.Value == nil {
		return 0
	}
	return *m.Counter.Value
}

// SetKvSubscriberConnected sets the subscriber-connected gauge for (service, ep).
// connected=1 when the ZMQ SUB socket is up and ingesting events; 0 during
// disconnect/rebuild. Called from ai_kv_subscriber.go on socket lifecycle
// transitions.
func SetKvSubscriberConnected(service, ep string, connected int) {
	kvSubscriberConnected.WithLabelValues(service, ep).Set(float64(connected))
}

// IncKvSubscriberReconnect increments the reconnect counter for (service, ep).
// Called on every successful socket rebuild after a dead-socket detection.
func IncKvSubscriberReconnect(service, ep string) {
	kvSubscriberReconnectTotal.WithLabelValues(service, ep).Inc()
}

// IncKvSubscriberRecvError increments the recv-error counter for (service, ep).
// Called on every RecvMultipart error.
func IncKvSubscriberRecvError(service, ep string) {
	kvSubscriberRecvErrorTotal.WithLabelValues(service, ep).Inc()
}

// IncKvInventoryCapHit increments the cap-eviction counter for
// (service, ep) by n. Called from ai_kv_subscriber.go AddBlocks when the per-EP
// kvMaxBlocks cap forces eviction. Uses .Add(n) (one call per eviction batch)
// rather than per-block.Inc to keep the eviction loop cheap under the write
// lock; the caller fires this OUTSIDE the critical section.
func IncKvInventoryCapHit(service, ep string, n int) {
	kvInvCapEvictionsTotal.WithLabelValues(service, ep).Add(float64(n))
}

// KvInventoryCapHitValue returns the current cap-eviction counter value for
// (service, ep). Test-only getter — reads the metric via dto.Metric.Write to
// avoid forcing the prometheus/testutil package into the loxinet import graph
// (mirrors SockproxySyncDropValue in sockproxy_sync_metrics.go).
func KvInventoryCapHitValue(service, ep string) float64 {
	c := kvInvCapEvictionsTotal.WithLabelValues(service, ep)
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		return 0
	}
	if m.Counter == nil || m.Counter.Value == nil {
		return 0
	}
	return *m.Counter.Value
}

// IncKvZeroHitWatchdog increments zero-hit watchdog
// counter (loxilb_pd_kv_zero_hit_watchdog_total) for a service. Called from
// pkg/loxinet/ai_kv_subscriber.go kvZeroHitWatchdog on EVERY lookup at-or-past
// the consecutive-zero-hit threshold — the [KV_ZEROHIT] WARN carries the
// transition edge, this counter carries the volume (shape).
// svcID is the rule number (the kvServices registry key), labeled service_id.
// Lazy CounterVec idiom (IncKvInventoryCapHit precedent): the series appears
// on first increment.
func IncKvZeroHitWatchdog(svcID uint32) {
	kvZeroHitWatchdogTotal.WithLabelValues(strconv.FormatUint(uint64(svcID), 10)).Inc()
}

// KvZeroHitWatchdogValue returns the current watchdog counter value for a
// service. Test-only getter — same dto.Metric.Write idiom as
// KvInventoryCapHitValue (keeps prometheus/testutil out of the loxinet import
// graph).
func KvZeroHitWatchdogValue(svcID uint32) float64 {
	c := kvZeroHitWatchdogTotal.WithLabelValues(strconv.FormatUint(uint64(svcID), 10))
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		return 0
	}
	if m.Counter == nil || m.Counter.Value == nil {
		return 0
	}
	return *m.Counter.Value
}
