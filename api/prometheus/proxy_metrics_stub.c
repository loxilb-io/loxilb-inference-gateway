/*
 * Weak stub for proxy_get_metrics.
 *
 * sockproxy_metrics.go declares `extern proxy_get_metrics(void)` in its CGO
 * preamble.  In the real binary the strong symbol from sockproxy.o satisfies
 * the reference.  During `go test ./api/prometheus/` no object file provides
 * that symbol, so the linker would fail.
 *
 * This weak implementation returns a zeroed snapshot and is automatically
 * overridden by the strong symbol when the full binary is linked.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct proxy_metrics_snapshot {
    uint64_t active_connections;
    uint64_t active_ssl_connections;
    uint64_t cache_backpressure_active;
    uint64_t conversation_sessions;
    uint64_t h2_sessions;

    uint64_t cache_high_water_events;
    uint64_t conversation_hits;
    uint64_t conversation_misses;
    uint64_t h2_total_streams;
    uint64_t chunked_responses;
    uint64_t cache_drain_partial;
    uint64_t peer_eof_graceful;
    uint64_t conversation_ttl_expired;

    uint64_t http_responses_total;
    uint64_t http_status_2xx;
    uint64_t http_status_3xx;
    uint64_t http_status_4xx;
    uint64_t http_status_5xx;

    uint64_t latency_bucket[12];
    uint64_t latency_sum_us;
    uint64_t latency_count;

    uint64_t cache_size_samples[100];
    uint32_t cache_size_sample_count;

    float chwbl_load_imbalance_ratio;

    uint64_t pd_kv_params_overflow;

    /* P/D Production Hardening gauges*/
    uint64_t pd_sessions_active;
    uint64_t pd_trie_nodes;
    uint64_t pd_cb_flips;
    uint64_t pd_fallback_to_normal;

    /* KV Tier 1.5 routing diagnostics (per-guard miss + fallthrough)*/
    uint64_t pd_kv_t15_miss_mode_off;
    uint64_t pd_kv_t15_miss_warmup;
    uint64_t pd_kv_t15_miss_text_empty;
    uint64_t pd_kv_t15_miss_model_empty;
    uint64_t pd_kv_t15_miss_tokenize;
    uint64_t pd_kv_t15_miss_hashes;
    uint64_t pd_kv_t15_miss_no_worker;
    uint64_t pd_kv_t15_miss_excluded;
    uint64_t pd_kv_t15_miss_shallow;
    uint64_t pd_kv_t15_miss_not_ready;
    uint64_t pd_kv_t15_miss_api_mode;
    uint64_t pd_kv_t15_miss_unsupported;
    uint64_t pd_kv_t15_miss_runtime_fault;
    uint64_t pd_kv_t15_fallthrough_total;

    /* Keep in lockstep with loxilb-ebpf/common/sockproxy_metrics.h and the
     * cgo preamble in sockproxy_metrics.go — a size mismatch corrupts the
     * by-value return when the weak stub is linked. */
    uint64_t pd_cb_proactive_heal;
    uint64_t pd_admission_shed;
    uint64_t pd_admission_queued;

    /* Failover observability counters */
    uint64_t pd_prefill_ep_died;
    uint64_t pd_decode_ep_died;
    uint64_t pd_decode_zero_byte_eof;
    uint64_t pd_connect_failover;
    uint64_t lb_select_failure_shutdown;

    /* SGLang P/D dual-dispatch counters (tail-append, three-way lockstep) */
    uint64_t pd_sg_prefill_abort_decode;
    uint64_t pd_sg_decode_close_drain;
    uint64_t pd_sg_room_retry;
    uint64_t pd_sg_prefill_reject_relay;
    uint64_t pd_sg_oversize_reject;

    /* TRT-LLM sequential-dialect counters (tail-append, three-way lockstep) */
    uint64_t pd_trt_ctx_early_exit;

    /* Relay-cache footprint gauges. The backpressure watermark is per
     * connection (PROXY_CACHE_HIGH_WATER), so nothing reports what the
     * process is holding in aggregate; these do. TAIL-APPEND ONLY — same
     * three-way lockstep contract as the blocks above. */
    uint64_t cache_bytes_total;
    uint64_t cache_bytes_max_conn;
    uint64_t cache_conns_queued;

    /* Same-EP reconnect counters. TAIL-APPEND ONLY — twin-declared in
     * loxilb-ebpf/common/sockproxy_metrics.h and the cgo preamble of
     * sockproxy_metrics.go; keep ALL THREE in lockstep, same commit. */
    uint64_t pd_connect_retry_same_ep;
    uint64_t pd_connect_retry_same_ep_ok;

    /* Bounded-admission overflow shed. TAIL-APPEND ONLY — twin-declared in
     * loxilb-ebpf/common/sockproxy_metrics.h and the cgo preamble of
     * sockproxy_metrics.go; keep ALL THREE in lockstep, same commit. */
    uint64_t pd_admission_overflow_shed;
    uint64_t hdr_deadline_drops;
    uint64_t proxy_context_inflight;
    uint64_t proxy_accept_blocked;
    uint64_t proxy_accept_bound;

    /* Half-close observation. TAIL-APPEND ONLY — twin-declared in
     * loxilb-ebpf/common/sockproxy_metrics.h and the cgo preamble of
     * sockproxy_metrics.go; keep ALL THREE in lockstep, same commit. */
    uint64_t hc_fin_gap_bucket[4][3][15];
    uint64_t hc_fin_gap_sum_us[4][3];
    uint64_t hc_fin_gap_count[4][3];
    uint64_t hc_fin_total[7][6];
    uint64_t hc_accel_early_fin;
    uint64_t hc_tls_fin[3][2];
    uint64_t hc_client_reset;
    uint64_t hc_user_agent[13];
    uint64_t hc_first_gap_bucket[3][15];
    uint64_t hc_first_gap_sum_us[3];
    uint64_t hc_first_gap_count[3];
    uint64_t hc_max_gap_bucket[3][15];
    uint64_t hc_max_gap_sum_us[3];
    uint64_t hc_max_gap_count[3];

    /* Half-close holds. TAIL-APPEND ONLY — same three-way lockstep. */
    uint64_t hold_held;
    uint64_t hold_oldest_ms;
    uint64_t hold_allowed;
    uint64_t hold_cap_sec;
    uint64_t hold_begun;
    uint64_t hold_ended[7];
    uint64_t hold_expired[2][3];
    uint64_t hold_refused_residue;
    uint64_t hold_reentry;
    uint64_t hold_empty_out;
    uint64_t hold_accel_skipped;
    uint64_t hold_default_mode;

    /* Tier-1.5 routing cost and match depth. TAIL-APPEND ONLY — same three-way lockstep. */
    uint64_t kv_stage_bucket[4][2][12];
    uint64_t kv_stage_sum_us[4][2];
    uint64_t kv_stage_count[4][2];
    uint64_t kv_blocks_bucket[2][12];
    uint64_t kv_blocks_sum[2];
    uint64_t kv_blocks_count[2];

    /* Streams that ended before their terminator. TAIL-APPEND ONLY — same three-way lockstep. */
    uint64_t stream_abandon_total[3];
    uint64_t stream_abandon_age_bucket[3][12];
    uint64_t stream_abandon_age_sum_s[3];
    uint64_t stream_abandon_age_count[3];
    uint64_t stream_stall_abort_sec;

    /* Pools allocated and not yet freed, and pools freed (sockproxy_pool.h). TAIL-APPEND ONLY — same three-way lockstep. */
    uint64_t pools_live;
    uint64_t pools_freed_total;

    /* P/D request-lifetime occupancy. Append-only: keep all three ABI mirrors aligned. */
    uint64_t pd_prefill_inflight;
    uint64_t pd_decode_inflight;
    uint64_t pd_parked_connections;
} proxy_metrics_snapshot_t;

__attribute__((weak))
proxy_metrics_snapshot_t proxy_get_metrics(void) {
    proxy_metrics_snapshot_t m;
    memset(&m, 0, sizeof(m));
    return m;
}

/*
 * Weak stub for proxy_get_qos_stats (Tier-1 byte shaper per-service state).
 *
 * Same contract as proxy_get_metrics above: qos_shaper_metrics.go declares the
 * extern, the strong symbol in sockproxy_http.o satisfies it in the real
 * binary, and this zero-service stub keeps `go test ./api/prometheus/`
 * linkable. The struct below is the third copy of the lockstep triple
 * (sockproxy_metrics.h is canonical; qos_shaper_metrics.go carries the second)
 * and must be updated in the same commit as the other two.
 */
typedef struct proxy_qos_svc_stat {
    uint32_t xip;
    uint16_t xport;
    uint8_t  protocol;
    uint8_t  dir;
    uint64_t cir_bps;
    uint32_t cbs_bytes;
    uint32_t n_parked[2];
    uint32_t pad;
    uint64_t bytes_pass[2];
    uint64_t bytes_delayed[2];
    uint64_t parks[2];
    uint64_t park_ns[2];
    int64_t  tokens[2];
} proxy_qos_svc_stat_t;

__attribute__((weak))
int proxy_get_qos_stats(proxy_qos_svc_stat_t *out, int max) {
    (void)out;
    (void)max;
    return 0;
}

/*
 * Weak stubs for proxy_get_fc_stats / proxy_get_fc_anomaly (AI admission gate
 * per-pool state).
 *
 * Same contract as the two above: ai_admission_metrics.go declares the
 * externs, the strong symbols in sockproxy_http.o satisfy them in the real
 * binary, and these zero stubs keep `go test ./api/prometheus/` linkable.
 * The struct below is the third copy of the lockstep triple
 * (sockproxy_metrics.h is canonical; ai_admission_metrics.go carries the
 * second) and must be updated in the same commit as the other two.
 */
#define PROXY_FC_ROLES 3
#define PROXY_FC_REASONS 13
#define PROXY_FC_POOL_LEN 64
#define PROXY_FC_QWAIT_BUCKETS 8
#define PROXY_FC_LIMITS 8
#define PROXY_FC_ADAPT_LIMITS 3

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
} proxy_fc_svc_stat_t;
/* Pinned to the layout in sockproxy_metrics.h. */
_Static_assert(sizeof(proxy_fc_svc_stat_t) == 376, "proxy_fc_svc_stat_t size");
_Static_assert(offsetof(proxy_fc_svc_stat_t, decisions) == 40, "decisions offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, pool) == 144, "pool offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, queued) == 208, "queued offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, qwait_bucket) == 224, "qwait_bucket offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, qwait_count) == 296, "qwait_count offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, telemetry_stale_ms) == 304, "telemetry_stale_ms offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, src) == 308, "src offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, effective_max_outstanding) == 320, "effective_max_outstanding offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, adaptive) == 332, "adaptive offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, warming_eps) == 338, "warming_eps offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, adapt_down) == 344, "adapt_down offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, tenants_active) == 360, "tenants_active offset");
_Static_assert(offsetof(proxy_fc_svc_stat_t, tenant_slots) == 368, "tenant_slots offset");

__attribute__((weak))
int proxy_get_fc_stats(proxy_fc_svc_stat_t *out, int max) {
    (void)out;
    (void)max;
    return 0;
}

__attribute__((weak))
uint64_t proxy_get_fc_anomaly(int kind) {
    (void)kind;
    return 0;
}
