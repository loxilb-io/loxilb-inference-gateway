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
} proxy_metrics_snapshot_t;

__attribute__((weak))
proxy_metrics_snapshot_t proxy_get_metrics(void) {
    proxy_metrics_snapshot_t m;
    memset(&m, 0, sizeof(m));
    return m;
}
