# KV-Cache Observability Design - Prometheus Metrics Export + Grafana Dashboard

> **Audience:** Infrastructure operators, DevOps engineers, and platform SREs.
> **Scope:** Three high-priority missing Prometheus metric exports (M1-M3) and the Grafana
> observability dashboard for KV-cache-aware AI routing (Tier 0 through Tier 2 + admission + KV
> subscriber + AI controller).
> **Status:** Design - implementation pending. Targets the current tree.
>
> Related: [KV-exact routing deep dive](08-kv-cache-aware-routing.md),
> [P/D deploy & debug](09-kv-cache-aware-routing-aws-pd-deep-dive.md),
> [Hierarchical routing architecture](10-hierarchical-kv-routing-architecture.md),
> [Configuration & tuning](11-hierarchical-kv-routing-config-tuning.md).

---

## 1. Problem Statement

The KV-cache-aware routing system (Tier 1.5) exports 30+ Prometheus metrics, but three critical
signals remain trapped in C-side atomics without a Prometheus bridge. This creates operator blind spots:

1. **How many P/D requests are in-flight right now?** - `pd_admission_total_inflight` gauge missing.
2. **How many requests did the global valve block?** - `pd_admission_total_blocked` counter missing.
3. **Which Tier-1.5 stage is the bottleneck?** - 4x2x12 `kv_stage_*` histograms never exported.

Additionally, there is no Grafana dashboard. Operators must `curl /metrics | grep` to diagnose KV
routing issues - an unsustainable workflow for production fleets.

**Design objectives:**
- Close the three missing metric exports with zero behavioral change.
- Design a Grafana dashboard that gives operators actionability in under 30 seconds.
- Follow the existing twin-struct lockstep pattern (precedent).
- No changes to hot paths. No new CGO crossings. Pure export plumbing.

---

## 2. Prometheus Metric Export Design (M1-M3)

### 2.1. Export Architecture - Twin-Struct Lockstep

The C-to-Go metric bridge uses a single flat struct (`proxy_metrics_snapshot_t`) copied every 10
seconds. The pattern (established):

```
C data plane                                    Go control plane
+------------------------+                      +---------------------------+
| proxy_get_metrics()    | | CGO struct mirror         |
|   atomic_load stats    |---- snapshot ------> | (import "C" block)        |
|   tail-append new      |                      +------------+--------------+
+------------------------+                           |
                                                     | promauto metrics
                                                   +---v-------------------+
                                                   | NewGauge/NewCounter   |
                                                   | NewHistogramVec       |
                                                   +------------+----------+
                                                                |
                                                  RunSockproxyMetrics (10s)
                                                  .Set() / delta .Add()
```

**Rules:**
- C side: tail-append only - never reorder, never change field types.
- Go CGO mirror: identical field order, identical types.
- Prometheus registration: `promauto` (auto-registers at init).
- Counters: monotonic delta with overflow guard (`if current >= prev`).
- Gauges: direct `.Set()` from point-in-time value.

---

### 2.2. M1 - Global P/D In-Flight Footprint (Gauge)

**Metric:** `loxilb_pd_admission_inflight`

**Type:** Gauge

**Help:** "P/D requests currently held in-flight across all connections and endpoints. Gauge - rises and falls. Corresponds to the C-side pd_admission_total_inflight atomic."

**Rationale:** Operators need the real-time load carried by loxilb for P/D workloads. This is the input for capacity planning and admission cap tuning. Unlike per-EP counters (shed/queued), this is a global view.

**Source:** `global_stats.pd_admission_total_inflight` (`_Atomic uint64_t` in `sockproxy.h:133`)

**File changes:**

| File | Change |
|------|--------|
| `loxilb-ebpf/common/sockproxy_metrics.h` | Tail-append `uint64_t pd_admission_total_inflight;` to `proxy_metrics_snapshot_t` |
| `loxilb-ebpf/common/sockproxy_metrics.c` | In `proxy_get_metrics()`: set `snapshot.pd_admission_total_inflight = atomic_load(&global_stats.pd_admission_total_inflight);` |
| `api/prometheus/sockproxy_metrics.go` (CGO) | Mirror `uint64_t pd_admission_total_inflight;` in C struct preamble |
| `api/prometheus/sockproxy_metrics.go` (promauto) | `promauto.NewGauge{Name: "loxilb_pd_admission_inflight", ...}` |
| `api/prometheus/sockproxy_metrics.go` (loop) | `.Set(float64(current.pd_admission_total_inflight))` - gauge, no delta |

---

### 2.3. M2 - Global P/D Admission Blocked Counter (Counter)

**Metric:** `loxilb_pd_admission_total_blocked_total`

**Type:** Counter

**Help:** "Total accept()s blocked by the global P/D total-inflight cap (LLB_PD_MAX_TOTAL_INFLIGHT). SYN left in listen backlog, never accepted into loxilb. Distinct from per-EP admission shed (which is after accept, before dispatch)."

**Rationale:** When the global cap is hit, the request never enters loxilb - rejected at the socket accept level. This is an early-warning signal for over-subscription. Operators need it to size `LLB_PD_MAX_TOTAL_INFLIGHT`.

**Source:** `global_stats.pd_admission_total_blocked` (`_Atomic uint64_t` in `sockproxy.h:134`)

**File changes:**

| File | Change |
|------|--------|
| `loxilb-ebpf/common/sockproxy_metrics.h` | Tail-append `uint64_t pd_admission_total_blocked;` |
| `loxilb-ebpf/common/sockproxy_metrics.c` | `snapshot.pd_admission_total_blocked = atomic_load(&global_stats.pd_admission_total_blocked);` |
| `api/prometheus/sockproxy_metrics.go` (CGO) | Mirror `uint64_t pd_admission_total_blocked;` in C struct |
| `api/prometheus/sockproxy_metrics.go` (promauto) | `promauto.NewCounter{Name: "loxilb_pd_admission_total_blocked_total", ...}` |
| `api/prometheus/sockproxy_metrics.go` (loop) | Standard monotonic delta: `if current >= prev { counter.Add(delta) }` |

---

### 2.4. M3 - Per-Stage Tier-1.5 Hot-Path Latency Histogram (HistogramVec)

**Metric:** `loxilb_pd_kv_stage_duration_seconds`

**Type:** HistogramVec

**Labels:** `stage` (tokenize | hash | cgo | scan), `outcome` (hit | miss)

**Buckets:** `{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}` seconds - mirrors TTFB histogram and C-side `latency_bucket_bounds_us[]`

**Help:** "Per-stage microsecond latency of Tier-1.5 KV-exact routing hot path, split by outcome. Stages: tokenize (HF tokenizer via CGO), hash (CBOR + chained block hash), cgo (best_worker CGO crossing), scan (inventory scan). Outcomes: hit (Tier-1.5 won), miss (fell through to Tier 2)."

**Rationale:** This is THE diagnostic metric for "why is KV routing slow?" Without it, operators see a slow request but cannot tell whether tokenization, hashing, CGO crossing, or the scan is the bottleneck. The hit/miss split reveals whether the cost is worth the TTFT savings.

**Source:** Three 3D/2D atomics in `sockproxy.h:155-157`:
- `kv_stage_buckets[4][2][12]` - cumulative per-bucket counts
- `kv_stage_sum_us[4][2]` - cumulative us sums
- `kv_stage_count[4][2]` - cumulative sample counts

**Enum mapping** (`sockproxy_kv_exact.h`):
```
Stage 0: tokenize     Stage 1: hash     Stage 2: cgo     Stage 3: scan
Outcome 0: miss       Outcome 1: hit
```

**File changes:**

| File | Change |
|------|--------|
| `loxilb-ebpf/common/sockproxy_metrics.h` | Tail-append three arrays: `kv_stage_buckets[4][2][12]`, `kv_stage_sum_us[4][2]`, `kv_stage_count[4][2]` |
| `loxilb-ebpf/common/sockproxy_metrics.c` | Nested loop in `proxy_get_metrics()`: 3D atomic_load + copy, plus 2D copies of sum_us and count |
| `api/prometheus/sockproxy_metrics.go` (CGO) | Mirror 3 arrays in CGO C struct |
| `api/prometheus/sockproxy_metrics.go` (promauto) | `promauto.NewHistogramVec{loxilb_pd_kv_stage_duration_seconds, []string{"stage", "outcome"}, Buckets: ...}` |
| `api/prometheus/sockproxy_metrics.go` (helpers) | Stage names: `[]string{"tokenize", "hash", "cgo", "scan"}` |
| `api/prometheus/sockproxy_metrics.go` (loop) | Per (stage, outcome): monotonic delta on count, then reconstruct from cumulative bucket deltas |

#### 2.4.1. Histogram Reconstruction - Shared Helper

The TTFB histogram and the eight KV stage histograms share identical reconstruction logic:
cumulative C-side buckets to per-range counts to `.Observe(boundary)`. To avoid duplication,
the TTFB reconstruction (currently inline in `RunSockproxyMetrics`) will be **extracted into a shared helper**:

```go
func observeHistogramFromCumulativeBuckets(
    hist         prometheus.Histogram,
    currentBuckets [12]uint64,
    prevBuckets    [12]uint64,
    currentCount   uint64,
    prevCount      uint64,
    bucketBounds   [12]float64,
    overflowBound  float64,
)
```

Both TTFB and KV section call this helper. TTFB section is minor refactoring; KV section is new.

**Important - unit conversion:** C-side atomics accumulate in **microseconds** (`kv_stage_sum_us`). The Go helper must divide observed values by 1,000,000 to produce seconds for Prometheus. The bucket bounds array (`0.001`, `0.005`, ...) is already in seconds and used directly as the `bucketBounds` parameter.

**Snapshot size impact:** 896 bytes (96×8 buckets + 8×8 sum_us + 8×8 count). Struct is ~5KB today;
at 6KB copied once per 10 seconds - negligible.

---

### 2.5. Testing Strategy

**Registration smoke test** (pattern: `TestKvTier15MissCountersRegistered`):

| Metric | Verification |
|--------|-------------|
| `loxilb_pd_admission_inflight` | Present in `prometheus.DefaultGatherer.Gather()` |
| `loxilb_pd_admission_total_blocked_total` | Present in gatherer output |
| `loxilb_pd_kv_stage_duration_seconds` | Both `_count` and `_sum` child series present |

**Build gates:**
- `make build` (Go + C + eBPF)
- `make lint` (golangci-lint all rules)

**CI/CD gate** (if applicable):
- Run `SCENARIO-ai-gateway-pd-routing` with metrics scrape
- Verify new series appear in `/metrics` output

---

## 3. Grafana Dashboard Design

### 3.1. Dashboard Overview

**Dashboard title:** "LoxiLB AI Gateway - KV-Cache Routing"

**UID:** `loxilb-ai-kv-routing`

**Target users:** Infra operators, SREs, platform engineers on call for AI inference clusters.

**Refresh:** 10 seconds (matches Prometheus scrape interval).

**Data source:** Prometheus (named `$datasource`, defaults to `Prometheus`).

**Template variables:**

| Variable | Type | Values | Purpose |
|----------|------|--------|---------|
| `datasource` | datasource | Prometheus | Override Prometheus server |
| `model` | query | `query_result(loxilb_ai_requests_total)` extract model label | Filter by model |
| `service` | query | `query_result(loxilb_pd_ep_info)` extract service label | Filter per-service |
| `endpoint` | query | `query_result(loxilb_kv_subscriber_connected)` extract ep label | Drill into specific EP |

---

### 3.2. Dashboard Philosophy

**V1 ships 12 panels across 3 rows.** That is the entire visible dashboard. Operators open Grafana during a page - they get one minute, not 20 panels.

Panels that are valuable but diagnostic (miss reasons, controller alpha, stage latency, eviction rate, trie nodes) are documented here in **V2** but deliberately excluded from the initial release. V2 adds only when operators ask "can you also show me X?" - that's faster than designing 25 panels upfront and shipping a dashboard nobody reads.

**V1 rule:** Every panel either answers "is something wrong?" or "where is the problem?" - nothing exists for curiosity alone.

---

### 3.3. V1 - Production Dashboard (12 panels, 3 rows)

#### Row 1: Fleet Health (6 panels)

*Question: "Is the system alive and under capacity?"*

| Panel | Type | Query | Alert |
|-------|------|-------|-------|
| **RPS** | Stat | `sum(rate(loxilb_ai_requests_total[1m]))` | - |
| **In-Flight** | Stat | `loxilb_pd_admission_inflight` (M1 - new) | Warning: > `cap_value * 0.8` (set in panel threshold) |
| **Active Streams** | Stat | `sum(loxilb_ai_active_streams)` | - |
| **KV Hit Rate** | Stat | `rate(loxilb_pd_kv_tier15_hits_total[5m]) / (rate(loxilb_pd_kv_tier15_hits_total[5m]) + rate(loxilb_pd_kv_tier15_fallthrough_total[5m])) * 100` | - |
| **KV Sub Uptime** | Stat | `avg(loxilb_kv_subscriber_connected) * 100` % | Critical: < 100% |
| **HTTP 5xx %** | Stat | `rate(loxilb_http_status_5xx_total[1m]) / rate(loxilb_http_responses_total[1m]) * 100` | Critical: > 1% |

#### Row 2: Latency (3 panels)

*Question: "Where is latency coming from?"*

| Panel | Type | Query |
|-------|------|-------|
| **Prefill p95** | Time series | `histogram_quantile(0.95, rate(loxilb_ai_pd_prefill_duration_seconds_bucket[5m]))` - p50/p95/p99 lines |
| **Decode TTFT p95** | Time series | `histogram_quantile(0.95, rate(loxilb_ai_pd_decode_ttft_seconds_bucket[5m]))` - p50/p95/p99 lines |
| **Per-EP Prefill** | Time series | `histogram_quantile(0.95, rate(loxilb_ai_pd_prefill_duration_per_ep_seconds_bucket[5m]))` per endpoint |

#### Row 3: Rejection and Pressure (3 panels)

*Question: "Is the system rejecting requests?"*

| Panel | Type | Query |
|-------|------|-------|
| **Blocked (Global)** | Stat | `rate(loxilb_pd_admission_total_blocked_total[5m])` (M2 - new) |
| **CB Flips** | Stat | `rate(loxilb_pd_cb_flips_total[5m])` |
| **Subscriber State** | Table | `loxilb_kv_subscriber_connected` per EP - 1=green, 0=red |

---

### 3.4. V2 - Deferred Panels (add when operators ask)

These panels are fully specified, queries are ready. Add them as collapsible rows when real operators request them.

#### KV Cache Inventory (3 panels)

*Trigger: "Which EP has the most cache? Is eviction happening?"*

| Panel | Type | Query |
|-------|------|-------|
| **Blocks per EP** | Bars | `loxilb_pd_kv_blocks` grouped by ep |
| **Eviction Rate** | Stat | `sum(rate(loxilb_kv_inv_cap_evictions_total[5m]))` |
| **Trie Nodes** | Stat | `loxilb_pd_trie_nodes` |

#### Tier-1.5 Diagnostics (3 panels)

*Trigger: "Why is our hit rate low? What are we missing on?"*

| Panel | Type | Query |
|-------|------|-------|
| **Miss Reasons** | Pie chart | `sum by (reason) (rate(loxilb_pd_kv_tier15_miss_reason_total[1m]))` top 5 |
| **Hits vs Fallback** | Time series (stacked) | `sum(rate(loxilb_pd_kv_tier15_hits_total[1m]))` vs `rate(loxilb_pd_kv_tier15_fallthrough_total[1m])` |
| **Spills (C4)** | Time series | `rate(loxilb_pd_kv_tier15_spills_total[1m])` |

#### KV Stage Latency - M3 Diagnostic (3 panels, collapsible, hidden by default)

*Trigger: "KV routing seems slow - which stage is the bottleneck?"*

| Panel | Type | Query |
|-------|------|-------|
| **Stage Latency p50/p95/p99** | Time series | 3 lines: p50, p95, p99 of `histogram_quantile(X, rate(loxilb_pd_kv_stage_duration_seconds_bucket{stage=~"$stage", outcome=~"$outcome"}[1m]))` |
| **Stage Throughput** | Stacked bar | `sum by (stage) (rate(loxilb_pd_kv_stage_duration_seconds_count[1m]))` |
| **Hit vs Miss p50** | Time series | `histogram_quantile(0.5, rate(loxilb_pd_kv_stage_duration_seconds_bucket{outcome="hit"}[1m]))` and `histogram_quantile(0.5, rate(loxilb_pd_kv_stage_duration_seconds_bucket{outcome="miss"}[1m]))` |

#### Admission Detail (2 panels)

*Trigger: "Are EPs shedding or parking requests?"*

| Panel | Type | Query |
|-------|------|-------|
| **Per-EP Shed vs Parked** | Time series (stacked) | `rate(loxilb_pd_admission_shed_total[1m])` vs `rate(loxilb_pd_admission_queued_total[1m])` |
| **Reconnect Rate** | Time series | `rate(loxilb_kv_subscriber_reconnect_total[5m])` |

#### AI Controller State (2 panels)

*Trigger: "What is the AI controller doing?" (rare - only if you use Smart mode)*

| Panel | Type | Query |
|-------|------|-------|
| **Alpha Decay** | Time series | `loxilb_pd_ctrl_alpha` (1.0 = Smart, 0.0 = Autonomous) |
| **Ctrl Mode** | Stat | `loxilb_pd_ctrl_mode` -> 0=Autonomous, 1=Stale, 2=Smart |

---

### 3.5. Alerts (V1 - ship with dashboard)

| Alert | Condition | Severity | Cooldown |
|-------|-----------|----------|----------|
| **KV Sub Disconnect** | `loxilb_kv_subscriber_connected == 0` for > 2m | Critical | 5min |
| **Admission Saturated** | `loxilb_pd_admission_inflight > 800` for > 1m (adjust to `LLB_PD_MAX_TOTAL_INFLIGHT * 0.8`) | Warning | 5min |
| **Global Valve Blocking** | `rate(loxilb_pd_admission_total_blocked_total[1m]) > 10` | Critical | 10min |
| **CB Flapping** | `rate(loxilb_pd_cb_flips_total[5m]) > 2` | Warning | 10min |

### 3.6. Alerts (V2 - add as needed)

| Alert | Condition | Severity | Cooldown |
|-------|-----------|----------|----------|
| **KV Inventory Eviction** | `rate(loxilb_kv_inv_cap_evictions_total[5m]) > 0` | Warning | 15min |
| **Tier-1.5 Hit Rate Low** | Hit rate < 10% for > 10m while `kvExactMode=1` | Warning | 15min |
| **Controller Stale** | `loxilb_pd_ctrl_mode == 1` for > 5m | Warning | 10min |

---

## 4. Metric Inventory Summary (Post-Implementation)

### Before this work

| Category | Count |
|----------|-------|
| AI Gateway (`ai_metrics.go`) | 14 |
| Sockproxy P/D (`sockproxy_metrics.go`) | 22 |
| KV Subscriber | 4 |
| KV Agent | 1 |
| AI Controller (`aictrl_metrics.go`) | 8 |
| **Total** | **~49** |

### After M1+M2+M3

| Metric | Type | Added By |
|--------|------|----------|
| `loxilb_pd_admission_inflight` | Gauge | M1 |
| `loxilb_pd_admission_total_blocked_total` | Counter | M2 |
| `loxilb_pd_kv_stage_duration_seconds` | HistogramVec (labels: stage, outcome) | M3 |
| **New** | **+3** | |

### Medium-Priority Gaps (documented, deferred)

| Gap | Why MEDIUM |
|-----|-----------|
| LMCache locality metrics (hit/match rates) | No C-side atomic exists yet; requires upstream LMCache integration |
| KV block utilization % gauge | Requires knowing per-EP block capacity; not currently tracked as atomic |

---

## 5. Implementation Order

### Metrics (ship together)
1. **M1 + M2** (admission gauge + counter) - small diff, same C section, same Go block
2. **M3** (KV stage histogram) - larger diff, 3D arrays, requires TTFB helper extraction
3. **Registration tests** - verify all 3 new metrics appear in `DefaultGatherer.Gather()`

### Dashboard (phased)
4. **V1 dashboard** (12 panels, 3 rows, 4 alerts) - ship with metrics. Fleet health, latency, and rejection/pressure only.
5. **V2 panels** - trigger based on operator feedback. Add V2 rows when someone asks "can you also show me..." - faster than designing upfront.

### V1 Dashboard Summary (12 panels, 3 rows)

Mirrors Section 3.3 layout:

| Row | Panels |
|-----|--------|
| **Fleet Health** (6) | RPS, In-Flight (M1), Active Streams, KV Hit Rate, KV Sub Uptime, HTTP 5xx% |
| **Latency** (3) | Prefill p95, Decode TTFT p95, Per-EP Prefill |
| **Rejection and Pressure** (3) | Blocked at Global (M2), CB Flips, Subscriber State |

**V2 deferred (13 panels):** Miss reasons, Spills, Per-EP shed/parked, Eviction rate, Trie nodes, Reconnect rate, Alpha decay, Ctrl mode, Stage latency heatmap, Stage throughput, Hit vs miss cost

---

## 6. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| C ABI break if struct fields reordered | Tail-append only - never insert in middle of existing struct |
| Snapshot too large for 10-second copy | ~6KB total at completion; memcpy is ~125us on modern CPU |
| Histogram reconstruction performance | Same algorithm as existing TTFB path; verified working at production scale |
| Dashboard breaks on metric rename | `$datasource` template variables; query metric names match Prometheus exactly |
| M3 histogram adds 896 bytes to snapshot | Acceptable; struct is ~5KB, copies once per 10s (0.14 KB/s bandwidth) |
| Histogram helper extraction breaks TTFB | TTFB is minor refactoring; existing inline logic is preserved in a single helper |

---

## 7. Dependencies and Prerequisites

- KV-cache-aware routing must be enabled (P/D mode: `mode: 4`, `pd_disagg_mode: true`)
- Prometheus must be scraping `/metrics` endpoint at regular intervals (recommended: 10s)
- Grafana requires Prometheus datasource configured
- C atomics `pd_admission_total_inflight`, `pd_admission_total_blocked` must be actively mutated by C code
- `record_kv_stage()` calls must be active in `sockproxy_metrics.c` to populate stage histograms

---

## 8. Rollback Plan

If any metric export causes unexpected behavior:
- C side: the tail-appended fields are zero-initialized until `proxy_get_metrics()` populates them - no behavioral impact on existing metrics
- Go side: each promauto registration is independent - comment out the specific registration to disable a metric
- Dashboard: remove the Grafana dashboard JSON without affecting any data plane or control plane code