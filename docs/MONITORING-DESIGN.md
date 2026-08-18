# LoxiLB Inference Gateway — Production Monitoring Design (Prometheus + Grafana)

> Audience: gateway developers (reviewers), then production operators (end users of the
> dashboards). Companion: `MONITORING-CICD.md` (the automated validation that keeps this
> design correct on every change). All metric names below are the current exporter names and
> are verified against `api/prometheus/*.go` by CI (metric-name resolution lint).

---

## 1. Goals and non-goals

**Goals**

- G1 — A production operator can answer, within one screen each: *"Is the gateway healthy right
  now?"*, *"Where is traffic going and is it balanced?"*, *"Why did latency/errors change?"*,
  *"Is an attack or policy drop happening?"* — without knowing loxilb internals.
- G2 — **Correctness over coverage.** Every panel binds only to metrics the exporter verifiably
  emits. No panel may show a constant, a dead series, or a misleading ratio.
- G3 — Alert rules that are actionable (each alert names the dashboard panel that explains it)
  and quiet (no flapping on idle systems).
- G4 — Everything as code in this repo (`deploy/monitoring/`), deployable with one command,
  identically on a lab host and at a production site.
- G5 — Validated end-to-end with real traffic (cicd scenarios + long-lived sessions for
  conntrack-derived metrics); the automated form of that validation runs continuously — see
  `MONITORING-CICD.md`.

**Non-goals (this iteration)**

- Multi-instance / HA-pair federation dashboards (single scrape target first; the design keeps
  an `instance` variable so multi-target is additive, not a rework).
- Alertmanager receiver integration (PagerDuty/Slack). We ship the **rules**; routing is
  site-specific. Validation verifies alerts reach the *firing* state in Prometheus.
- loxilb-ui embedded charts (separate track).
- DPU/DOCA dashboards. `doca_*` / `loxilb_acl_hw_*` exist **only when the DOCA plugin
  attaches**. We add one conditional row, not a dashboard (§4.7).

---

## 2. Architecture

```
┌──────────────────────────── monitoring host ───────────────────────────┐
│                                                                        │
│  ┌────────────────┐  scrape :11111/netlox/v1/metrics ┌──────────────┐  │
│  │ loxilb (docker)│ ◄────────────────────────────────│  prometheus  │  │
│  │                │                                  │  v2.53.x     │  │
│  └────────────────┘                                  └──────┬───────┘  │
│         ▲                                                   │ datasource
│         │ traffic drivers (cicd netns containers)     ┌─────▼───────┐  │
│   tcplb / tcpkali / iperf3 / ai-sse-quota / secfilter │   grafana   │  │
│                                                       │   v11.x     │  │
│                                                       └─────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

- **Stack**: `docker compose` (two containers: `prom/prometheus:v2.53.4`,
  `grafana/grafana:11.x`) on the same host as the loxilb container so scraping does not
  depend on external routing. Prometheus 2.53.4 matches the promtool version the metric
  surface is lint-verified against.
- **Scrape target**: loxilb REST API, `metrics_path: /netlox/v1/metrics`.
  Metrics collection must be enabled first (`POST /netlox/v1/config/metrics`); while disabled
  the endpoint returns **HTTP 503**, which Prometheus records as `up == 0` — this is by design
  and is what the scrape-down alert keys on.
- **Scrape access model.** The `/netlox/v1/metrics` endpoint is a
  **control-plane REST route**, so it can only be secured by control-plane mechanisms — the
  product's supported mTLS is the **data-path / per-LB-rule** feature (`sockproxy_mtls.*`,
  `HAVE_MTLS`) and does **not** apply here. loxilb's REST API applies its app-auth
  (go-swagger `Bearer` security scheme → `BearerAuthAuth`, `api/restapi/handler/auth.go`)
  **in the handler, on every listener**, whenever an auth mode is enabled
  (`--userservice`/`--oauth2`/manual-token); with none enabled the endpoint is open subject
  only to network reach. Two facts follow: (a) mTLS on the API TLS listener is *transport*,
  not authentication — the `Bearer` check still runs on top of it; (b) enabling
  `--userservice` puts `/metrics` behind JWT on **both** `:11111` and `:8091`.
  - **Default / recommended — same-host, network-isolated scrape.** Run Prometheus on the
    loxilb host and scrape `http://127.0.0.1:11111/netlox/v1/metrics`; bind loxilb's plain
    listener to localhost (`--host 127.0.0.1`) or firewall `:11111`. No certs, no auth
    plumbing. This is the shipped default.
  - **If app-auth is enabled** (userservice/oauth2), the scraper must send
    `Authorization: Bearer <token>`. loxilb user JWTs are short-lived (~24 h) and there is no
    long-lived service token today, so this is a **known operational constraint**: rely on
    network isolation for the scrape, or accept token rotation, or add a service-token /
    metrics-exempt feature in a future iteration (out of scope here).
  - **Optional — transport encryption across an untrusted network.** If you must scrape
    across a network, start loxilb with `--tls` and scrape `https://<host>:8091`; this
    encrypts the channel but does **not** authenticate the scraper (auth still follows the
    rule above). The stock go-swagger `--tls-ca`/`RequireAndVerifyClientCert` client-cert
    path is transport hardening, **not** a supported product auth mechanism — do not treat it
    as the security boundary. `deploy/monitoring/certs/gen-certs.sh` is provided as optional
    tooling for this path only.
- **Scrape interval: 10 s.** The loxilb stats sweep runs every 10 s; scraping faster only
  duplicates samples, slower halves the resolution of `loxilb_new_flows` (a per-sweep sampled
  gauge). `scrape_timeout: 5s`.
- **Retention**: 15 d (`--storage.tsdb.retention.time=15d`) — enough for week-over-week trend
  comparison; disk cost at ~110 idle families + traffic labels is negligible (<1 GB).
- **Provisioning as code**: Grafana datasource + dashboard provisioning files and dashboard
  JSONs live in the repo; Grafana is stateless and can be recreated at any time.

### 2.1 Repository layout

```
deploy/monitoring/
├── README.md                       # operator quick start (deploy, certs, enable metrics, URLs)
├── docker-compose.yml
├── .env.example                    # GF_SECURITY_ADMIN_USER/PASSWORD, target host — copy to .env (§9)
├── certs/
│   ├── gen-certs.sh                # self-signed CA + loxilb server cert + prometheus client cert
│   └── .gitignore                  # generated keys/certs never committed
├── prometheus/
│   ├── prometheus.yml              # default: http scrape of 127.0.0.1:11111 (TLS optional, commented)
│   └── rules/
│       └── loxilb-alerts.yml       # alert rules, §5
└── grafana/
    ├── provisioning/
    │   ├── datasources/prometheus.yml
    │   └── dashboards/loxilb.yml   # file provider → /var/lib/grafana/dashboards
    └── dashboards/
        ├── loxilb-overview.json
        ├── loxilb-l4-loadbalancer.json
        ├── loxilb-l7-proxy.json
        ├── loxilb-ai-gateway.json
        └── loxilb-security.json
```

---

## 3. Dashboard design principles (applies to every dashboard)

1. **Five dashboards, fixed order, no more.** Overview is the landing page; the other four are
   drill-downs, linked from Overview panels. An operator should never wonder which dashboard
   to open.
2. **Top row = verdict, not data.** Each dashboard starts with stat tiles (green/amber/red
   thresholds) answering that dashboard's core question; timeseries and tables follow.
3. **Rates, not lifetime totals.** All `_total` counters are displayed with
   `rate(...[$__rate_interval])`. Counters reset on process restart — `rate()` absorbs that;
   raw-counter stat tiles are forbidden except explicitly-labeled "since start" tiles.
4. **Ratios computed in PromQL from raw counters** (the exporter deliberately does not ship
   pre-cooked ratios): affinity hit rate, load-distribution %, 5xx %.
5. **Absence ≠ zero.** Panels over conditional families (`doca_*`, `aictrl_*` before first
   window, per-EP series after decommission) must use "No data" display text, never render
   absent as 0. Conntrack-derived panels get a description noting they reflect
   **established sessions only** (§6.1).
6. **Bounded cardinality in panels.** `sip`-labeled series (client top-talkers) and `cidr`
   ipfilter series appear only in `topk(10, ...)` tables, never as unbounded multi-line
   timeseries.
7. **Every alert has a home.** Each alert rule in §5 maps to exactly one panel; the alert
   annotation carries that dashboard/panel name.
8. Template variables on every dashboard: `$instance` (from `up{job="loxilb"}`), plus
   `$service` (L4), `$model`/`$tenant` (AI) where noted. Default time range 1 h, refresh 10 s.

---

## 4. Dashboard specifications

Legend: **[S]** stat tile · **[TS]** timeseries · **[TB]** table · **[H]** heatmap ·
**[G]** gauge/bar-gauge. Thresholds shown as green / amber / red.

### 4.1 `LoxiLB / Overview` — "Is the gateway healthy right now?"

Row 1 — Verdict tiles:

| Panel | Type | Query | Thresholds |
|---|---|---|---|
| Gateway up | [S] | `up{job="loxilb"}` | 1 green / 0 red (0 also means metrics disabled → 503) |
| Healthy endpoints | [S] | `loxilb_healthy_endpoints` | >0 green / 0 red when `loxilb_lb_rules > 0` |
| Unhealthy endpoints | [S] | `loxilb_unhealthy_endpoints` | 0 green / ≥1 amber / ≥50 % of EPs red |
| LB rules | [S] | `loxilb_lb_rules` | neutral (info) |
| Active sessions (L4) | [S] | `loxilb_active_conntrack_entries` | neutral; description: established sessions only |
| Active connections (L7) | [S] | `loxilb_proxy_active_connections` | neutral |
| Error rate | [S] | `sum(rate(loxilb_errors_total[5m]))` | 0 green / >0 amber |
| 5xx ratio (L7, 5m) | [S] | `sum(rate(loxilb_proxy_http_responses_by_status_total{status_class="5xx"}[5m])) / sum(rate(loxilb_proxy_http_responses_total[5m]))` | <1 % green / ≥1 % amber / ≥5 % red |

Row 2 — Traffic at a glance:

| Panel | Type | Query |
|---|---|---|
| Throughput (bps in/out of DP) | [TS] | `rate(loxilb_processed_bytes_total[$__rate_interval]) * 8` |
| Packets/s by protocol | [TS] | `rate(loxilb_processed_tcp_packets_total[$__rate_interval])`, `..._udp_...`, `..._sctp_...` |
| L4 requests/s (new sessions) | [TS] | `rate(loxilb_requests_total[$__rate_interval])` |
| L7 responses/s by class | [TS] | `sum by (status_class) (rate(loxilb_proxy_http_responses_by_status_total[$__rate_interval]))` |

Row 3 — System & HA:

| Panel | Type | Query | Thresholds |
|---|---|---|---|
| CPU / Memory / Disk | [G] ×3 | `loxilb_system_cpu_utilization_percent`, `..._memory_...`, `..._disk_...` | <70 green / ≥70 amber / ≥90 red |
| HA sync errors/s | [TS] | `rate(loxilb_sockproxy_sync_apply_errors_total[$__rate_interval])` + `..._drop_total`, `..._conflict_total`, `..._overflow_total` | any sustained >0 = amber |
| HA sync push latency p95 | [TS] | `histogram_quantile(0.95, sum by (le) (rate(loxilb_sockproxy_sync_push_latency_seconds_bucket[$__rate_interval])))` | site-tunable |
| Conntrack stat resets/s | [TS] | `rate(loxilb_conntrack_stat_resets_total[$__rate_interval])` | 0 green; >0 sustained amber (counter-baseline churn — see panel description) |

**CPU utilization scope.** `loxilb_system_cpu_utilization_percent` reports the
scope loxilb runs in, not always the machine:

| Deployment | Source | Denominator |
|---|---|---|
| Container | cgroup v2 `cpu.stat`, or v1 `cpuacct.usage` | the cgroup's CPU quota (`cpu.max`, `cpu.cfs_quota_us`), or the affinity-constrained core count when unlimited |
| Bare metal | `/proc/stat` idle/total delta | all cores |

Docker does not namespace `/proc/stat`, so a containerized loxilb reading it
measures the whole host: anything else on the box that saturates the CPUs pins
the gauge at 100 while loxilb itself is idle, and the gauge stops describing the
gateway at all. Containerized deployments therefore read cgroup accounting,
which is scoped to the container.

`loxilb_host_cpu_utilization_percent` is always whole-machine. It exists so a
saturated host stays visible after the primary gauge stops reporting it — the
two disagreeing (host near 100, system near 0) means the pressure is coming from
outside the container, which is a real condition worth alerting on and not a
loxilb problem. On bare metal the two gauges are identical by construction.

### 4.2 `LoxiLB / L4 Load Balancer` — "Where is traffic going, is it balanced?"

Variable: `$service` from `label_values(loxilb_service_requests_total, service)`.

| Panel | Type | Query |
|---|---|---|
| Requests/s per service | [TS] | `sum by (service) (rate(loxilb_service_requests_total{service=~"$service"}[$__rate_interval]))` |
| Errors/s per service | [TS] | `sum by (service) (rate(loxilb_service_errors_total{service=~"$service"}[$__rate_interval]))` |
| Traffic share per service | [TS] (stacked 100 %) | `sum by (service) (rate(loxilb_service_traffic_bytes_total[5m])) / ignoring(service) group_left sum(rate(loxilb_service_traffic_bytes_total[5m]))`. A per-**endpoint** split is intentionally absent: the exporter's `dip` label carries the VIP (forward leg) / client IP (return leg), never the endpoint IP, so a per-endpoint distribution is not derivable from the current metrics; the panel can be added if a future exporter change attributes traffic to endpoint IPs |
| Service throughput | [TS] | `sum by (service) (rate(loxilb_service_traffic_bytes_total{service=~"$service"}[$__rate_interval])) * 8` |
| Active flows by protocol | [TS] | `loxilb_active_flow_count_tcp`, `_udp`, `_sctp` |
| Conntrack entries | [TS] | `loxilb_active_conntrack_entries` (description: established sessions only; short-lived flows may never appear — §6.1) |
| New flows per sweep | [TS] | `loxilb_new_flows` (sampled gauge per 10 s sweep — not an exact counter) |
| Top clients (pkts/s) | [TB] | `topk(10, sum by (service, sip) (rate(loxilb_client_traffic_packets_total[5m])))` |
| Firewall drops/s | [TS] | `rate(loxilb_fw_drop_packets_total[$__rate_interval])` |
| Top dropping FW rules | [TB] | `topk(10, rate(loxilb_fw_rule_drop_packets_total[5m]))` by `fw_rule` |

### 4.3 `LoxiLB / L7 Proxy` — "Why did latency or errors change?"

| Panel | Type | Query | Notes |
|---|---|---|---|
| Active conns / TLS conns | [S]+[TS] | `loxilb_proxy_active_connections`, `loxilb_proxy_active_ssl_connections` | |
| Responses/s by status class | [TS] | `sum by (status_class) (rate(loxilb_proxy_http_responses_by_status_total[$__rate_interval]))` | color-mapped: 2xx green, 4xx amber, 5xx red |
| TTFB p50 / p95 / p99 | [TS] | `histogram_quantile(0.5|0.95|0.99, sum by (le) (rate(loxilb_proxy_http_ttfb_seconds_bucket[$__rate_interval])))` | const-histogram from DP buckets |
| TTFB distribution | [H] | `sum by (le) (increase(loxilb_proxy_http_ttfb_seconds_bucket[$__interval]))` | |
| HTTP/2 sessions created/s | [TS] | `rate(loxilb_proxy_http2_sessions_total[$__rate_interval])` | counter, **not** an active gauge (§6.5) |
| Session-affinity hit rate | [S]+[TS] | `sum(rate(loxilb_proxy_conversation_hits_total[5m])) / (sum(rate(loxilb_proxy_conversation_hits_total[5m])) + sum(rate(loxilb_proxy_conversation_misses_total[5m])))` | computed in PromQL (§3.4) |
| Conversation sessions / TTL expiries | [TS] | `loxilb_proxy_conversation_sessions`; `rate(loxilb_proxy_conversation_ttl_expired_total[$__rate_interval])` | |
| Cache backpressure | [TS] | `loxilb_proxy_cache_backpressure_ratio` + `rate(loxilb_proxy_cache_high_water_events_total[$__rate_interval])` + `rate(loxilb_proxy_cache_drain_partial_total[$__rate_interval])` | sustained backpressure >0.8 amber |
| Chunked / graceful close | [TS] | `rate(loxilb_proxy_chunked_responses_total[$__rate_interval])`, `rate(loxilb_proxy_graceful_close_total[$__rate_interval])` | |

### 4.4 `LoxiLB / AI Gateway` — "Are models serving, who is being throttled?"

Variables: `$model`, `$tenant` from `loxilb_ai_requests_total`.

| Panel | Type | Query | Notes |
|---|---|---|---|
| AI requests/s by model | [TS] | `sum by (model) (rate(loxilb_ai_requests_total{model=~"$model",tenant=~"$tenant"}[$__rate_interval]))` | counter increments at SSE **stream completion** |
| AI requests/s by status | [TS] | `sum by (status) (rate(loxilb_ai_requests_total{...}[$__rate_interval]))` | `status` carries the real backend status |
| AI error ratio (non-2xx) | [S] | `sum(rate(loxilb_ai_requests_total{status!~"2.."}[5m])) / sum(rate(loxilb_ai_requests_total[5m]))` | <1 % green / ≥5 % red |
| Request duration p95 by model | [TS] | `histogram_quantile(0.95, sum by (model, le) (rate(loxilb_ai_request_duration_seconds_bucket{model=~"$model"}[$__rate_interval])))` | buckets reach 300 s (SSE) |
| Duration heatmap | [H] | `sum by (le) (increase(loxilb_ai_request_duration_seconds_bucket[$__interval]))` | |
| Active SSE streams | [S]+[TS] | `loxilb_ai_active_streams` | |
| Rate-limit hits/s | [TS] | `rate(loxilb_ai_rate_limit_hits_total[$__rate_interval])` | denials are **not** in `loxilb_ai_requests_total` |
| Model-not-allowed/s | [TS] | `rate(loxilb_ai_model_not_allowed_total[$__rate_interval])` | |
| PD row: requests, prefill p95, decode TTFT p95 | [TS] | `rate(loxilb_ai_pd_requests_total[...])`; `histogram_quantile(0.95, ... loxilb_ai_pd_prefill_duration_seconds_bucket ...)`; same for `loxilb_ai_pd_decode_ttft_seconds_bucket` | row collapsed by default; only populated on PD-disagg deployments |
| KV routing row: tier-1.5 hit ratio, spills, fallthrough | [TS] | `rate(loxilb_pd_kv_tier15_hits_total[...])` vs `..._spills_total`, `..._fallthrough_total`, `..._miss_reason_total` by reason | collapsed by default |
| KV agent up | [S] | `loxilb_kv_agent_up` | loxilb-side gauge = the correct liveness signal |
| TTFT prediction error p90 | [TS] | `aictrl_ttft_pred_err_ratio_p90` | **absent until first window** — "No data" is normal (§3.5) |

### 4.5 `LoxiLB / Security` — "Is an attack or policy drop happening?"

| Panel | Type | Query |
|---|---|---|
| SYN flood: passed vs blocked/s | [TS] | `rate(loxilb_security_syn_passed_total[$__rate_interval])`, `rate(loxilb_security_syn_blocked_total[...])`, `rate(loxilb_security_syn_cookies_total[...])` |
| Conn-rate limiter: passed vs blocked/s | [TS] | `rate(loxilb_security_conn_passed_total[...])`, `rate(loxilb_security_conn_blocked_total[...])` |
| UDP flood: passed vs blocked (pps + bps) | [TS] | `rate(loxilb_security_udp_passed_total[...])`, `..._udp_blocked_total`, `..._udp_bytes_blocked_total * 8` |
| Unique source IPs | [TS] | `loxilb_security_unique_ips` |
| Blocked ratio (all L4 security) | [S] | `sum(rate(loxilb_security_syn_blocked_total[5m]) + rate(loxilb_security_conn_blocked_total[5m]) + rate(loxilb_security_udp_blocked_total[5m])) / <same sum over passed+blocked>` — 0 green / >0 amber |
| ipfilter: blacklist hits | [TB] | `topk(10, sum by (cidr, zone) (rate(loxilb_ipfilter_blacklist_packets_total[5m])))` |
| ipfilter: whitelist traffic | [TS] | `sum(rate(loxilb_ipfilter_whitelist_packets_total[$__rate_interval]))` |
| Policy inventory | [S] ×4 | `loxilb_firewall_rules`, `loxilb_ipfilter_rules` by `type`, `loxilb_opa_firewall_rules`, `loxilb_lb_rules` |
| OPA health | [TS] | `loxilb_opa_circuit_breaker_state`, `rate(loxilb_opa_watcher_syncs_total[...])`, `histogram_quantile(0.95, ... loxilb_opa_sync_duration_seconds_bucket ...)` |
| FW drops/s (+ per-rule table) | [TS]+[TB] | same queries as §4.2, repeated here for the security workflow |

### 4.6 Cross-dashboard links

- Overview "5xx ratio" → L7 Proxy; "Error rate" → L4; "Unhealthy endpoints" → L4
  endpoint-distribution panel; HA row → (future) HA dashboard placeholder.
- Every drill-down dashboard links back to Overview in the nav.

### 4.7 Conditional DPU row (not a dashboard)

One collapsed row at the bottom of Overview: `doca_offload_active_flows`,
`rate(doca_offload_failures_total[...])`, `doca_ct_pipe_utilization`,
`rate(doca_meter_pool_exhausted_total[...])`. Panels display "N/A (no DPU attached)" when the
series are absent. On non-DPU hosts this row is validated only for correct absent-handling.

---

## 5. Alert rules (`prometheus/rules/loxilb-alerts.yml`)

Severity model: `critical` = page (service impact now), `warning` = ticket/business-hours,
`info` = annotation only, no route. All alerts carry `dashboard` + `panel` annotations (§3.7).

| Alert | Expr (condensed) | For | Sev |
|---|---|---|---|
| `LoxilbScrapeDown` | `up{job="loxilb"} == 0` | 1m | critical — also fires when metrics collection was disabled (503); runbook note says to check `POST /netlox/v1/config/metrics` first |
| `LoxilbNoHealthyEndpoints` | `loxilb_healthy_endpoints == 0 and loxilb_lb_rules > 0` | 1m | critical |
| `LoxilbUnhealthyEndpoints` | `loxilb_unhealthy_endpoints > 0` | 5m | warning |
| `LoxilbHigh5xxRatio` | 5xx/all (§4.1 expr) `> 0.05 and sum(rate(loxilb_proxy_http_responses_total[5m])) > 1` | 5m | critical |
| `LoxilbElevated5xxRatio` | same `> 0.01`, traffic-guarded | 10m | warning |
| `LoxilbL4ErrorBurst` | `sum(rate(loxilb_errors_total[5m])) > 0` | 10m | warning |
| `LoxilbHighTTFB` | p95 TTFB `> 2` (site-tunable) with request-rate guard | 10m | warning |
| `LoxilbAIErrorRatio` | non-2xx AI ratio `> 0.05`, guarded `sum(rate(loxilb_ai_requests_total[5m])) > 0.1` | 5m | critical |
| `LoxilbAIRateLimitSpike` | `rate(loxilb_ai_rate_limit_hits_total[5m]) > 10` (tunable) | 5m | warning |
| `LoxilbCpuHigh` / `MemHigh` / `DiskHigh` | `loxilb_system_*_utilization_percent > 90` | 10m | warning (disk: critical at 95) |
| `LoxilbHaSyncFailing` | `rate(loxilb_sockproxy_sync_apply_errors_total[5m]) > 0` | 5m | critical (HA correctness) |
| `LoxilbKvAgentDown` | `loxilb_kv_agent_up == 0 and max_over_time(loxilb_kv_agent_up[1h]) == 1` | 2m | warning — guarded: the gauge registers 0 even with no KV agent deployed, so only alert if it was recently up |
| `LoxilbSynFloodActive` | `rate(loxilb_security_syn_blocked_total[5m]) > 0` | 2m | info |
| `LoxilbUdpFloodActive` | `rate(loxilb_security_udp_blocked_total[5m]) > 0` | 2m | info |
| `LoxilbFwDropSurge` | `rate(loxilb_fw_drop_packets_total[5m]) > 100` (tunable) | 5m | warning |
| `LoxilbConntrackStatResets` | `rate(loxilb_conntrack_stat_resets_total[10m]) > 0` | 10m | info |
| `LoxilbConntrackNearCapacity` | `loxilb_active_conntrack_entries / loxilb_conntrack_max_entries > 0.8` | 5m | warning (critical at `> 0.95`) |

**Capacity gauge**: `loxilb_conntrack_max_entries` — a constant gauge exporting the datapath
conntrack capacity (`LLB_CT_MAP_ENTRIES` from `loxilb-ebpf/common/llb_dpapi.h`, reachable via
cgo in `pkg/loxinet/dpebpf_linux.go`). It enables the utilization alert above and the capacity
panels next to "Active sessions (L4)" in §4.1/§4.2.

Deliberate omissions: no alert on `loxilb_new_flows` (sampled gauge, noisy); no alerts on
`doca_*` (absent on non-DPU sites → permanent no-data flapping risk).

Rule-file hygiene gates: `promtool check rules` clean; every expr exercised against a live
Prometheus by the CI sweeps (`MONITORING-CICD.md` Tier 1); traffic-rate guards on all ratio
alerts so an idle system can never fire them (0/0).

---

## 6. Correctness notes baked into the design

These are the exporter/datapath facts that shape panel and alert semantics — reviewers should
check each panel spec against them:

1. **Conntrack-derived metrics reflect established sessions.** `loxilb_active_conntrack_entries`,
   `loxilb_requests_total`, `loxilb_processed_*`, per-service/EP/client traffic all come from
   the 10 s conntrack sweep. Sessions shorter than the sweep window may never be sampled;
   an idle-or-short-lived-only workload legitimately shows empty conntrack.
   This is confirmed behavior, not a hypothesis: with held-open sessions every
   conntrack-derived metric tracks reality (100+ `est` entries, gauges/counters following the
   driven load); an empty conntrack under short-lived-only traffic is a sampling artifact,
   not a data-plane bug.
1a. **Per-service metrics require NAMED LB rules**: unnamed rules produce
   empty `servName` in conntrack, so `loxilb_service_*` never appears and `service` labels
   are empty. Operator guidance: always create LB rules with `--name`. Endpoint health
   probing likewise needs an explicit probe (`--probetype=tcp --probeport=...` via the
   endpoint API); `--monitor` alone leaves `ptype none` and endpoint state never changes.
2. **Counters reset on restart** → `rate()`/`increase()` everywhere; no raw-counter tiles.
3. **Absence ≠ zero** for `doca_*`, `aictrl_ttft_pred_err_ratio_*` (lazy registration),
   per-EP gauges after decommission (lifecycle-managed series deletion).
4. **`loxilb_new_flows` is a per-sweep sample**, not a counter — display as-is, never `rate()`.
5. **`loxilb_proxy_http2_sessions_total` is a counter** of sessions created, not an
   active-sessions gauge — only meaningful under `rate()`.
6. **AI request counter increments at stream completion**; rate-limit/model denials live in
   dedicated counters. Panels must not imply `requests_total` covers denials.
7. **`model` label caps at 64 values** (overflow → `"other"`); `status`/`tenant` carry real
   backend/API-key data.
8. **Client-IP (`sip`) and `cidr` labels are unbounded** in principle → table-only, `topk`'d
   (§3.6), and excluded from alert exprs.

---

## 7. Validation test plan — real traffic

The plan below is the full manual walkthrough; its automated equivalents run continuously in
CI (`MONITORING-CICD.md`). It assumes loxilb in a docker container with the cicd traffic
scenarios (netns traffic/endpoint containers driven via `cicd/common.sh`).

### T0 — Stack deployment (no traffic)

Default path (network-isolated plaintext scrape — the shipped model, §2):

1. Copy `deploy/monitoring/` to the host; copy `.env.example`→`.env` (Grafana admin creds).
2. Confirm loxilb's plain listener is reachable to the host only (`--host 127.0.0.1` or
   `:11111` firewalled); `prometheus.yml` target = `127.0.0.1:11111`, `scheme: http`.
3. `docker compose up -d` (host network; no certs needed on this path).
4. Verify 503-handling: with metrics disabled, `up{job="loxilb"} == 0` and `LoxilbScrapeDown`
   reaches *firing* in Prometheus UI (this doubles as the first alert drill).
5. Enable metrics (`POST /netlox/v1/config/metrics`); `up == 1` within one interval.
6. Grafana reachable with the `.env` admin credential (anonymous access off); datasource
   healthy; all 5 dashboards auto-provisioned.

Optional path (transport encryption across a network — §2): start loxilb with `--tls`, point
the target at `:8091` `scheme: https` with `tls_config.ca_file`, and verify the channel is
encrypted. Note this authenticates nothing by itself — if an app-auth mode is on, the scraper
also needs a `Bearer` token (§2). The `--tls-ca` client-cert path is transport hardening
only, not the auth boundary.

**Pass**: all default-path checks; `promtool check rules` clean; scrape duration p99 < 1 s.

### T1 — Idle baseline (correctness gate)

1. No traffic for 15 min. Record `count({__name__=~"loxilb_.*"})` and family count
   (expected ≈108 idle families).
2. Screenshot pass over all dashboards: every panel must show either plausible idle data or
   an intentional "No data" (§3.5) — **zero panels showing constants, errors, or
   `N/A (query error)`**.
3. Confirm no alert is pending/firing on the idle system — validates the 0/0 traffic guards.

**Pass**: family count matches scrape; all-panel screenshot review signed off; alert list empty.

### T2 — Short-lived L4 traffic (`cicd/tcplb`)

Run `tcplb` config + validation. Expect: `loxilb_lb_rules`/`loxilb_healthy_endpoints` reflect
the scenario; L7-independent panels move. **Explicitly record** whether conntrack-derived
panels stay empty (short-lived curl sessions < 10 s sweep) — this is the control group for T3.

### T3 — Long-lived traffic → conntrack metrics (the critical phase)

Conntrack only reports established sessions, so this phase holds sessions open **well past
several 10 s sweeps**:

1. On top of the `tcplb` topology, drive held-open connections:
   - `tcpkali`: endpoint-side `tcpkali -l 8080` servers + client-side
     `tcpkali -c 50 -T 600 -r 100 <VIP>:2020`
     (50 concurrent connections, 10 min, steady message rate) — reuses `cicd/tcpkali` assets
     with a lengthened `-T`.
   - `iperf3` TCP: `iperf3 -c <VIP> -t 600` for a high-throughput long flow
     (reuses `cicd/iperf3lb` topology; switch `-u` off, lengthen `-t`).
2. During the run, verify in order — each step gates the next:
   a. `curl /netlox/v1/config/conntrack/all` → **non-empty**, states `est`.
   b. `loxilb_active_conntrack_entries > 0` and tracks the tcpkali `-c` count (±).
   c. `loxilb_requests_total`, `loxilb_processed_bytes_total`, per-service/EP/client
      counters increase monotonically across ≥6 consecutive sweeps.
   d. Grafana: L4 dashboard per-service traffic-share panel sums to ~100 %; Top-clients
      table shows the client IPs; Overview throughput matches iperf3's reported bitrate
      within ~10 %.
3. Kill one endpoint mid-run → `loxilb_unhealthy_endpoints` rises,
   `LoxilbUnhealthyEndpoints` fires after its `for:`; distribution shifts to surviving EPs;
   restore and watch recovery.
4. **If 2a fails** (conntrack still empty with held-open established sessions), that
   contradicts the established-sessions model in §6.1 and is a release blocker for L4
   dashboards — escalate, don't paper over.

**Pass**: 2a–2d + 3.

### T4 — L7 + AI traffic (`cicd/ai-sse-quota`, `cicd/httpsproxy`)

1. `ai-sse-quota`: SSE streams with `[SSE_DONE]` `latency_ms` → AI dashboard: requests by
   `model="sse-test"`/`status="200"`, duration histogram populated in sub-second buckets,
   active streams gauge >0 during streams, rate-limit panel moves when quota trips (the
   scenario's quota-exceed leg) — verify the `429` path lands in
   `loxilb_ai_rate_limit_hits_total`, not `loxilb_ai_requests_total`.
2. `httpsproxy` (or `e2ehttpsproxy` for TLS-terminating + re-encrypt): L7 dashboard —
   responses by status class, TTFB quantiles plausible (>0, sub-second), active SSL
   connections >0 during the run, affinity hit-rate panel computes without error.

**Pass**: listed panels populated with values cross-checked against scenario logs
(request counts within ±2 of client-side counts; SSE latency matches `latency_ms` markers).

### T5 — Security traffic (`cicd/secfilter`)

Run the `secfilter` scenario. Verify Security dashboard:
syn/conn/udp passed+blocked counters move in the expected legs, blocked-ratio tile goes
amber during the attack leg and back to green, ipfilter blacklist table shows the scenario
CIDRs, `LoxilbSynFloodActive`/`LoxilbUdpFloodActive` reach firing, then resolve.

**Pass**: per-leg metric deltas match scenario assertions; both info alerts fire and resolve.

### T6 — Alert drill matrix

Every `critical`/`warning` rule must be observed **firing and resolving** at least once:

| Alert | Trigger method |
|---|---|
| ScrapeDown | disable metrics via REST (from T0) |
| NoHealthyEndpoints / UnhealthyEndpoints | stop all / one endpoint container (from T3) |
| High5xxRatio | point one EP at a 500-returning backend (reuse ai-sse-quota mock with error mode, or nginx `return 500`) |
| AIErrorRatio | same, via AI path |
| AIRateLimitSpike | ai-sse-quota quota-exceed leg (T4) |
| HighTTFB | mock server with `sleep`-delayed first byte |
| Cpu/Mem/DiskHigh | `stress-ng` on host (or temporarily lower threshold to current value — allowed, but record it) |
| HaSyncFailing | not triggerable on a single node → **verified by expr dry-run only**; noted as residual risk |
| KvAgentDown | stop the kv-agent if a KV-cache setup is up; else expr dry-run |

**Pass**: matrix table filled in with fire+resolve timestamps (or explicit dry-run-only note).

### T7 — Soak (≥ 12 h)

Looped moderate traffic (cron: tcpkali 10-min sessions hourly + periodic ai-sse-quota runs).
Check after soak:

- No counter goes backwards except at deliberate restarts; no scrape gaps
  (`count_over_time(up[12h])` ≈ 12h/10s).
- Series cardinality stable: `prometheus_tsdb_head_series` flat after first hour
  (guards against label leaks, e.g. unbounded `sip`).
- Prometheus/Grafana container RSS stable; TSDB disk growth linear and small.
- Zero panels degraded to errors; dashboards render < 2 s over the 12 h range.

**Pass**: all four.

### Exit criteria (definition of done for the whole track)

- T0–T7 pass (their automated equivalents stay green in CI — `MONITORING-CICD.md`).
- All dashboard JSONs + rules + compose files in `deploy/monitoring/`, provisioned from
  scratch on a clean `docker compose up -d` with zero manual clicks.
- `deploy/monitoring/README.md` operator quick start reviewed.

---

## 8. Risks / mitigations

| Risk | Mitigation |
|---|---|
| Alert thresholds wrong for real production scale (lab ≠ prod traffic) | Tunables isolated at top of rules file with comments; ratios+guards preferred over absolute rates |
| Grafana/Prometheus version drift at customer sites | Versions pinned in compose; dashboards use only core panel types (stat/timeseries/table/heatmap/bar-gauge), schema v39+, no plugins |
| Dashboard JSON review is hard in PRs | Each JSON accompanied by this doc's panel table as the source of truth; reviewers review the table, spot-check the JSON |

---

## 9. Design decisions

1. **Scrape security = the §2 access model.** The metrics route is control-plane, so
   data-path mTLS does not apply; default is a same-host network-isolated plaintext scrape,
   app-auth `Bearer` token when an auth mode is enabled (with the short-lived-token caveat),
   and `--tls` for optional transport encryption only. `gen-certs.sh` is retained solely as
   tooling for the transport-TLS path.
2. **`LoxilbHighTTFB`: global-with-tunable for v1.** 2 s default, tunable at the
   top of the rules file; per-route SLOs deferred.
3. **`loxilb_conntrack_max_entries` gauge is in scope.** Exporter gauge +
   `LoxilbConntrackNearCapacity` alert + capacity panels (§5).
4. **Dashboards stay operator-only.** loxilb-ui and this Grafana stack are and remain
   separate; no shared styling/datasource-UID constraints.
5. **HA-pair testing is post-release.** Single-node validation is sufficient for this
   release; the `$instance` variable keeps multi-node additive.
6. **Grafana admin credentials via env file** (`.env`, git-ignored; `.env.example`
   committed). Anonymous-viewer mode not used.
