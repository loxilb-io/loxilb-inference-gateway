# LoxiLB Inference Gateway — Production Monitoring Design (Prometheus + Grafana)

> Status: **REVIEWED — decisions locked** (2026-07-18, §9). Ready for implementation.
> Audience: gateway team (reviewers), then production operators (end users of the dashboards).
> Companion docs: `METRICS-AUDIT-PLAN.md`, `METRICS-AUDIT-EXECUTION.md`, `METRICS-MIGRATION-UI.md`.
> All metric names below are the **post-overhaul names** (2026-07-18 audit) and were
> verified against `api/prometheus/*.go` on branch `inference-gateway-port`.

---

## 1. Goals and non-goals

**Goals**

- G1 — A production operator can answer, within one screen each: *"Is the gateway healthy right
  now?"*, *"Where is traffic going and is it balanced?"*, *"Why did latency/errors change?"*,
  *"Is an attack or policy drop happening?"* — without knowing loxilb internals.
- G2 — **Correctness over coverage.** Every panel binds only to metrics proven live in the
  2026-07 audit. No panel may show a constant, a dead series, or a misleading ratio.
- G3 — Alert rules that are actionable (each alert names the dashboard panel that explains it)
  and quiet (no flapping on idle systems).
- G4 — Everything as code in this repo (`deploy/monitoring/`), deployable with one command,
  identically on the kv-loxilb testbed and at a customer site.
- G5 — Validated end-to-end on the **kv-loxilb testbed with real traffic** (cicd scenarios +
  long-lived sessions for conntrack-derived metrics) before we call it done.

**Non-goals (this iteration)**

- Multi-instance / HA-pair federation dashboards (single scrape target first; the design keeps
  an `instance` variable so multi-target is additive, not a rework).
- Alertmanager receiver integration (PagerDuty/Slack). We ship the **rules**; routing is
  site-specific. On the testbed we verify alerts reach the *firing* state in Prometheus UI.
- loxilb-ui embedded charts (separate track; see `METRICS-MIGRATION-UI.md`).
- DPU/DOCA dashboards. `doca_*` / `loxilb_acl_hw_*` exist **only when the DOCA plugin
  attaches**; the testbed has no DPU. We add one conditional row, not a dashboard (§4.7).

---

## 2. Architecture

```
┌──────────────────────────── kv-loxilb host ────────────────────────────┐
│                                                                        │
│  ┌───────────────┐  scrape :11111/netlox/v1/metrics  ┌──────────────┐  │
│  │ llb1 (docker) │ ◄─────────────────────────────────│  prometheus  │  │
│  │ loxilb        │                                   │  v2.53.x     │  │
│  └───────────────┘                                   └──────┬───────┘  │
│         ▲                                                   │ datasource
│         │ cicd traffic (l3h*/l3ep* netns containers)  ┌─────▼───────┐  │
│   tcplb / tcpkali / iperf3 / ai-sse-quota / secfilter │   grafana   │  │
│                                                       │   v11.x     │  │
│                                                       └─────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

- **Stack**: `docker compose` (two containers: `prom/prometheus:v2.53.4`,
  `grafana/grafana:11.x`) on the same host as the loxilb container so scraping does not
  depend on external routing. Prometheus 2.53.4 matches the promtool version the metric
  surface was lint-verified against.
- **Scrape target**: loxilb REST API, `metrics_path: /netlox/v1/metrics`.
  Metrics collection must be enabled first (`POST /netlox/v1/config/metrics`); while disabled
  the endpoint returns **HTTP 503**, which Prometheus records as `up == 0` — this is by design
  and is what the scrape-down alert keys on.
- **Scrape transport: TLS + mTLS client-cert auth** (decision §9.1). loxilb is started with
  its TLS listener (`--tls --tls-port 8091 --tls-certificate/--tls-key`) **plus `--tls-ca`**,
  which flips the server to `RequireAndVerifyClientCert` (`api/restapi/server.go`) — only
  clients presenting a cert signed by our CA can reach the API at all. Prometheus scrapes
  `scheme: https`, target `:8091`, with
  `tls_config: {ca_file, cert_file, key_file, server_name}`. A self-signed **private CA**
  issues both the loxilb server cert and the Prometheus client cert;
  `deploy/monitoring/certs/gen-certs.sh` (openssl-based, no external deps) generates
  CA + server + client keypairs with SANs for the target host/IP. mTLS doubles as the auth
  mechanism — no token plumbing (loxilb's user-service tokens expire and don't suit an
  unattended scraper). Caveat the README must state: `--tls` adds the HTTPS listener **in
  addition to** the plain HTTP `:11111` listener — production guidance is to bind the plain
  listener to localhost (`--host 127.0.0.1`) or firewall `:11111`, otherwise mTLS on `:8091`
  protects nothing. On the testbed we keep `:11111` open because cicd scripts use it; the T0
  mTLS matrix tests the `:8091` path specifically.
- **Scrape interval: 10 s.** The loxilb stats sweep runs every 10 s; scraping faster only
  duplicates samples, slower halves the resolution of `loxilb_new_flows` (a per-sweep sampled
  gauge). `scrape_timeout: 5s`.
- **Retention**: 15 d (`--storage.tsdb.retention.time=15d`) — enough for week-over-week trend
  comparison; testbed disk cost at ~110 idle families + traffic labels is negligible (<1 GB).
- **Provisioning as code**: Grafana datasource + dashboard provisioning files and dashboard
  JSONs live in the repo; Grafana is stateless and can be recreated at any time.

### 2.1 Repository layout (deliverables of the implementation phase)

```
deploy/monitoring/
├── README.md                       # operator quick start (deploy, certs, enable metrics, URLs)
├── docker-compose.yml
├── .env.example                    # GF_SECURITY_ADMIN_USER/PASSWORD, target host — copy to .env (§9.6)
├── certs/
│   ├── gen-certs.sh                # self-signed CA + loxilb server cert + prometheus client cert
│   └── .gitignore                  # generated keys/certs never committed
├── prometheus/
│   ├── prometheus.yml              # https/mTLS scrape config (target templated via env)
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
4. **Ratios computed in PromQL from raw counters** (post-audit rule — the exporter no longer
   ships pre-cooked ratios): affinity hit rate, load-distribution %, 5xx %.
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

### 4.2 `LoxiLB / L4 Load Balancer` — "Where is traffic going, is it balanced?"

Variable: `$service` from `label_values(loxilb_service_requests_total, service)`.

| Panel | Type | Query |
|---|---|---|
| Requests/s per service | [TS] | `sum by (service) (rate(loxilb_service_requests_total{service=~"$service"}[$__rate_interval]))` |
| Errors/s per service | [TS] | `sum by (service) (rate(loxilb_service_errors_total{service=~"$service"}[$__rate_interval]))` |
| Endpoint load distribution % | [TS] (stacked 100 %) | ~~per-`dip` ratio~~ **BLOCKED by T3 finding F2**: the exporter's `dip` label carries VIP (forward leg) / client IP (return leg), never the endpoint IP, so a per-endpoint split is not derivable from the current metrics. v1 ships a per-service traffic share panel instead (`sum by (service) (rate(loxilb_service_traffic_bytes_total[5m])) / ignoring(service) group_left sum(rate(loxilb_service_traffic_bytes_total[5m]))`); the per-endpoint panel returns with the exporter attribution fix (proposed rollout step 2b, needs review) |
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
| TTFB p50 / p95 / p99 | [TS] | `histogram_quantile(0.5|0.95|0.99, sum by (le) (rate(loxilb_proxy_http_ttfb_seconds_bucket[$__rate_interval])))` | const-histogram from DP buckets (accurate post-audit) |
| TTFB distribution | [H] | `sum by (le) (increase(loxilb_proxy_http_ttfb_seconds_bucket[$__interval]))` | |
| HTTP/2 sessions created/s | [TS] | `rate(loxilb_proxy_http2_sessions_total[$__rate_interval])` | counter, **not** an active gauge (post-audit type change) |
| Session-affinity hit rate | [S]+[TS] | `sum(rate(loxilb_proxy_conversation_hits_total[5m])) / (sum(rate(loxilb_proxy_conversation_hits_total[5m])) + sum(rate(loxilb_proxy_conversation_misses_total[5m])))` | replaces deleted lifetime-ratio gauge |
| Conversation sessions / TTL expiries | [TS] | `loxilb_proxy_conversation_sessions`; `rate(loxilb_proxy_conversation_ttl_expired_total[$__rate_interval])` | |
| Cache backpressure | [TS] | `loxilb_proxy_cache_backpressure_ratio` + `rate(loxilb_proxy_cache_high_water_events_total[$__rate_interval])` + `rate(loxilb_proxy_cache_drain_partial_total[$__rate_interval])` | sustained backpressure >0.8 amber |
| Chunked / graceful close | [TS] | `rate(loxilb_proxy_chunked_responses_total[$__rate_interval])`, `rate(loxilb_proxy_graceful_close_total[$__rate_interval])` | |

### 4.4 `LoxiLB / AI Gateway` — "Are models serving, who is being throttled?"

Variables: `$model`, `$tenant` from `loxilb_ai_requests_total`.

| Panel | Type | Query | Notes |
|---|---|---|---|
| AI requests/s by model | [TS] | `sum by (model) (rate(loxilb_ai_requests_total{model=~"$model",tenant=~"$tenant"}[$__rate_interval]))` | counter increments at SSE **stream completion** |
| AI requests/s by status | [TS] | `sum by (status) (rate(loxilb_ai_requests_total{...}[$__rate_interval]))` | real backend status post-audit |
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
series are absent. Not exercised on the testbed — validated only for correct absent-handling.

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
| `LoxilbKvAgentDown` | `loxilb_kv_agent_up == 0 and max_over_time(loxilb_kv_agent_up[1h]) == 1` | 2m | warning — guarded: the gauge registers 0 even with no KV agent deployed (T1 finding), so only alert if it was recently up |
| `LoxilbSynFloodActive` | `rate(loxilb_security_syn_blocked_total[5m]) > 0` | 2m | info |
| `LoxilbUdpFloodActive` | `rate(loxilb_security_udp_blocked_total[5m]) > 0` | 2m | info |
| `LoxilbFwDropSurge` | `rate(loxilb_fw_drop_packets_total[5m]) > 100` (tunable) | 5m | warning |
| `LoxilbConntrackStatResets` | `rate(loxilb_conntrack_stat_resets_total[10m]) > 0` | 10m | info |
| `LoxilbConntrackNearCapacity` | `loxilb_active_conntrack_entries / loxilb_conntrack_max_entries > 0.8` | 5m | warning (critical at `> 0.95`) |

**New exporter gauge (in scope, decision §9.3)**: `loxilb_conntrack_max_entries` — constant
gauge exporting the datapath conntrack capacity (`LLB_CT_MAP_ENTRIES` from
`loxilb-ebpf/common/llb_dpapi.h`, already reachable via cgo in `pkg/loxinet/dpebpf_linux.go`).
Small additive change in `api/prometheus/`; no rename, promtool-clean naming; enables the
utilization alert above and a capacity gauge panel next to "Active sessions (L4)" in §4.1/§4.2.

Deliberate omissions: no alert on `loxilb_new_flows` (sampled gauge, noisy); no alerts on
`doca_*` (absent on non-DPU sites → permanent no-data flapping risk).

Rule-file hygiene gates (implementation phase): `promtool check rules` clean; every expr
dry-run against the live testbed Prometheus; traffic-rate guards on all ratio alerts so an
idle system can never fire them (0/0).

---

## 6. Correctness notes baked into the design

These are the audit findings that shape panel/alert semantics — reviewers should check each
panel spec against them:

1. **Conntrack-derived metrics reflect established sessions.** `loxilb_active_conntrack_entries`,
   `loxilb_requests_total`, `loxilb_processed_*`, per-service/EP/client traffic all come from
   the 10 s conntrack sweep. Sessions shorter than the sweep window may never be sampled;
   an idle-or-short-lived-only workload legitimately shows empty conntrack.
   **T3 verdict (2026-07-19): CONFIRMED.** With held-open sessions every conntrack-derived
   metric works (100+ `est` entries, gauges/counters tracking reality); the metrics-audit
   "conntrack empty under cicd traffic" issue was a short-lived-session sampling artifact,
   not a data-plane bug — that investigation is closed.
1a. **Per-service metrics require NAMED LB rules** (T3 finding F1): unnamed rules produce
   empty `servName` in conntrack, so `loxilb_service_*` never appears and `service` labels
   are empty. Operator guidance: always create LB rules with `--name`. Endpoint health
   probing likewise needs an explicit probe (`--probetype=tcp --probeport=...` via the
   endpoint API); `--monitor` alone leaves `ptype none` and state never changes (F3).
2. **Counters reset on restart** → `rate()`/`increase()` everywhere; no raw-counter tiles.
3. **Absence ≠ zero** for `doca_*`, `aictrl_ttft_pred_err_ratio_*` (lazy registration),
   per-EP gauges after decommission (lifecycle-managed series deletion).
4. **`loxilb_new_flows` is a per-sweep sample**, not a counter — display as-is, never `rate()`.
5. **`loxilb_proxy_http2_sessions_total` is a counter** (old "active sessions" gauge was
   broken) — only meaningful under `rate()`.
6. **AI request counter increments at stream completion**; rate-limit/model denials live in
   dedicated counters. Panels must not imply requests_total covers denials.
7. **`model` label caps at 64 values** (overflow → `"other"`); `status`/`tenant` come from
   real backend/API-key data post-audit.
8. **Client-IP (`sip`) and `cidr` labels are unbounded** in principle → table-only, `topk`'d
   (§3.6), and excluded from alert exprs.

---

## 7. Test plan — kv-loxilb testbed, real traffic

Testbed: `kv-loxilb` (61.107.201.161, ssh alias, user `kong`; loxilb in docker `llb1`,
image `latest-u24` = overhauled binary; traffic hosts are netns containers `l3h*`/`l3ep*`
driven via cicd `common.sh`). Code synced from this Mac (not a git checkout there); cicd
scripts run **as kong, no leading sudo**; non-interactive ssh needs
`export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin`.

### T0 — Stack deployment + mTLS (no traffic)

1. Sync `deploy/monitoring/` to kv-loxilb; run `certs/gen-certs.sh` (self-signed CA, server
   cert with SAN for the llb1 address, prometheus client cert).
2. Restart `llb1` loxilb with `--tls --tls-port 8091 --tls-certificate ... --tls-key ...
   --tls-ca <our CA>`; confirm the plain flow (`rmconfig/config/validation` of a trivial
   scenario) still works so the TLS flags don't disturb cicd.
3. `docker compose up -d` (certs bind-mounted read-only into the Prometheus container;
   Grafana admin credentials from `.env`).
4. **mTLS verification matrix**:
   a. Prometheus target page: scrape over `https://...:8091` healthy (`up == 1` once metrics
      enabled).
   b. `curl --cacert CA https://<host>:8091/netlox/v1/metrics` **without** a client cert →
      TLS handshake rejected (proves `RequireAndVerifyClientCert` is active).
   c. `curl` **with** a cert signed by a different CA → rejected.
   d. `curl` with the prometheus client cert → 200 (or 503 pre-enable).
5. Verify 503-handling: with metrics disabled, `up{job="loxilb"} == 0` and
   `LoxilbScrapeDown` reaches *firing* in Prometheus UI (this doubles as the first alert drill).
6. Enable metrics (`POST /netlox/v1/config/metrics`, over mTLS); `up == 1` within one interval.
7. Grafana reachable with the `.env` admin credential (anonymous access off); datasource
   healthy; all 5 dashboards auto-provisioned.

**Pass**: all checks incl. the 4-row mTLS matrix; `promtool check rules` clean; scrape
duration p99 < 1 s.

### T1 — Idle baseline (correctness gate)

1. No traffic for 15 min. Record `count({__name__=~"loxilb_.*"})` and family count
   (expected ≈108 idle families per Phase F).
2. Screenshot pass over all dashboards: every panel must show either plausible idle data or
   an intentional "No data" (§3.5) — **zero panels showing constants, errors, or
   `N/A (query error)`**.
3. Confirm no alert (other than none) is pending/firing on the idle system — validates the
   0/0 traffic guards.

**Pass**: family count matches scrape; all-panel screenshot review signed off; alert list empty.

### T2 — Short-lived L4 traffic (`cicd/tcplb`)

Run `tcplb` config + validation. Expect: `loxilb_lb_rules`/`loxilb_healthy_endpoints` reflect
the scenario; L7-independent panels move. **Explicitly record** whether conntrack-derived
panels stay empty (short-lived curl sessions < 10 s sweep) — this is the control group for T3.

### T3 — Long-lived traffic → conntrack metrics (the critical phase)

Conntrack only reports established sessions, so this phase holds sessions open **well past
several 10 s sweeps**:

1. On top of the `tcplb` topology, drive held-open connections:
   - `tcpkali`: `l3ep* tcpkali -l 8080` servers + `l3h* tcpkali -c 50 -T 600 -r 100 <VIP>:2020`
     (50 concurrent connections, 10 min, steady message rate) — reuses `cicd/tcpkali` assets
     with a lengthened `-T`.
   - `iperf3` TCP: `iperf3 -c <VIP> -t 600` for a high-throughput long flow
     (reuses `cicd/iperf3lb` topology; switch `-u` off, lengthen `-t`).
2. During the run, verify in order — each step gates the next:
   a. `curl /netlox/v1/config/conntrack/all` → **non-empty**, states `est`.
   b. `loxilb_active_conntrack_entries > 0` and tracks the tcpkali `-c` count (±).
   c. `loxilb_requests_total`, `loxilb_processed_bytes_total`, per-service/EP/client
      counters increase monotonically across ≥6 consecutive sweeps.
   d. Grafana: L4 dashboard endpoint-distribution panel sums to ~100 % across `dip`s and is
      ~balanced (rr); Top-clients table shows `l3h*` IPs; Overview throughput matches
      iperf3's reported bitrate within ~10 %.
3. Kill one endpoint (`l3ep1`) mid-run → `loxilb_unhealthy_endpoints` rises,
   `LoxilbUnhealthyEndpoints` fires after its `for:`; distribution shifts to surviving EPs;
   restore and watch recovery.
4. **If 2a fails** (conntrack still empty with held-open established sessions), that
   *disproves* the short-lived-traffic explanation and re-opens the pre-existing DP issue
   (see `METRICS-MIGRATION-UI.md` §6) as a release blocker for L4 dashboards — escalate,
   don't paper over.

**Pass**: 2a–2d + 3; explicit written verdict on the conntrack hypothesis.

### T4 — L7 + AI traffic (`cicd/ai-sse-quota`, `cicd/httpsproxy`)

1. `ai-sse-quota` (already validated post-overhaul): SSE streams with `[SSE_DONE]`
   `latency_ms` → AI dashboard: requests by `model="sse-test"`/`status="200"`, duration
   histogram populated in sub-second buckets (H-9 monotonic-latency fix visible), active
   streams gauge >0 during streams, rate-limit panel moves when quota trips (the scenario's
   quota-exceed leg) — verify `429`-path lands in `loxilb_ai_rate_limit_hits_total`, not
   `loxilb_ai_requests_total`.
2. `httpsproxy` (or `e2ehttpsproxy` for TLS-terminating + re-encrypt): L7 dashboard —
   responses by status class, TTFB quantiles plausible (>0, sub-second), active SSL
   connections >0 during the run, affinity hit-rate panel computes without error.

**Pass**: listed panels populated with values cross-checked against scenario logs
(request counts within ±2 of client-side counts; SSE latency matches `latency_ms` markers).

### T5 — Security traffic (`cicd/secfilter`)

Run the `secfilter` scenario (built during the security audit). Verify Security dashboard:
syn/conn/udp passed+blocked counters move in the expected legs, blocked-ratio tile goes
amber during the attack leg and back to green, ipfilter blacklist table shows the scenario
CIDRs, `LoxilbSynFloodActive`/`LoxilbUdpFloodActive` reach firing, then resolve.

**Pass**: per-leg metric deltas match scenario assertions; both info alerts fire and resolve.

### T6 — Alert drill matrix

Every `critical`/`warning` rule must be observed **firing and resolving** at least once:

| Alert | Trigger method |
|---|---|
| ScrapeDown | disable metrics via REST (from T0) |
| NoHealthyEndpoints / UnhealthyEndpoints | stop all / one `l3ep*` (from T3.3) |
| High5xxRatio | point one EP at a 500-returning backend (reuse ai-sse-quota mock with error mode, or nginx `return 500`) |
| AIErrorRatio | same, via AI path |
| AIRateLimitSpike | ai-sse-quota quota-exceed leg (T4) |
| HighTTFB | mock server with `sleep`-delayed first byte |
| Cpu/Mem/DiskHigh | `stress-ng` on host (or temporarily lower threshold to current value — allowed, but record it) |
| HaSyncFailing | not triggerable on single-node testbed → **verified by expr dry-run only**; noted as residual risk |
| KvAgentDown | stop kv-agent if the sglang-kvcache setup is up; else expr dry-run |

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

**Pass**: all four; soak-report appended to the execution doc.

### Exit criteria (definition of done for the whole track)

- T0–T7 pass, recorded in a new `docs/MONITORING-EXECUTION.md` (same format as
  `METRICS-AUDIT-EXECUTION.md`: per-phase record, gotchas, evidence commands).
- All dashboard JSONs + rules + compose files in `deploy/monitoring/`, provisioned from
  scratch on a clean `docker compose up -d` with zero manual clicks.
- `deploy/monitoring/README.md` operator quick start reviewed.
- Explicit verdict on the conntrack established-session hypothesis (T3.4).

---

## 8. Rollout plan & risks

**Implementation order** (each step is a review checkpoint):
1. `deploy/monitoring/` skeleton: compose + `.env` + certs/gen-certs.sh + prometheus.yml
   (mTLS) + rules → T0/T1 on testbed (incl. mTLS matrix).
2. Exporter change: `loxilb_conntrack_max_entries` gauge (§5) + rebuild/redeploy llb1 image
   (cgo relink gotcha applies — see `METRICS-AUDIT-EXECUTION.md` Phase F).
3. Overview + L4 dashboards (incl. conntrack utilization panel) → T2/T3.
4. L7 + AI dashboards → T4.
5. Security dashboard + alert drills → T5/T6.
6. Soak → T7; write `MONITORING-EXECUTION.md`; final review.

Everything remains **uncommitted until explicit approval** (standing hold), same as the
metrics overhaul itself.

**Risks / mitigations**

| Risk | Mitigation |
|---|---|
| T3 disproves the established-session hypothesis → L4 traffic panels blind | Pre-declared escalation path (T3.4); L7/AI/security dashboards are independent and ship regardless |
| Alert thresholds wrong for real production scale (testbed ≠ prod traffic) | Tunables isolated at top of rules file with comments; ratios+guards preferred over absolute rates |
| Grafana/Prometheus version drift at customer sites | Versions pinned in compose; dashboards use only core panel types (stat/timeseries/table/heatmap/bar-gauge), schema v39+, no plugins |
| Dashboard JSON review is hard in PRs | Each JSON accompanied by this doc's panel table as the source of truth; reviewers review the table, spot-check the JSON |
| kv-loxilb repo is rsync'd, not git — deploy dir could drift | `MONITORING-EXECUTION.md` records the exact sync command; rsync does not propagate deletions (known gotcha) — use `--delete` for `deploy/monitoring/` |

---

## 9. Review decisions (internal review, 2026-07-18 — LOCKED)

1. **Scrape security → TLS + auth between Prometheus and loxilb, built and tested with a
   self-signed CA.** Implemented as mTLS (loxilb `--tls ... --tls-ca` →
   `RequireAndVerifyClientCert`; Prometheus `tls_config` with CA + client cert). Cert
   tooling ships as `deploy/monitoring/certs/gen-certs.sh`; live-verified in T0's mTLS
   matrix. See §2.
2. **`LoxilbHighTTFB`: global-with-tunable accepted for v1.** 2 s default, tunable at the
   top of the rules file; per-route SLOs deferred.
3. **`loxilb_conntrack_max_entries` gauge: approved, pulled into scope.** Exporter change +
   `LoxilbConntrackNearCapacity` alert + capacity panels. See §5, rollout step 2.
4. **Dashboards stay operator-only.** loxilb-ui and this Grafana stack are and remain
   separate; no shared styling/datasource-UID constraints.
5. **HA-pair testing is post-release.** Single-node validation is sufficient for this
   release; `$instance` variable keeps multi-node additive.
6. **Grafana admin credentials via env file** (`.env`, git-ignored; `.env.example`
   committed). Anonymous-viewer mode not used.
