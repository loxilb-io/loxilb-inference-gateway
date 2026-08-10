# LoxiLB Inference Gateway — Monitoring CI/CD Validation Plan

> Companion to `MONITORING-DESIGN.md` (what the monitoring stack is). This doc describes the
> **automated, repeatable, assertion-based CI** that protects the correctness of metrics,
> Prometheus, and Grafana on every change: Tier 0 gates every relevant PR, Tier 1 runs per
> merge, Tier 2 runs nightly.

---

## 1. What is protected

The monitoring stack ships in this repo:

- `deploy/monitoring/` — compose, `gen-certs.sh`, `prometheus.yml`, 21 alert rules, 5 dashboards
  (+ bootstrap).
- Exporter — `loxilb_conntrack_max_entries` gauge, the `loxilb_l4_error_events_total`
  collector (`api/prometheus/l4_error_metrics.go`), SCTP error accounting read from conntrack
  state (`prometheus.go`).
- eBPF datapath — TTFB samples are recorded unconditionally (`record_latency_sample` in the
  always-compiled `sockproxy_metrics.c`); the `ct_err_stats` map is always-on and registered.
- Every metric the committed dashboards/rules reference is emitted by the committed exporter
  (enforced — Tier 0 §4).

Without CI, the next exporter rename, dashboard edit, or submodule bump could silently break
any of this. The tiers below close exactly that gap.

---

## 2. The correctness principle

**Each metric is checked against independently-known ground truth, never against itself**
(conntrack entries == driven conn count; AI-request delta == streams sent; security counters
move in the expected legs). Every tier below asserts against ground truth the *driver*
controls, not against whatever the exporter happens to report.

Three correctness surfaces, asserted at every tier that can reach them:

| Surface | "Correct" means | How CI asserts it |
|---|---|---|
| **Metrics (exporter)** | the number equals reality | driver knows N (reqs/conns/bytes/streams) → assert `Δmetric ≈ N` within tolerance; counters monotonic; histogram `count == Σbuckets`; conditional families absent when idle, present under traffic |
| **Prometheus** | scrape + rules + query engine are sound | `promtool check rules/config`; `up==1`, scrape-duration budget, no gaps; **every dashboard/alert PromQL expr runs without error**; alerts fire→resolve on the right condition; **idle system fires zero alerts** (0/0 guard) |
| **Grafana** | provisioning + wiring render real data | dashboards provision (`/api/search`), datasource healthy, **each panel's query returns data through the datasource proxy** where traffic exists, "No data" only where designed |

---

## 3. Tier map (cost vs. cadence vs. runner)

| Tier | What | Cadence | Runner | Where |
|---|---|---|---|---|
| **0** | Hermetic static gate (no loxilb, no traffic) | every PR touching the stack or exporter | any (`ubuntu-latest`) | §4 |
| **1** | Stack-up + traffic correctness (ground-truth cross-checks) | per merge to main (opt: per PR) | `ubuntu-22.04` (eBPF-capable; **not** hosted u24 — E2BIG) | §5 — `cicd/monitoring` + `monitoring-e2e.yml` |
| **2** | Alert fire→resolve drills + short soak | nightly / scheduled | `ubuntu-22.04` or self-hosted | §6 — `cicd/monitoring/drill.sh` + `monitoring-drill.yml` |

**Runner reality (hard constraint):** the hosted u24 runner (kernel 6.17-azure) rejects the
loxilb eBPF program with `E2BIG` and lacks `bpftool`. Tiers 1–2 need the *real* DP metrics, so
they run on `ubuntu-22.04` GitHub-hosted (kernel 6.x, already proven green by
`ai-gateway-sanity`). Tier 0 has no such constraint.

---

## 4. Tier 0 — hermetic static gate

**Deliverables:**
- `deploy/monitoring/ci/lint-monitoring.py` — stdlib-only linter (optional `promtool`).
- `.github/workflows/monitoring-lint.yml` — installs pinned promtool `2.53.4`, runs the linter;
  triggers on `deploy/monitoring/**`, `api/prometheus/**`, `cmd/loxilb-ai-controller/**`,
  `doca/**`, and the workflow itself.

**Run locally:** `python3 deploy/monitoring/ci/lint-monitoring.py`
(add `--promtool <path>` for the rule/PromQL-syntax checks; without it those are skipped with a
warning, structural checks still run).

**Checks (ERROR = fails build):**
1. Every dashboard JSON parses; unique `uid` across dashboards; unique panel `id` within a
   dashboard (recurses collapsed-row child panels).
2. Every panel/target datasource `uid == loxilb-prom` (Grafana built-ins exempt).
3. **Metric-name resolution** — every `loxilb_*`/`doca_*`/`aictrl_*` name in dashboards **and**
   rules resolves to a metric the exporter source actually declares (histogram
   `_bucket`/`_count`/`_sum` suffixes normalized; Prometheus/Go infra names allowlisted). This
   is the highest-value check: it makes a metric rename that orphans a panel fail CI.
4. Every alert `dashboard:`/`panel:` annotation resolves to an existing dashboard title + panel
   title (design principle §3.7 — every alert has a home).
5. `promtool check rules` clean.
6. Every dashboard target expr parses as PromQL (Grafana macros substituted, wrapped as
   recording rules, `promtool`-parsed).

**Warnings (non-fatal):** `loxilb_*` selector without `$instance`; panel over a lazy/conditional
family (`doca_*`/`aictrl_*`/`loxilb_ai_*`/`loxilb_l4_error_*`) without `noValue` (§3.5);
missing `$instance` template var.

**Known accepted warning:** the Overview `Error rate` panel queries the lazy
`l4_error_events` family without `noValue`; because the panel uses a `rate()` expr, absence
already renders as an empty panel, so the warning is cosmetic and left as-is.

---

## 5. Tier 1 — integration + traffic correctness

The `cicd/monitoring` scenario follows the existing `common.sh` pattern
(`config.sh` / `validation.sh` / `rmconfig.sh`), extended to stand up Prometheus + Grafana and
assert via their **APIs** (not raw `/metrics` greps). It reuses existing traffic topologies
rather than reinventing drivers. Precedent already in-repo: `cicd/ai-sse-quota/validation.sh`
does a before/after `loxilb_ai_requests_total` delta — Tier 1 generalizes that pattern through
Prometheus/Grafana.

### 5.1 `config.sh`
1. Bring up loxilb + a base topology (reuse `tcplb` / `httpsproxy` / `ai-sse-quota` assets).
2. Enable metrics collection: `POST /netlox/v1/config/metrics`.
3. `docker compose up -d` (CI profile: host-network, plaintext host-local scrape target —
   the shipped default scrape model, see `MONITORING-DESIGN.md` §2). For the optional
   transport-TLS path, `deploy/monitoring/certs/gen-certs.sh` generates the material — see
   the gotchas in §10 for cert placement and the `TLS_CA_CERTIFICATE` wiring.

### 5.2 `validation.sh` — assertions by surface

**Scrape matrix:** metrics disabled → endpoint returns 503 → `up==0`; enabled → `up==1`.
There is no client-cert auth matrix: the metrics route is control-plane and its TLS is
transport-only (see `MONITORING-DESIGN.md` §2), so the default plaintext host-local scrape is
what CI asserts; the auth-token path is documented, not asserted.

**Metrics correctness (ground-truth cross-checks — the assertion catalog, §7):** drive each
topology, then query Prometheus `/api/v1/query` and assert `Δmetric ≈ driven N` within
tolerance. Long-lived L4 uses a python hold-driver (tcpkali is not available on the runner).

**Prometheus correctness:** `up==1`; scrape-duration budget; extract **every** dashboard + rule
expr and run through `/api/v1/query` — assert `status==success` and non-empty where traffic
exists; **idle-guard**: with a quiet system assert `/api/v1/alerts` has zero `firing` (validates
the 0/0 traffic guards — the production false-positive property).

**Grafana correctness:** `/api/health`; `/api/search` returns the 6 dashboards; datasource
health; for each panel POST its target expr through the datasource proxy
(`/api/datasources/proxy/<id>/api/v1/query`) — the scriptable replacement for a manual
"screenshot pass, zero panels showing constants/errors."

### 5.3 Datapath regression guards (locked-in behavior)
- After L7 traffic, `loxilb_proxy_http_ttfb_seconds_count > 0` — TTFB samples are recorded
  unconditionally in the datapath.
- An SCTP abort increments the L4 error signal.
- A backend RST increments `loxilb_l4_error_events_total{reason="rst_server"}`.

---

## 6. Tier 2 — alert drills + soak (nightly)

Alert `for:` windows (1–10 m) are too slow for per-PR, so drills run nightly:

- For each triggerable alert: induce the condition, poll `/api/v1/alerts` until `firing`, clear
  it, poll until `inactive`. (Trigger methods per alert: `MONITORING-DESIGN.md` §7 alert-drill
  matrix.)
- **Short soak** (1–2 h in CI, not 12 h): assert `prometheus_tsdb_head_series` flat
  (cardinality/label-leak guard — e.g. unbounded `sip`), `avg_over_time(up[window]) ≈ 1` (no
  gaps), container RSS stable.
- Capacity/system alerts (CPU/Mem/Disk/conntrack) that can't be reached safely on a shared
  runner: threshold-lowered drills (rules restored after — a sanctioned technique,
  `MONITORING-DESIGN.md` §7) — or expr dry-run only, logged as such.

---

## 7. Assertion catalog (ground-truth checks)

The concrete numeric checks Tier 1/2 encode:

| Scenario | Ground truth | Assert (Prometheus/Grafana) | Tol |
|---|---|---|---|
| `ai-sse-quota` | N SSE streams completed | `Δloxilb_ai_requests_total{status="200"} == N`; duration histogram `count == N` | exact |
| `httpsproxy` (L7) | N HTTP responses | `Δloxilb_proxy_http_responses_total == N`; `ttfb_seconds_count > 0` | ±2 |
| L4 hold-driver | C held-open conns | `loxilb_active_conntrack_entries ≈ C` (both NAT legs); `/config/conntrack/all` non-empty `est` | ±C |
| L4 (named rule) | requests on `--name=svc` | `loxilb_service_requests_total{service="svc"}` attributes correctly (unnamed rules produce no `service` label — always name LB rules) | exact |
| EP kill | 1 of 3 EPs down | `healthy 3→2`, `unhealthy 0→1`; `LoxilbUnhealthyEndpoints` fires after `for:` | — |
| `secfilter` + flood | SYN/UDP blocked legs | `loxilb_security_*_blocked_total` move; blocked-ratio tile amber; `LoxilbSyn/UdpFloodActive` fire→resolve | — |
| server-RST drive | R abortive closes | `Δloxilb_l4_error_events_total{reason="rst_server"} ≈ 2R` (each abortive close yields two events) | — |
| idle | no traffic | family count ≈ 108; **zero alerts firing**; no panel shows a constant/error | — |

---

## 8. Behavior locked in by permanent regression tests

Three product-level behaviors shape the sharpest CI assertions; each is protected by a
permanent regression test so it cannot silently regress:

| Behavior (current) | Why it matters | CI regression test |
|---|---|---|
| The `/netlox/v1/metrics` route is control-plane: when an API auth mode (`--userservice`/`--oauth2`) is enabled, scrapes must send a `Bearer` token; the product's supported mTLS is data-path only and never authenticates a scraper. The shipped default is a same-host, network-isolated plaintext scrape (`MONITORING-DESIGN.md` §2). | scraping must not silently 401; operators need one clear supported model | Tier 1 asserts the default `http://127.0.0.1:11111` scrape reaches `up==1`; the auth-token path is documented, not asserted |
| The sockproxy records non-SSE responses at response-complete, so plain-JSON errors are counted in `loxilb_ai_requests_total` and visible to `LoxilbAIErrorRatio`. | the AI error ratio must see the most common AI error shape | Tier 1: N plain-JSON 500s via an AI rule → `Δai_requests_total{status="500"} == N` (note: `ai_gw_mode` derives from sse_mode/pd/apikey, so plain mode-4 rules are outside AI accounting by design — asserted separately) |
| The datapath counts `CT_TCP_ERR` only on established/closing connections, so management-plane / short REST connections do not tick `loxilb_l4_error_events_total`. | any REST poller would otherwise false-fire `LoxilbL4ErrorBurst` | Tier 1: 30 REST polls → ≈0 `l4_error` delta; server RSTs still increment |

---

## 9. What runs where

- **Tier 0** — `.github/workflows/monitoring-lint.yml` + `deploy/monitoring/ci/lint-monitoring.py`;
  gates every stack/exporter change.
- **Tier 1** — `cicd/monitoring/{config.sh,validation.sh,rmconfig.sh}` + `docker-compose.ci.yml`:
  the scrape matrix, the §7 ground-truth cross-checks (SSE, non-SSE, conntrack hold-driver,
  server-RST), and the full PromQL-expr + Grafana-proxy sweeps
  (`deploy/monitoring/ci/sweep-monitoring.py`). Runs per merge via
  `.github/workflows/monitoring-e2e.yml` (build-from-source, `ubuntu-22.04`).
- **Tier 2** — `cicd/monitoring/drill.sh`: ScrapeDown / L4ErrorBurst / UnhealthyEndpoints
  fire→resolve with shortened (30 s) drill windows, original rules restored afterwards, plus
  the short soak. Runs nightly via `.github/workflows/monitoring-drill.yml`.

---

## 10. Notes / gotchas

- `cicd/<scenario>/cert/` bind-mount shadows `/opt/loxilb/cert/` — install monitoring certs
  there, not via `docker cp`.
- `--tls-ca` is passed as env `TLS_CA_CERTIFICATE`, not a CLI flag (loxilb main's parser rejects
  the flag; the API sub-parser reads the env var).
- Editing rules on disk ≠ loaded — `docker kill -s HUP loxilb-prometheus` and verify via
  `/api/v1/rules` (a stale-rules footgun).
- Prometheus container runs `user: "0"` to read the `0600` client key bind-mount.
- Disable securityrate with `DELETE /config/securityrate` (POST-all-false is rejected 400).
- Drain and close hold-driver connections cleanly before asserting on the management-plane
  L4-error counter — an un-drained close emits client-RST error events that leak into the
  assertion.
