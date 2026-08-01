# LoxiLB Inference Gateway — Monitoring CI/CD Validation Plan

> Status: **Tiers 0–2 implemented; Tier 1 GREEN in CI (2026-08-01, run 30694327968:
> all ground-truth asserts exact, 124/124 PromQL exprs clean, 6/6 dashboards / 80 panels
> live, 0 idle alerts). Tier 2 nightly awaits its first scheduled run.**
> Companion to `MONITORING-DESIGN.md` (what the stack is) and `MONITORING-EXECUTION.md`
> (the one-shot manual validation on the dev testbed). This doc turns that manual T0–T7 run into
> **automated, repeatable, assertion-based CI** so correctness is protected on every change.
> Goal: production-ready **correctness** of metrics, Prometheus, and Grafana — the three
> surfaces the user called out.

---

## 1. Why this exists (the gap)

The stack is implemented and committed, and internally consistent (verified 2026-07-27):

- `deploy/monitoring/` — compose, `gen-certs.sh`, `prometheus.yml`, 21 alert rules, 5 dashboards
  (+ bootstrap) — **committed**.
- Exporter additions — `loxilb_conntrack_max_entries` gauge, `loxilb_l4_error_events_total`
  collector (`api/prometheus/l4_error_metrics.go`), SCTP-error fix reading `CState`
  (`prometheus.go`, F6) — **committed**.
- eBPF fixes at pinned submodule `40745f6` — TTFB records unconditionally (F4,
  `record_latency_sample` in always-compiled `sockproxy_metrics.c`); `ct_err_stats` always-on
  map registered (F7) — **landed**.
- Every metric the committed dashboards/rules reference is emitted by the committed exporter
  (this is now enforced — Tier 0 §4).

It was also **validated deeply, once, by hand**: T0–T7 passed on the dev testbed with real traffic;
18/21 alerts observed fire→resolve on live data; 16 h soak clean. That work was high quality —
it *found and fixed* F4/F6/F7.

**The gap for production:** every bit of that validation was human-driven, screenshot/eyeball-
based, one-shot, on an rsync'd (non-git) testbed, with **nothing that re-runs**. The next
exporter rename, dashboard edit, or submodule bump has zero automated guard. CI closes exactly
that gap.

---

## 2. The correctness principle

The reason the manual runs were trustworthy: **each metric was checked against independently-
known ground truth, never against itself** (conntrack entries == driven conn count; AI-request
delta == streams sent; security counters moved in the expected legs). CI's job is to **codify
those same assertions**. Every tier below asserts against ground truth the *driver* controls,
not against whatever the exporter happens to report.

Three correctness surfaces, asserted at every tier that can reach them:

| Surface | "Correct" means | How CI asserts it |
|---|---|---|
| **Metrics (exporter)** | the number equals reality | driver knows N (reqs/conns/bytes/streams) → assert `Δmetric ≈ N` within tolerance; counters monotonic; histogram `count == Σbuckets`; conditional families absent when idle, present under traffic |
| **Prometheus** | scrape + rules + query engine are sound | `promtool check rules/config`; `up==1`, scrape-duration budget, no gaps; **every dashboard/alert PromQL expr runs without error**; alerts fire→resolve on the right condition; **idle system fires zero alerts** (0/0 guard) |
| **Grafana** | provisioning + wiring render real data | dashboards provision (`/api/search`), datasource healthy, **each panel's query returns data through the datasource proxy** where traffic exists, "No data" only where designed |

---

## 3. Tier map (cost vs. cadence vs. runner)

| Tier | What | Cadence | Runner | Status |
|---|---|---|---|---|
| **0** | Hermetic static gate (no loxilb, no traffic) | every PR touching the stack or exporter | any (`ubuntu-latest`) | ✅ **built** (§4) |
| **1** | Stack-up + traffic correctness (ground-truth cross-checks) | per merge to main (opt: per PR) | `ubuntu-22.04` (eBPF-capable; **not** hosted u24 — E2BIG) | ✅ **built** (§5 — `cicd/monitoring` + `monitoring-e2e.yml`) |
| **2** | Alert fire→resolve drills + short soak | nightly / scheduled | `ubuntu-22.04` or self-hosted | ✅ **built** (§6 — `cicd/monitoring/drill.sh` + `monitoring-drill.yml`) |

**Runner reality (hard constraint):** the hosted u24 runner (kernel 6.17-azure) rejects the
loxilb eBPF program with `E2BIG` and lacks `bpftool`. Tiers 1–2 need the *real* DP metrics, so
they run on `ubuntu-22.04` GitHub-hosted (kernel 6.x, already proven green by
`ai-gateway-sanity`). Tier 0 has no such constraint.

---

## 4. Tier 0 — hermetic static gate ✅ (built)

**Deliverables (committed):**
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

**Self-test performed (2026-07-27):** clean tree → 0 errors, 1 warning (a real §3.5 nit — the
Overview `Error rate` panel now points at the lazy `l4_error_events` family without `noValue`).
Negative tests confirmed detection of: a lowercase metric rename (1 attributed error), a broken
PromQL expr, a stale panel annotation, and an empty exporter surface (safety-net error). All
returned exit 1.

**Follow-up (optional):** decide whether to fix the one live warning (add `noValue: "No data"`
to the Overview `Error rate` panel) or downgrade it — the panel uses a `rate()` expr so absence
already renders empty; cosmetic only.

---

## 5. Tier 1 — integration + traffic correctness 📋

A new `cicd/monitoring` scenario following the existing `common.sh` pattern
(`config.sh` / `validation.sh` / `rmconfig.sh`), extended to stand up Prometheus + Grafana and
assert via their **APIs** (not raw `/metrics` greps). Reuses existing traffic topologies rather
than reinventing drivers. Precedent already in-repo: `cicd/ai-sse-quota/validation.sh` T3 does a
before/after `loxilb_ai_requests_total` delta — Tier 1 generalizes that pattern through
Prometheus/Grafana.

### 5.1 `config.sh`
1. Bring up loxilb + a base topology (reuse `tcplb` / `httpsproxy` / `ai-sse-quota` assets).
2. `deploy/monitoring/certs/gen-certs.sh <targets>`; install certs where `common.sh` expects
   (⚠ `cicd/<scenario>/cert/` bind-mount shadows `/opt/loxilb/cert/` — see EXECUTION gotchas).
3. Restart loxilb with `--tls` (+ `TLS_CA_CERTIFICATE` env — **not** a `--tls-ca` flag; see
   EXECUTION T0 wiring note); `POST /netlox/v1/config/metrics`.
4. `docker compose up -d` (CI profile: host-network, target = the loxilb container IP).

### 5.2 `validation.sh` — assertions by surface

**mTLS matrix (T0):** no-cert → rejected; foreign-CA cert → rejected; valid client cert → 200;
metrics-disabled → 503 → `up==0`.

**Metrics correctness (ground-truth cross-checks — the assertion catalog, §7):** drive each
topology, then query Prometheus `/api/v1/query` and assert `Δmetric ≈ driven N` within
tolerance. Long-lived L4 uses a python hold-driver (tcpkali is not on the runner — EXECUTION
T3 used this).

**Prometheus correctness:** `up==1`; scrape-duration budget; extract **every** dashboard + rule
expr and run through `/api/v1/query` — assert `status==success` and non-empty where traffic
exists; **idle-guard**: with a quiet system assert `/api/v1/alerts` has zero `firing` (validates
the 0/0 traffic guards — the production false-positive property).

**Grafana correctness:** `/api/health`; `/api/search` returns the 6 dashboards; datasource
health; for each panel POST its target expr through the datasource proxy
(`/api/datasources/proxy/<id>/api/v1/query`) — the scriptable replacement for the manual
"screenshot pass, zero panels showing constants/errors."

### 5.3 Regression guards for the DP bugs already fixed (lock them)
- **F4** — after L7 traffic, `loxilb_proxy_http_ttfb_seconds_count > 0`.
- **F6** — an SCTP abort increments the L4 error signal.
- **F7** — a backend RST increments `loxilb_l4_error_events_total{reason="rst_server"}`.

---

## 6. Tier 2 — alert drills + soak 📋 (nightly)

Alert `for:` windows (1–10 m) are too slow for per-PR. Nightly, codify EXECUTION T6:

- For each triggerable alert: induce the condition, poll `/api/v1/alerts` until `firing`, clear
  it, poll until `inactive`. (Triggers table in EXECUTION T6 / DESIGN §5.)
- **Short soak** (1–2 h in CI, not 12 h): assert `prometheus_tsdb_head_series` flat
  (cardinality/label-leak guard — e.g. unbounded `sip`), `avg_over_time(up[window]) ≈ 1` (no
  gaps), container RSS stable.
- Capacity/system alerts (CPU/Mem/Disk/conntrack) that can't be reached safely on a shared
  runner: threshold-lowered drills (DESIGN §7-sanctioned), rules restored after — or expr
  dry-run only, logged as such.

---

## 7. Assertion catalog (ground truth harvested from `MONITORING-EXECUTION.md`)

These are the concrete numeric checks the manual run established; Tier 1/2 encode them verbatim.

| Scenario | Ground truth | Assert (Prometheus/Grafana) | Tol |
|---|---|---|---|
| `ai-sse-quota` | N SSE streams completed | `Δloxilb_ai_requests_total{status="200"} == N`; duration histogram `count == N` | exact |
| `httpsproxy` (L7) | N HTTP responses | `Δloxilb_proxy_http_responses_total == N`; `ttfb_seconds_count > 0` (F4) | ±2 |
| L4 hold-driver | C held-open conns | `loxilb_active_conntrack_entries ≈ C` (both NAT legs); `/config/conntrack/all` non-empty `est` | ±C |
| L4 (named rule) | requests on `--name=svc` | `loxilb_service_requests_total{service="svc"}` attributes (F1: unnamed → empty) | exact |
| EP kill (T3.3) | 1 of 3 EPs down | `healthy 3→2`, `unhealthy 0→1`; `LoxilbUnhealthyEndpoints` fires after `for:` | — |
| `secfilter` + flood | SYN/UDP blocked legs | `loxilb_security_*_blocked_total` move; blocked-ratio tile amber; `LoxilbSyn/UdpFloodActive` fire→resolve | — |
| server-RST drive (F7) | R abortive closes | `Δloxilb_l4_error_events_total{reason="rst_server"} ≈ 2R` (2 events/conn — EXECUTION noted the factor) | — |
| idle | no traffic | family count ≈ 108; **zero alerts firing**; no panel shows a constant/error | — |

---

## 8. Prerequisites / blockers — the three findings

Product-level correctness gaps that block the "production-ready" bar. **F11 is resolved as a
design revision (no code); F12 and F13 remain open** (verified in the tree 2026-07-27). Each
becomes a permanent CI regression test:

| # | Defect | Production impact | Resolution | CI regression |
|---|---|---|---|---|
| **F11** ✅ | `--userservice` puts `/netlox/v1/metrics` behind JWT → scrape 401 (control-plane `Bearer` runs on every listener; mTLS never bypasses it) | metrics endpoint can't be secured by the data-path mTLS we ship | **RESOLVED — design revision, no loxilb code** (2026-07-27): metrics is control-plane; supported mTLS is data-path only. Default = same-host network-isolated plaintext scrape; `Bearer` token when API auth is on (long-lived-token caveat); `--tls` = optional transport encryption only. See `MONITORING-DESIGN.md` §2 / §9.1. | Tier-1 mTLS matrix dropped; assert default `http://127.0.0.1:11111` scrape `up==1`; document (not assert) the userservice+token path |
| **F12** ✅ | `llb_ai_record_request` had one callsite (SSE `[DONE]` only) → plain-JSON errors uncounted | `LoxilbAIErrorRatio` blind to the most common AI error shape | **RESOLVED (2026-08-01)** — `sockproxy` now records non-SSE responses at response-complete (submodule fix landed; testbed A/B: 5→9 on 4 non-SSE requests) | Tier-1 T3: N plain-JSON 500s via the AI rule → `Δai_requests_total{status="500"} == N` (note: `ai_gw_mode` derives from sse_mode/pd/apikey, so plain mode-4 rules are outside AI accounting by design — asserted as T3b) |
| **F13** ✅ | mgmt-plane / short REST conns ticked `l4_error_events{tcp,error}` (~3.5/call; drove 0.96/1.0) | any REST poller could **false-fire `LoxilbL4ErrorBurst`** | **RESOLVED (2026-08-01)** — `llb_kern_ct.c` counts `CT_TCP_ERR` only on established/closing connections (testbed A/B: 30 REST calls +161→+0) | Tier-1 T6: 30 REST polls → ≈0 `l4_error` Δ; T7: server RSTs still increment |

Ordering note: F11 is resolved in the design (no code). The remaining sharpest Tier-1/2
correctness tests (AI error-ratio, L4-error-burst) depend on F12/F13. Build Tier 1's harness
against what already works (L4/L7/SSE ground-truth + fired-alert drills), and add the two
data-path regression guards as each fix lands.

---

## 9. Step-by-step rollout (what "follow this doc" means)

0. **Tier 0** — ✅ done. Merge `monitoring-lint.yml` + the linter; it gates every stack/exporter
   change from now on.
1. **Tier 1 scaffold** — ✅ done 2026-08-01: `cicd/monitoring/{config.sh,validation.sh,rmconfig.sh}` +
   `docker-compose.ci.yml`; scrape matrix (disable→`up==0`→enable→`up==1`) per the F11 design
   revision (plaintext host-local scrape; mTLS matrix dropped).
2. **Tier 1 metrics** — ✅ done 2026-08-01: §7 ground-truth cross-checks (SSE, non-SSE, conntrack
   hold-driver, server-RST) + PromQL-expr and Grafana-proxy sweeps
   (`deploy/monitoring/ci/sweep-monitoring.py`).
3. **Tier 1 workflow** — ✅ done 2026-08-01: `.github/workflows/monitoring-e2e.yml`
   (build-from-source like `ai-gateway-sanity`, `ubuntu-22.04`); per-merge.
4. **Fix F12 / F13** — ✅ landed 2026-08-01 (submodule); §8 regression guards live as Tier-1
   T3 / T6 / T7.
5. **Tier 2** — ✅ done 2026-08-01: `drill.sh` (ScrapeDown / L4ErrorBurst / UnhealthyEndpoints
   fire→resolve with 30s drill windows, rules restored) + soak; nightly `monitoring-drill.yml`.
6. **Exit** — ✅ Tier 1 green in CI 2026-08-01 (run 30694327968; the first run's two failures
   were test defects, fixed: the non-SSE guard drove a rule outside AI accounting by design,
   and the hold-driver's un-drained close leaked client-RST events into the mgmt-plane
   assert). The manual T-plan is now a CI job. ⬜ remaining: first nightly
   `monitoring-drill.yml` run (drills + soak).

---

## 10. Notes / gotchas carried from `MONITORING-EXECUTION.md`

- `cicd/<scenario>/cert/` bind-mount shadows `/opt/loxilb/cert/` — install monitoring certs
  there, not via `docker cp`.
- `--tls-ca` is passed as env `TLS_CA_CERTIFICATE`, not a CLI flag (loxilb main's parser rejects
  the flag; the API sub-parser reads the env var).
- Editing rules on disk ≠ loaded — `docker kill -s HUP loxilb-prometheus` and verify via
  `/api/v1/rules` (a stale-rules footgun bit the F7 drill).
- Prometheus container runs `user: "0"` to read the `0600` client key bind-mount.
- Disable securityrate with `DELETE /config/securityrate` (POST-all-false is rejected 400).
