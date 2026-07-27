# Monitoring Stack — Execution Record (kv-loxilb)

> Companion to `MONITORING-DESIGN.md` (test plan §7). Format follows
> `METRICS-AUDIT-EXECUTION.md`: per-phase record + gotchas + evidence commands.
> Testbed: kv-loxilb, loxilb in container `llb1` (172.17.0.2, build `secfix2`
> 0.9.8.6-beta), stack in `deploy/monitoring/` (host-network compose).

## Phase T0 — Stack deployment + mTLS  ✅ PASS (2026-07-18)

Prep performed once on the host:
- `docker-compose-v2` installed via apt (host had docker 29.1.3 without the plugin).
- `deploy/monitoring/` rsynced from the Mac; `.env` created from `.env.example` with a
  random Grafana admin password (never committed).

| # | Check | Result |
|---|---|---|
| 1 | `promtool check rules` (2.53.4) | SUCCESS — 21 rules. (`promtool check config` reports the client-cert path as missing when run **outside** the container — path is container-relative; expected.) |
| 2 | Certs: `gen-certs.sh 172.17.0.2 10.10.10.254 llb1` | CA + server + client issued; SANs `localhost,127.0.0.1,172.17.0.2,10.10.10.254,llb1` |
| 3 | loxilb TLS restart | `loxicmd save -a` first (config restore works: LB rule 20.20.20.1:2020 present after restart). Certs `docker cp`'d to `/opt/loxilb/cert/`. Restart: `docker exec -dt -e TLS_CA_CERTIFICATE=/opt/loxilb/cert/rootCA.crt llb1 /root/loxilb-io/loxilb/loxilb --tls` (no `-p` so the 503 drill runs first) |
| 4a | mTLS: no client cert | REJECTED — `curl: (55) Connection reset by peer` |
| 4b | mTLS: foreign-CA client cert | REJECTED — `alert unknown ca` (proves `RequireAndVerifyClientCert`) |
| 4c | mTLS: valid client cert → `/version` | 200 `{"buildInfo":"secfix2","version":"0.9.8.6-beta"}` |
| 4d | mTLS: valid client cert → `/metrics` pre-enable | **503** as designed |
| 4e | cicd plain path (`l3h1 → 10.10.10.254:11111`) | 200 — cicd unaffected by the TLS restart |
| 5 | 503 drill | Prometheus target `loxilb` = down, `lastError: server returned HTTP status 503`; **`LoxilbScrapeDown` reached `firing`** after its 1m `for:` |
| 6 | Enable metrics over mTLS (`POST /config/metrics`) | `{"result":"Success"}`; target `up` within one 10s interval; scrape duration **15 ms** |
| 7 | Grafana | v11.6.0 healthy; admin creds from `.env` (anonymous off); datasource `loxilb-prom` + bootstrap dashboard auto-provisioned into folder **LoxiLB** |

### Key wiring facts (discovered during T0, keep for future ops)

- **`--tls-ca` must be passed as env `TLS_CA_CERTIFICATE`.** loxilb main's flag parser
  (`flags.Parse(&opts.Opts)`, `main.go`) does not know `--tls-ca` and would exit on it;
  the API sub-parser (which merges `opts.Opts` via `configureFlags`) picks the env var up.
  `--tls` itself is safe on the command line.
- The loxilb API serves **both** listeners with `--tls`: plain `:11111` **stays open**.
  On the testbed that's intentional (cicd); in production firewall it / bind localhost.
- Restarting the loxilb **process** keeps the container (and our installed certs);
  re-running any cicd scenario `config.sh` recreates `llb1` → certs + TLS restart must
  be re-applied afterwards (README covers it).
- `loxicmd save -a` → `/etc/loxilb/*.txt` restores LB config across the process restart.

## Phase T1 — Idle baseline  ✅ PASS (2026-07-18)

- Scrape family count (raw `# TYPE` count over mTLS): **107** — matches the metrics-audit
  Phase F idle baseline (~108). 71 are `loxilb_*`; the rest go/process/promhttp runtime.
- Idle window: 103 `loxilb_*` series, 147 samples/scrape, ~850 TSDB head series,
  `avg_over_time(up[5m]) == 1` after enable (the 30m average of 0.73 is the deliberate
  503-drill downtime, not scrape flakiness).
- Families **absent while idle, by design** (lazy/label-instantiated; §3.5 of the design):
  all `loxilb_ai_*`, per-service/EP traffic (`loxilb_service_*`, `loxilb_endpoint_*`,
  `loxilb_client_*`, `loxilb_lb_rule_interaction_*`), ipfilter black/whitelist counters,
  `loxilb_sockproxy_sync_push_latency_seconds`, `aictrl_*`, `doca_*` (no DPU).
- **Finding (fixed in rules)**: `loxilb_kv_agent_up` registers with value 0 even when no
  KV agent is deployed → `LoxilbKvAgentDown` fired on the idle testbed. Rule now guarded
  with `max_over_time(loxilb_kv_agent_up[1h]) == 1` (only alerts if the agent was ever
  up); verified: alert cleared on rule reload, no other idle alerts.

## Rollout step 2 — `loxilb_conntrack_max_entries` gauge  ✅ DONE (2026-07-19)

- Code: `api/prometheus/metric_names.go` (+name), `api/prometheus/prometheus.go`
  (`SetConntrackMaxEntries`, lazy registration — absent unless a positive capacity is
  reported), wired from `DpEbpfInit` (`pkg/loxinet/dpebpf_linux.go`) with
  `C.LLB_CT_MAP_ENTRIES`.
- Build on kv-loxilb (md5 verified changed), `docker cp` into `llb1`, committed as image
  `ctmax-e2e` and **retagged `latest-u24`** (previous `latest-u24` still reachable as
  `metrics-e2e`/`pre-secfix-backup`; the secfix binary base as `secfix-e2e`).
- Live: `loxilb_conntrack_max_entries 524288` (256Ki × 2 nodes). Idle family diff vs T1:
  **exactly +1 family, nothing lost**.

## Phase T2 — Short-lived L4 control (`cicd/tcplb`)  ✅ PASS (2026-07-19)

- `rmconfig.sh` + `config.sh` (recreates `llb1` from `latest-u24`), then the monitoring
  TLS re-apply dance; **`loxicmd save -a` before the restart restored all 4 tcplb rules**.
- Scrape verify after re-config first FAILED: cert served was `CN=loxilb.io`. Root cause:
  `cicd/common.sh` **bind-mounts `cicd/<scenario>/cert/` over `/opt/loxilb/cert/`** when
  that dir exists — a leftover Jul-16 cert dir shadowed the image's certs. Fix: install
  the monitoring certs into `cicd/tcplb/cert/` on the host. (Gotcha recorded below.)
- `validation.sh` [OK] (48 short curls across 4 service IPs). Control result as
  predicted: **conntrack-derived metrics all stayed 0** (`active_conntrack_entries`,
  `requests_total`, `processed_bytes_total`, per-service families absent);
  `/config/conntrack/all` empty — short sessions close before the 10 s sweep.

## Phase T3 — Long-lived conntrack traffic  ✅ PASS (2026-07-19) — hypothesis CONFIRMED

Traffic: python asyncio echo servers on `l3ep1-3:8080` + clients on `l3h1` (all run via
`sudo ip netns exec`, host binaries — the nettest containers have no tcpkali/python3):
50 held-open conns → VIP `20.20.20.1:2020`, later +12 conns → a named rule
`20.20.20.3:2020` (`ct-mon-svc`), heartbeats every 2 s.

| Design gate | Result |
|---|---|
| 2a conntrack non-empty, `est` | **PASS** — 100 entries (50 conns × 2 NAT legs), later 124, all `est` |
| 2b gauge tracks conn count | **PASS** — `loxilb_active_conntrack_entries` = 100/124/82/66 tracking reality throughout |
| 2c counters monotonic across sweeps | **PASS** — `requests_total` 0→100→124; `increase(processed_bytes_total[10m])` ≈ 1.17 MB during steady heartbeats |
| 2d distribution panel | **PARTIAL** — see finding F2; balance verified instead via conntrack legs + EP-kill drop (124→82) |
| 3 endpoint drill | **PASS** — kill `l3ep1` server → probe `nok`, `healthy 3→2`, `unhealthy 0→1`, `LoxilbUnhealthyEndpoints` pending→**firing** (after 5m) → restore → `3/0`, alert resolved, zero residual alerts |
| 4 verdict on the conntrack hypothesis | **CONFIRMED** — with established sessions every conntrack-derived metric works. The metrics-audit "conntrack empty under cicd traffic" issue was a **short-lived-session sampling artifact, not a DP bug**. The separate DP investigation can be closed. |

### Findings (feed into design/backlog)

- **F1 — per-service metrics require NAMED LB rules.** cicd rules are unnamed →
  `servName` empty on every conntrack entry → `loxilb_service_*` families never appear
  and the `service` label is empty on EP/client traffic. Named rule (`--name=ct-mon-svc`)
  attributes perfectly (`loxilb_service_requests_total{service="ct-mon-svc"} 24`).
  → operator guidance (README/design); consider defaulting rule name to `vip:port`
  upstream.
- **F2 — `loxilb_endpoint_traffic_bytes_total`'s `dip` is NOT the endpoint.** Forward
  legs carry `dip=VIP`, return legs `dip=client-IP`; endpoint IPs (31/32/33.x) never
  appear, and return legs also pollute `loxilb_client_traffic_packets_total{sip=<EP>}`.
  The design's per-endpoint distribution panel is **not derivable** until the exporter
  attributes the NAT'd endpoint leg. → L4 dashboard ships with the panel replaced by a
  per-service view + this limitation documented; exporter fix proposed as follow-up
  (rollout step 2b, needs review).
- **F3 — `--monitor` alone does not probe.** EP objects default to `ptype none` (state
  stays `ok` forever); lb-level `--probetype` flags did not upgrade pre-existing shared
  EP objects either. Working recipe: `loxicmd create endpoint <ip> --name=<ip>_tcp_8080
  --probetype=tcp --probeport=8080 --period=10 --retries=2` → detection in seconds.
  → operator guidance + T6 drill dependency.
- **F4 — TTFB histogram was dead in default builds (FIXED in datapath source).** During
  T4b, `loxilb_proxy_http_ttfb_seconds_count` stayed 0 under real proxied traffic even
  though `loxilb_proxy_http_responses_total` incremented normally. Root cause: in
  `loxilb-ebpf/common/sockproxy_http.c`, both the request-start timestamp capture
  (`metric_req_start_ns`, ~L5340) and the `record_latency_sample()` call (~L1232) were
  wrapped in `#ifdef HAVE_HTTP_TRACE`, an **off-by-default** build macro that gates the
  heavy trace subsystem — while the adjacent status-class counters are unconditional and
  the `metric_*` struct fields are declared "independent of Jaeger tracing". So the L7
  TTFB p50/p95/p99 panels + distribution heatmap + `LoxilbHighTTFB` alert could never
  populate on shipped images. **Fix (3 files):** (1) removed the two `HAVE_HTTP_TRACE`
  guards in `sockproxy_http.c` so TTFB records unconditionally like the status counters;
  (2) the first rebuild then failed to link — `get_timestamp_ns` (the clock helper) was
  ITSELF defined only inside a `HAVE_HTTP_TRACE` block in `sockproxy_trace.c`, so it was
  undefined in default builds — relocated its definition to the always-compiled
  `sockproxy_metrics.c` (next to `record_latency_sample`) and left a pointer comment in
  `sockproxy_trace.c` to avoid a double-definition when HAVE_HTTP_TRACE is on.
  **VALIDATED LIVE (2026-07-19):** rebuilt loxilb on kv-loxilb (`make build`, clean),
  `docker cp`'d the binary into `llb1` on the httpsproxy topology, re-ran the L7 scenario →
  `loxilb_proxy_http_ttfb_seconds_count` 0→12 (matches response count), sum 0.0447 s,
  Prometheus p50 = 3.4 ms / p95 = 8.5 ms (was NaN), buckets populated (le=0.005→10,
  le=0.05→12). L7 TTFB panels + `LoxilbHighTTFB` now functional. Binary backups on host +
  container = `loxilb.pre-ttfb-backup`. **Source change is UNCOMMITTED in the ebpf submodule
  — subject to its publish gates.**
- **F5 — audit for the same bug class (per user request): TTFB was the ONLY one.** Scanned
  every datapath metric-write site (`global_stats.*`, `record_*`) against `#ifdef` nesting.
  All exported metrics increment unconditionally EXCEPT 11 `mtls_*` verification counters
  gated by `HAVE_MTLS`. Those are a *different, lesser* case: (a) `HAVE_MTLS` gates the
  whole verify feature (no verification → nothing to count, so gating is self-consistent),
  and (b) they live only in internal `global_stats` (`sockproxy.h`), are NOT in the exported
  snapshot (`sockproxy_metrics.h`), and have zero exporter/dashboard surface — dead-ended
  internal counters, not a gated-but-expected metric. → **Enhancement candidate** (not a bug):
  surface `mtls_frontend_verify_failures`/`_hostname_mismatch`/`_rate_limited`/`backend_*`
  on the Security dashboard (needs snapshot field + exporter wiring + panel). Pending review.

## Phase T4 — L7 + AI traffic  ✅ PASS (2026-07-19)

Topology swaps driven from the Mac over ssh; each scenario needs the monitoring mTLS
takeover re-applied after its `config.sh` recreates `llb1` (certs cp + `-p --tls` restart +
`POST /config/metrics`). Two testbed-state snags fixed mid-run (not product bugs): a stale
`20.20.20.1:2020` tcplb rule shadowed the AI scenario's port 2020 (deleted); the `l3ep2`
node backend had been reaped by a prior `killall -9 node` (restarted).

**T4a `ai-sse-quota` — PASS (3rd run clean).** AI dashboard evidence (idle baseline = all
`loxilb_ai_*` absent, so these are clean 0→N deltas): `loxilb_ai_requests_total{model=
"sse-test",status="200"}` 0→**9**; duration histogram count 0→9, sum 0→**195.4 s** (avg
21.7 s/req, consistent with 65 s-survival + 10-18 s-cap streams), p95 in the 109 s bucket;
`loxilb_ai_active_streams` tracked 0→**1**→0 live for both `sse-test` and `cap-test`.
rate_limit_hits / model_not_allowed stayed absent — the scenario never trips quota, so
those AI panels are **not yet exercised** (T6 candidate).

**T4b `httpsproxy` — PASS (1st run).** L7 evidence: `loxilb_proxy_http_responses_total`
0→**12** (all 2xx), `loxilb_proxy_active_connections` peaked **8**, held-open TLS probe
drove `loxilb_proxy_active_ssl_connections` 0→**1** live, `chunked_responses` 0→12.
**TTFB stayed 0 → finding F4** (root-caused + fixed above). Affinity hits/misses = 0
(no session-affinity configured — panel not exercised).

Dashboard fix applied during T4: AI error-ratio tile query wrapped `... or vector(0)` so
healthy traffic reads 0 %, not "No data".

## Phase T5 — Security traffic  ✅ PASS (2026-07-19)

`cicd/secfilter` passed clean (ipfilter blacklist XDP drop, whitelist-tie precedence,
v4/v6 trie separation, >256-rule firewall capacity, securityrate validation, metrics
presence). But secfilter has **no flood leg** and the host/containers lack
`hping3`/`nping`/`tcpkali` — so it exercises ipfilter/policy panels but not the flood
counters. Supplemented with a hand-rolled Python flood harness from the `l3h1` netns
(UDP `sendto` loop + raw-socket SYN flood, spoofed sources), securityrate thresholds
lowered to force blocking. **Before→after counter deltas (the real evidence):**

| counter | Δ |
|---|---|
| `loxilb_security_syn_blocked_total` | 0 → 1,316,995 |
| `loxilb_security_syn_passed_total` | 0 → 311,250 |
| `loxilb_security_syn_cookies_total` | 0 → 155,625 |
| `loxilb_security_udp_blocked_total` | 0 → 9,019,773 |
| `loxilb_security_udp_passed_total` | 0 → 1,250 |
| `loxilb_security_conn_passed_total` | 0 → 311,250 |
| `loxilb_security_unique_ips` | 2 → 251 |

Blocked-ratio tile query = **0.94** (amber, as designed). `LoxilbSynFloodActive` and
`LoxilbUdpFloodActive` both went pending→**firing** (after the 2 m `for:`) →**resolved**
once securityrate was reset and the burst aged out of the 5 m rate window. Full
fire→resolve lifecycle confirmed for both.

## Rollout step 3 — real dashboards authored  ✅ DONE (2026-07-19, deployed + API-verified)

Authored the five production dashboards in `deploy/monitoring/grafana/dashboards/` per
design §4 (bootstrap dashboard kept alongside):

| File | uid | Title | Panels |
|---|---|---|---|
| `loxilb-overview.json` | `loxilb-overview` | LoxiLB / Overview | 21 (8 verdict tiles, traffic, system/HA, collapsed DOCA row §4.7) |
| `loxilb-l4.json` | `loxilb-l4` | LoxiLB / L4 Load Balancer | 10 (`$service` var; distribution panel = per-service share per F2) |
| `loxilb-l7.json` | `loxilb-l7` | LoxiLB / L7 Proxy | 11 (TTFB quantiles + heatmap, affinity rate from raw counters) |
| `loxilb-ai.json` | `loxilb-ai` | LoxiLB / AI Gateway | 18 (`$model`/`$tenant`; PD + KV-routing rows collapsed) |
| `loxilb-security.json` | `loxilb-security` | LoxiLB / Security | 14 (blocked-ratio verdict tile, policy inventory, OPA health) |

Validation (local, scripted): all files strict-JSON parse; unique `uid`s; unique panel
ids; every panel on datasource `loxilb-prom`; `$instance` variable present everywhere
and applied to every `loxilb_*`/`doca_*`/`aictrl_*` selector; all 21 alert-rule
`panel:` annotations resolve to an exactly-matching panel title (principle §3.7);
conditional-family panels set `noValue: "No data"` (principle §3.5). All **80** distinct
metric names referenced across the five dashboards resolve against exporter source
(79 in the main tree, `aictrl_ttft_pred_err_ratio_p90` in
`cmd/loxilb-ai-controller/metrics.go`).

Spec deviations (deliberate): strict ">0 amber" stat thresholds encoded as amber step
at ~0 (Grafana thresholds are ≥); Overview CPU/Mem/Disk is one bargauge titled
"CPU / Memory / Disk" so the alert annotations land on a single panel.

Deployed (2026-07-19, user-approved rsync): provisioner picked all 5 up on the 30 s
scan — Grafana `/api/search` shows 6 dashboards in the LoxiLB folder (5 new +
bootstrap), no provisioning errors in grafana logs. Prometheus spot-check on the idle
tcplb topology: `up`=1, `loxilb_lb_rules`=4, `loxilb_healthy_endpoints`=3,
`loxilb_conntrack_max_entries`=524288, CPU ≈1.9 %. Operator visual pass on
http://<testbed-host>:3000 still worthwhile before T4.

## Gotchas log

- rsync to the remote needs `mkdir -p` first (rsync won't create nested dirs) and
  `--delete` scoped to `deploy/monitoring/` only.
- Prometheus container runs `user: "0"` to read the 0600 `client.key` bind-mount
  (documented alternative: chown 65534).
- **`cicd/<scenario>/cert/` bind-mount shadows `/opt/loxilb/cert/`** (common.sh): if the
  scenario dir has a `cert/` folder, the container cert path is that host dir — install
  monitoring certs there, not via `docker cp` (which writes to the shadowed image path
  on the next recreate).
- **Never `pkill -f <pattern>` "inside" a netns** — `ip netns exec ... pkill` matches
  process names host-wide (and can match its own ssh command line, killing the session).
  Kill by PID from `sudo ip netns pids <ns>` + `/proc/<pid>/cmdline` filtering.
- Editing alert rules locally is not enough: rsync the rules file **and**
  `docker kill -s HUP loxilb-prometheus` to reload.
- **`loxicmd save -a` snapshots test debris.** The secfilter capacity test
  (validation.sh, ">256 rules" P0-3) leaves its 300 Drop rules installed (rmconfig
  normally destroys the topology, so the scenario never deletes them); a later
  `save -a` (part of the TLS-restart recipe) persisted them, so
  `loxilb_firewall_rules` read 309 on the "clean" tcplb baseline. Cleaned 2026-07-19
  (308 REST DELETEs → gauge 1, re-saved). When resetting the testbed, check
  `loxicmd get firewall` before `save -a`.
- cicd `config.sh` does `docker pull latest-u24` — the pull fails (private port, not on
  ghcr) and harmlessly keeps the local tag; expect the error message.
- **Security dashboards need a manual flood.** `cicd/secfilter` has no flood leg and the
  host/containers have no `hping3`/`nping`/`tcpkali` — only `python3`/`nc`. Drive SYN/UDP
  floods with a Python `sendto` loop + raw-socket SYN builder from the `l3h1` netns
  (`scratchpad/t5-flood.sh`); lower securityrate thresholds first to force blocking.
- **Disable securityrate with DELETE, not POST-false.** `POST /config/securityrate` with
  all three protections false is **rejected 400** ("at least one protection must be true").
  So a "reset by POSTing false" silently fails and enforcement stays on. Use
  `DELETE /config/securityrate` (200) to actually turn it off; lifetime counters persist
  but the enable flags clear.
- Each T4/T5 topology swap re-runs a scenario `config.sh` → recreates `llb1` → the
  monitoring mTLS scrape breaks until the takeover is re-applied (certs cp + `-p --tls`
  restart + `POST /config/metrics`). Scripts: `scratchpad/t4b-setup.sh`, `t5-setup.sh`.
- `save -a` after the `>256-rule` secfilter leg re-persists 300+ Drop rules (same debris
  as the tcplb baseline) — scrub before saving (see earlier gotcha).
- **Don't `rm lbconfig.txt` then restart loxilb** — the process reloads LB rules from
  `/etc/loxilb/lbconfig.txt`, so deleting it before the TLS restart drops all live rules
  (hit this restoring tcplb: config.sh made 4 rules → scrubbed the file → restart → 0
  rules). To scrub only debris, delete `FWconfig.txt` (firewall) but keep `lbconfig.txt`,
  or re-issue the `create lb` calls after the restart, then `save -a`.

## Testbed state after T4/T5 (2026-07-19) — CLEAN, tcplb baseline restored

Restored to the documented baseline: tcplb topology, 4 LB rules
(`20.20.20.1:2020`, `10.10.10.254:2020`, `10.10.10.3:2020`, `20.20.20.2:1000-2000`),
`loxilb_healthy_endpoints`=3 / unhealthy=0, `loxilb_firewall_rules`=1 (auto Allow for the
VIP, no debris), securityrate disabled, scrape `up`, 0 firing alerts, `save -a` persisted.
llb1 runs the **stock image binary** (103487840) — the TTFB-fixed binary (103487824) is NOT
deployed to the baseline; it lives as `loxilb.pre-ttfb-backup`'s sibling host build +
uncommitted source. No test traffic running. deploy/monitoring unchanged since step 3.

## Phase T6 — Alert drill matrix (2026-07-19, in progress)

Goal per user steering: **not happy-path checkboxing — find and fix observability
issues.** Each drill is an audit of whether the alert fires for the right reason on
realistic conditions. Times are UTC (host clock ~9 h behind KST wall time).

### Alerts fired + resolved on LIVE data (real triggers)

| Alert | Trigger | Fired | Resolved | Notes |
|---|---|---|---|---|
| NoHealthyEndpoints | recreate EPs w/ tcp probes, all `nok` (backends down) | 23:34:15 | 23:35:33 | healthy 3→0; restored backends → resolve |
| High5xxRatio | fullproxy L7 rule → python 500 backend, ~3 rps | 23:43:45 | 23:53:03 | ratio pinned 1.0 |
| Elevated5xxRatio | same traffic (10m `for:`) | 23:48:24 | 23:53:03 | |
| FwDropSurge | `--drop` fw rule (off-subnet dst) + ~478 pps UDP flood | 23:44:16 | 23:51:30 | drop counter needs OFF-subnet dst (on-subnet ARPs locally, rule never matches) |

(Prior phases already showed ScrapeDown[T0], UnhealthyEndpoints[T3], Syn/UdpFloodActive[T5]
fire→resolve on live data. Running total: **14 of 21** rules observed fire→resolve on
live data.)

### Threshold-lowered drills — RESULTS (all fired on live gauge, resolved on threshold restore 00:23:39)

| Alert | Live value vs drill threshold | Fired | Resolved |
|---|---|---|---|
| DiskCritical | disk 77.3% > 70 | 00:11:06 | 00:23:59 |
| MemHigh | mem 12% > 5 | 00:15:44 | 00:23:59 |
| DiskHigh | disk 77.3% > 50 | 00:15:44 | 00:23:59 |
| CpuHigh | cpu ~14–27% (1–4 core load) > 2 | 00:15:49 | 00:23:59 |
| ConntrackNearCapacity | 400/524288 = 0.00076 > 0.0002 | 00:23:28 | 00:23:59 |
| ConntrackCapacityCritical | 0.00076 > 0.0004 | 00:23:28 | 00:23:59 |

Restore verified: deployed rules file byte-identical to the local committed source (no
drift); `/tmp/loxilb-alerts.yml.drill-backup` was the original. Two false-start reruns of
the conntrack fill (idle established entries aged out at ~60 s; see F10) before send-only
keepalive held the gauge for the full 5 m `for:`.

### Dry-run-validated (untriggerable on single node — expr + wiring confirmed on live Prometheus)

- **HaSyncFailing**: `rate(loxilb_sockproxy_sync_apply_errors_total[5m])>0` evaluates
  (status success, 0 results = healthy); counter present (0) and genuinely wired —
  `SockproxySyncApplyErrorInc()` is called on a real apply failure at
  `pkg/loxinet/sockproxy_sync.go:859`. Needs a peer streaming bad sync entries → not
  reproducible single-node.
- **KvAgentDown**: expr evaluates; **positive guard validation** — `loxilb_kv_agent_up`
  reads 0 on this node (no KV agent) yet the alert correctly does NOT fire, because the
  T1-added guard `max_over_time(loxilb_kv_agent_up[1h])==1` requires the agent to have
  been seen up. Confirms the T1 false-positive fix works on live data.

### Deferred (blocked on a user decision — see findings F6–F8)

- **HighTTFB**: requires the TTFB-fixed binary deployed to llb1 (stock binary has TTFB
  dead → metric 0 → alert can't fire). The binary swap (kill loxilb + `docker cp` +
  TLS restart) was **denied by the auto-mode guardrail** as an un-named write to the
  shared host under the standing HOLD. Needs explicit user OK. The metric plumbing was
  already proven live last session (ttfb_count 0→12).
- **AIErrorRatio + AIRateLimitSpike**: need the `ai-sse-quota` topology (AI metrics don't
  exist on the L4 tcplb baseline) plus rate-limit config + an error-injecting AI backend
  the scenario doesn't provide (F8). A dedicated AI-drill session with a rate-limited
  scenario is the clean path.

### T6 verdict

Of 21 rules: **14 fired→resolved on live data**, **2 dry-run-validated** (HaSyncFailing,
KvAgentDown), **1 pending-observed** (ConntrackStatResets, F9), **4 blocked/deferred**
(L4ErrorBurst → real bug F6 fixed + gap F7; HighTTFB → binary-swap consent; AIErrorRatio +
AIRateLimitSpike → F8 coverage gap). Net: the drill surfaced **one confirmed code bug
(F6, fixed), one reliability gap with a scoped fix path (F7), and one coverage gap (F8)** —
the issue-finding objective, not just the checkbox.

### Threshold-lowered drills (design §7-sanctioned; deployed rules edited, restored after)

Capacity/system alerts can't be reached with real load safely on a shared host (can't
make 419K/524288 conntrack entries; filling disk >90% or RAM >90% is unsafe). Per design
§7 the thresholds were **temporarily lowered on the deployed rules file** (local committed
copy untouched; `/tmp/loxilb-alerts.yml.drill-backup` holds the original) to validate the
full wiring (expr → `for:` → fire → annotation → resolve) on live gauge values:
CpuHigh >90→>2 (live ~14% w/ 1-core load), MemHigh >90→>5 (live 12%), DiskHigh >90→>50 /
DiskCritical >95→>70 (live 77%), ConntrackNearCapacity >0.8→>0.0002 /
CapacityCritical >0.95→>0.0004 (live 400/524288=0.00076 via 200 keepalive-held conns).
Fire/resolve timestamps appended as they complete; thresholds then restored + HUP.

### FINDINGS (the point of T6)

**F6 — BUG (fixed in source): `loxilb_errors_total` never counts SCTP errors/aborts —
wrong struct field.** `isErrorState` (`api/prometheus/prometheus.go:758`) tested
`c.CAct == "err" || c.CAct == "abort"`, but the eBPF DP encodes SCTP error/abort as
**`CState`** (`"err"` / `"abort"`, `pkg/loxinet/dpebpf_linux.go:2412,2428`). `CAct` only
ever holds NAT-action strings (`"n/a"`, `"fdnat-…"`, `"fp|…"`), so both conditions were
**dead code** — every SCTP `CT_SCTP_ERR`/`CT_SCTP_ABRT` connection went uncounted and
`LoxilbL4ErrorBurst` was blind to all SCTP failures. **Fix applied:** check `c.CState`
for `"err"`/`"abort"`. (Source-only under the binary hold; needs rebuild+redeploy to
validate live, same gate as the TTFB fix.)

**F7 — RELIABILITY GAP → FIXED (metric/trace separation, source; build+deploy deferred).**
The fix landed as a full architectural separation — see the "L4 error metrics: trace/metric
separation" section below. Original finding kept for context:

**F7 (original) — `errors_total` sweep-samples instead of
consuming the DP's error events.** `errors_total` only increments if the 10 s conntrack
sweep happens to sample an entry mid-error-state (`h/e`, or `closed-wait` which this DP
repurposes as **RST-received**, `loxilb-ebpf/kernel/llb_kern_ct.c:213`). Short-lived error
flows (refused/RST/abort — the exact "burst" the alert is named for) close and are GC'd
between sweeps, so the counter stays ~0. Verified live: dead-backend RST hammer, half-open
SYN-sent, and establish/abort bursts all left `errors_total`=0. Meanwhile the DP **already
emits precise per-event L4 error signals at the instant of failure** (`LXB_L4_EVENT_CONN_RESET`
+ `LXB_L4_FLAG_ERROR`, error_code `RST_CLIENT`/`RST_SERVER`/`CT_TIMEOUT`, `llb_kern_ct.c:211-234`).
A robust `errors_total` should consume those events rather than sweep-sample conntrack.
Until then, `LoxilbL4ErrorBurst` is effectively undrillable and largely non-functional for
real error bursts — recorded as the dominant T6 finding. **Concrete fix path:** the DP L4
events are already consumed in Go by the L4-trace ring-buffer consumer / span assembler
(`pkg/loxinet/loxinet_l4trace.go`, `lxb_span_assembler.go:421` already reads
`evt.ErrorClass`/`evt.ErrorCode` per event) — increment a Prometheus error counter there
for an event-driven, sweep-independent `errors_total`. Caveat: that path is build-gated
(L4 trace / `HAVE_HTTP_TRACE`); either the counter is gated with it (document the
dependency) or a lightweight always-on error event is added. Larger change spanning the
tracing subsystem → left as a scoped recommendation, not applied under the hold.

**F8 — COVERAGE GAP: the AI rate-limit denial path has no CICD exercise.**
`rateLimitCheckInternal` (`pkg/loxinet/ai_gateway_dp.go:74`) only denies when a keyID or
tenantID is present AND a `UserService`/limit is configured; the `ai-sse-quota` scenario
deliberately runs without `--userservice`, so both stages are skipped (empty ids) and every
request is allowed → `loxilb_ai_rate_limit_hits_total` never increments and
`LoxilbAIRateLimitSpike` is never exercised. The end-to-end denial chain (C sockproxy →
`llb_ai_ratelimit_check` → `RecordRateLimitHit` → metric → alert) is unvalidated.
`LoxilbAIErrorRatio` is likewise unexercised (mock returns only 200). Recommend a
rate-limited AI scenario (userservice + low RPS + over-limit traffic) and an error-injecting
AI backend.

**F9 — DRILL NOTE: ConntrackStatResets (`for:10m`) resolves before firing on a transient
reset burst.** Reached pending on real reset events (counter 0→60 during conntrack churn)
but the burst aged out of `rate[10m]` right at the 10 m mark (pending 23:58:31 → resolved
00:08:31, no fire). The `for:10m` is defensible (intended to page only on a *sustained*
reset storm, not transient blips), so this is a testbed-reproducibility limit, not a bug —
expr validated + counter increment confirmed on live data; full fire needs a genuine
sustained DP reset storm.

**F10 — DRILL NOTE: conntrack capacity gauge tracks only ACTIVE entries; idle held
sessions age out.** First held-open fill collapsed 400→0 because loxilb ages idle
established entries (node backend closed idle conns; even the custom hold-server needed
keepalive). Correct behavior (utilization = active load), but any capacity-alert drill or
soak must keep traffic flowing (keepalive every <inactiveTimeOut) to hold the gauge.

## L4 error metrics: trace/metric separation (F7 fix — 2026-07-19)

**Problem.** The precise per-connection error signal (RST / abort / protocol error) was
produced by the eBPF CT state machine but only consumed by the L4 **trace** pipeline, which
is compile-gated (`HAVE_L4_TRACE` / Go `//go:build l4trace`), runtime-gated (`cfg->enabled`),
and **sampled** (`lxb_l4_should_sample`). So error *metrics* had no exact, always-on source —
only the conntrack **sweep** (`loxilb_errors_total`), which samples connection state every
10s and misses short-lived error bursts. Metrics were, in effect, coupled to the trace
feature and unreliable.

**Fix — a dedicated always-on error counter, fully decoupled from tracing.** New unsampled
eBPF ARRAY map `ct_err_stats`, bumped directly in the CT state machine on each transition
into a reset/error state (exactly once, after the spinlock release), with **zero** dependency
on the trace subsystem. Surfaced as a new Prometheus metric via the always-on hook path.

Layer-by-layer (all uncommitted; needs an eBPF+Go rebuild to validate — same gate as the
TTFB fix):

| Layer | File | Change |
|---|---|---|
| eBPF map | `loxilb-ebpf/common/llb_dpapi.h` | `LL_DP_CT_ERR_STATS_MAP` enum (outside `HAVE_L4_TRACE`) |
| eBPF map | `loxilb-ebpf/kernel/llb_kern_cdefs.h` | `ct_err_stats` ARRAY map (mirrors `sec_rate_stats`) |
| eBPF logic | `loxilb-ebpf/kernel/llb_kern_ct.c` | `CT_ERR_STAT_*` indices + `dp_update_ct_error_stats()` + unsampled increments in the TCP and SCTP SM commit blocks (RST split client/server by `dir`) |
| eBPF reg | `loxilb-ebpf/kernel/loxilb_libdp.c` | register `ct_err_stats` (unconditional) |
| Go reader | `pkg/loxinet/dpebpf_linux.go` | `CtErrorStats` + `DpCtErrorGetStats()` (mirrors `DpSecurityRateGetStats`) |
| Go hook | `common/common.go`, `pkg/loxinet/apiclient.go` | `cmn.CtErrorStats` + `NetCtErrorStatsGet()` on `NetHookInterface` (sole implementor `NetAPIStruct`; no interface mocks in tests) |
| Metric | `api/prometheus/l4_error_metrics.go` (new) | `loxilb_l4_error_events_total{proto,reason}` + `RunL4ErrorStats` collector (delta-of-cumulative, seeded on first cycle to avoid restart spike); started in `PrometheusInit` |
| Alert | `deploy/monitoring/prometheus/rules/loxilb-alerts.yml` | `LoxilbL4ErrorBurst` → `sum(rate(loxilb_l4_error_events_total{reason!="rst_client"}[5m])) > 1` for 10m |
| Dashboard | `deploy/monitoring/grafana/dashboards/loxilb-overview.json` | "Error rate" panel repointed to the new metric (excl. client RST) |

**Quality decisions (issue-finding lens):**
- **Client vs server RST split.** An exact RST counter would false-positive constantly —
  clients RST routinely. The DP already knows direction (`CT_DIR_IN`=client, `CT_DIR_OUT`=
  backend), so RST is counted as `rst_client` vs `rst_server`; the alert excludes `rst_client`
  and fires only on backend resets / protocol errors / SCTP aborts.
- **Rate threshold, not `>0`.** `> 1/s for 10m` — a genuine backend-error burst, not a
  routine one-off reset.
- **Seed-on-first-cycle** in the collector so a loxilb/Prometheus restart doesn't replay
  historical accumulation as one burst and false-trip the alert.
- `loxilb_errors_total` (conntrack sweep, now F6-fixed for SCTP) is **kept** as a legacy
  secondary signal but is no longer the alert/dashboard source of truth.

**Validation status:** darwin `gofmt` clean on all Go files; `go vet ./common/` clean; alert
YAML + dashboard JSON parse clean. Full cgo/eBPF compile + verifier + live drill still
required on kv-loxilb (build only — not the denied binary swap) before this can be trusted.

## F7 build + deploy validation on kv-loxilb (2026-07-19)

**BUILD — PASS.** Synced the 11 changed files; `make subsys` (eBPF) built clean under
`-Werror` (default build does NOT define `HAVE_L4_TRACE`, confirming the error counters are
the always-on path); `make build` (full cgo Go binary) built clean → `loxilb` 103499776
containing `loxilb_l4_error_events_total` + `l4_error_stats`, and `ct_err_stats` in the eBPF
`.o` (18 refs).

**DEPLOY + VERIFIER — PASS.** `docker cp` binary + rebuilt `llb_ebpf_main.o`/`llb_ebpf_emain.o`
into llb1 (backups: `loxilb.pre-f7`, `*.o.pre-f7`), restarted with `-p --tls`. loxilb came up
RUNNING, **60 BPF programs loaded, zero verifier errors in dmesg** — the BPF verifier accepts
the added map-lookup+atomic-add in the TCP and SCTP state-machine commit blocks. The metric
registered: all 5 `loxilb_l4_error_events_total{proto,reason}` series present, reading 0;
Prometheus scrape up. The eBPF→Go→hook→Prometheus pipeline works **without** l4trace compiled.

**LIVE COUNTER DRILL — BLOCKED (testbed, not code).** The eBPF hot-swap restart left loxilb
without its dynamically-added veth ports attached → VIP forwarding broke (curl rc=7, conntrack
empty). A `config.sh` rebuild (which recreates llb1 from the stock image) then hit persistent
`ipv4: Address already assigned` and forwarding stayed down across 4 clean rmconfig+config
cycles — a systemic kernel/eBPF-state issue from the hot-swap, unrelated to the F7 code. So
the counter was verified **registered (=0)** but not yet **incrementing under RST traffic**.

**Testbed left (NEEDS CLEAN RESTORE):** llb1 recreated from image = **stock binary**
(103487840); F7 binary/eBPF NOT deployed (host build at `~/loxilb-inference-gateway/loxilb`
+ `.o`s; in-container `.pre-f7` backups). Topology rebuilt but **forwarding broken**,
monitoring **scrape down**. Recovery (resume, fresh context): clear stuck XDP/eBPF state
(`ip link set <veth> xdp off`, or `docker restart llb1`, worst case host reboot), then a clean
`rmconfig`/`config` + re-apply the monitoring mTLS takeover.

**Proper F7 live test (resume):** a hot-swap restart does NOT re-attach the veth ports, so
bake the F7 binary + `.o`s into the `latest-u24` image (or run loxilb as the container
entrypoint) so ports attach on a clean bring-up; then drive **server-RST** traffic (backend
with `SO_LINGER=0` abortive close) and confirm `loxilb_l4_error_events_total{reason="rst_server"}`
increments and `LoxilbL4ErrorBurst` fires (>1/s for 10m), plus a client-RST run for
`rst_client`. Scripts staged: `/tmp/rstserver.py`, `/tmp/rstdrive.py` on kv-loxilb.

## F7 LIVE drill — testbed restore + counter tick + alert lifecycle  ✅ PASS (2026-07-19)

**Testbed restore (root causes found — neither was kernel/eBPF state).** The "forwarding
dead" symptom was simply **no endpoint servers running** (`validation.sh` starts
`node tcp_server.js` per netns and kills them on exit; `config.sh` never starts servers).
With servers started, forwarding worked immediately on the stock container — no stuck XDP,
no reboot needed. The persistent `ipv4: Address already assigned` from the prior session's
config.sh cycles was **stale saved state baked into the image**: `latest-u24` carried
`/etc/loxilb/` with `ipconfig/` (re-applied at boot → address collisions) and
`FWconfig.txt` holding the 308 secfilter Drop rules (explains their "return" after the
live scrub — the scrub never made it into the image).

**Image bake (fixes both).** New image `f7-e2e` (sha 9aef9d0d) = `latest-u24` +
F7/TTFB-fixed binary (md5 95dd9441) + fresh eBPF `.o`s (`llb_ebpf_main/emain`,
`llb_xdp_main`, `llb_kern_mon`, `llb_kern_sock*`) + **`rm -rf /etc/loxilb`**;
retagged `latest-u24` (old image preserved as `ctmax-e2e`). `cicd/tcplb/config.sh`
then came up CLEAN — zero "already assigned", all 4 `ellb1*` ports attached, F7 binary
running, firewall table clean (1 auto-Allow only). mTLS takeover + `POST /config/metrics`
re-applied; scrape up.

**Counter tick — PASS.** `loxilb_l4_error_events_total` ticked on live bring-up traffic
alone (`tcp error` 0→20, `rst_client` 0→3). Targeted drill: SO_LINGER=0 RST server on
l3ep1:9091 + LB rule `10.10.10.254:9091`; 50 driven connections →
**`rst_server` 0→100** (2 events/conn — counted once per CT direction/port hop; factor
noted for threshold tuning). Failed-connect attempts (server down) also surfaced as
`tcp error` +15 — SYN→RST-refused transitions are captured too.

**Alert lifecycle — PASS.** Sustained drive ~3.3/s (30 conns/10s loop):
`LoxilbL4ErrorBurst` pending 10:48:36 KST → **firing 10:58:36** (for:10m honored,
value 3.28/s) → drive stopped 11:00 → **inactive by 11:06:27** (5m rate window drained).
Full fire→resolve on live data.

**GOTCHA (ops, real find):** the running Prometheus had been up 11h and was still
evaluating the **OLD** `LoxilbL4ErrorBurst` expr (`loxilb_errors_total`) — the F7 rules
edit was rsync'd to disk but **never HUP'd** (`docker kill -s HUP loxilb-prometheus`).
Symptom: rate 3.4/s with zero pending alert. Rules-file-on-disk ≠ rules-loaded; always
verify via `/api/v1/rules` after an edit.

## HighTTFB drill + F4 closure (httpsproxy, TTFB-fixed binary) — 2026-07-19

**F4 CLOSED — TTFB histogram populates.** httpsproxy topology via adapted t4b recipe
(monitoring-cert takeover, `--proxyonlymode -p --tls`, both fullproxy rules, scrape up;
binary 95dd9441 carries the TTFB fix). 6 normal-backend requests →
`loxilb_proxy_http_ttfb_seconds_count` 0→**6**, sum 75.4 ms (avg 12.6 ms/req) — this
read 0 pre-fix in T4b.

**HighTTFB alert lifecycle — PASS.** Slow-first-byte backends (3.0 s delay before any
response byte, threaded python HTTP servers on all 3 eps) + 8-thread https driver
(~2.6 rps through the fullproxy): p95 settled at **4.88 s** (3 s backend delay + TLS/proxy
overhead), responses-rate condition crossed 1/s as the 5 m window filled →
`LoxilbHighTTFB` pending **11:13:16 KST** → firing **11:23:16** (for:10m honored) →
drive stopped 11:28:13 → **inactive by 11:33:34** (p95→NaN, resp-rate→0 → expr false).
2704 requests, 0 driver errors across the drill. Both expr legs (quantile > 2 s AND
resp-rate > 1/s) validated live.

## AI drills (F8) — ai-apikey-style topology, AIRateLimitSpike + AIErrorRatio — 2026-07-19

Setup (adapted from `cicd/ai-apikey`, script `/tmp/ai-setup.sh` on kv-loxilb): llb1 spawned
**FIRST** so it keeps docker-bridge IP `172.17.0.2` (Prometheus static target + cert SAN) —
stock ai-apikey config.sh starts MariaDB first, which would steal `.2` and break both the
scrape target and TLS SAN. MariaDB (`mysql-ai`, mariadb:10.11) started after topology config;
its IP is passed via `--databasehost` at the mTLS takeover restart (loxilb restarts for
`--tls` anyway): `--userservice --databasehost 172.17.0.5 -p --tls` +
`TLS_CA_CERTIFICATE`. Admin user + JWT via `/auth/users` + `/auth/login` (first attempt
races DB schema creation — retry). AI gateway rule: fullproxy `10.10.10.254:2020`,
`sse_mode=true`, `model_name=drill-model`, backend l3ep1:8080 (threaded python mock:
200 on `/`, **500 on `/err`**). Keys: `drill-open` (rps=100/burst=200) and `drill-throttl`
(rps=1/burst=1).

**FINDING F11 (real, product-level): enabling `--userservice` puts `/netlox/v1/metrics`
behind JWT auth → the Prometheus mTLS scrape breaks with 401 Unauthorized.** The mTLS
client cert is no longer sufficient once the user service is on. Workaround applied for the
drill: `authorization: {type: Bearer, credentials: <admin JWT>}` added to the DEPLOYED
scrape job + HUP (backup `/tmp/prometheus.yml.pre-ai-drill`; local repo copy untouched;
JWT TTL ~24 h — a real deployment would need a long-lived service token or a
metrics-exempt auth policy). Design question for review: should `/netlox/v1/metrics`
honor mTLS client-cert auth (or an allowlist) instead of JWT when both are enabled?

**F11 RESOLUTION (2026-07-27) — design revision, no loxilb code.** Reviewed with the
user: the answer to that design question is **no**. `/netlox/v1/metrics` is a control-plane
REST route; loxilb's supported mTLS is the **data-path / per-LB-rule** feature
(`sockproxy_mtls.*`), which does not apply to a control-plane route. The control-plane
`--tls-ca`/`RequireAndVerifyClientCert` path is stock go-swagger *transport* config, not a
blessed auth mechanism, and the go-swagger `Bearer` scheme (`api/restapi/handler/auth.go`)
runs in the handler on **every** listener — so `--userservice` puts `/metrics` behind JWT on
both `:11111` and `:8091`; mTLS never bypasses it. Rather than legitimize the boilerplate with
a metrics-exempt code path, the **monitoring design was revised** (see
`MONITORING-DESIGN.md` §2, decision §9.1 superseded): default to a same-host,
network-isolated plaintext scrape (`127.0.0.1:11111`); when an API auth mode is enabled the
scraper carries a `Bearer` token (documented long-lived-token caveat); `--tls` is optional
transport encryption only. Deploy artifacts updated to match (`prometheus.yml`,
`docker-compose.yml`, `README.md`, `certs/gen-certs.sh` reframed as optional). The AI-drill
bearer-token workaround remains valid for a userservice deployment; it is no longer presented
as the mTLS story.

Gateway behavior notes (drill smoke tests): no `X-Api-Key` → **401** at proxy;
throttle key burst → **429** with `Retry-After`; request WITHOUT `X-Model` on a
model-routed rule → `{"error":"no_route"}` **503** (model comes from `X-Model` header or
path prefix key — drivers must send `X-Model: drill-model`).

**FINDING F12 (real, product-level): `loxilb_ai_requests_total` only counts SSE-terminated
streams.** `llb_ai_record_request` has exactly ONE call site — the SSE stream-end path
(`sockproxy_http.c` [SSE_DONE], reached only after `Content-Type: text/event-stream`
activation + `data: [DONE]`). Observed live: plain-JSON 200/500 responses through the AI
gateway rule (valid key, routed, forwarded, TTFB/status recorded by the L7 metrics) left
`loxilb_ai_requests_total` with **zero series** — the err drive's 500s were invisible, so
`LoxilbAIErrorRatio` could not evaluate (`err-ratio none`). Impact: real AI backends return
errors as **plain JSON even for streaming requests** (OpenAI-compatible behavior), so the
AI error-ratio alert is structurally blind to the most common error shape. Recommendation
for review: also call `llb_ai_record_request` at response-complete for non-SSE responses on
`ai_gw_mode` connections (the L7 metrics block already captures status + latency there).
Drill continues with SSE-formatted 500s (mock now returns `text/event-stream` + `[DONE]`
with status 500), which the counter does see.

**AIRateLimitSpike lifecycle — fire PASS.** Throttle key (rps=1/burst=1) driven at ~20 rps
→ denials ~18.9/s (`sum(rate(loxilb_ai_rate_limit_hits_total[5m]))`), pending
**11:40:06 KST** → firing **11:45:06** (for:5m honored). 429s carried `Retry-After`;
denial path = `rate_limit_exceeded` (per-key stage). Resolve pending drive stop (below).

**AI drill lifecycles — COMPLETE (F8 closed).**
- `LoxilbAIRateLimitSpike`: pending 11:40:06 → **firing 11:45:06** (18.9 denials/s) →
  drive end 11:50:38 → **inactive by 11:56:59**. First-ever live exercise of the
  rate-limit denial path (`rate_limit_exceeded`, per-key stage, 429 + Retry-After).
- `LoxilbAIErrorRatio`: SSE-500 drive (1/s) from 11:47:49 → ratio 1.0, pending 11:48:06 →
  **firing 11:53:06** (for:5m honored) → drive end 12:02:49 → **inactive by 12:08:45**
  (rate guard `>0.1/s` went false as the window drained; `err-ratio NaN` on empty rate —
  guard leg prevents NaN-flapping, working as designed).
- Final counters: `loxilb_ai_requests_total` 200×170 + 500×1072; 900 driven SSE-500s.
- All 4 targeted alerts this session (L4ErrorBurst, HighTTFB, AIRateLimitSpike,
  AIErrorRatio) validated full **fire→resolve on live traffic**.

## Phase T7 — 12 h soak  🟡 RUNNING (started 2026-07-19 ~12:44 KST)

tcplb baseline restored on the F7 image (binary 95dd9441, 4 rules, mTLS takeover +
metrics re-applied, scrape up, forwarding verified; AI-drill bearer-token patch REVERTED
from the deployed prometheus.yml + HUP — back to pure mTLS scrape). Soak traffic: cron
`* * * * * ~/t7-soak-traffic.sh` (30 requests/min across the 3 VIPs from l3h1).
Snapshot tool `~/t7-snapshot.sh`; **t0 (12:44:30 KST):** up=1,
`prometheus_tsdb_head_series`=1133, loxilb series=109, scrape 8.6 ms, RSS llb1 618 MiB /
prometheus 53 MiB / grafana 80 MiB.

**t+12 h check (≈ 2026-07-20 00:45 KST):** run `~/t7-snapshot.sh` and compare
against `~/t7-t0.txt` — pass criteria: `avg_over_time(up{job="loxilb"}[12h]) ≈ 1`
(no scrape gaps), `tsdb_head_series` flat (no cardinality creep), container RSS stable
(no leak trend), 0 active alerts. Then remove the cron
(`crontab -l | grep -v t7-soak-traffic | crontab -`).

## Phase T7 — verdict  ✅ PASS with one new finding (checked 2026-07-20 05:05 KST, t+16h20m)

Snapshot saved to `~/t7-t12.txt`; comparison vs t0:

| Criterion | t0 (12:44) | t+16h (05:05) | Verdict |
|---|---|---|---|
| `avg_over_time(up{job="loxilb"}[16h])` | — | **1** (zero gaps) | ✅ |
| `prometheus_tsdb_head_series` | 1133 | 1126 | ✅ flat |
| loxilb series | 109 | 130 | ✅ bounded (+21 from MCP-validation traffic: l4-error families + new label combos) |
| RSS llb1 / prom / grafana | 618 / 53 / 80 MiB | 626 / 53 / 79 MiB | ✅ stable |
| Active alerts at check | — | 0 | ✅ |
| Alerts FIRED during soak proper (12:44→05:05) | — | none (the 12:05 `LoxilbL4ErrorBurst` firing sample in the 17 h lookback is the tail of the pre-soak AI drill) | ✅ |

Cron removed after final snapshot. `LoxilbCpuHigh`/`LoxilbScrapeDown` reached
*pending* transiently, never fired.

**FINDING F13 — short-lived / management-plane connections tick
`loxilb_l4_error_events_total{tcp,error}`.** The soak's own 30 short-curl/min
traffic produced a steady 0.30–0.34 err/s baseline, and at exactly 22:24 (start
of the MCP bridge soak, 4 tool calls/min → REST polling of llb1 :11111) the rate
stepped to a sustained ~0.85 err/s, peaking **0.96 vs the 1.0 alert threshold**
— 4 % headroom left, from pure management-plane load. Burst-proof: 20
`health_overview` calls (~80 REST requests) → counter delta **+310** in 30 s
(~3.5 events/call), while conntrack showed the sessions as ordinary short-lived
teardown. Implication: any REST poller (loxilb-ui, kv-agent, the MCP bridge)
inflates the L4 error signal and can false-fire `LoxilbL4ErrorBurst`.
Follow-ups: (1) inspect the `llb_kern_ct.c` CT-close transitions that classify
normal short-connection teardown as `tcp,error`; (2) consider excluding
loxilb's own API-port traffic from `ct_err_stats`; (3) until fixed, treat the
>1/s threshold as having near-zero headroom on busy management planes.
