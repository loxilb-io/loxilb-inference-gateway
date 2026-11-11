# Changelog

All notable changes to loxilb-inference-gateway are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Because this is a fork of [loxilb](https://github.com/loxilb-io/loxilb), releases
follow upstream's version scheme — `vMAJOR.MINOR.PATCH` with an optional fourth
build component (e.g. `v0.9.8.7`), plus `-rc.N` for a release candidate — so the
upstream baseline is readable at a glance. The reported version is derived from
the release tag at build time, never pinned in source. Changes inherited from an
upstream loxilb sync are summarized here by their upstream version; only the
inference-gateway delta is enumerated in detail.

## [Unreleased]

### Bundled CLI

- Pin the embedded CLI to `973c53c2`, including EPP + P/D support with explicit
  FailOpen. FailClose and an omitted mode are rejected before any API request.
- Build the CLI with its own explicit version (`v0.9.9.2`), independently of the
  Gateway image version. Release identity verification checks both the pinned
  source revision and CLI version.

### Fixed

- HA role gating follows configured KA/BFD or a valid cistate request. CT-only
  cluster peers, role-unmanaged active-active deployments, and egress endpoints
  retain NotDefined advertisements. Xsync startup requests run on an independent
  worker with per-peer backoff and source-address hello readiness; dead-peer
  network I/O no longer holds the broker membership mutex. Normal gobgpd shutdown
  sends SIGTERM, waits for graceful exit, and uses a bounded 5-second SIGKILL
  fallback. External daemon crashes retain their separate recovery semantics.

- Clustered BGP startup prepares the daemon and configuration independently of
  the HA hello wait. Initial peer registration, membership changes and transport
  reconnections request conntrack again; an empty startup peer list cannot
  permanently suppress sync. Early CT notifications are ignored until the local zone/rule
  initialization barrier opens. Configured HA blocks new and recovered LB
  advertisements until its role is known. Egress-only VXLAN endpoints retain
  standalone advertisements and reconnect replay without requiring an HA role.
  Application VIPs wait for both CI initialization (including saved BFD) and
  boot configuration replay before advertising, so LB replay cannot precede
  role-barrier activation. The 90-second wait default and
  MASTER/BACKUP advertisement priorities are unchanged. Wait logs distinguish
  ready, timeout and cancellation; hello readiness does not prove full CT sync.

- A delayed BGP speaker no longer blocks independent snapshot domains or
  quarantines the complete snapshot after the boot retry allowance. Independent
  LB rules keep serving while the BGP group retries; readiness remains 503.
  Persist and auto-persist merge live non-BGP state with the original pending
  BGP configuration. BGP mutation APIs return `409 bgp_domain_pending` until
  recovery or a successful full interactive restore replaces that intent.
  Late recovery re-advertises current LB routes without resurrecting deleted
  rules. `loxilb_boot_bgp_pending` exposes pending state.
- Deleting an LB now withdraws its BGP advertisement (VIP and secondary IPs)
  based on the stored rule. Previously, withdrawal depended on the `bgp` field
  of the delete request, and a single-port lookup key mismatch skipped secondary
  IPs, so a deleted LB's VIP could remain advertised.
- Fix HTTP 500 from `GET /config/snapshot` when BGP is enabled without a
  global configuration.
- Native HTTP/1 P/D requests follow the configured roles. Bodyless requests
  use decode endpoints without holding prefill/decode role units. Requests
  previously relayed whole to prefill now fail explicitly. Non-JSON uploads,
  including those above 64 KiB, receive `415 pd_body_unsupported_media`.
  JSON bodies above 768 KiB or the configured `LLB_PD_MAX_BODY_BYTES` limit
  receive `413 pd_body_too_large`, and chunked JSON bodies receive
  `413 pd_body_unbufferable`. Rewrite and allocation failures receive
  `500 pd_prepare_failed` before connecting either role, with reservations
  released. Pipelined native P/D requests receive
  `400 pd_pipelining_unsupported` instead of counting subsequent requests
  against the current body's limit. The legacy `loxilb_pd_fallback_to_normal_total` metric is
  deprecated and remains zero after removal of the role-0 fallback.

### Changed

- When a snapshot is selected at boot, a stale `BFDconfig.txt` is no longer
  applied before it. Strict failures retain snapshot authority; legacy replay
  remains available only through the explicit compat fallback.

- **OWNER REVIEW PENDING.** AI gateway: a refusal the gateway writes before any
  request byte reaches a backend now carries `X-Loxilb-Refusal-Stage` with the
  stage of its `sec.ai.deny` record (`auth`, `conflict`, `ratelimit`, `reserve`,
  `capacity`, `objective`, `route`, `framing`, `security`), or `queue` for a
  request that ended while it waited for capacity. Only `capacity` and `queue`
  are congestion. Refusals written by the prefill/decode code itself stay
  unmarked. Additive: no existing header, `error` code, body field, status or
  audit field changes. See
  [the client refusal contract](docs/load-balancing/27-ai-gateway-client-refusal-contract.md).

- **OWNER REVIEW PENDING.** AI gateway: an answer the gateway writes itself, a
  refusal or an outage, echoes the request's own ID as `X-Request-Id` (the
  client's, at most 255 bytes, or the minted one), on HTTP/1.1 and HTTP/2. The
  header is absent when the request has no ID of its own at that moment, and it
  is never another request's on a keep-alive connection. A relayed backend
  response keeps the backend's own header.

- **OWNER REVIEW PENDING.** AI gateway: `X-Loxilb-Refusal-*` fields sent by a
  backend are removed from every relayed response head, with or without
  `fc_expose_headers` (HTTP/1.1: a head that arrives in one read; HTTP/2: the
  interim and the final head).

- **OWNER REVIEW PENDING.** AI gateway: the HTTP/2 `503` capacity body gains
  `retry_after`, equal to the `retry-after` header, as on HTTP/1.1; the queue
  endings' plain fallback answers gain `Content-Length`.

## [v0.9.9.1] - 2026-11-03

`v0.9.9.1` is the first final release since `v0.9.8.7` (2026-08-10); `v0.9.8.9-rc.1` (2026-08-28) was a pre-release between them. Neither has its own section, so this one holds everything since the fork from upstream loxilb `0.9.8.6-beta`, including what `v0.9.8.7` first shipped. AI routing and enforcement stay opt-in per load-balancer rule; some defaults changed for every deployment, see Changed and Upgrade notes.

### Added

- **Idempotent API-key creation and one transaction per management write.**
  A generated key's secret is delivered once, so a create whose answer was
  lost to a store stall (504) could leave an enabled key nobody holds the
  secret of, and a retry made a second one. `POST /config/ai/apikey` takes an
  optional `client_op_id` (also the `Idempotency-Key` header): a retry with
  the same id converges on one row per tenant. While that key has never
  authenticated the secret is minted again and delivered with the same
  `key_id` and `reused: true`, and the earlier secret stops authenticating
  everywhere; once it has, the retry answers 409 `api_key_already_delivered`
  naming the `key_id`. The id shows on the key's summary. A key create with
  class fields, a PATCH of several fields, a tenant limit with its model
  quotas and a user limit with its model quotas each run as one store
  transaction, applied whole or not at all. Every write answered 504 now
  leaves an audit result with reason `store_outcome_unknown` (a create's
  detail carries the tenant and `client_op_id`) and steps
  `loxilb_ai_store_write_outcome_unknown_total{plane}` (`aikey`, `mgmt`), so
  the writes an operator must reconcile are countable and findable.
  (docs/AI-KEY-STORE.md, "Time budgets and the write-outcome contract")
- **Data-path isolation for the API-key store.** A cache miss during a store
  stall no longer costs every proxy worker one full lookup budget for as long
  as the stall lasts. Two guards sit in front of the data-path reads (the key
  lookup on a miss and the quota-row reads behind a request): an in-flight
  bound (`LLB_AI_KEY_LOOKUP_MAX_INFLIGHT`, 2; the wait for a slot shares the
  lookup budget, so a worker is parked at most one budget in total) and a
  store-health circuit (`LLB_AI_KEY_LOOKUP_CIRCUIT_FAILURES`, 3, consecutive
  failures; `LLB_AI_KEY_LOOKUP_CIRCUIT_COOLDOWN_MS`, 5000) that, once open,
  refuses misses without contacting the store and serves every quota read from
  the last store-confirmed value, admitting one probe per cool-down. The
  management plane, readiness and the snapshot refresher bypass it;
  `store_reachable` and the new `loxilb_ai_key_store_circuit_open` gauge are
  independent signals, and the gauge stays 1 after recovery until a miss runs
  the probe. A bounded negative cache (`LLB_AI_KEY_NEGATIVE_CACHE_MS`, 2000;
  `LLB_AI_KEY_NEGATIVE_CACHE_CAP`, 4096) refuses a hash the store said does not
  exist without another round trip. New families:
  `loxilb_ai_key_store_lookup_seconds{result}`,
  `loxilb_ai_key_store_circuit_open`, `loxilb_ai_key_store_lookup_inflight`.
  Fixed on the way: a key's per-key RPS and token quota read as unlimited when
  the by-ID row could not be read during an outage. The by-hash validation and
  the by-ID read now keep the last store-confirmed view of the key, and a key
  the process has never seen described fails closed with 503
  `policy_store_unavailable` instead of being admitted on zero limits.
  (docs/AI-KEY-STORE.md, "Data-path isolation")
- **P/D decode selection counters: `loxilb_ai_pd_decode_selected_total{path=hint|score|score_kv,model}`
  and `loxilb_ai_pd_decode_kv_fill_total{model}`**. Both
  are seeded per model so a first event shows in `increase()`. `kv_fill` rising
  means the pool is being scored without a fresh KV reading. (docs 10 §3.6, 11)
- **`GET /netlox/v1/version` lists the gateway-only capabilities of the build
  under `features`** (`api_key_auth`, `jwt_auth_profile`), as stable tokens a
  controller checks before it sends the matching rule fields. The REST layer
  ignores fields it does not know, so a build without a token would install a
  rule without the credential policy the caller asked for and report success;
  kube-loxilb reads this list to refuse the rule instead. Absent on builds
  that predate the field.
- **Helm chart** `deploy/helm/loxilb-inference-gateway`: one release installs
  the loxilb-igw DaemonSet, the kube-loxilb controller (from
  `integration/inference-gateway`, with its CRDs) and the Gateway API objects
  that express the endpoint-selection policy, one InferencePool + HTTPRoute per
  `inference.pools[]` with `loxilb.io/model-name`, `loxilb.io/epselect`,
  `loxilb.io/sse-mode` and free-form `loxilb.io/*` annotations. A pre-install
  hook fails with the install commands when the Gateway API (v1.5.1) or
  Inference Extension (v1.6.0) CRDs are missing, or applies them with
  `crds.installGatewayAPI=true`; `helm test` checks the management REST flavor
  and InferencePool -> Service -> loxilb rule. `inference.pools[].auth` renders
  `loxilb.io/api-key-auth` / `loxilb.io/jwt-auth-profile`, which kube-loxilb
  `feat/auth-annotation` (830fa59) carries into the rule; the kube-loxilb
  subchart ships that branch's `JWTAuthProfile` CRD and RBAC, and NOTES warns
  when an older kube-loxilb, a missing profile or a gateway without its
  API-key store would leave such a rule unauthenticated or refusing every
  token. A pre-delete drain deletes the chart's HTTPRoutes and InferencePools
  while kube-loxilb still runs and waits for the Services it derived from them,
  so `helm uninstall` leaves nothing but the CRDs. The new scenario
  `cicd/k3d-helm-inference-gwapi` installs the chart with `values-k3d-dev.yaml`,
  re-runs the `k3d-incluster-inference-gwapi` assertions unchanged against it,
  and then upgrades, uninstalls and reinstalls the release.
  `docs/HELM-INSTALL.md` is the operator's guide: prerequisites, values,
  install, `helm test`, upgrade, uninstall, authenticated pools, pools with an
  Endpoint Picker and troubleshooting. `inference.externalEndpointPicker`
  points every pool at an Endpoint Picker Service the operator deploys;
  kube-loxilb `feat/auth-annotation` resolves it onto the rule, and the
  gateway follows the picker with `FailOpen` / `FailClose` as declared. The
  `loxilb-igw` image defaults to `ghcr.io/loxilb-io/loxilb-inference-gateway:v0.9.9.1` (Ubuntu 22.04 base), which carries the picker client and lists `epp` beside the credential features.
- **P/D occupancy gauges.** Three new metrics read the P/D load at each
  collection: `loxilb_pd_prefill_inflight` and `loxilb_pd_decode_inflight`
  (the admission units held on prefill and on decode endpoints now) and
  `loxilb_pd_parked_connections` (client connections parked for a prefill
  slot). They are gauges of the snapshot and return to zero when the load is
  gone. The C, Go and stub mirrors of the snapshot now assert the struct's
  size, so a mirror that falls out of step fails the build instead of
  reading the wrong fields.
- **Priority bands in the capacity gate's queue:** a request's class
  (`critical`, `standard`, `sheddable`) is its band at the gate. Under
  `fc_wake_policy: strict` (the default) a freed unit goes to the highest band
  with a waiter able to run, and a newcomer waits only behind its own band or a
  higher one; a sheddable request at the ceiling is refused `429
  admission_shed`, or, with `fc_shed_queue: on`, waits and gives its place to a
  higher band's arrival at a full queue. Nine rule knobs configure the bands —
  `fc_wake_policy`, `fc_band_weights`, `fc_band_min_share_pct`,
  `fc_critical_reserve_pct`, `fc_band_wait_ms`, `fc_band_queue_pct`,
  `fc_shed_queue`, `fc_tenant_wake`, `fc_llmd_headers` — read back in
  `fc_effective` with their sources. New counter
  `loxilb_ai_fc_band_total{service,band,outcome}` (outcomes `admitted`,
  `queued`, `shed`, `expired`, `cancelled`; fifteen series per service) and the
  reason `shed` in `loxilb_ai_admission_decisions_total`. A pool whose requests
  are all `standard` admits and wakes as before. The band counter splits the
  gate's decisions; it is not a second request count: in
  `loxilb_ai_requests_total` a shed or expired request is one `denied` request
  and a cancelled one is `aborted` with cause `client`. See
  `docs/load-balancing/23-ai-admission-flow-control.md`.
- **Weighted wake and tenant rotation for the priority bands:**
  `fc_wake_policy: weighted` serves the bands as a deficit round robin by
  `fc_band_weights`: within a round the bands are served highest first, and the
  credit decides how many each band gets per round (with `8:3:1`, every 12
  wakes are 8 critical, 3 standard and 1 sheddable, while all three bands
  wait); `fc_tenant_wake: rr` rotates
  across the tenants waiting inside a band. Floors still come first; a change
  of policy or weights loses no waiter. Both are off by default (`strict`,
  `fifo`). See `docs/load-balancing/23-ai-admission-flow-control.md`.
- **Wait windows and queue shares per band, and the llm-d headers:**
  `fc_band_wait_ms` gives a band its own wait window, a cap inside the rule's
  `fc_max_queue_wait_ms`, and `fc_band_queue_pct` bounds a band's own occupancy
  of the queue depth (a ceiling, not a reservation). With `fc_llmd_headers` on,
  refusals carry `x-llm-d-request-dropped-reason`, a shorter
  `x-llm-d-inference-ttl` shortens a request's wait (answered `429
  admission_ttl_expired` when the client's TTL ended it; a window of the rule
  still ends in `504`), and the objective and fairness identity forwarded to the
  backend are the gateway's resolved values. Off by default; a rule that sets
  none of them is unchanged. See
  `docs/load-balancing/23-ai-admission-flow-control.md`.
- **Priority floors and a critical reserve for the capacity gate:**
  `fc_band_min_share_pct` guarantees a priority band a share of the service
  ceiling while it has a waiter (a guarantee under contention, not a
  reservation), and `fc_critical_reserve_pct` holds units back from every other
  band even when critical is idle. Both read back in `fc_effective.bands`
  (`floor_units`, `critical_reserve_pct`, `critical_reserve_units`). See
  `docs/load-balancing/23-ai-admission-flow-control.md`.
- **Every HTTP/2 client connection logs one line when it ends, naming why**
  (client closed, header deadline, idle timeout, a backend connection ending,
  listener delete, endpoint teardown, the P/D reaper, an error), the backend
  connection and endpoint when one caused it, the open streams and the time
  since the last request. Info for an ordinary end, warning when requests were
  lost or the gateway decided.
- **KV-cache-aware routing** for LLM serving fleets: cache-locality-aware
  endpoint selection driven by the serving engines' native contracts
  (vLLM `--kv-events-config` ZMQ events; SGLang radix-cache semantics).
- **Prefill/decode (P·D) disaggregation** routing, including KV-exact mode over
  a prefill/decode topology (`kvExactMode:1` + endpoint role, as shipped for
  vLLM) and single-role KV-exact over a role-less pool (`kvExactMode:3`, as
  shipped for SGLang). `kvExactMode` selects the topology; the serving engine
  and its block-hash contract are selected independently by `kvEngineType`.
- **Consistent-hash cache routing** (CHWBL) for aggregated vLLM pools.
- **MCP gateway** support: session-sticky routing for Model Context Protocol
  server pools.
- **AI gateway controls**: per-rule API-key auth and rate limiting, armed via
  `sse_mode` on L7 fullproxy rules.
- **AI control plane**: `loxilb-ai-controller` (TTFT-adaptive controller) and
  `loxilb-kv-agent` (DOCA) components, plus AI metrics export.
- **eBPF data-path extensions** for inference routing, tracked in the
  `loxilb-ebpf-inference-gateway` fork and pinned via the `loxilb-ebpf`
  submodule.
- **REST API / swagger** extensions for all AI fields (`api/swagger-extras.yml`
  and generated models).
- **Documentation** under `docs/load-balancing/` covering AI gateway L7, REST
  API reference, KV-cache-aware routing (incl. hierarchical and P·D deep dives),
  MCP gateway, and AI gateway controls.
- **CI**: `ai-gateway-sanity`, `mcp-sanity`, `l7-proxy-sanity`, and
  `vllm-proxy-sanity` workflows, plus the automated upstream-sync chain
  (`upstream-sync.yml`, `ebpf-pin-bump.yml`). `ebpf-pin-check.yml` fails a
  pull request, and main, whose `loxilb-ebpf` pin is not a commit on the ebpf
  fork's main; a pull request pinned to an unmerged ebpf change on purpose
  carries the `ebpf-temp-pin` label, which turns that into a warning. Every
  loxilb the scenario harness spawns gets a REST readiness probe
  (`[rest-probe]` lines in the job log: time to the first answer, or a dump
  of the container state and loxilb's output on timeout); it reports and never
  fails unless `LOXILB_REST_PROBE=fail`.
- **Token quotas (tokens-per-minute)** for AI gateway rules: per-tenant and
  per-tenant-and-model budgets enforced from the tokens the serving engine
  reports. Usage is read from the engine's own `usage` block, with
  `stream_options.include_usage` injected on streaming requests so a client
  cannot opt out of accounting. Requests are checked **before** dispatch —
  the prompt plus any declared completion ceiling is reserved up front and
  reconciled at completion — so an over-budget request is refused with `429`
  instead of being detected after the GPU has already been spent. Quota is a
  smooth token bucket, so a tenant recovers continuously rather than at a
  fixed window boundary, and idle per-tenant state is evicted. Configured via
  `tokens_per_min` on the tenant rate-limit API and optional `model_limits`
  for per-model budgets. Bucket capacity — how much of a minute's budget a
  fully idle tenant may spend at once — defaults to one whole minute and can be
  narrowed or widened per tenant with `burst_pct` on the same API.
- **Traffic policing and shaping**, layered:
  - **Load-balancer-rule policers** (eBPF) — a bandwidth budget attached to a
    rule rather than a port, applied to both directions of the session.
  - **Egress-direction port policers** behind `--egr-hooks`, applied to
    host-originated egress and to transit traffic leaving through the port.
    Transit is policed after the forwarding decision, against the port the
    packet actually leaves by, so both classes meet the same budget.
  - **An L7 byte shaper** for full-proxy AI rules, which *paces* payload bytes
    to the configured rate in either direction instead of dropping them.
    Shaper-paused time is excluded from idle and stream-duration reaping, so
    pacing a long response or an SSE stream cannot manufacture a disconnect.
- **Observability for both of the above**: Prometheus series for token
  consumption (split by how the count was obtained), quota utilization and
  limits, quota denials, and per-service shaper counters — bytes passed and
  delayed, pause count and duration, currently-paused connections, and the
  configured rate and burst. The bundled AI dashboard gains a token-quota row
  and a byte-shaper row. `GET /metrics` is exempt from management-plane bearer
  auth so a scraper needs no credential, except under `--mgmt-profile remote-tls`,
  which asks for credentials.

- **Request priority: objectives and classes.** A request on an AI-gateway
  rule has a priority and a class (`critical`, `standard`, `sheddable`). It
  asks for an objective by name with the header `x-llm-d-inference-objective`
  (the older `x-gateway-inference-objective` is accepted), or, without one,
  with the body's `service_tier` (`flex`, `priority`, `fast`); on both
  channels a hint that raises the request above what it gets without one
  must be in the identity's `allowed_objectives` (a tier as `tier:flex`,
  `tier:priority`, `tier:fast`), and a hint at or below that is always
  applied and never `objective_denied`, strict rule or not. What it gets is held under the
  `priority_class` of its tenant (a tenant that sets none is held at
  `standard`), lowered by its API key or JWT auth profile and the
  network-identity binding that named its tenant, so a client can lower its
  request and never raise it above what its tenant was granted. New:
  `POST` / `GET` / `DELETE /config/ai/objective`; `priority_class`,
  `default_objective` and `allowed_objectives` on tenants and API keys;
  `priority_class` on JWT auth profiles and network-identity bindings; the
  rule knob `ai_objective_strict` (403 `objective_not_allowed` for an
  objective or a raise the caller may not use, instead of its default);
  `X-Loxilb-Admission-Class` / `X-Loxilb-Admission-Objective` on admitted
  responses of a rule with `fc_expose_headers`; `priority_class`, `priority`,
  `objective`, `objective_denied` and `hint_not_applied` on the
  `data.ai.complete` record and on the `sec.ai.deny` record of a request
  refused after its class was decided. A `service_tier` the gateway read as
  a hint is replaced by `null` in the forwarded body (same length), every
  top-level occurrence of it; with the key more than once the last is the
  one read. With no
  objective and no class field configured anywhere nothing is read and
  every request is handled as before. Objectives and classes live in the AI
  key store and are served from the last-known-good file `aigw-lkg.json`
  (under `--config-path`), which also carries the tenant, tenant-and-model
  and default limit rows, by a gateway that starts while the store is away:
  a tenant named by a network-identity binding is then served with its
  limits, a request with an API key is refused 503 `policy_store_unavailable`
  (keys are never written to disk). `fc_effective.config_source`,
  `loxilb_ai_class_config_lkg_intervals_total` and the `source` /
  `source_timestamp` of `GET /config/ai/objective` (which answers with the
  applied list while the store is away) say where the configuration in
  force came from; `store_reachable` and `store_last_read` on both say,
  whatever the source, whether the store answered its latest read and
  when a read last answered. See
  `docs/load-balancing/19-ai-gateway-controls.md`.
- **P/D decode is measured in two parts, and the prefill fallback is
  counted.**
  - New `loxilb_ai_pd_decode_duration_seconds`: decode dispatch to the end
    of the decode response. That is what `loxilb_ai_pd_decode_ttft_seconds`
    measured before; see Upgrade notes.
  - New `loxilb_ai_pd_prefill_fallback_total{model,reason}`: one count per
    prefill recomputed on the decode leg, by the condition that forced it:
    `origin_5xx`, `origin_408`, `origin_429`, `no_status`, `truncated` (a
    reply that was usable but cut) or `other` (a 1xx/3xx).
  - New `loxilb_ai_pd_terminator_synthesized_total`: the `[DONE]`
    terminators the gateway wrote for a decode engine that went silent
    without one.
  - New phase `{phase="decode",status="truncated"}` on
    `loxilb_ai_pd_requests_total`: the gateway ended or cut an answer in
    progress for a cause other than the engine dying (engine silence, a
    duration cap).
  - The dashboard's P/D row gains "Decode duration p95" and "Prefill
    fallbacks by reason". The MCP `ai_traffic_report` and
    `diagnose_ai_latency` report both.
- **Two counters that are expected to stay at 0** (unlabelled, exported
  at 0 from start-up; the data plane's counts are pulled every 10 s):
  `loxilb_ai_reap_fallback_total` (a reaper ended a connection from the
  health thread because its owner worker could not be handed the end; the
  request it freed has no request record) and
  `loxilb_ai_route_host_missing_total` (a request reached dispatch with no
  usable Host on a listener whose pools name models). A non-zero rate on
  either means requests are missing from, or misrouted outside,
  `loxilb_ai_requests_total`.
- **`loxilb_ai_pd_requests_total{phase="aborted",status="client"}`**: the
  P/D client left, at any stage (before any answer, with its answer open,
  or it stopped reading). One-to-one with the P/D requests in
  `loxilb_ai_requests_total{outcome="aborted",cause="client"}`.
- **`instance:loxilb_ai_error_ratio:rate5m`**, the error ratio per
  instance (see Changed).
- **Monitoring lint rules** (`deploy/monitoring/ci/lint-monitoring.py`): a
  selector on `outcome="aborted"` must name its `cause`; on a dashboard
  with `$model`/`$tenant`, a selector of a family with that label must
  carry the variable; a panel no filter reaches says "(global)" in its
  title and one a filter reaches does not; an instance/model/tenant
  variable with All has `allValue: ".*"`; `increase()` of a family whose
  series appear lazily is refused (the form to use is in the message);
  the loxilb scrape job's `cluster` label must equal
  `external_labels.cluster`; the MCP module's copy of the alert rules
  must equal the default package's.

- **TensorRT-LLM (`trtllm-serve`) is a supported engine:** KV-exact routing, prefill/decode disaggregation and admission guards, with an attestation adapter and drain-ownership enforcement. (#71, #93)
- **llama.cpp (`llama-server`) is a supported engine (`kvEngineType: "llamacpp"`):** plain L7 load balancing with CHWBL or session affinity. KV and P/D rule shapes are refused on it. A create probes every endpoint's `/props` and warns about fleet skew; it never refuses for it. (#72)
- **SGLang prefill/decode disaggregation:** `pd_disagg_mode` with `kvEngineType=sglang`, the `pdBootstrapPort` service argument, the `loxilb_pd_sg_*` families, and bounded Tier-1.5 cold-start seeding (`LOXILB_KV_COLDSTART_SEED_N`, `LOXILB_KV_COLDSTART_MIN_BLOCKS`). (#69)
- **CHWBL on plain-LB rules:** with `cb_enable`, an endpoint that keeps answering 5xx is demoted and re-admitted only by a real origin success; all five CHWBL/WRR_HASH settings take effect from the API through read-back. (#73, #165)
- **Strict KV-exact routing per model and engine:** model-prompt profiles, contract-bound engine attestation for vLLM, SGLang and TensorRT-LLM, in-process chat-template execution, and refusal of strict requests the engine would render differently. `GET /config/ai/model-profiles` reads the published profiles, `GET /status/capabilities` says whether this gateway can accept such rules before a client tries, and `docs/SUPPORTED-MODELS.md` with `scripts/models/install-models.sh` lists and stages the qualified models. (#82, #93, #100, #103, #253, #294, #303, #321)
- **Separate credential planes on PostgreSQL:** `api_key_auth: "required" | "disabled"` per load-balancer service, independent of `sse_mode` and `pd_disagg_mode` (unset resolves to `disabled`); each plane has its own store, database role, schema and cache. See Upgrade notes. (#80, docs/AI-KEY-STORE.md)
- **JWT admission on the inference data plane:** named issuer profiles under `/config/ai/jwtauthprofile`, enforced on a rule that names one in `jwt_auth_profile`, with `loxilb_ai_jwt_validation_total{tenant,reason}` and `loxilb_ai_jwks_refresh_total{profile,outcome}`. (#168, #179)
- **Four-level rate-limit ladder:** every rate and quota resolves as explicit row, then configured default (rule over global), then unlimited, most specific first, so a tenant limit bounds the sum of its users. Adds `/config/ai/user/ratelimit`, `/config/ai/ratelimit/defaults` and PATCH of a key's rate fields. An API key's own `tokens_per_min` was stored and ignored before; it is now enforced, so a key that has one starts being limited on upgrade. (#181, #182)
- **Capacity admission gate, configurable per rule:** `fc_mode` and per-rule ceilings, read back with the source of each value; a bounded FIFO queue (`fc_max_queue_depth`, `fc_max_queue_wait_ms`); an adaptive ceiling and endpoint warm-up; a per-tenant share of a pool (`fc_tenant_max_share_pct`, refused with 429 `admission_tenant_share`); admission headers on admitted responses (`fc_expose_headers`); the `loxilb_ai_admission_*` families and admission alerts. (#281, #286, #288, #289, #291, #297, #306)
- **Audit trail, on by default:** a durable local record under `--audit-dir` (default `/var/log/loxilb/audit`) of every management change, written before the change is applied (a failed write answers 503 `audit_unavailable`), and of the inference path's completions, token settlements and refusals. If the directory cannot be prepared the gateway starts and refuses every audited management call; `--audit-required` makes it refuse to start instead. Without an authentication service a record's actor is `none`. Also `GET /audit/status`, a delegated originator (`X-Loxilb-Originator`, trusted only on an account with `delegation_allowed`), a runtime audit policy, remote sinks (`/audit/sink`, `/audit/sinks/{name}`) kept in the configuration document, and the `loxilb_audit_*` families. (#272, #276, #277, #280, #282, #326, #329, #330)
- **Configuration that survives a restart:** a restore touches only the domains its document declares (`included_domains`) and verifies content digests; L7 policies, CORS, certificates and tracing are persisted; a document declares its external recovery dependencies and a required one is verified before anything is changed; persists are crash-consistent with a lineage generation; `--config-boot-profile` chooses strict or compat; `GET /status/ready` reports the boot replay's outcome; secret values in documents are encrypted under a node-local secret kept beside the document, so a volume backup holds both. (#95, #105)
- **Management exposure and maintenance:** `--mgmt-profile legacy|appliance-local|remote-tls` (default `legacy`, unchanged) validated before any socket binds, and `remote-tls` also asks for credentials on `GET /metrics`; `PUT/GET /maintenance` freezes configuration changes with an idempotent enter and leave; `GET /diagnostics` assembles what the gateway knows about itself. (#128, #129, #159)
- **Sockmap acceleration per service:** `sockMapMode: off | both | request | response` on plaintext TCP full-proxy services, gated per direction so `api_key_auth` can accelerate responses, isolated by address and direction, refused where the data plane rewrites every request in the accelerated direction, and a `sockmapreset` call stops acceleration on connections already running. Needs `--sockmapsupport`. (#176, #195, #211, #226, #228, #259)
- **A client that half-closes keeps its answer:** `half_close_mode: hold` on a service, with `/config/halfclose` for process-wide settings and `defaultMode`. Off by default. (#325, #336)
- **Backend TLS by certificate ID:** `POST /config/cert` takes `usage` (`server`, `ca`, `client`), a rule verifies its backends and presents a client certificate by ID, a `GET` never returns a key, and a rule GET reports what the listener installed in `backend_tls_effective`. (#342-#344)
- **Per-rule prefill timeout:** `pd_prefill_timeout_sec` (0..3600; 0 or omitted keeps the process default, 30 seconds or `LLB_PD_PREFILL_TIMEOUT_SEC`) applies to one P/D service. (#337)
- **Source controls on full-proxy rules:** `allowedSources` is enforced by a firewall pair the rule owns and `connectionLimit` at accept. Optional aggregate SYN, connection-SYN, UDP packet and byte budgets sit beside the per-source limits, and `--xdp-native` attaches XDP in native mode on the interfaces it names. (#380, #384, docs/security/ddos-and-admission-fullproxy.md)
- **MCP 2026-07-28 stateless mode:** the opt-in, immutable rule field `mcp_protocol_version` validates and selects a backend per request; legacy session transport on existing rules is unchanged. (#391)
- **Endpoint Picker:** a load-balancer rule can delegate endpoint selection for a request to an external picker (Gateway API Inference Extension); the build lists `epp` under `features` in `GET /version`. (#468)
  - **With prefill/decode disaggregation:** a rule with `pd_disagg_mode: true` can name an EPP only with `eppFailureMode: FailOpen`. The EPP's pick (the decode pod's routing sidecar) is served as is; when the EPP gives no decision, the rule's own prefill/decode selection picks both endpoints and runs both legs. `FailClose`, or no `eppFailureMode`, is refused with 400 and the rule is not created. (#513)
- **Relay and stream knobs:** `LLB_PROXY_WORKERS` (1..32, default 4), `LLB_SSE_STALL_ABORT_SEC` (1..86400, default 0, off), `LOXILB_KV_TOKENIZE_BYTES_PER_TOKEN` (4..256, default 16), with `loxilb_proxy_stream_abandoned_total{reason}`, `loxilb_proxy_stream_abandon_age_seconds{reason}`, `loxilb_kv_exact_stage_seconds{stage,outcome}`, `loxilb_kv_exact_prompt_blocks` and `loxilb_kv_exact_overlap_blocks`. (#385, #386, #388, #389)
- **Monitoring contract:** a generated, versioned metric ownership manifest; per-backend traffic, `config_dirty`, KV freshness and HA peer exporters; recording rules, KV, P/D, persistence and policy alerts, and Alertmanager. `GET /version` also names the `product`. (#64, #118, #120-#122, #124-#126, #154)
- **`loxilb_ai_tokens_missing_total{reason}` counts 2xx AI responses that carried no usage object** (`response_complete`, `h2_stream_close`, `connection_close`, `stream_estimated`, and an `unknown` backstop). Only `stream_estimated` is charged. (#186, #201)

### Changed

- **eBGP peers now see a one-hop-shorter AS_PATH for VIPs, which can change best-path selection upstream.** A peer sees the gateway's AS once (`64512`) where it saw `64512 {64512}`. A peer or upstream policy that compares path length or matches the AS_SET can choose differently. Preference between the HA master and backup is unchanged; it comes from MED and local preference.

- **With `LLB_PD_DECODE_KV_WEIGHT=W` (default 0 = off), the P/D decode min-load
  score adds the endpoint's scraped KV-cache usage (`vllm:kv_cache_usage_perc` /
  `sglang:token_usage`) × W/100**. Unknown or stale
  readings take the fleet mean; pools that report no usage family behave as
  before. Session-pinned decode, prefill selection and admission are unchanged.
  (docs 10 §3.6, 11)
- **Request-body keys and the `service_tier` value are compared decoded;
  escaped spellings of `service_tier`, `model` and `user` are read like their
  literal spellings.** An escaped model name is now matched by
  `allowed_models`; an escaped `service_tier` is read and nulled before
  forwarding. A value with an invalid JSON escape is cut at the escape.
  KV-prefix hashing still uses the raw bytes (unchanged). (QA 2026-10-23,
  the JSON train: loxilb-ebpf #131.)
- **Three AI dashboard titles carry their scope mark first**: `(all tenants)
  Active SSE streams`, its trend panel and the P/D row. At 1600×900 the narrow
  stat clipped to `Active SSE strea…` and the mark was out of sight (QA
  2026-10-21, MON-05). The monitoring README now also says that the **Model**
  and **Tenant** variables list a value only after its first completed request,
  and that `increase()` on a first event reads about 1.0 to 1.4 by
  extrapolation; the acceptance reading is the raw delta of 1 with a positive
  rate.
- **A configured queue wait window is the enforced window.** A waiting
  request's deadline (`fc_max_queue_wait_ms`, a band's `fc_band_wait_ms`, a
  client's `x-llm-d-inference-ttl`) was swept by the health pass at most
  once a second, so a 100 ms or 150 ms window ended between 775 and 1005 ms.
  The deadlines are now met by a timer armed to the earliest pending
  deadline across the pools, re-armed on every park and after every pass,
  at 25 ms granularity; with no waiter anywhere it is not armed and no pass
  runs. The pass reads one word per pool and enters only the queues whose
  earliest deadline has passed, never a connection list; every expiry still
  ends the wait through the one compare-and-swap that settles a queued
  request, and answers as before (`504 admission_queue_timeout`, `429
  admission_ttl_expired`). No API field changes: the values were always the
  contract (QA 2026-10-23, QA-03).
- **A client-supplied engine priority (`X-Vllm-Priority`, body `priority`)
  is no longer forwarded on AI-gateway rules; the tenant band decides
  order.** The band queue decides the admission order, but once admitted an
  engine that reorders by its own priority field (vLLM reads the
  `X-Vllm-Priority` header first, then the body's top-level `priority`;
  SGLang reads the body field) let a client outrank the band from inside
  the engine. Where the class stage runs, the header is stripped on HTTP/1.1
  and HTTP/2, and a top-level body `priority` is renamed in place, at the
  same length, to `_gw_prio`, a key no engine reads: every engine then sees
  what it sees for a request that never carried the field (it is not
  written as 0, which is vLLM's default but a mid rank on SGLang, where an
  absent priority ranks lowest; an engine that refuses unknown fields
  refused `priority` already). An operator who sees `_gw_prio` in an
  engine's request log is looking at the gateway's rename of a client's
  `priority`, not at a client field. A nested `priority` (inside
  `messages` or a tool's arguments) is no engine field and is left as
  sent. One info line per service, at most every 10 s, names the clients
  that send one. Rules without an AI gateway are unchanged (QA 2026-10-23,
  QA-01).
- **A rule replace that differs from the stored rule only in `id` rebinds
  the id in place and answers success** instead of 409 `lbrule-exists`. The
  data plane is not touched and the rule keeps its connections; the new id
  resolves on `GET /config/loadbalancer/id/{id}` and the old one no longer
  does. This is what a controller needs when it starts sending deterministic
  ids for rules it installed earlier under minted ones, or when a restart
  restored a rule under the id the snapshot kept. An id bound to another rule
  is still refused (`lbrule-id conflict`).
- **A fullproxy rule whose `api_key_auth` or `jwt_auth_profile` differs from
  the rules already on its listener (address, port, protocol) is refused with
  400** instead of being accepted with a warning. The admission gate reads the
  credential policy once per listener, before a request is matched to a rule
  by host, path or model, so a rule that declared `jwt` next to a rule that
  declared nothing was served unauthenticated or not depending on install
  order. An unset policy and an explicit `disabled` are different values (the
  latter strips `X-Api-Key`). A configuration restored from a snapshot is kept
  whole and the disagreement is logged, as for the listener's TLS settings.
  The refusal names the rule already there and the arguments, never a value.
- **The AI dashboard's model-only panels say `(all tenants)`** (QA
  2026-10-21, MON-05). The active-stream gauge and the P/D lifecycle,
  timing, fallback, tier and session families carry a model label and no
  tenant label, so the Tenant selection never reached them, and a stream
  tenant B held read, with A selected, as A's. Their titles end in `(all
  tenants)` and their descriptions say the selection does not apply;
  `ci/lint-monitoring.py` requires the mark on a panel the model filter
  reaches and the tenant filter does not, and forbids it on one the tenant
  filter reaches. No metric changed: a per-tenant active-stream count would
  be a new label on the gauge, not a filter.
- **`loxilb_ai_pd_requests_total{phase="complete",status="success"}` is
  defined as HTTP completion of the decode answer** (its last chunk, its
  Content-Length satisfied, or its EOF on an unframed answer), not semantic
  completion of the stream: a stream the engine ends cleanly without
  `finish_reason`, `usage` or the SSE `[DONE]` event is a success, one the
  gateway ended without finish evidence is `decode/truncated` (with it, a
  completion: see Fixed), one the engine broke `decode/error`. The HELP
  text, the monitoring README and the P/D panel now say so (QA 2026-10-21,
  contract question).
- **A request whose client did not get the whole answer is
  `outcome="aborted"`, with a new `cause` label on
  `loxilb_ai_requests_total`** (this supersedes the Stage 2 behaviour
  S2-7, which recorded such an answer as `completed`; Upgrade notes rows
  25–28). `cause` is `client` (it cancelled, reset or stopped reading),
  `engine` (the backend died under the answer) or `gateway` (a duration
  cap, a reaper or the listener cut it), and empty on `completed` and
  `denied`. `status` is what the client got: `200` for a cut stream,
  `none` when it left before any status was sent. A data plane that names
  no end code is counted as before.
  - `loxilb_ai_request_duration_seconds` observes `completed` requests
    only: an aborted request's latency is the time to its cut.
    `loxilb_ai_pd_decode_ttft_seconds` still samples an aborted stream
    that reached its first event, so the two `_count` series need not
    agree.
  - Audit: `data.ai.complete` for an aborted answer is no longer
    `outcome.reason="ok"`: the client's cancel or stall is
    `client_abort`, a cap or a reaper `timeout`, the engine dying
    `backend_conn`, and a response cut by its listener going away
    (`listener_closed`) `gateway_shutdown` — a new value of the
    vocabulary, the gateway's own cut with no backend at fault. (It read
    `backend_conn`, the closest available reason, until this value
    existed.) The vocabulary is add-only; the envelope version stays 1.
- **The AI error ratio counts what the engine and the gateway cut, not
  what the client cancelled:**
  `(completed 5xx + aborted{cause=~"engine|gateway"}) / (completed + aborted)`.
  `LoxilbAIErrorRatio` (both rule copies) takes this ratio: its numerator
  was every non-2xx completion (a completed 4xx paged; a cut 200 did not),
  and its denominator was completed only. It is recorded per instance as
  the new `instance:loxilb_ai_error_ratio:rate5m`.
  `instance:loxilb_ai_5xx_ratio:rate5m` (completed 5xx over completed; it
  did not see `aborted`) is **removed**. It was deprecated and removed
  within this same unreleased span, so no shipped release carried it as
  deprecated: a reader of the old name moves to the new rule now. The AI
  Gateway dashboard's
  panel 1 ("AI error ratio (5xx + engine/gateway aborts, 5m)") is this
  ratio, panel 5 ("AI requests/s by status") splits by cause too, and
  panel 54 ("Uncharged-on-close rate: per tenant vs fleet") leaves denials
  out of its denominator. The MCP `ai_traffic_report` no longer counts
  aborted as completed: it reports `requests_aborted`,
  `requests_aborted_errors` and `requests_5xx`, and its `error_ratio` is
  this ratio.
- **The counted families are seeded at zero**, so a window's first error
  is an increase, not a series appearing: `loxilb_ai_pd_requests_total`
  (every phase and status, 10) and `loxilb_ai_pd_prefill_fallback_total`
  (every reason, 6) per model label at its registration and for
  `model="other"` at start; `loxilb_ai_requests_total` per (model, tenant)
  pair at the pair's first record, for a keyed tenant only: every
  combination whose status the gateway decides, plus the common error
  statuses. `completed`: 400 401 403 404 408 429 500 502 503 504 and the
  redirects 301 302 303 307 308 (15); `denied`: the same ten and 413 (11);
  `aborted`: 200 for `client`, `engine` and `gateway`, `none` for `client`
  and `engine` (5). 31 series. Open sets are not seeded: other backend
  statuses, and an L7 REJECT code an operator chose; nor is `aborted`
  `none` for `gateway`, the rule's listener going before any answer, which
  nothing in the product does today (a rule delete keeps the listener).
  `tenant=""` is never seeded.
- **Every AI Gateway panel obeys the dashboard's model and tenant
  filters.** `$model`, `$tenant` and `$instance` (and `$instance` on the
  L4, L7, overview and security dashboards) have `allValue: ".*"`, so All
  includes `tenant=""` (a refusal before the key resolved), which used to
  vanish from every filtered panel. Panels 1, 2, 6, 7, 8, 9, 10, 13, 14,
  15, 25, 48, 52, 64 and 65 now apply `$model`/`$tenant` to every selector
  of a family that carries the label. The 32 panels no filter can reach
  (their families carry neither label) say "(global)" in the title, and
  the alerts whose `panel` annotation names one moved with them (Upgrade
  notes row 33).
- **The scraped series carry `cluster`.** The loxilb scrape job sets
  `labels: {cluster: loxilb-default}`, the value of
  `external_labels.cluster`, which Prometheus only adds to what leaves it;
  the `cluster:`/`instance:` recording rules and the KV alerts group by
  it. Set it per site in both places.

- **Every request the gateway refuses is counted once in
  `loxilb_ai_requests_total{outcome="denied"}`, whatever refused it:** the
  policy gate, capacity, routing (`model_unavailable`, `no_route`,
  `no_rules`, an L7-policy reject), framing (the 413s, the model-required
  400, `invalid_cache_salt`) and the content-security block, with the status
  the client got. The count moved from the four Go gate exports to the deny
  record the data plane takes once per refusal; refusals made only in the
  data plane were missing before. A routing or framing refusal never takes a
  new model label (unknown names read `other`); one that named no model
  reads `model="none"`. The deny record names the new stages `route`,
  `framing` and `security`. The new refusals and the outcome changes below
  take effect with the loxilb-ebpf revision that reports them.
- **An answer the gateway writes when no backend can take the request** (an
  outage, a P/D timeout or leg failure, a connect failure) **is counted as
  `outcome="completed"` with the status it wrote,** so the error ratio sees
  it. `loxilb_proxy_http_responses_by_status_total` counts the gateway's own
  HTTP/1.1 answers, and the TTFB histogram samples backend replies only.
  `deploy/monitoring/README.md` lists the families that count the same
  requests from another angle and must not be summed with the request total.
- `loxilb_ai_admission_decisions_total{reason="queued"}` now counts each park once;
  a re-park after a lost wake no longer counts twice.
- `loxilb_ai_admission_queue_wait_seconds` takes one sample per park, when the
  park ends (admitted, expired, shed by eviction or cancelled), measured from the
  first park; it used to sample every resume, splitting one wait into shorter
  ones, and did not sample expired or cancelled waits.
- Every answer that ends a wait in the capacity queue (`504
  admission_queue_timeout`, `503 admission_drained`, `429 admission_shed` to an
  evicted waiter) now carries `Content-Length`; for the `504` and the `503` that
  is one header added, nothing removed.
- **On an AI-gateway pool, requests matched by an L7 FORWARD route now pass
  the pool's capacity gate (ceiling and queue) like every other request;** the
  route's private pool copy used to bypass it. Selection inside the route is
  unchanged — round-robin, weighted when the route's weights differ.
- **An HTTP/2 request body is held in its own copy while it is sent to the
  backend,** so memory per in-flight HTTP/2 request grows by the body size.
- Container image renamed to `ghcr.io/loxilb-io/loxilb-inference-gateway`.
- README rewritten around inference-gateway use cases; `loxilb-ebpf` submodule
  repointed to the `loxilb-ebpf-inference-gateway` fork.
- **Audit trail: a request authenticated by a bearer token (JWT) is recorded
  with `actor.auth: "bearer"`.** It used to be recorded as `"none"`, the
  value an unauthenticated request has, because the data-path actor only
  knew API keys. The new value is written on `data.ai.complete`,
  `data.ai.settle` and `sec.ai.deny` once the token has validated; a request
  whose token did not validate is still `"none"`, and API-key requests are
  still `"apikey"`. `schema_version` stays `1`. **SIEM impact:** a rule or
  dashboard that matches `actor.auth == "none"` no longer matches JWT
  traffic, and a consumer that validates `actor.auth` against a closed list
  must accept `"bearer"` (and `"network"`, written when a network-identity
  binding decided the tenant).

- **The default reservation is per rule.** Where several rules share a VIP
  and port (told apart by host, path or model), a request without
  `max_tokens` now reserves by `ai_default_reservation` /
  `ai_default_max_tokens` of the rule it routes to. Before, the rule
  installed first on the listener decided for all of them. With it go the
  reply text `Success; warning: ai_default_reservation: …` on a rule whose
  neighbours resolve differently, and the value `listener` of
  `fc_effective.source.default_reservation` / `.default_max_tokens`: a
  rule's read-back is its own. A client that matched either should stop.
  A request an L7 policy forwards to another pool reserves by the rule its
  host, path and model select.
- **Log calls no longer wait for the log's device.** The gateway's log and
  the data-plane log are written by one writer each, from an in-memory queue;
  a worker thread that logs copies its line and returns. When the device is
  slow or stalled, lines are dropped and counted in the new
  `loxilb_log_lines_dropped_total{level}` and the writer reports the drop in
  the log; requests are not held. Before, one stalled log write stopped every
  connection of the worker that made it. The data-plane log is now rotated by
  its own writer (rename and reopen; no line lost at a rotation). The stdout
  copy of the gateway's log is unchanged except that a message with no
  trailing newline now gets one. See `docs/LOG-ROTATION.md`.
- **Per-request log lines of the AI gateway moved from `info` / `warn` to
  `debug`**: key validated, empty or invalid key, expired key, model not
  allowed, rate-limited, token quota exceeded, pre-admission denied, capacity
  refused, request refused 413, stream start / end. Each of these is in the
  audit trail (`data.ai.complete`, `sec.ai.deny`) and the metrics. **Impact:**
  a log-based alert or a script that matches these lines sees them only at
  `--loglevel debug`; use the audit trail or `loxilb_ai_*` counters instead.
  Store-outage and fault lines are unchanged.

- **The default `--loglevel` is `info`,** not `debug`. Per-request AI lines are in the entry above. (#257)
- **A client that stops reading a chunked or SSE response on HTTP/1.1 is paused at 768 KiB of unread data,** not 12 MiB. Clients that read normally see no change; HTTP/2 keeps the binary mark. (#387)
- **`loxilb_system_cpu_utilization_percent` is scoped to the container the gateway runs in,** not the whole host. The host value is `loxilb_host_cpu_utilization_percent`. (#68)
- **Full-proxy rules on one listener must agree.** A rule whose `security`, backend TLS policy or `allowedSources` differs from the rule already on that address, port and protocol (for `allowedSources`, also an overlapping port range) is refused with 400, and the rule API waits for the data plane's answer. A saved configuration still restores whole, and the log names each disagreeing rule. (#343, #383)
- **Proxy-only mode refuses what it cannot enforce.** An ipfilter add, a firewall add, security-rate settings and a rule's `allowedSources` answer 400 naming the mode; they used to answer success and do nothing. (#380, #384)
- **Relay changes for connection-heavy traffic:** listeners are polled by their own worker with batched accepts, a backend connect no longer holds a relay worker for a round trip, receive buffers are recycled, and a rule's connection list is constant-time. `LLB_MALLOC_MMAP_THRESHOLD` overrides the pinned allocator threshold. (#258, #261, #262)
- **Dependencies refreshed:** images and packages build with Go 1.26.10; both images carry GoBGP v3.35.0; the gateway uses grpc v1.83.2 and x/net v0.60.0; Ubuntu runtime packages are upgraded at image build. (#223, #381, #393)
- **A CHWBL chat body with no system message now hashes the first 256 bytes of its first user message,** so user-only traffic co-locates. `LLB_LLM_USER_PREFIX_FALLBACK_LEN` overrides the length and `0` restores the old behaviour. (#73)
- **`architecture` in the device status reports the machine name, and sizes round upward with unit promotion;** filesystem selection can differ from GNU `df`. (#458)

### Fixed

- **Originated VIP routes carried our AS twice to eBGP peers and were denied by standard iBGP peers.** The gateway added its own AS to the AS_PATH of every route it originates. eBGP peers received `64512 {64512}`, a standard iBGP peer (no `allowas-in`) denied the route with "as-path contains our own AS", and GoBGP v3.35.0 did not send it to iBGP peers at all. Present since 2023, including v0.9.8.7. An originated route now carries no AS of ours: eBGP peers see `64512` and iBGP peers an empty AS_PATH.

- **A clustered gateway with BGP came back from a restart with no configuration.** Auto-persist (on by default) saves the BGP global config and neighbors in `snapshot.json`. On a clustered node `gobgpd` starts only after the cluster sync wait, so boot replay gave up after about 30 s, moved the whole snapshot aside as `snapshot.json.failed-*`, and started empty, load-balancer rules included. A snapshot that fails only because `gobgpd` is not up yet is now retried for up to 150 s after boot; on a clustered node, config writes answer 503 for up to about two minutes after a restart, until the replay settles. A BGP neighbor add or delete made while `gobgpd` is starting answered 500; it now waits up to 30 s for `gobgpd`.

- **A management-store verdict is never reported as a store outcome.** Since
  the write-outcome contract, `POST /auth/users` with a username that exists
  retried the insert three times and answered 504 `store_outcome_unknown`
  instead of 409, because the verdict reached the classifier meant for the
  store's own failures; a refused password or role took the same path to 504
  instead of 400. A verdict (the name is taken, the role or the password was
  refused, the row does not exist, the credential is wrong) is now answered
  at the first attempt, as it was made, and the store operations classify
  their own transport errors at the statement. Found by the new audit-mgmt
  T21 on the bed.
- **Every key-store and management-store statement carries a deadline, and a
  write says whether the server may still apply it.** A PostgreSQL that stalled
  while keeping its TCP connections open (hung or overloaded server, stalled
  volume, black-holing path, paused container) was answered never: a management
  write committed after its client had given up, `/status/ready` hung, and a
  cache-miss key lookup parked the proxy worker thread that asked. Budgets, as
  environment variables in milliseconds: `LLB_AI_STORE_OP_TIMEOUT_MS` (3000,
  one management operation, retries included; also the session
  `statement_timeout`), `LLB_AI_STORE_PING_TIMEOUT_MS` (1000, readiness and
  housekeeping pings), `LLB_AI_STORE_REFRESH_TIMEOUT_MS` (3000, one snapshot
  refresh, clamped to half the refresh interval), `LLB_AI_KEY_LOOKUP_TIMEOUT_MS`
  (300, one data-path store round trip). Idle pooled connections are dropped
  after 60 s. The management hooks take the request's context, so a client
  that hangs up cancels its own statement. Write endpoints now distinguish
  **503** (`ai_key_store_unavailable`: nothing was sent, retry is safe) from
  **504** (`ai_key_store_outcome_unknown`, management-plane result
  `store_outcome_unknown`: the statement was sent and not answered within the
  budget; read the resource back before retrying), declared in swagger on
  every write operation of both planes. The `DBTX` interfaces of `pkg/aikey`
  and `pkg/user` carry only the context-taking methods, and
  `scripts/check-store-deadlines.sh` fails CI on a store call without one.
  (`docs/AI-KEY-STORE.md`, "Time budgets and the write-outcome contract")

- **The capacity-queue deadline timer is opened before any worker thread
  starts** (candidate qualification 2026-10-24, TSAN-01): a start-up data race
  on the queue deadline timer's descriptor between the deadline thread, which
  opened it at its own start, and the health pass, which read it on every pass
  to decide whether it owed the fallback deadline sweep. The effect was one
  redundant fallback sweep in the first second; no client-visible effect. The
  timer is now opened in `proxy_main` before the threads exist, so every
  thread's start orders its reads after the open; the deadline thread only
  checks that a timer exists, arms and waits, and a process whose timer could
  not be opened logs it once and leaves the deadlines to the 1 Hz pass, as
  before. A source invariant (`check_deadline_init_order`, mutation-tested)
  keeps the order.
- **A rule whose `id` is already bound to another rule is refused with 400
  and the reason** (`lbrule-id conflict: id already bound to a different
  rule`). It was answered 500 `Internal service error` with the wording
  hidden, which told a controller to retry a request that can only succeed
  once the other rule gives the id up. Create and replace alike.
- **A backend status line split across reads reached no class count and no
  TTFB sample** (QA 2026-10-21, MON-02-EDGE). The client received the whole
  answer and `loxilb_ai_requests_total` carried its status, but
  `loxilb_proxy_http_responses_by_status_total` and
  `loxilb_proxy_http_ttfb_seconds` did not move: the capture sniffed the
  status line from the first bytes of a backend read, and `HTTP/1.1 200`
  followed by ` OK` in the next read is no such read. The response framer,
  which assembles the line whatever the read boundaries, now records the
  answer too, once per request (loxilb-ebpf-inference-gateway#123).
- **A backend's own `100 Continue` took the response record meant for its
  answer** (F-21, found by the F-20 review). The gateway forwards a client's
  `Expect: 100-continue` to the backend unless it answered the `100` itself
  (the streamed path), and the backend's interim line reached the
  once-per-request capture first: `loxilb_proxy_http_responses_total` moved
  with no class, `loxilb_proxy_http_ttfb_seconds` sampled the `100`, and the
  `200` or `5xx` behind it was a latched no-op, never counted by status. The
  response framer repaired the status in `loxilb_ai_requests_total` after the
  fact; the trace kept `100`. An interim `1xx` is now no answer to either
  capture (`101` is: it ends the HTTP/1.1 exchange). The record waits for the
  final status line and takes it once, class, TTFB and trace status alike
  (loxilb-ebpf-inference-gateway#130, Upgrade notes row 42).
- **An HTTP/2 stream's answer reached no class count and no TTFB sample**
  (F-7, #415 rows 1–2). `loxilb_proxy_http_responses_total`,
  `loxilb_proxy_http_responses_by_status_total` and
  `loxilb_proxy_http_ttfb_seconds` were written against the connection's
  request latch, which an HTTP/2 stream does not have, so an HTTP/2 client's
  answers showed in `loxilb_ai_requests_total` only and the README said so.
  Each HTTP/2 stream now takes the record once, at its final status: a
  backend `:status` with the TTFB sample, a gateway-written refusal or outage
  frame without one, as the HTTP/1.1 pair. The help texts and the README row
  no longer say HTTP/1.1 only (loxilb-ebpf-inference-gateway#126, Upgrade
  notes row 43).
- **The first error of a cold (model, tenant) pair, or of a freshly started
  gateway, was invisible to `rate()` and `increase()`** (QA 2026-10-21,
  MON-04): the series was born with it, so its first scrape already read 1
  and no window saw a 0 → 1 step; seeding cannot reach the series the event
  itself creates. The exporter stamps every counter with its creation time,
  and `deploy/monitoring` now carries it to Prometheus: the loxilb scrape
  job reads the protobuf exposition (`scrape_protocols: [PrometheusProto,
  …]`, the one format that carries the stamp) and Prometheus runs with
  `--enable-feature=created-timestamp-zero-ingestion`, writing a 0 at the
  creation instant before the first sample. The first error is a positive
  increase, and the error ratio reads it as 100 % of one request;
  `ci/lint-monitoring.py` fails either file without its setting. The AI
  dashboard reads the counter itself in a new **AI 5xx observed (raw
  counter)** stat beside the ratio, and the ratio's empty state says `No AI
  traffic (5m)`, not `No data`.
- **MCP refusals, the HTTP/2 outage answers and the request-smuggling 400
  reached no `loxilb_ai_requests_total` record.** On HTTP/2 the MCP 413s
  (operand, headers, body too large) and the MCP gate's 400/405/413, and the
  503s written when no backend could take the stream (`backend_unreachable`,
  `mcp_backend_unavailable`); on HTTP/1.1 the MCP refusals and the 400 that
  refuses an unparseable or ambiguously framed request before admission. Each
  is now recorded by what its status means: a 4xx as `outcome="denied"` at
  the framing stage (`mcp_invalid_request`, `mcp_method_not_allowed`,
  `mcp_request_too_large`, `bad_request`), a 5xx as `outcome="completed"`
  with the status written, so an MCP outage moves the error ratio as any
  other. The HTTP/1.1 ones also take the responses-by-status class count.
  Wire bytes are unchanged. AI-gateway rules only: an MCP service that is not
  one still records nothing (Upgrade notes row 41).
- **A P/D client that left before any answer reached no record.** It is
  now recorded once in both families: `loxilb_ai_requests_total`
  `outcome="aborted"`, `status="none"`, `cause="client"`, and
  `loxilb_ai_pd_requests_total{phase="aborted",status="client"}`. A client
  that cancelled or stopped reading with its P/D answer open is recorded
  the same way, with the status it got (Upgrade notes row 27). A listener
  going away before any answer has no lifecycle record: nothing in the
  product tears a listener down with requests on it (a rule delete keeps
  the listener open and answers 503).
- **A client that left before any answer on a rule that is not P/D reached
  no record.** It is now recorded once in `loxilb_ai_requests_total`:
  `outcome="aborted"`, `status="none"`, `cause="client"`. No lifecycle
  family pairs with a request off P/D, so that record alone keeps the
  families 1:1 (Upgrade notes row 38). A request still being read, an idle
  keep-alive connection and a half-close hold the gateway ended are not
  recorded, nor is any request on a rule whose answers go by the kernel (an
  `api_key_auth` rule with sockMapMode `response`): no status is
  seen there, so an answered request cannot be told from one that was not,
  and those answers are not recorded either.
- **A P/D client that left at the gate, in the capacity queue or parked
  reached no record.** It is now recorded once in both families, as a
  client leaving in the prefill is: `outcome="aborted"`, `status="none"`,
  `cause="client"` and `{phase="aborted",status="client"}` (row 39). A
  client giving up while parked is the signal that the queue is too long.
- **A plain backend that closed before any answer left the client a bare
  close and reached no record.** The client now gets the gateway's 502
  `backend_unreachable`, as for a refused connect or a TLS leg failing
  before its answer, recorded the same way: `outcome="completed"`,
  `status="502"` (row 40). An engine dying before its first byte no longer
  vanishes from the metrics, and it counts in the error ratio as any
  completed 5xx. Only a client that could not be told is recorded
  `outcome="aborted"`, `status="none"`, `cause="engine"`.
- **A stream the inline teardown freed stayed on the active-streams
  gauge** (`loxilb_ai_active_streams`) until the process restarted. It is
  ended there now.
- **A request with no usable Host could be sent to another model's
  pool** on a listener whose pools name models. It is routed to the pool
  of the model it named, or refused (503 `model_unavailable` /
  `no_route`), and counted by `loxilb_ai_route_host_missing_total`.
- **A prefill 4xx cut at the buffer cap was recomputed on the decode
  leg** and counted as a `truncated` fallback. The client now gets the
  engine's status with a short gateway error body, the request records
  `prefill/rejected`, and no decode call or fallback is made. The
  `truncated` fallback reason now means a cut 2xx only (Upgrade notes
  row 36).
- **A reaper's health-thread fallback freed a request with no record and
  no count.** It is counted by `loxilb_ai_reap_fallback_total`.
- **A lazy family's first event was invisible to the alerts and panels
  built on `increase()`:** the series did not exist before it.
  `LoxilbAIAdmissionAnomaly` and `KvExactEchoChallengeFailures`
  (`loxilb-alerts.yml`, both copies), `LoxilbKvZeroHitWatchdog`,
  `LoxilbTrtllmDrainOwnershipFault` and `LoxilbKvReconnectStorm`
  (`loxilb-ai-kv-alerts.yml`; the last undercounted), the AI Gateway
  dashboard's panels 37 (query D), 39 (query D) and 59, and the security
  dashboard's top dropping FW rules now use
  `clamp_min(X - X offset W, 0) or (X unless X offset W)`, which counts a
  series' first value.

- **A reaped chunked answer got a `[DONE]` terminator its client could not
  read.** When the gateway ended a vLLM stream whose engine went silent
  without its terminator, it wrote `data: [DONE]` unframed into a chunked
  body. The client's chunked decoding broke (curl exit 18) and it never saw
  `[DONE]`. The framing now follows the answer the client is being sent,
  never a backend leg, on both reaper paths: on the owner worker that
  normally writes it, and on the health-thread fallback used when that
  worker cannot be woken. The same applies to the SSE duration-cap and
  stalled-client events.
- **A P/D stream the gateway ended was counted as a success.** It is now
  `decode/truncated`. A decode engine that dies mid-stream is now
  `decode/error`; before, it got no P/D record at all on a chunked answer,
  and `complete/success` where the sweep later reached it. The P/D
  requests that the stream timeout, the idle cap and the duration cap end
  also had no P/D record; they are now recorded by cause (Upgrade notes
  rows 20–22).
- **An answer a reaper ended after its 200 had gone out had no
  `loxilb_ai_requests_total` record** when the reaper freed the connection
  itself: the graceful-`[DONE]` sweep, the stream timeout and the P/D idle
  cap. It is now recorded once, `completed`, with the status the client
  received.

- **A P/D answer sent without a length or chunked framing never ended for the
  client.** The decode answer was relayed whole, but after `[DONE]` the flow
  reset, and when the engine then closed its connection the gateway kept the
  client's connection open as if for its next request. Such an answer ends
  only when the connection closes, so the client waited until its own
  timeout. The client's connection is now closed with the engine's, after
  every byte still owed to it is sent. This affects only engines that end
  their body by closing; vLLM streams chunked and ends on the last chunk, so
  its answers are framed and its clients keep their connection as before.
- **The gateway no longer writes a status line into an answer the client has
  already begun to receive,** on any path that answers on its own (refusals,
  outages, reaper timeouts): a stream whose headers are out ends with an SSE
  error event naming the code, anything else is closed. This is a guarantee
  of the code, not the fix of an observed failure.
- **Five answers the gateway writes raw were sent in clear on a TLS client
  connection:** the P/D destroy-path 503 (prefill) and 502/503 (decode), the
  502 when no backend took the request at connect, the 400 for an
  unparseable request refused before admission, and the LlamaFirewall 403.
  Each wrote with a plain send, bypassing the client's TLS session, so a TLS
  client got plaintext bytes inside the encrypted stream in place of the
  answer. They now go through TLS on a TLS client.
- **loxilb started with `--nonlp` crashed in its periodic interface
  reconciliation** (a nil netlink handle behind the interface filter). The
  `--blacklist` / `--whitelist` filter is now set up without netlink, so
  `--nonlp` reconciles interfaces under the same filter as a netlink start.

- **A request waiting in the capacity queue was reset instead of answered
  when its wait was longer than the rule's idle bound** — the idle pass
  (`inactiveTimeout`, and the L7 member-data deadline on the same pass) saw a
  parked connection send nothing and shut it, so the client got a reset in
  place of the queue's `504` and the request counted as cancelled — a waiting
  request is now bounded only by its queue window; a client that leaves while
  it waits still frees its place at once.
- **A P/D request waiting on the per-endpoint prefill queue could be refused
  `429 admission_capacity` when another request took the freed capacity unit
  first** — it now waits at the capacity gate, keeping its queue position and
  deadline.
- **A P/D request's admission unit could be released by another request, and a
  parked request could be woken out of turn.** The opt-in legacy P/D FIFO now
  reserves a bounded prefill unit atomically before dispatch, and each request
  owns its prefill and decode units through connection setup, rollback, retry,
  cancellation and cleanup, so those paths return only the request's units,
  also with the cap disabled; a decode routing hint alone cannot release
  another request's unit. A returned unit wakes the oldest still-registered
  FIFO entry on its owner with a generation-qualified wake, and a late wake of
  an earlier request on a kept connection leaves a parked request parked while
  its own entry is still queued (loxilb-ebpf-inference-gateway#127).
- **A decode engine that died between admission and the decode dial failed the
  request on the first connect.** The decode endpoint is chosen at admission
  and dialled only after the prefill reply. The dial is now retried once on a
  healthy endpoint before health polling notices, a refused connect counts on
  that endpoint's breaker, and the request's reservation moves atomically to
  the endpoint it connected to. There is no retry once anything was written or
  received on the decode leg (loxilb-ebpf-inference-gateway#128).
- **A finished P/D decode stream that lost its `[DONE]` was recorded
  `decode/truncated`, and a decode backend that closed after the finish was
  counted an engine death.** vLLM's P/D path omits `[DONE]` for a small share
  of streams under concurrency. The response framer now tracks finish evidence
  per decode stream: a complete SSE data event that finished every choice,
  followed only by events with no choice (the usage event) or `[DONE]`. With
  it, the idle sweep records the stream a completion (the terminator is still
  the gateway's, counted by `loxilb_ai_pd_terminator_synthesized_total`) and a
  decode EOF completes the stream instead of recording `decode/error` and a
  dead endpoint. Without it both paths are unchanged
  (loxilb-ebpf-inference-gateway#129).
- **HTTP/2 requests on a busy, healthy client connection occasionally failed
  together with no response (the connection was closed)** — the
  header-completion (slowloris) deadline charged the connection with a header
  block start that was not its current one: the start was read by the health
  pass with no ordering against the worker that wrote it, and on HTTP/2 a
  header block reset before its headers completed left the clock running — the
  deadline now times only the header block in progress on that connection; it
  never runs while a request is in flight or between requests.
- **On a non-AI-gateway listener, a WebSocket or CONNECT upgrade — or any
  connection relayed raw after its headers — was closed by the
  header-completion deadline about ten seconds in.** The HTTP/1.1 header clock
  kept running after the header block had completed; it now stops at header
  completion, and the deadline pass reads only that clock.
- **An HTTP/2 client connection is no longer closed when one of its backend
  connections ends;** in-flight requests on the other backends continue.
  Requests that were on the backend connection that ended are answered on
  their own streams: 503 backend_unreachable when no response had started, a
  stream reset when one was in progress.
- **On a P/D pool, an HTTP/2 backend connection that ended no longer released
  a prefill and a decode unit charged to endpoint 0** (and, with an admission
  queue, no longer woke a request waiting for endpoint 0), so endpoint 0's
  in-flight counts stay correct.
- **An HTTP/2 request the gateway answered itself (no pool for the model, an
  admission or capacity refusal, an L7 reject or redirect) could corrupt
  memory** — the stream was still read, and on a capacity refusal written,
  after the answer had freed it. The answer is now the last thing that touches
  the stream.
- **An HTTP/2 client sending several requests at once could crash the gateway
  when one request's answer was waiting on the client's flow-control window**
  — forwarding the next request flushed that answer and freed its stream while
  the gateway was still walking the list. Each request is now looked up again
  before it is forwarded.
- **On a CHWBL pool, an HTTP/2 request with an invalid cache_salt got no
  answer and hung until the client timed out** — the refusal went through a
  responder that only works during L7 routing. The client now gets 400
  invalid_cache_salt on that stream.
- **An HTTP/2 client that reset a request while its body was still going to
  the backend could crash the gateway** — the backend read the body from the
  client stream's buffer, which the reset had freed. The body is now sent from
  its own copy, and a failed allocation while forwarding no longer leaks it.
- **HTTP/2 requests on a pool using default round-robin could land on the same
  backend when two workers picked at the same moment, skewing the spread.**
  The shared round-robin counter was read and written without synchronisation;
  each pick now takes its value with one atomic add.
- **Immediately after a gateway start (rollout or HA failover), an HTTP/1.1
  client could wait indefinitely for a response the backend had already sent,
  or have its next request held.** Two workers handling their first responses
  at the same moment both initialised the shared response-parser settings, and
  the second could clear them under the first. The settings are now
  initialised once, before any connection uses them, on the request and
  response sides.
- **An L7 policy FORWARD that names some of a listener's endpoints no longer
  routes through a shared copy of the pool.** Such a route used one scratch
  copy of the listener's pool, rewritten by every request on every worker
  and freed when the policy was replaced or detached while connections
  routed through it still wrote to it. It now selects among the named
  endpoints of the listener's own pool, so endpoint health, circuit
  breakers, drains and per-endpoint accounting are the pool's, and on an
  AI-gateway pool the request passes the capacity gate it used to skip.
  Policy routes are also read under the proxy lock: a replace or detach
  could free them, compiled patterns included, under a request being
  routed.
- **A rule add whose routing index cannot be built is refused cleanly.** The
  rule no longer stays in the table while the API answers an error; a
  delete in the same case lets go of the pool at the next change instead of
  keeping it for the life of the process.
- **Deleting or re-creating a full-proxy rule no longer leaks its endpoint
  pool, and no longer frees state that live connections still use.** Every
  delete of a full-proxy rule, and every replace that changes more than the
  admission gate (a replace with new endpoints is a delete and an add), left
  the rule's pool allocated: 58,368 bytes per pool, for the life of the
  process, so a controller that churns rules grew the gateway without bound.
  The pool could not simply be freed at the delete, because connections,
  HTTP/2 sessions and streams, and held admission permits kept using it; the
  delete also destroyed two locks of the pool those users still took. A pool
  is now reference-counted by everything that holds it and freed when the last
  holder lets go, after every proxy worker has passed a quiescent point (an
  idle worker counts as quiescent, so a quiet gateway frees promptly). The
  lookups that find a pool by its rule read an index that is replaced, never
  edited in place, and an old index is freed the same way, so a request routed
  while a rule is deleted can no longer read a table entry that was just freed.
  Nothing changes in the configuration, the API or the answers a client gets.
  Two new metrics show it: `loxilb_proxy_pools_live` (pools allocated and not
  yet freed, a deleted rule's pool included until its last holder is gone) and
  `loxilb_proxy_pools_freed_total`. Under rule churn the live count returns to
  the number of rules once the deleted rules' connections end; one that only
  grows is a holder that never lets go.
- **Bytes a client sends while a streamed answer is running are no longer
  relayed to the backend.** On a rule with `sse_mode`, anything a client sent
  on an HTTP/1.1 connection while its streamed answer was still in progress
  went to the backend behind the request being answered, without passing the
  admission gate: a second request sent early was served with no credential
  checked, no model allowlist, no rate limit and no charge. On a JWT service
  whose profile has `forward_identity` the gateway also wrote the first
  request's verified `X-Auth-Tenant` / `X-Auth-User` into those bytes, so the
  backend read them as an authenticated request. The gateway now closes the
  connection when a client sends anything before its streamed answer has
  ended; the unfinished stream is counted as one its client left, and each
  such close is counted in `loxilb_ai_stream_early_bytes_closed_total{service}`
  and logged once at debug. A streamed answer has ended when its framing
  ends, whether or not it carried the `[DONE]` event, so the next request on
  a kept connection is admitted as any request. **Impact:**
  a client that pipelines a request behind a streamed answer on HTTP/1.1 has
  the connection closed and must send that request on a new one (or wait for
  the answer to end, or use HTTP/2). Clients that wait for their answer are
  not affected.
- **A request or response body is no longer edited as if it were a header
  block.** On the path that relays a connection's later reads, any read that
  held a blank line was taken for a header block: on a service that declares
  `api_key_auth`, lines beginning `X-Api-Key:` (and on a service with a
  forwarding network-identity binding, lines beginning `X-Auth-`) were
  removed from it, in a request body, in a backend's response headers and in
  a response body alike, leaving the message shorter than its
  `Content-Length`. Header lines are now removed only from the header block
  of a request, once, and a response body is never touched.
- **A backend's `X-Api-Key` response header is removed on purpose, where it
  was removed by accident.** On an HTTP/1.1 service that declares
  `api_key_auth` (any declared value) the gateway already removed a
  backend's `X-Api-Key` response header, as a side effect of the defect
  above. It still does, now as a rule: `X-Api-Key` is the gateway's
  credential header on such a service and a backend does not get to hand a
  key to a client under that name. The header is removed from the response
  head only, when the head arrives whole in one read. **Behaviour change:**
  the rule now holds on HTTP/2 as well: on an HTTP/2 service that declares
  `api_key_auth` a backend's `x-api-key` response field, which earlier
  releases passed through, is dropped from the response head (not from
  trailers). Unchanged from earlier releases: a backend's `X-Auth-*` response
  headers pass through on every service; on a service that makes no
  `api_key_auth` declaration, and on a rule whose response direction is
  carried by `sockMapMode`, a backend's `X-Api-Key` passes through as well.

- **`GET /logs` could not page back through older history** — page two re-read the newest page forwards — paging now walks backwards and covers every line once. (#65)
- **A rule with `security=3` was stored and read back but served plaintext** — the API enum allowed a value the data path has no branch for — it is refused with 422. (#66)
- **Policer refusals answered a bare 500** — a below-floor rate and the egress-without-hooks refusal missed the validation class — both answer 400 with the reason, and a rate refusal names the field. (#92, #169)
- **IPsec and VXLAN failures answered 200 with the error in `result`** — those paths used the success responder — they answer their classified 404, 409, 400 or 500, so a client must read the status. (#112)
- **A global rate-limit default answered 404 when `rule_ident` was also sent** — the store was keyed on it although the API ignores it for that scope — it is ignored as declared. (#210)
- **A removed or lifted quota kept being enforced** — a removed per-user model quota and a lifted tenant token quota stayed in force — both stop on the change. (#215)
- **Rate-limiter state did not sync on an HA pair serving only L7 AI traffic** — the push loop skipped its tick without dialling, and only session sync or key invalidation dialled — the push loop connects for itself, so such a pair now exchanges quota state; see Upgrade notes. (#224)
- **A restore failed on a host with no config directory** — publishing a file did not create it — the directory is created. (#249)
- **A load-balancer `POST` could take about a second under load** — the data-path worker slept up to one second between queue drains — it wakes on its queue. (#257)
- **A config write about three seconds after another answered 503 "restore in progress" with no restore running** — auto-persist, after its 3-second quiet period, took the gate a restore holds — writes wait out the capture. (#260)
- **A valid request on an unprovisioned server was told its arguments were malformed** — server preconditions shared the malformed-argument answer — they answer 412. (#263)
- **`connectionLimit` could not be set through REST** — POST, PATCH and GET did not carry it — all three do. (#275)
- **A create body without its object crashed three create handlers** — the body was not checked — it is refused. (#285)
- **A panicking management handler left no audit result** — the gate did not record panics — the result is recorded. (#285)
- **A rule whose TLS context could not be built stopped the gateway** — the data plane asserted on it — the rule fails with its reason in the log and the gateway keeps serving. (#340)
- **A certificate delete or rotation reported success when the rules could not be consulted** — the failed call was read as an answer — it answers 500, and nothing is deleted. (#352)
- **On a rule that re-encrypts to its backends, a backend TLS failure reached the client as an empty reply or a cut-off response** — the leg's failure paths wrote no complete answer — the client gets a complete `backend_unreachable`, 502 on HTTP/1.1 and 503 on HTTP/2. (#354)
- **On a non-AI-gateway rule, a kept-alive HTTP/1.1 client kept the old backend TLS policy after a replace or rotation** — its backend connection outlived the change — an idle connection closes within about a second, one in flight after its answer, and an answer still owed at 30 seconds is cut. (#355)
- **An audit sink could lose records while reading `connected`** — a socket write was taken for an acknowledgment — what was not acknowledged is sent again, and a segment is pruned once. (#357)
- **A rule taking over a kept listener ran with the previous rule's TLS setup, so after an endpoint update trusted clients were refused, a rule requiring a client certificate could serve a client with none, and an HTTP/2 backend rule was not served** — the kept listener's setup was reused — the rule is judged by its own arguments. (#359)
- **A cluster standby refused every full-proxy rule with 400, so a new master had none after failover** — the VIP is not bound on a standby — the rule is kept and installed on takeover, and a refused install says whose problem it is. (#362)
- **A replace or merge-patch answered 200 or `lbrule-exists` and kept the old value** — one half of the path dropped several accepted values — `name`, `probeTimeout`, `probeRetries`, endpoint values and `mtls_frontend` are applied, and a `name` that changes the cluster instance or VIP handling is refused with 409. (#363)
- **A replace the data plane refused left the rule not serving and showing the refused values** — the request was stored before the push — the rule returns to what it was. (#364)
- **A client that read a rule and sent it back dropped its timeouts, TLS and HSTS settings** — GET did not serialize them — GET returns them. (#365)
- **A created certificate's minted ID could not be learned** — the create answered empty — the answer carries the ID. (#365)
- **A `tls_ciphers` string the TLS library rejects answered 412 on a rule that terminates TLS** — it was reported as a gateway condition — it answers 400 naming the field, and on a replace the rule is untouched. (#366)
- **A proxy-only gateway could not restore its own snapshot on restart** — the disabled security-rate domain touched absent kernel maps — that state is normalized without them. (#374)
- **Logout answered 200 and the Bearer session stayed usable** — the revoke hashed the whole `Authorization` header — it revokes the token itself, and the old token answers 401. (#378)
- **Deleting one pool on a shared listener removed source rules a remaining pool still needed, so a denied client could reach that pool** — the entries were owned per pool — they stay until the last interested pool goes. (#383)
- **A rule with equal `port` and `portMax` returned success while TCP clients timed out** — the control plane built a range mark the data plane treats as a singleton — equal bounds are one port. (#397)
- **An HTTP/1.1 backend connection failure answered 502 with no audit completion** — the local response path skipped the recorder — one completion is recorded. (#399)
- **BGP policy bindings were lost across a restore** — capture omitted the assignments — schema 1.12 carries them (older documents do not gain them), and a replacement that would discard live ones is refused before it starts. (#403)
- **A certificate path that could not be read crashed boot or a rule add** — any stat error other than not-found dereferenced nil — it reads as absent and is logged once. (#456)
- **Device, filesystem and process status reads failed intermittently** — the SIGCHLD reaper took their children's exit status — they read kernel files directly. (#458, #460)
- **`GET` of BFD sessions answered 500 on a gateway with none** — a lifecycle hint was read as availability — it answers 200 with an empty list. (#464)
- **An HA gateway could wedge at boot adding a BFD session** — session add and the receive path took two locks in opposite order — the lock is not held across the BFD table. (#475)
- **A restarted HA node could take MASTER back with no synced conntrack, and a rolling restart lost sessions on failback** — only the first boot BFD session waited for the initial sync — every boot add waits for that sync and its cool-off; adds after it are not delayed. (#482)
- **A container with `--sockmapsupport` did not come back after `docker restart`** — the mount script trusted the directory, not the mount — the cgroup2 mount is verified at boot. (#486)

### Upstream

- Based on upstream loxilb `d6adfb77` (after `v0.9.8.6`), with selected upstream fixes ported; loxilb-ebpf pin `f00d8b3f7de5b70e3971167a791ce5a3cf5d78e4`.

### Notes

- **Bundled loxicmd:** v0.9.9.2 (`1d9e9463f5732c8d170e08d85964f255ef5338f1`), set by `ARG LOXICMD_TAG` in every Dockerfile.
- This release preserves full upstream loxilb functionality; classic L4/L7
  load balancing is unchanged and documented upstream.

### Known issues

- **`loxicmd delete lb` without `--bgp` leaves the VIP advertised.** The rule is removed but its route is not withdrawn, so peers keep sending traffic to an address with no rule. Present since v0.9.8.7. Workaround: delete a rule created with `--bgp` with `--bgp` as well.
- **govulncheck lists findings with no fix in this release.** GO-2026-6860 and GO-2026-6866 (`golang.org/x/net/html`, fixed in x/net 0.62.0) and GO-2026-5932 (`golang.org/x/crypto/openpgp`, no fix) are module-level: no affected function is in the binaries. GO-2026-4736 (GoBGP NEXT_HOP handling, no fixed version) is listed against GoBGP functions in `gobgp`, `gobgpd` and `loxilb`; its crash did not reproduce in 30 attempts against GoBGP v3.

### Upgrade notes

- **Streaming no longer implies API-key enforcement, and MySQL/MariaDB is gone.** A rule that relied on its streaming flag to enforce keys must declare `api_key_auth: "required"`; unset resolves to `disabled`, and every quota write warns while nothing enforces. The `--database*` flags are replaced by `--mgmt-db-*`, and the data plane uses `--aikey-db-*`. Both stores are PostgreSQL. Keys are no longer read from the old database, so move them first. With no `--aikey-db-host`, a rule with `api_key_auth: "required"` answers 503 `policy_store_unavailable`, and a rule that declares nothing admits requests without a key. (#80, docs/AI-KEY-STORE.md)

- **Mixed credential policies on one listener are refused.** A snapshot that
  holds fullproxy rules with different `api_key_auth` / `jwt_auth_profile` on
  one address, port and protocol still restores (each disagreement is logged
  with the rule it disagrees with), but the next create or replace of such a
  rule is refused with 400 until every rule of the listener declares the same
  policy. Declare it on each rule, or move the differing rule to its own port.
- **Metric meanings change for P/D requests and for every answer the gateway
  writes itself.** Dashboards and alerts built on the families below read
  different numbers after the upgrade. Nothing is removed; the panel titles
  of row 33 gain "(global)", and the recording rule of row 30 is
  deprecated under its old meaning, with its successor beside it. The
  families that count the same requests from another angle, and must not be
  summed with `loxilb_ai_requests_total`, are listed in
  `deploy/monitoring/README.md`. Commits are loxilb-ebpf (`ebpf`) or this
  repository (`gateway`).

  | # | Family | Label / outcome | Before | After | Commit |
  |---|---|---|---|---|---|
  | 1 | `loxilb_ai_requests_total` | `status`, P/D (vLLM, TensorRT-LLM) | the prefill reply's status | the status the client received: the decode leg's, or the prefill leg's when it answered the client. SGLang P/D is unchanged | ebpf `e0ece83` |
  | 2 | `loxilb_ai_requests_total` | `status="500"` / `"429"` from a prefill 5xx/429 that decode recomputed | counted as 500/429 | counted as 200, the status the client got. The fallback itself is counted by `loxilb_ai_pd_prefill_fallback_total` (row 19) | ebpf `e0ece83` |
  | 3 | `loxilb_proxy_http_responses_by_status_total`, `loxilb_proxy_http_responses_total` | P/D | one count per request, by the prefill status | one count per request, by the status the client received | ebpf `e0ece83` |
  | 4 | `loxilb_proxy_http_ttfb_seconds` | P/D | sampled when the prefill reply arrived | sampled at the client's first byte (the decode leg's first response, or the relay of a prefill answer) | ebpf `e0ece83` |
  | 5 | `loxilb_ai_pd_requests_total` | vLLM prefill 4xx (not 408/429) | decode called; `complete/success` | decode not called, the prefill's 4xx relayed verbatim; `prefill/rejected` | ebpf `82c7ef8` |
  | 6 | `loxilb_ai_pd_requests_total` | non-SSE decode completion | `complete/success` whatever the status | 2xx/3xx `complete/success`; 4xx `decode/rejected` (new); 5xx `decode/error`; no status line read `decode/unknown` (new) | ebpf `d428679`, gateway `753041da` |
  | 7 | `loxilb_ai_requests_total` | unknown model whose head and body arrive in separate reads | forwarded to the listener's first pool without the model check (QA saw a backend 404, `outcome="completed"`) | refused 503 `model_unavailable`, `outcome="denied"`, `model="other"` | ebpf `7d332ca` (routing), `14b2951` + gateway `35042841` (count) |
  | 8 | `loxilb_ai_requests_total` | `outcome="denied"`: who writes it | the four Go gate exports, so only the refusals a Go export decided (key, bearer, rate limit, quota, policy store) | the deny record the data plane takes once per refusal (`llb_ai_record_deny`), with the status written. The Go exports no longer count, so no refusal is counted twice | gateway `35042841` |
  | 9 | `loxilb_ai_requests_total` | `outcome="denied"`: refusals added | absent | route: 503 `model_unavailable`, `no_route`, `no_rules`, L7-policy REJECT/no-match. Framing: both 413s, the model-required 400, 400 `invalid_cache_salt`, the SGLang oversize 503. Capacity: 429 capacity/queue full, 504 queue timeout, 503 drain, the P/D in-flight 429, 504 `pd_admission_park_timeout`. The five C-only gate arms: `netid_unavailable`, `objective_not_allowed`, 400 `model_conflict`, 403 `model_not_allowed` (binding), 403 `network_tenant_mismatch`. Security: the LlamaFirewall 403 (only in builds with it) | ebpf `14b2951`, `9bffd3b`, `56bd489` (never also completed); gateway `35042841` |
  | 10 | `loxilb_ai_requests_total` | `model` on a route or framing refusal | n/a (not counted) | never takes a new label: a served model keeps its name, any other reads `other`; a route refusal that named no model reads `none`, a framing one `""` | gateway `35042841` |
  | 11 | `loxilb_ai_requests_total` | `model` on the keyless shared-bucket refusal | `""` | the model the request named | gateway `35042841` |
  | 12 | `loxilb_ai_requests_total` | `outcome="completed"`: gateway-written answers added | absent; the P/D ones only in `loxilb_ai_pd_requests_total` | the status written: 503 `no_healthy_backend` / `pd_pool_unavailable` / `service_unavailable`; P/D leg timeouts 504 (prefill, decode, idle) and the stalled decode stream 502; the P/D decode-init, decode-response and prefill-death 503s, the decode zero-byte 502, the vLLM failover 503, the SGLang 502/503s; the connect-failure 502; an L7-policy REDIRECT with its 3xx. (`backend_unreachable` 502 was already counted.) | ebpf `14b2951`, `9bffd3b` |
  | 13 | `loxilb_proxy_http_responses_by_status_total`, `loxilb_proxy_http_responses_total` | the gateway's own HTTP/1.1 answers | not counted (backend replies only); `backend_unreachable` 502 moved the 5xx class only if a backend reply did | counted by class: every refusal, outage, timeout, P/D/connect/SGLang failure and L7-policy answer in rows 9 and 12, and `backend_unreachable` | ebpf `14b2951`, `9bffd3b` |
  | 14 | `loxilb_proxy_http_ttfb_seconds` | the gateway's own answers | not sampled | not sampled (unchanged; now stated in the help text). Backend replies only | ebpf `14b2951` |
  | 15 | `sec.ai.deny` audit records, `loxilb_ai_netid_requests_total` | refusals and stages | gate and capacity refusals | also route, framing, the P/D in-flight 429 and park timeout, L7-policy REJECT and security; new stage names `route`, `framing`, `security` | ebpf `14b2951`, `9bffd3b`; gateway `35042841` |
  | 16 | all of the above on HTTP/2 | | | refusals move `requests_total{denied}`, outages `requests_total{completed}`; HTTP/2 has no class count or TTFB sample for any response | ebpf `14b2951` |
  | 17 | `loxilb_ai_pd_decode_ttft_seconds` | P/D | decode dispatch to the end of the decode response, every request | decode dispatch to the first streamed event (the first SSE data object, a role-only delta included), streamed requests only. **Its values drop by design**, by about the stream's length, and non-streamed P/D requests stop adding samples. No shipped alert or recording rule reads this family. **Revisit any local alert or SLO tuned on the old values**, and compare those values with row 18, not with the new TTFT | ebpf `2fbbe68`, gateway `292de52a` |
  | 18 | `loxilb_ai_pd_decode_duration_seconds` (new) | P/D | absent | decode dispatch to the end of the decode response (row 17's old meaning); not sampled for a request a reaper ended | gateway `292de52a` |
  | 19 | `loxilb_ai_pd_prefill_fallback_total` (new) | `model`, `reason` | absent | one count per prefill recomputed on the decode leg. The reason is the condition that forced it, in verdict order: a status that forces it on its own is the reason even when the reply was also cut | ebpf `2fbbe68`, gateway `292de52a` |
  | 20 | `loxilb_ai_pd_requests_total` | a P/D answer the gateway ended or cut: the graceful-`[DONE]` sweep, the stream timeout, the idle cap on a begun answer, the duration cap | `complete/success` (sweep) or no record (the others) | `decode/truncated` (new): the gateway ended or cut an in-progress answer for a cause other than engine death. How it ended is `loxilb_ai_pd_terminator_synthesized_total` (row 24) | ebpf `aa7dbc2`, `a8a0906`, `6e8821d`; gateway `292de52a` |
  | 21 | `loxilb_ai_pd_requests_total` | the decode engine dies mid-stream (EOF) | no record on a chunked answer; `complete/success` where the sweep reached it | `decode/error`: `decode/error` now means only that the engine died | ebpf `a8a0906` |
  | 22 | `loxilb_ai_pd_requests_total` | a P/D client that stopped reading (stall abort) or cancelled | no record | still no record. A client-cancelled P/D request carries no TTFT or fallback sample either. **Superseded by row 27** | — |
  | 23 | `loxilb_ai_requests_total` | `outcome="completed"`: an answer a reaper ended after its 200 (the sweep, the stream timeout, the idle cap) | no record | one record, the status the client received (200). **Superseded by row 25** for the answers the gateway cut; the graceful `[DONE]` sweep stays `completed` | ebpf `a8a0906`, `6e8821d` |
  | 24 | `loxilb_ai_pd_terminator_synthesized_total` (new) | | absent | the terminators the sweep wrote. The rest of row 20's `decode/truncated` is answers cut with an error | ebpf `2fbbe68`, gateway `d3bca14b` |
  | 25 | `loxilb_ai_requests_total` | an answer the client did not get whole: cut by the engine dying, a cap, a reaper (not the graceful `[DONE]` sweep) or the listener; the client cancelling or stalling | `completed` with its status (row 23), or no record | `outcome="aborted"` (new) with its status and a `cause` (new label): `engine`, `gateway` or `client`. Supersedes the Stage 2 behaviour S2-7. Every selector of this family in a ratio must name its outcome, and one on `aborted` its cause | ebpf `6ec80a3`; gateway `e64ce853` |
  | 26 | `loxilb_ai_requests_total` | `status` of a request that got no status | n/a (not recorded) | `status="none"` | ebpf `66e4c2d`; gateway `e64ce853` |
  | 27 | `loxilb_ai_pd_requests_total`, `loxilb_ai_requests_total` | a P/D client that left: before any answer, with its answer open, or it stopped reading | no record in either (row 22) | one record in each: `{phase="aborted",status="client"}` (new) and `outcome="aborted",cause="client"` with the status it got (`none` before any answer) | ebpf `6ec80a3`, `66e4c2d`; gateway `e64ce853` |
  | 28 | `loxilb_ai_request_duration_seconds` | an aborted request | sampled where the request was recorded (the cut answers of row 23) | not sampled: completed requests only. `loxilb_ai_pd_decode_ttft_seconds` still samples an aborted stream that reached its first event | gateway `e64ce853` |
  | 29 | `LoxilbAIErrorRatio` (alert) | numerator, denominator | every non-2xx completion over completions | completed 5xx plus aborted with cause `engine`/`gateway`, over completed + aborted. **A completed 4xx no longer counts; a cut 200 now does; a client cancel never does.** Revisit any routing, silence or inhibition built on its old firing | gateway `cab041c9` |
  | 30 | `instance:loxilb_ai_5xx_ratio:rate5m` (recording rule) | | completed 5xx over completed | **removed** (deprecated at `dd69b7db`, removed in this same release; it did not see `aborted`). Use `instance:loxilb_ai_error_ratio:rate5m` (new), the ratio of row 29 per instance | gateway `dd69b7db`, this PR |
  | 31 | `loxilb_ai_pd_requests_total`, `loxilb_ai_pd_prefill_fallback_total`, `loxilb_ai_requests_total` | series present before their first event | from the first event | at 0: per model label at registration (P/D, 16 series), per keyed (model, tenant) pair at its first record (31 series: every gateway-decided combination, see Changed). A query counting series, or using `absent()`, reads differently | gateway `905afa49` |
  | 32 | AI Gateway dashboard | `$model`, `$tenant`, `$instance` All; filters on panels 1, 2, 6, 7, 8, 9, 10, 13, 14, 15, 25, 48, 52, 64, 65 | All omitted `tenant=""`; those panels ignored the picker | All is `.*`; the panels obey it. `$instance` All is `.*` on the L4, L7, overview and security dashboards too | gateway `5f407545` |
  | 33 | panel titles and the alerts' `panel` annotation | the 32 panels no filter reaches | the plain title | the title plus " (global)": AI Gateway "KV subscribers up", "Tier-1.5 hits vs spills vs fallthrough/s", "KV miss reasons/s", "Tier-1.5 hits by endpoint", "Cold fail-open windows", "Policer attachment (datapath truth)", "Shaped throughput by service and direction", "Bucket saturation (delayed / passed)", "Parks/s", "Mean park duration", "Readers parked now", "Bucket level vs burst depth", "KV attestation", "KV event integrity", "P/D endpoint failures", "Policy store / unmetered", "KV event staleness", "KV inventory freshness", "P/D & KV inventory levels", "KV inventory pressure", "P/D robustness events", "P/D stream terminations", "Full-proxy cache", "Payload parser", "Gate mode by pool", "Capacity in flight vs ceiling", "Gate decisions/s by reason", "Gate accounting anomalies", "Queued vs queue depth", "Queue wait p50 / p95", "Adaptive ceiling vs configured", "Accept valve: contexts vs bound". Alerts whose annotation moved: `LoxilbKvWireReject`, `LoxilbKvSubscriberDisconnected`, `LoxilbKvReconnectStorm`, `LoxilbKvZeroHitWatchdog`, `LoxilbTrtllmDrainOwnershipFault`, `LoxilbPdSameEpRetryExhausted`, `LoxilbPdEndpointDied`, `LoxilbPolicyStoreUnavailable`, `LoxilbUnmeteredTraffic` (`loxilb-ai-kv-alerts.yml`); `KvExactEnforcementFault`, `KvExactRuleNotReady`, `KvExactAttestationProbeFailures`, `KvExactEchoChallengeFailures`, `LoxilbAIAdmissionShedding`, `LoxilbAIAdmissionQueueTimeouts`, `LoxilbAIAdmissionQueueNearDepth`, `LoxilbAIAdmissionAdaptiveFrozen`, `LoxilbProxyAcceptValveBlocking`, `LoxilbAIAdmissionAnomaly` (`loxilb-alerts.yml`, both copies). A link or a notification template that matches a panel by title needs the new one | gateway `5f407545` |
  | 34 | every scraped loxilb series | `cluster` | absent (only `external_labels`, on what leaves Prometheus) | `cluster="loxilb-default"` from the scrape job; the `cluster:`/`instance:` recording rules and the KV alerts now carry it. Set the same value per site in both places | gateway `72c5ecdf` |
  | 35 | the alerts and panels of Fixed (lazy families) | first event of a series | not counted by `increase()` | counted: the alerts can fire on the first event of a kind | gateway `0d05de6c` |
  | 36 | `loxilb_ai_pd_prefill_fallback_total{reason="truncated"}`, `loxilb_ai_pd_requests_total` | a prefill 4xx cut at the buffer cap | recomputed on the decode leg; `truncated` fallback, `complete/success` | relayed with its status; `prefill/rejected`, no fallback. `truncated` is a cut 2xx only | ebpf `8d85276` |
  | 37 | `data.ai.complete` audit records | `outcome.reason` of an aborted answer | `ok` | `client_abort` (cancel, stall, leaving before any answer), `timeout` (a cap or a reaper), `backend_conn` (the engine dying), `gateway_shutdown` (the listener going away under the answer; a new vocabulary value — it read `backend_conn` before) | gateway `e64ce853`, this change |
  | 38 | `loxilb_ai_requests_total` | a client that left before any answer, on a rule that is not P/D (HTTP/1.1) | no record | `outcome="aborted"`, `status="none"`, `cause="client"`, one record; no `loxilb_ai_pd_requests_total` record (no lifecycle family pairs with it). **`status="none"` (row 26) is no longer P/D-only**. Not on a rule whose answers go by the kernel (sockMapMode `response`): no record there, as for its answers | ebpf `174fb525` (#119), `bcfb6bf`; gateway CI row TP-I |
  | 39 | `loxilb_ai_requests_total`, `loxilb_ai_pd_requests_total` | a P/D client that left at the gate, in the capacity queue or parked (before any prefill) | no record in either | one record in each: `outcome="aborted"`, `status="none"`, `cause="client"` and `{phase="aborted",status="client"}`, as row 27 for a client leaving in the prefill | ebpf `6294e71` (#120); gateway CI row TP-K |
  | 40 | `loxilb_ai_requests_total`, `loxilb_proxy_http_responses_by_status_total` | a backend on a rule that is not P/D that closed before any answer (HTTP/1.1) | no record; the client got a bare close | the client gets the gateway's 502 `backend_unreachable`: `outcome="completed"`, `status="502"`, one record, no lifecycle record (as a refused connect, row 13, and a TLS leg failing before its answer). Only when the client cannot be told: `outcome="aborted"`, `status="none"`, `cause="engine"` | ebpf `0a77af5` (#120), `b0c647d`; gateway CI row TP-J |
  | 41 | `loxilb_ai_requests_total`, `loxilb_proxy_http_responses_by_status_total` | the MCP refusals (400/405/413) on both protocols; the HTTP/2 503s `backend_unreachable` and `mcp_backend_unavailable`; the HTTP/1.1 400 refusing an unparseable or ambiguously framed request before admission | no record (allowlisted as "MCP accounting", F-6/F-7, "before a request exists") | 4xx: `outcome="denied"`, stage `framing`, error `mcp_invalid_request` / `mcp_method_not_allowed` / `mcp_request_too_large` / `bad_request`; 5xx: `outcome="completed"` with the status written. HTTP/1.1 ones also counted by class. Wire bytes unchanged. AI-gateway rules only | ebpf `d348af5` (#125) |
  | 42 | `loxilb_proxy_http_responses_total`, `loxilb_proxy_http_responses_by_status_total`, `loxilb_proxy_http_ttfb_seconds` | a backend's interim `1xx` (its own `100 Continue` after a forwarded `Expect`, a `103 Early Hints`) ahead of its answer (HTTP/1.1) | the `1xx` took the record: `responses_total` +1 with no class, TTFB sampled at the `1xx`, the final status a no-op (repaired by the framer in `loxilb_ai_requests_total` only); trace status `1xx` | the `1xx` is ignored; the final answer is recorded once: class, TTFB, trace status. `101` is still the answer | ebpf `94bd346` (#130) |
  | 43 | `loxilb_proxy_http_responses_total`, `loxilb_proxy_http_responses_by_status_total`, `loxilb_proxy_http_ttfb_seconds` | an HTTP/2 stream's answer: a backend `:status`, a gateway-written refusal or outage frame, the L7 synthetic answer | no record; HTTP/2 showed in `loxilb_ai_requests_total` only | one record per stream at its final status (`>= 200`): the class count on every answer, the TTFB sample on a backend's. `loxilb_ai_requests_total` keeps its own rules (rows 41–42) | ebpf `7994efc` (#126) |

- **`tenant_rate_limits` gains a `burst_pct` column.** The gateway adds it on
  start-up if it is missing, so an existing database needs no manual step and
  an already-migrated one is left alone. The column defaults to `0`, which
  means "use the server default", so tenants configured before this release
  keep exactly the capacity they had.

- **Token-quota state does not interoperate across this change in an HA pair.**
  Quota is synchronized between peers over an unchanged wire format, and this
  release reuses one of its existing integer fields to carry a bucket
  drain-time timestamp instead of a consumed-token count. The two are merged
  by taking the larger value, which makes the incompatibility **one-way**:

  - **New peer → old peer is harmful.** The old build reads a millisecond
    timestamp as a token count, concludes the tenant is enormously over
    budget, and denies its traffic with `429` until the entry ages out.
  - **Old peer → new peer is harmless.** A token count interpreted as a
    timestamp lands far in the past, so it loses the merge to the new peer's
    own value and cannot deny anyone.

  So a **rolling upgrade of an HA pair is not supported while token quotas are
  enabled.** Prefer upgrading both peers together.

  If the peers must be upgraded one at a time, set `tokens_per_min` to `0`
  **before** upgrading the first one. Quota entries are only created when a
  limit is configured, so a peer that restarts into the new build with quotas
  disabled never creates quota state and therefore never sends any. Ordering
  matters: disabling quotas does not retract entries that already exist — the
  upgraded peer starts with an empty map, but a peer left running keeps its
  entries until they idle out (about 10 minutes by default, `LLB_AI_QUOTA_EVICT_WINDOWS`).
  Re-enable quotas once both peers run the same build.

  Request-rate limits, API-key authorization and model authorization are
  unaffected and may stay enabled throughout. This applies only to peers
  exchanging quota state — a standalone gateway upgrades normally.

<!--
Template for future releases:

## [vX.Y.Z.W] - YYYY-MM-DD
### Added
### Changed
### Fixed
### Upstream
- Synced loxilb <upstream-version> / loxilb-ebpf <pin>.
-->
