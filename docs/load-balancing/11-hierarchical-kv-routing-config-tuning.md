# Hierarchical KV-Cache-Aware Routing — Configuration & Tuning Guide

> **Audience:** operators and platform engineers configuring LoxiLB's AI routing hierarchy.
> **Scope:** every operator-facing knob — REST rule fields, LoxiLB environment variables, the
> AI-controller flags, vLLM-side matching configuration — plus a tuning playbook and the
> observability needed to verify each layer engaged.
> **Prerequisite reading:** [10 — Architecture & concepts](10-hierarchical-kv-routing-architecture.md)
> for what each layer does; [08 §6](08-kv-cache-aware-routing.md) for Tier-1.5 onboarding
> (tokenizer staging, per-model runbook).
> **Last verified** against branch `` (2026-07-06).

---

## 1. Configuration surface at a glance

The hierarchy is configured in **four places**; each row of the ladder maps to specific knobs:

| Layer | Where configured | Key knobs |
|---|---|---|
| Rule shape (P/D vs single-pool) | REST rule | `mode`, `pd_disagg_mode`, `ep_role`, `nixl_port` |
| Tier 0 stickiness | REST rule | `pd_session_ttl_sec` (P/D); `sel:3` / session headers (single-pool) |
| Tier 1 trie | REST rule | `pd_cache_aware_mode`, `pd_cache_threshold`, `pd_balance_abs_threshold` |
| Tier 1.5 KV-exact | REST rule + LoxiLB env + vLLM flags | `kvExactMode`, `kvZmqPort`, `kvHashAlgo`, `kvBlockSize`, `kvWarmupSec`; `LLB_KV_NONE_HASH_SEED`, `LOXILB_KV_MAX_BLOCKS`; vLLM parity triad |
| Tier 1.5 blend law | LoxiLB env | `LOXILB_KV_LB_MODE`, `LOXILB_KV_MEAN_LOAD_FACTOR`, `LOXILB_KV_LOAD_PENALTY`, `LOXILB_KV_SPILL_RELIEF`, `LOXILB_KV_CAP_SUM_MILLI` |
| Admission gate | LoxiLB env | `LLB_PD_MAX_INFLIGHT_PER_EP`, `LLB_PD_QUEUE_DEPTH_PER_EP`, `LLB_PD_MAX_PARK_SEC`, `LLB_PD_MAX_TOTAL_INFLIGHT` |
| Single-pool cache affinity | REST rule | `sel:8/9/10`, `chwbl_*` fields |
| Controller loop | LoxiLB env + controller flags + registry YAML | `LOXILB_AI_CTRL_ADDR`, `AICTRL_*`, `ai-controller.yaml` |
| TLS posture | REST rule / loxicmd | `security`, `host`, cert staging |

**Environment variables are read once at process start** (both the Go `LOXILB_*` family and the
C `LLB_*` family) — changing any of them requires recreating the LoxiLB container. REST rules
can be re-posted at runtime.

---

## 2. REST rule fields

Endpoint: `POST http://<loxilb>:11111/netlox/v1/config/loadbalancer`. Schema:
`api/swagger.yml`; generated model `api/models/loadbalance_entry.go`.

> **Field-casing trap (silent!):** `pd_disagg_mode`, `pd_cache_aware_mode`, `pd_session_ttl_sec`,
> `pd_cache_threshold`, `pd_balance_abs_threshold`, `ep_role`, `nixl_port` are **snake_case**;
> `kvExactMode`, `kvZmqPort`, `kvHashAlgo`, `kvBlockSize`, `kvWarmupSec`, `externalIP`,
> `targetPort` are **camelCase**. A wrong-cased field is silently dropped — the API does not
> error, the feature just never engages.

### 2.1 Service-level (`serviceArguments`)

| Field | Type | Default | Values | Meaning |
|---|---|---|---|---|
| `mode` | int | 0 | 0–6 | NAT mode. **4 = fullproxy is required** for every L7/AI feature here (0 DNAT, 1 onearm, 2 fullnat, 3 dsr, 5 hostonearm, 6 aigw) |
| `sel` | int | 0 (rr) | 0–10 | Selector. Single-pool cache affinity: **8 = chwbl, 9 = gpuaware, 10 = wrr-hash**. Under P/D, `sel` matters only for the Tier-2 C2 arm (9 enables capacity-blend scoring) |
| `security` | int | 0 | 0/1/2 | 0 plain, 1 HTTPS/TLS termination, 2 end-to-end HTTPS |
| `host` | string | — | — | Host key for L7/HTTPS rules; **HTTPS rules are keyed by it — deletion must repeat `--host`** |
| `sse_mode` | bool | false | — | Marks an SSE/streaming AI service (suppresses idle timeouts mid-stream). Set explicitly — `pd_disagg_mode` does **not** turn it on. (Both `pd_disagg_mode` and `sse_mode` independently enable the internal `ai_gw_mode` datapath, `dpebpf_linux.go:1748-1780`, but the `sse_mode` idle-timeout behavior is gated on this field only.) |
| `pd_disagg_mode` | bool | false | — | Enables P/D disaggregation and the full tier ladder |
| `pd_session_ttl_sec` | int32 | 0 | ≥0 | Tier-0 pin TTL. 0 ⇒ data-plane default 300 s |
| `pd_cache_aware_mode` | bool | false | — | Enables Tier 1 (radix-trie affinity) |
| `pd_cache_threshold` | int32 | 20 | 0–100 | Tier-1 minimum prefix match-rate (%); lower = more aggressive affinity |
| `pd_balance_abs_threshold` | int32 | 3 | ≥0 | Tier-1 load-imbalance bypass: skip affinity when max−min active conns exceeds this |
| `kvExactMode` | int | 0 | 0/1/(2) | Tier 1.5: 0 off, 1 ZMQ inventory (2 = NATS, reserved) |
| `kvZmqPort` | int | 5557 | 1–65535 | vLLM KV-events PUB port (prefill EPs) |
| `kvHashAlgo` | string | `sha256_cbor` | `sha256_cbor`\|`xxhash_cbor` | Must match the vLLM fleet's `--prefix-caching-hash-algo` |
| `kvBlockSize` | int | 16 | ≥1 | Must equal vLLM `--block-size` |
| `kvWarmupSec` | int | 30 | ≥0 | Guard-B window after subscriber start before Tier 1.5 activates |
| `probeRetries` | int | 0 | — | Health-probe retry count (probe state does **not** feed data-plane exclusion — see [10 §5](10-hierarchical-kv-routing-architecture.md)) |
| `chwbl_prefix_hash_level` | int | 1 | 1–3 | Single-pool prefix-hash depth: 1 = prefix+model (+present L1 fields), 2/3 fold in more context |
| `chwbl_mean_load_factor` | int | **175** (effective) | 100–300 | Single-pool bounded-load cap = factor/100 × mean load (175 ⇒ 1.75×). ⚠ swagger annotates `default:125` but that value is **not applied** — the handler overrides only on a non-zero field (`loadbalancer.go:155`), so an omitted field falls to the C-side init of 175 (`sockproxy_http.c`, `dpbroker.go:402`). Set it explicitly if you want 125 |
| `chwbl_replication` | int | 100 | — | Hash-ring vnodes per EP |
| `chwbl_enable_cache_salt` | bool | false | — | Fold the request `cache_salt` into the prefix hash |
| `model_name` | string | "" | — | Pool-selection key for model-routed multi-pool setups (empty = wildcard) |

### 2.2 Endpoint-level (`endpoints[]`)

| Field | Type | Default | Meaning |
|---|---|---|---|
| `endpointIP` | string | — | Backend IP |
| `targetPort` | int | — | Backend port (prefill and decode typically differ, e.g. 8100/8200) |
| `weight` | int | 1 | Endpoint weight (WRR / ring weighting) |
| `ep_role` | int32 | 0 | 0 normal, **1 prefill, 2 decode** (only meaningful with `pd_disagg_mode`) |
| `nixl_port` | int32 | 0 | vLLM NIXL side-channel port (0 ⇒ targetPort); required for the P/D KV handoff, conventionally 5600 |

There is **no loxicmd flag** for the P/D, `kv*` fields — those are REST-only.
`cmd/loxicmd-enterprise/cmd/create/create_lb.go:201-215` (the source in *this* repo) exposes
`--tcp/--udp/--sctp`, `--mode`, `--security`, `--host`, `--path-prefix`, `--path-match-mode`,
`--model-name`, `--endpoints`, `--sse-mode`, `--max-stream-duration-sec`,
`--backend-keepalive-interval-sec`, `--backend-protocol`, and `--inactive-timeout`.

The **single-pool CHWBL family** *is* loxicmd-configurable at runtime — the gated CICD scenarios
(`cicd/vllm-httpproxy*/config.sh`) drive `--select=chwbl` / `--select=chwblwrr` with
`--chwbl-prefix-hash-level`, `--chwbl-mean-load-factor`, `--chwbl-replication` against the
shipped loxilb container's loxicmd, and doc 12 §5 uses the same form. (Those `--select`/`--chwbl-*`
flags are not in this repo's `cmd/loxicmd-enterprise` source but ship in the container image's
loxicmd.) The **portable, always-available path** for every field here is the REST rule body
(§2.1) — prefer it in automation.

---

## 3. LoxiLB process environment variables

Set with `docker run -e …`; all read once at startup.

### 3.1 Go control plane — Tier-1.5 blend + inventory + controller link

| Var | Default | Accepted | Effect |
|---|---|---|---|
| `LOXILB_KV_LB_MODE` | (unset → `hard`) | `off`\|`hard`\|`soft`\|`adaptive`\|`adaptive-soft` | Tier-1.5 selection law ([10 §4](10-hierarchical-kv-routing-architecture.md)). Garbage → warn + `hard` |
| `LOXILB_KV_UNIFIED_MODE` | ON | disable: `0/false/off/no` | Legacy toggle, consulted only when `LOXILB_KV_LB_MODE` is unset; disable ⇒ `off` (pure overlap-argmax) |
| `LOXILB_KV_MEAN_LOAD_FACTOR` | 175 (ε=0.75) | int 100–1000 | Static ε for `hard` mode, as (1+ε)·100 |
| `LOXILB_KV_LOAD_PENALTY` | 32 | int 1–100000 | Static λ for `soft` mode |
| `LOXILB_KV_SPILL_RELIEF` | OFF | `1/true/on/yes` | Hot-prefix spill goes to least-loaded under-cap EP (opt-in) |
| `LOXILB_KV_CAP_SUM_MILLI` | 0 (off) | positive int | Deployment Σcapacity (milli-units) for capacity-normalized adaptive law; factor sanity-clamped [1/8, 8] |
| `LOXILB_KV_TLOAD_LOG` | off | `1` | Promote per-selection `[KV_INV] totalLoad=` diagnostics to Info |
| `LOXILB_KV_MAX_BLOCKS` | 1,000,000 | int 1000–100,000,000 | Per-EP inventory cap (FIFO eviction; watch `loxilb_kv_inv_cap_evictions_total`) |
| `LOXILB_AI_CTRL_ADDR` | unset (no controller) | `host:port` | Master gate for the controller applier; e.g. `10.0.0.13:18856` |
| `LOXILB_AI_CTRL_DECAY_WINDOW_SEC` | 30 | int >0 | α(t) decay window after staleness deadline |
| `LOXILB_AI_CTRL_HYSTERESIS_SEC` | 5 | int >0 | Apply hysteresis |
| `LOXILB_AI_CTRL_ACK_TIMEOUT_SEC` | 10 | int >0 | Snapshot-ack RPC timeout |
| `LOXILB_AI_CTRL_APPLY_JITTER_PCT` | 10 | int ≥0 | Anti-herding apply jitter |

### 3.2 C data plane — Tier-1.5 parity, admission, timeouts

| Var | Default | Accepted | Effect |
|---|---|---|---|
| `LLB_KV_NONE_HASH_SEED` | unset (zero NONE_HASH) | ≤23 bytes | **Must equal vLLM's `PYTHONHASHSEED`** (parity triad leg) |
| `LLB_KV_HASH_DEBUG` | off | `1` | `[KV_HASH]` per-block forensic logging (testbed only) |
| `LLB_KV_LOADGUARD` | off | non-`0` | Hard load-imbalance pre-guard before Tier 1.5 |
| `LLB_PD_PREFILL_TIMEOUT_SEC` | 30 | int | Prefill-leg timeout. **Raise to ≥180 for long-context (32k) fleets** — the 30 s default 504s most requests under load |
| `LLB_PD_MAX_INFLIGHT_PER_EP` | 0 (off) | 0<n<100000 | Admission: per-EP in-flight prefill cap |
| `LLB_PD_QUEUE_DEPTH_PER_EP` | 0 (off) | n>0 (clamped 64) | Admission: park queue depth (hold-don't-drop) |
| `LLB_PD_MAX_PARK_SEC` | 0 (→ prefill timeout) | 0<n<100000 | Admission: parked-request reap deadline (504) |
| `LLB_PD_MAX_TOTAL_INFLIGHT` | 0 (off) | n>0 | Admission: global valve — refuse accept() beyond this |

### 3.3 vLLM side — the parity triad (must match or Tier 1.5 silently degrades to Tier 2)

| vLLM setting | Must match |
|---|---|
| `PYTHONHASHSEED=0` (env) | LoxiLB `LLB_KV_NONE_HASH_SEED=0` |
| `--block-size 16` | rule `kvBlockSize: 16` |
| `--prefix-caching-hash-algo sha256_cbor` | rule `kvHashAlgo: "sha256_cbor"` (vLLM's default pickle-`sha256` is **not** portable — always set `*_cbor`) |
| `--kv-events-config '{"enable_kv_cache_events":true,"publisher":"zmq","endpoint":"tcp://*:5557"}'` | rule `kvZmqPort: 5557`; prefill EPs only; `*` binds PUB mode (`127.0.0.1` silently publishes nothing) |
| vLLM version v0.17.0 | LoxiLB's vendored hash contract (see [08 §4](08-kv-cache-aware-routing.md)) |

Plus tokenizer staging on the LoxiLB host: the served model's HF `tokenizer.json` at
`/etc/loxilb/tokenizers/<model-slug>/tokenizer.json`, slug = model id with `/` → `__`
(e.g. `Qwen__Qwen2.5-7B-Instruct`). Missing tokenizer ⇒ Guard-E `tokenize` misses ⇒ silent
fall-through (per-model onboarding checklist: [08 §6.5](08-kv-cache-aware-routing.md)).

---

## 4. AI-controller configuration (optional layer)

The controller runs as a separate container, typically **not** on the LoxiLB host. Flags (or
`AICTRL_*` envs), from `cmd/loxilb-ai-controller/options.go`:

| Flag / env | Default | Effect |
|---|---|---|
| `--grpc-addr` / `AICTRL_GRPC_ADDR` | `:18856` | Snapshot bus bind |
| `--metrics-addr` / `AICTRL_METRICS_ADDR` | `:18857` | Prometheus bind |
| `--registry` / `AICTRL_REGISTRY` | `/etc/loxilb/ai-controller.yaml` | Capability registry (services, EPs, capacity priors, calibration) |
| `--epoch-period-sec` | 10 | Decision/emission period (staleness deadline = 3×) |
| `--scrape-interval-sec` | 5 | vLLM `/metrics` scrape interval |
| `--stale-budget-sec` | 15 | Per-source staleness budget (stale source ⇒ neutral 100) |
| `--ewma-alpha` | 0.3 | Weight smoothing |
| `--dead-band` | 5 | No-move band (weight points) |
| `--max-step-pct` | 20 | Max weight movement per epoch |
| `--lmc-cost` (+ `--lmc-max-pts` 15, `--lmc-stale-sec` 15, `--lmc-lookup-url`) | OFF | LMCache-locality cost term |
| `--ttft-weight` (+ `--ttft-coef-file`, `--ttft-max-pts` 15, `--ttft-stale-sec` 15, `--ttft-ref-prompt-tokens` 4096) | OFF | Expected-TTFT term; needs a fitted coefficient file to arm |
| `--feature-snap-file` | "" | Per-epoch feature JSONL (input for offline TTFT fitting via `cmd/aictrl-ttft-fit`) |

Registry essentials (`ai-controller.yaml`): per-service `key: <vip>:<port>:tcp`; per-EP
`expected_num_gpu_blocks` (capacity prior), `serving_throughput_prior` (role-relative ratio),
and optional measured `calibration: {throughput_ratio, fingerprint}` blocks — a fingerprint
mismatch falls back to the prior and increments `aictrl_fingerprint_mismatch_total`.

Activation on the LoxiLB side is one env: `LOXILB_AI_CTRL_ADDR=<controller>:18856` (recreate the
container). Without it the applier does not exist and nothing dials out.

---

## 5. Per-layer enablement matrix

What turns each layer on, and the *fastest* check that it engaged:

| Layer | Enable | Verify (metrics on `GET /netlox/v1/metrics` unless noted) |
|---|---|---|
| P/D ladder | rule: `mode:4`, `pd_disagg_mode:true`, ≥1 `ep_role:1` + ≥1 `ep_role:2` | `loxilb_ai_pd_requests_total` advances; response `X-Request-Id` carries `___prefill_addr_…___decode_addr_…___` |
| Tier 0 | on by default under P/D (`pd_session_ttl_sec`) | `loxilb_ai_pd_session_hits_total` advances on repeat `X-Conversation-Id` |
| Tier 1 | rule: `pd_cache_aware_mode:true` | repeat-prefix requests pin; imbalance bypass visible in logs |
| Tier 1.5 | rule: `kvExactMode:1` + triad + tokenizer + warmup elapsed | `loxilb_pd_kv_tier15_hits_total{ep_idx}` advances; `loxilb_pd_kv_blocks` > 0; `loxilb_kv_subscriber_connected` = 1 |
| Blend law | `LOXILB_KV_LB_MODE` (default `hard`) | `loxilb_pd_kv_tier15_spills_total` under hot-prefix load; `LOXILB_KV_TLOAD_LOG=1` shows `[KV_INV] totalLoad=` |
| Admission | `LLB_PD_MAX_INFLIGHT_PER_EP` > 0 (+ queue/park knobs) | `loxilb_pd_admission_queued_total` / `loxilb_pd_admission_shed_total` (also emitted in docker logs) |
| Controller | `LOXILB_AI_CTRL_ADDR` + controller running | `loxilb_pd_ctrl_mode` = 2 (Smart), `loxilb_pd_ctrl_alpha` = 1, `loxilb_pd_ctrl_effective_weight` per EP; controller side `aictrl_watchers_connected` ≥ 1 |
| TTFT term | controller `--ttft-weight --ttft-coef-file=…` | controller `aictrl_ttft_active` = 1, `aictrl_ttft_alpha` near 1, `aictrl_ttft_pred_err_ratio_p50/p90` sane |
| Single-pool affinity | rule: `sel:8` or `sel:10` + `chwbl_*` | same-prefix requests land on one EP (banner/served-by check); spread resumes past the load cap |

---

## 6. Tuning playbook

### 6.1 Choosing the Tier-1.5 mode

Grounded in /92 sweeps (goodput@SLO, N=6, live GPU fleet):

| Situation | Recommendation |
|---|---|
| Default / unknown workload | `hard` (the shipped default, ε=0.75). The A/B record shows the blend is the only mode that beats round-robin at the loose SLO under hot-prefix load — it cut the hot EP's TTFT p90 ~15.9 s → ~10.0 s |
| Load varies widely across the day (0.5×–2× design rate) | `adaptive` — one mode that was tied-or-better vs static at every calibrated rate. Set `LOXILB_KV_CAP_SUM_MILLI` if your fleet's Σcapacity differs from the calibration fleet |
| Latency-tolerant batch, cache hit-rate is everything | `hard` with a **higher** `LOXILB_KV_MEAN_LOAD_FACTOR` (e.g. 300 ⇒ ε=2.0) — affinity-preserving, spills late |
| Strict per-request SLA, spiky arrivals | `hard` with **lower** factor (tighter cap, earlier spill), or `soft` with λ raised above 32 to price queueing more heavily |
| Debug / A/B baseline | `off` — byte-identical to the legacy pure overlap-argmax |

Static-knob intuition from the sweep: the best ε and λ **increase with load** (ε 175→300,
λ 50 000→100 000 as the fleet moves from moderate rate to saturation). If you must run static,
tune for your *peak*; if you can, run `adaptive` and let the law move.

### 6.2 Tier-1 thresholds (when running without KV-exact)

- `pd_cache_threshold` 20 is conservative; RAG workloads with long shared preambles can drop to
  10–15 for more affinity. Raise it if you observe affinity wins going to barely-matching
  prefixes.
- `pd_balance_abs_threshold` 3 is tuned for ~4-EP pools; scale roughly with pool size (it is an
  absolute connection-count delta, not a ratio).

### 6.3 Warmup, timeouts, session TTL

- `kvWarmupSec`: 30 s suits steady fleets; increase to 60 s+ when vLLM restarts under load
  produce large event replays. Requests inside the window take Tier 2 by design
  (`loxilb_pd_kv_tier15_miss_reason_total{reason="warmup"}`).
- `LLB_PD_PREFILL_TIMEOUT_SEC`: size to your p99.9 prefill duration. For 32k-context on L4-class
  GPUs the production value is **180**; the 30 s default will 504 the bulk of saturated traffic.
- `pd_session_ttl_sec`: match your conversational think-time. Too long pins conversations to
  workers whose cache has moved on; too short forfeits the multi-turn affinity win.

### 6.4 Admission (opt-in — protection, not throughput)

Enable only with a latency SLO to protect. Starting points measured on the reference fleet:
`LLB_PD_MAX_INFLIGHT_PER_EP` ≈ the per-EP concurrency at which prefill queue-divergence begins
(from a per-EP calibration ramp), `LLB_PD_QUEUE_DEPTH_PER_EP` 8–16,
`LLB_PD_MAX_PARK_SEC` ≤ your client timeout minus p99 prefill. Watch
`loxilb_pd_admission_shed_total` — a steadily climbing shed count means the cap is below fleet
capacity. Remember verdict: FIFO admission **regressed** goodput at saturation on
the reference fleet; it exists for tail-latency control.

### 6.5 Inventory sizing

`LOXILB_KV_MAX_BLOCKS` = 1M blocks ≈ 8 MB per EP of hash inventory, comfortably above what a
single vLLM instance publishes. Alert on `loxilb_kv_inv_cap_evictions_total` > 0 — nonzero means
an EP's publisher outran the cap and overlap scoring for that EP is degraded (routing remains
correct; only the optimization decays).

### 6.6 Controller cadence

Defaults (scrape 5 s / epoch 10 s / stale 3× = 30 s / max-step 20 pts / dead-band 5) are the
validated production set. Shorten the epoch only with commensurate scrape-interval cuts —
deciding on stale scrapes just adds noise that EWMA then has to remove. Arm `--ttft-weight` only
after fitting coefficients **on your own fleet** (`--feature-snap-file` → `aictrl-ttft-fit`) and
after `aictrl_ttft_pred_err_ratio_p90` on a shadow run looks sane; the α confidence decay protects
against regime shift but not against a never-valid model.

---

## 7. Observability quick reference

LoxiLB metrics: `GET http://<loxilb>:11111/netlox/v1/metrics`. Controller: `:18857/metrics`.
Inventory snapshot: `GET /netlox/v1/config/ai/kv/inventory`.

**The routing-decision set:**
`loxilb_pd_kv_tier15_hits_total{ep_idx}` · `loxilb_pd_kv_tier15_miss_reason_total{reason}` (reasons:
`mode_off, warmup, text_empty, model_empty, tokenize, hashes, no_worker, excluded`) ·
`loxilb_pd_kv_tier15_fallthrough_total` · `loxilb_pd_kv_tier15_spills_total` ·
`loxilb_pd_ep_info` (joins `ep_idx` → IP).

**Inventory-plane health:**
`loxilb_pd_kv_blocks{service, ep_idx}` · `loxilb_kv_subscriber_connected` ·
`loxilb_kv_subscriber_reconnect_total` · `loxilb_kv_subscriber_recv_error_total` ·
`loxilb_kv_inv_cap_evictions_total`.

**P/D serving:**
`loxilb_ai_pd_requests_total` · `loxilb_ai_pd_prefill_duration_seconds` ·
`loxilb_ai_pd_decode_ttft_seconds` · `loxilb_ai_pd_session_hits_total` ·
`loxilb_pd_admission_shed_total` / `loxilb_pd_admission_queued_total`.

**Controller influence (LoxiLB side):**
`loxilb_pd_ctrl_mode` (0 autonomous / 1 stale / 2 smart) · `loxilb_pd_ctrl_alpha` ·
`loxilb_pd_ctrl_effective_weight{ep}` · `loxilb_pd_ctrl_state{ep}` ·
`loxilb_pd_ctrl_override_events_total` (local-health vetoes) · `loxilb_pd_ctrl_nacks_total`.

**Controller side:** `aictrl_snapshots_emitted_total` (liveness) · `aictrl_ep_weight` ·
`aictrl_source_staleness_seconds` / `aictrl_fleet_stale` · `aictrl_ttft_active` /
`aictrl_ttft_alpha` / `aictrl_ttft_pred_err_ratio_p50|p90` · `aictrl_fingerprint_mismatch_total`.

**Log grep keys** (docker logs of the loxilb container — C-plane logs go to stdout, not
`/var/log/loxilb`): `[KV_T15]` per-request decisions and guard misses · `[KV_INV]` inventory ops
and (with `LOXILB_KV_TLOAD_LOG=1`) per-selection totalLoad · `kv-subscriber:` lifecycle ·
`kv-router:` tokenizer loads · `[KV_HASH]` (with `LLB_KV_HASH_DEBUG=1`) hash forensics ·
`[KV_CONFIG]` rule-level KV parameters as parsed.

### 7.1 The three silent-degradation patterns to alert on

1. **Silent RR (hash-contract mismatch):** `tier15_hits` flat + `misses{reason="no_worker"}`
   climbing + `blocks_total` **non-empty** ⇒ parity triad broken (seed / block size / algo /
   tokenizer / vLLM version). See the decoder table in [08 §6.5](08-kv-cache-aware-routing.md).
2. **Silent RR (no inventory):** `blocks_total` = 0 + `kv_subscriber_connected` = 1 ⇒ vLLM not
   publishing (missing `--kv-events-config`, wrong bind, or decode EP mistagged `ep_role:1`).
3. **Controller neutralized:** `loxilb_pd_ctrl_mode` stuck at 0/1 with the controller up ⇒
   stream evicted or staleness — check `aictrl_watcher_dropped_snapshots_total` and the
   controller's `aictrl_source_stale`.

---

## 8. Operational cautions (fleet-proven)

- **Never hard-kill the LoxiLB container** on a `--net=host` deployment: orphaned XDP hooks can
  wedge the host's networking until reboot. Always `docker stop -t 30`.
- **LoxiLB restart drops runtime-POSTed LB rules** — re-register rules after any recreate
  (keep your rule JSON in a script; see doc 12's `--rules-only` pattern).
- The HTTPS cert is loaded **once per container lifetime**; rotate via REST cert API or a
  container recreate, and remember HTTPS rules are host-keyed on delete.
- Env changes (all `LOXILB_*`/`LLB_*`) need a container recreate — plan them together with rule
  re-registration.
- When results look wrong, **check the harness/client first** (the fleet's most common
  "routing bug" has been an unset parity leg or a non-JSON request body — Guard C/D misses),
  then the metrics above, then the code.
