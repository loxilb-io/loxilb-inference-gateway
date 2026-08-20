# Hierarchical KV-Cache-Aware Routing — Architecture & Concepts

> **Audience:** AI/LLM platform engineers, SREs, and control-plane / data-plane developers who
> need to understand *how* LoxiLB decides which vLLM worker serves each request.
> **Scope:** the complete endpoint-selection hierarchy as shipped on the current tree —
> the P/D tier ladder (admission gate, Tier 0 stickiness, Tier 1 trie, Tier 1.5 KV-exact with the
> unified CHWBL blend, Tier 2 min-load), the single-pool (non-disaggregated) prefix-hash path,
> and the control loop above the ladder (adaptive ε/λ, the external AI controller, the
> Expected-TTFT term).
> **Companions:**
> [08 — KV-cache-aware routing (Tier-1.5 internals)](08-kv-cache-aware-routing.md) — the
> block-hash contract, guard ladder, ZMQ inventory plane in byte-level detail;
> [09 — AWS P/D deploy & debug](09-kv-cache-aware-routing-aws-pd-deep-dive.md);
> [11 — Configuration & tuning](11-hierarchical-kv-routing-config-tuning.md).

---

## 1. Why cache-aware routing exists

vLLM keeps a **prefix cache**: the KV tensors for token prefixes it has already computed. If a
new request's prompt shares a prefix with blocks a particular worker already holds, sending the
request to *that* worker skips the prefill recomputation for the shared span — dramatically lower
TTFT (time-to-first-token) and freed prefill capacity.

A load balancer that ignores this (plain round-robin) scatters same-prefix requests across the
fleet, so every worker recomputes the same preamble. A load balancer that *only* chases cache
affinity herds every hot-prefix request onto one worker while its siblings idle. The routing
problem is therefore **hierarchical**: prefer the strongest affinity signal available for the
request, but bound it by load, capacity, health, and admission — and fall through gracefully when
any signal is missing.

LoxiLB implements this as a **strict priority ladder** evaluated per request inside the userspace
sockproxy (fullproxy) data plane, plus a **control loop** above it that retunes the ladder's
parameters at runtime. Every layer is **fail-open**: a miss at any layer falls through to the
next; the ladder can make a request smarter, never undeliverable.

### 1.1 Terminology: "layers" and "tiers"

Historically the selection stages are called **tiers** (Tier 0/1/1.5/2); operators often say
**Layer 1 / 1.5 / 2 / 3** for the same thing. This document uses the tier numbering of the code.
The mapping:

| Operator shorthand | Code tier | What it is |
|---|---|---|
| Layer 0 | Tier 0 | Conversation/session stickiness |
| Layer 1 | Tier 1 | Radix-trie prefix cache affinity (heuristic, P/D) / prefix-hash CHWBL (single-pool) |
| Layer 1.5 | Tier 1.5 | KV-exact block-hash routing (mirrors vLLM's real cache state) |
| Layer 2 | Tier 2 | Min-load fallback with RR tie-break |
| "Layer 3" | — (control plane) | Not a data-path tier: the adaptive ε/λ law, the external AI controller and the Expected-TTFT term, which *bias* Tiers 1.5/2 rather than select directly |

---

## 2. The two deployment shapes

The hierarchy behaves differently depending on whether the service is **P/D-disaggregated**:

| Shape | Rule shape | Selection hierarchy |
|---|---|---|
| **P/D disaggregation** | `mode:4` (fullproxy) + `pd_disagg_mode:true`, endpoints tagged `ep_role:1` (prefill) / `ep_role:2` (decode), ≥1 of each. The *orchestration flavor* follows `kvEngineType`: empty/`"vllm"` = the sequential vLLM machine; `"sglang"` = the concurrent dual-dispatch machine (bootstrap triple injection + `pdBootstrapPort`, [doc 16 §1](16-sglang-vs-vllm-routing-differences.md)). The selection ladder is identical in both flavors | The full P/D tier ladder (§3–§5): admission → Tier 0 → Tier 1 → Tier 1.5 → Tier 2, then decode selection |
| **Single pool (non-disaggregated)** | `mode:4` fullproxy, one endpoint pool (no `pd_disagg_mode`) | The **selector-algorithm** path (§6): prefix-hash CHWBL (`sel:8`) or weighted CHWBL (`sel:10`), else sticky/WRR/RR |

**The load-bearing constraint:** Tier 1.5 KV-exact block-hash routing is reachable **only inside
the P/D ladder**. The gate in the data plane
(the P/D gate in `loxilb-ebpf/common/sockproxy_ep.c`) is:

```c
if (tepval->pd_disagg_enabled && tepval->n_prefill_eps > 0 && tepval->n_decode_eps > 0)
```

A single-pool rule never invokes `pd_select_prefill()`, so a `kvExactMode:1` rule without
`pd_disagg_mode` would populate inventories that no selection path consumes — it is therefore
**rejected at POST time** with `kv-exact zmq mode requires pd_disagg_mode=true (use
kvExactMode=3 for a single pool)` (see the legacy note in §6). For
single-pool deployments, cache-aware routing is delivered by the **prefix-hash CHWBL family**
(§6), which approximates cache locality without mirroring vLLM's cache, or by the single-role
KV-exact mode `kvExactMode:3`. See
[09 §1](09-kv-cache-aware-routing-aws-pd-deep-dive.md) for the same rule stated operationally.

---

## 3. The P/D tier ladder — one request, top to bottom

All of the ladder logic below lives in `pd_select_prefill()`
(`loxilb-ebpf/common/sockproxy_pd.c`), invoked from the connection-setup path in
`sockproxy_ep.c` (and again on force-connect retry). Architecture split: the tier
*sequencing, guards, admission and Tier-2 load scoring* are C; the *Tier-1.5 overlap argmax and
the unified CHWBL/soft/adaptive blend* are Go (`pkg/loxinet/ai_kv_unified.go`,
`ai_kv_subscriber.go`), reached through one CGO crossing (`llb_ai_kv_best_worker`).

```
            client request (OpenAI JSON) on a P/D rule
                              │
      ┌───────────────────────▼──────────────────────────┐
      │ excluded_mask seeding (sockproxy_ep.c)           │  health/CB pre-filter
      │  every inv or CB-OPEN EP is masked out of ALL    │
      │  tiers below                                     │
      └───────────────────────┬──────────────────────────┘
      ┌───────────────────────▼──────────────────────────┐
      │ Controller fold-in │ pd_ctrl DISABLED EPs → mask
      │ (sockproxy_pd.c)                                 │  DRAINING collected
      └───────────────────────┬──────────────────────────┘
      ┌───────────────────────▼──────────────────────────┐
      │ Admission gate (default-OFF) │ per-EP in-flight caps
      │ (sockproxy_pd.c)                                 │  all capped → park (hold) or
      │                                                  │  shed 429; global valve at accept()
      └───────────────────────┬──────────────────────────┘
   ┌──▶ Tier 0  session stickiness      pd_session_lookup
   │      key: user_id / X-Conversation-Id → pinned (prefill, decode) pair
   │      miss / unhealthy pin → evict + fall through
   ├──▶ Tier 1  radix-trie prefix affinity   pd_trie_match
   │      pd_cache_aware_mode only; match_rate ≥ pd_cache_threshold
   │      AND load-imbalance guard (pd_balance_abs_threshold)
   ├──▶ Tier 1.5  KV-exact block-hash        pd_kv_exact_select
   │      tokenize → vLLM-contract block hashes → CGO argmax over
   │      per-EP inventories, blended by the unified CHWBL law (§4)
   │      any GUARD A–G miss → fall through
   └──▶ Tier 2  min-load + RR tie-break      (inline in pd_select_prefill)
          score = active_conns + queued_requests (lower wins)
          RR counter advanced only on a genuine tie
                              │
      ┌───────────────────────▼──────────────────────────┐
      │ Decode selection      pd_select_decode           │
      │  session-pinned decode hint, else min-load + RR  │
      └───────────────────────┬──────────────────────────┘
      ┌───────────────────────▼──────────────────────────┐
      │ Both fail → pd_select_any_healthy (role-0 EPs,   │
      │ normal mode) → else 503 (sockproxy_ep.c)         │
      └──────────────────────────────────────────────────┘
```

### 3.1 Ladder reference table

| Stage | Purpose | Code | Falls through when |
|---|---|---|---|
| excluded_mask seeding | Skip down/CB-open EPs in **every** tier (so an excluded Tier-1.5 winner falls to the 2nd-best *prefill*, never straight to RR) | excluded_mask seeding in `sockproxy_ep.c` | — (always runs) |
| Controller fold-in | OR controller-DISABLED EPs into the mask; collect DRAINING set | controller fold-in block in `sockproxy_pd.c` | no-op when `pd_ctrl_mode==0` (no controller) |
| Admission gate | Per-EP in-flight caps; park or shed when all capped | admission gate in `sockproxy_pd.c` | cap unset (`LLB_PD_MAX_INFLIGHT_PER_EP=0`, default) → byte-identical skip |
| **Tier 0** | Sticky `(prefill, decode)` pair per conversation | `pd_session_lookup` (`sockproxy_pd.c`) | no key; pin unhealthy/excluded/CB-open/stale (evicted) |
| **Tier 1** | Radix-trie prefix affinity (heuristic — LoxiLB's own trie of observed prefixes, not vLLM state) | `pd_trie_match` (`sockproxy_pd.c`) | `pd_cache_aware_mode` off; empty prefix; imbalance guard; `match_rate < pd_cache_threshold` |
| **Tier 1.5** | KV-exact: route to the prefill EP whose *actual* vLLM prefix cache best overlaps the prompt, bounded by load (§4) | `pd_kv_exact_select` (`sockproxy_kv_exact.c`); Go blend `ai_kv_unified.go` | `kv_exact_mode != 1`; any guard A–G miss (see [08 §5](08-kv-cache-aware-routing.md)) |
| **Tier 2** | Min-load fallback | inline in `pd_select_prefill` (`sockproxy_pd.c`) | terminal (−1 only if no healthy candidate) |
| Decode select | Pick decode EP | `pd_select_decode` (`sockproxy_pd.c`) | pinned hint invalid → min-load + RR among `ep_role:2` |
| Any-healthy | Non-P/D "normal mode" rescue using role-0 EPs | `pd_select_any_healthy`, called from `sockproxy_ep.c` | none healthy → 503 `pd_pool_unavailable` |

> **There is no data-path "Tier 3."** Below Tier 2 is only the any-healthy rescue. What operators
> sometimes call layer 3 is the control loop of §7, which biases the ladder instead of selecting.

### 3.2 Tier 0 — session stickiness

Session key = the request's `user_id` JSON field if present, **overridden** by a client-supplied
`X-Conversation-Id` header — unless that header value begins with `auto-` (LoxiLB's own
auto-generated conversation IDs are deliberately *not* used as stickiness keys)
(`sockproxy_pd.c`). A hit pins the full `(prefill_ep, decode_ep)` pair for
`pd_session_ttl_sec` (REST default 0 → data-plane default `PD_SESSION_DEFAULT_TTL` = 300 s,
`sockproxy_pd.c`). The table is TTL-evicted and LRU-capped; a pinned EP that is unhealthy,
masked, or CB-open causes the key to be evicted and the ladder to continue — stickiness never
overrides health.

**Why Tier 0 outranks the cache tiers:** a multi-turn conversation's KV state (its growing
prefix) lives on the workers that served the previous turns. Keeping the pair stable *is* the
strongest cache-affinity signal available, and it costs nothing to evaluate.

### 3.3 Tier 1 — radix-trie prefix affinity (heuristic)

Enabled by `pd_cache_aware_mode:true`. LoxiLB maintains its **own** radix trie of prompt
prefixes it has routed before (capacity 8192 entries, LRU-evicted — the trie is *updated* after
Tier-2 decisions too). On a request, `pd_trie_match` looks up the
prompt prefix; the trie leaf remembers which EP last served that prefix.

Two guards keep the heuristic honest (both REST-tunable):

- **Match-rate threshold** — the matched span must cover ≥ `pd_cache_threshold` percent
  (default 20) of the prompt, or the affinity is judged too weak.
- **Load-imbalance guard** — if `max(active_conns) − min(active_conns)` across prefill EPs
  exceeds `pd_balance_abs_threshold` (default 3), affinity is bypassed so a hot EP is not made
  hotter.

Tier 1 differs from Tier 1.5 in a fundamental way: the trie tracks *what LoxiLB routed*, not
*what vLLM actually holds*. It is cheap (no tokenization, no hashing) and needs no vLLM-side
configuration, but it can go stale when vLLM evicts. Tier 1.5 tracks the truth; Tier 1 is a
useful heuristic when KV-exact is not deployable (no ZMQ events, no tokenizer staged).

### 3.4 Tier 1.5 — KV-exact block-hash routing

The centerpiece. LoxiLB mirrors each prefill EP's **actual prefix-cache content** (as a set of
uint64 block hashes streamed over vLLM's ZMQ KV-events channel), and on each request recomputes
the same block hashes vLLM would compute for the prompt (tokenize → per-block canonical CBOR →
SHA-256/XXH3 → truncate), then scores every prefill EP by **overlap count** and routes through
the unified blend law of §4.

The mechanics — the ZMQ inventory plane, the vLLM v0.17.0 hash contract, the guard ladder A–G,
the parity triad (`PYTHONHASHSEED` / `--block-size` / hash algo), and the miss-reason metrics —
are documented exhaustively in [doc 08](08-kv-cache-aware-routing.md) and are **unchanged** in
substance. What has evolved since doc 08 was written is *what happens after the overlap scores
are computed*: the selection is no longer a bare argmax but a load- and capacity-aware blend
(§4), optionally retuned at runtime (§7).

Operational prerequisite alongside the parity triad: the served model's HuggingFace fast
`tokenizer.json` must be pre-staged on the LoxiLB host at
`/etc/loxilb/tokenizers/<model-slug>/tokenizer.json` (slug = model id with `/` → `__`) —
see [08 §6.3](08-kv-cache-aware-routing.md) for the download and container-mount procedure. A
missing tokenizer fails silently (Guard E → lower tiers).

An optional pre-guard exists on the C side: `LLB_KV_LOADGUARD` (env, default off) applies a
hard load-imbalance check before Tier 1.5 runs (`pd_kv_loadguard_enabled` in `sockproxy_pd.c`).

### 3.5 Tier 2 — min-load with RR tie-break

Despite its historical name ("Tier-2 RR"), the current Tier 2 is a **min-load scorer**
(the Tier-2 block in `pd_select_prefill`):

- **Default arm (C1):** `score = active_conns + queued_requests`, lower wins.
- **Capacity-blend arm (C2):** engaged **only** when the rule's selector is GPU-aware
  (`sel:9` → `PROXY_SEL_GPU_AWARE`): `pd_capacity_blend_score()` weighs
  `active_conns·20 + queued·50 + swap·30` (weights in `sockproxy.h`) normalized by
  per-EP capacity (the `pd_capacity_weighted_cap` helpers in `sockproxy_kv_exact.h`).

The round-robin counter `pd_tier2_rr` advances **only on a genuine tie**,
so it is a tie-breaker, not the algorithm.

### 3.6 Decode selection

After the prefill EP is chosen, `pd_select_decode` (`sockproxy_pd.c`) picks the decode
EP: (1) the Tier-0 session-pinned decode hint if valid (role 2, healthy, CB closed); else
(2) min-load (`active_conns + queued_requests`) among decode EPs with its own RR tie-break
counter (`pd_decode_rr`). Decode EPs are **never** KV-selection candidates — they publish no KV
events and hold no scored inventory.

### 3.7 The admission gate (default-OFF)

Before any tier body runs, the admission gate can exclude prefill EPs at their in-flight cap and,
when **all** are capped, either **park** the request (hold-don't-drop: enqueue on the shortest
per-EP FIFO, suspend the client fd, resume when capacity frees) or **shed** it with a retriable
`429 pd_overloaded`. A separate global valve refuses `accept()` beyond a total-in-flight bound,
converting overload into TCP backlog backpressure. All four knobs (`LLB_PD_MAX_INFLIGHT_PER_EP`,
`LLB_PD_QUEUE_DEPTH_PER_EP`, `LLB_PD_MAX_PARK_SEC`, `LLB_PD_MAX_TOTAL_INFLIGHT`) default to 0 =
off, and the A/B campaign that shipped it concluded **NO-SHIP as a default** (FIFO admission
regressed saturated-rate goodput) — treat it as an opt-in protection for latency-SLO fleets, not
a throughput optimizer. Return-code plumbing: `PD_PREFILL_PARKED → PD_SETUP_PARKED` (suspend),
`PD_PREFILL_NO_CAPACITY → 429` (`sockproxy_ep.c`). When a parked request's EP later becomes
ineligible (CB-open or otherwise), that EP's parked FIFO is drained by `pd_parked_drain_ep()`
(invoked from the health pass in `sockproxy_health.c`) and the parked requests are resumed
against a healthy EP via `pd_resume_parked()` rather than being left to reap at the park
deadline.

---

## 4. The unified selection law (Tier 1.5's blend modes)

Raw overlap-argmax is load-blind: 50 clients sharing one hot preamble would all route to the
same prefill EP. The **unified mode** (the shipped default) bounds cache affinity by a
capacity-weighted load cap, in the spirit of CHWBL (consistent hashing with bounded loads). All
of this executes in Go inside `llb_ai_kv_best_worker` → `kvSelectArm`
(`ai_kv_unified.go`); mode selection via `LOXILB_KV_LB_MODE`.

### 4.1 The candidate set

Each prefill EP *i* contributes a candidate carrying:

- `overlap_i` — matched block-hash count against the prompt's hash chain;
- `load_i` — LoxiLB's **own** per-EP `active_conns` (not vLLM's view);
- `capacity_i` — the EP's advertised KV-block capacity (`num_gpu_blocks`), clamped to
  `[1, 8_000_000]` (`kvClampCapacity`, `ai_kv_unified.go`), optionally scaled by the
  controller weight (§7.2).

### 4.2 `hard` mode (default) — capacity-weighted bounded load

Per-EP cap (`kvCapFor`, `ai_kv_unified.go`; C mirror `pd_capacity_weighted_cap`,
`sockproxy_kv_exact.h` — the two constants must stay numerically identical):

```
cap_i = ceil( (1+ε) · totalLoad · capacity_i / totalCap )
```

with `ε` expressed as `mean_load_factor_pct = (1+ε)·100`, default **175 ⇒ ε = 0.75**, and
`totalLoad = Σ load_i`, `totalCap = Σ capacity_i` over the candidate set. Selection
(`kvUnifiedSelect`, `ai_kv_unified.go`):

1. **Argmax overlap among under-cap EPs** (`load_i < cap_i`); ties → least load → lowest index.
2. If the global overlap winner was over its cap and selection moved off it, that is a **spill**
   (`loxilb_pd_kv_tier15_spills_total`).
3. **Negligible-overlap refinement:** if the best under-cap overlap is ≤ 0, pick the
   least-loaded under-cap EP (there is no affinity worth honoring).
4. **Saturated case** (all over cap): least-loaded among the positive-overlap candidates.

Intuition: an EP may hold its cache-affinity traffic while it carries at most `(1+ε)×` its
capacity-fair share of the current total load; beyond that, the excess spills to siblings. Higher
ε ⇒ more affinity-preserving; lower ε ⇒ more aggressive spilling.

An optional refinement, `LOXILB_KV_SPILL_RELIEF` (default OFF), redirects hot-prefix spills to
the *least-loaded under-cap* EP rather than the next-best-overlap EP, for faster pressure relief
(`kvSpillReliefSetting`, `ai_kv_unified.go`).

### 4.3 `soft` mode — continuous cost blend

No hard cutoff; argmin of a cost that prices both the cache miss and the queue
(`kvSoftBlendSelect`, `ai_kv_unified.go`):

```
cost_i = uncached_blocks_i · 1000  +  (λ · load_i) / capacity_i
uncached_blocks_i = promptBlocks − overlap_i
```

λ (`LOXILB_KV_LOAD_PENALTY`) defaults to **32**; `1000` is the fixed `kvSoftCostScale`. At zero
load, soft mode reduces exactly to overlap-argmax.

### 4.4 `adaptive` / `adaptive-soft` — the load-keyed ε/λ law

The sweep proved **no static ε/λ is optimal across load**: the best values increase
with load (tight ε=175 wins at moderate rate, loose ε=300 at saturation). Adaptive mode scales
the knob with the load the selector itself observes:

```
L        = Σ active_conns over the candidate set (the selector's own totalLoad)
ε_eff(L) = clamp( 175 + 125·(L−16)/10 ,  175, 300 )     // adaptive (hard-arm)
λ_eff(L) = clamp( 50000 + 5000·(L−16) , 50000, 100000 ) // adaptive-soft
```

(`kvAdaptiveMeanLoadFactor` / `kvAdaptiveLoadPenalty` in `ai_kv_unified.go`;
anchors: floor at L≤16 — the calibrated rate-1.0 operating point — cap at L≥26 — saturation.)
Below the anchor the behavior is byte-identical to static hard/soft; the law only loosens the
bound where the sweep showed loosening wins. `adaptive` runs the §4.2 selector with `ε_eff`;
`adaptive-soft` runs §4.3 with `λ_eff` — nothing else differs.

Two supporting facts to know:

- **Capacity normalization:** the anchors above were calibrated on one fleet's absolute
  Σcapacity. On a resized fleet, set `LOXILB_KV_CAP_SUM_MILLI` so the law normalizes
  `L′ = L · capRef / capActual` (sanity-clamped to `[1/8, 8]`; `ai_kv_unified.go`).
  Unset ⇒ normalization off ⇒ the law mis-keys on fleets much larger/smaller than the
  calibration fleet.
- **EWMA smoothing exists but is not wired:** `kvAdaptiveEwmaLoad` (α=1/k=4,
  `ai_kv_unified.go`) is implemented and unit-tested, but the live path currently feeds
  the **raw** per-request totalLoad (`ai_kv_subscriber.go`). Expect per-request law
  jitter at noisy load; do not document-or-depend on smoothing being active.

### 4.5 Mode resolution and precedence

`kvLbMode()` (`ai_kv_unified.go`): a valid `LOXILB_KV_LB_MODE`
(`off|hard|soft|adaptive|adaptive-soft`) wins outright. Unset → legacy `LOXILB_KV_UNIFIED_MODE`
mapping (an explicit disable value → `off`, anything else/unset → `hard`). Garbage → warn +
`hard`. So the **out-of-box default is `hard` with ε=0.75** and `off` restores the pre-blend pure
overlap-argmax.

---

## 5. Resilience semantics of the ladder

- **Health/CB pre-filter:** the excluded_mask seeded in `sockproxy_ep.c` guarantees the
  documented failover contract — *an excluded Tier-1.5 winner falls to the 2nd-best-overlap
  prefill EP, never to a decode EP and never straight to RR* (CICD scenario.3).
- **Circuit breaker:** per-EP `CLOSED → OPEN → HALF_OPEN`, gated by the per-rule REST knob
  `cb_enable` (which gates all circuit-breaker checks). For P/D services the control plane
  auto-enables it with **threshold 3 consecutive failures, 30 s open window**
  (the P/D CB auto-enable block in `pkg/loxinet/rules.go`); the C-side default of 5
  (`sockproxy.h`) applies only where no explicit configuration lands. CB state is local-only,
  never HA-synced.
- **Exclusion is reactive:** REST health-probe state does not reach the data plane's `eps[].inv`;
  real exclusion comes from observed failure — connect-failure retry (`excluded_mask`), admin
  down, or an open CB (design record: [08 §10.8](08-kv-cache-aware-routing.md)).
- **Mid-request failover is shipped:** a prefill EP that dies mid-request is retried once by
  `pd_retry_prefill()` (saved headers/body re-driven, receipt rewritten via
  `pd_receipt_rewrite()` to the EP that actually served); a decode zero-byte EOF becomes an HTTP
  502 `{"error":"pd_decode_backend_died"}`; non-P/D services get a generalized mid-cycle connect
  failover in `sockproxy_ep.c` (RR walk over healthy EPs; exhausted → 502 `backend_unreachable`,
  all-down → 503 `no_healthy_backend`); and a CB-open/ineligible EP's parked admission FIFO is
  drained (`pd_parked_drain_ep()` from `sockproxy_health.c`, resumed via `pd_resume_parked()`).
  Counters: `loxilb_pd_prefill_ep_died_total`, `loxilb_pd_decode_ep_died_total`,
  `loxilb_pd_decode_zero_byte_eof_total`, `loxilb_pd_connect_failover_total`, and the tripwire
  `loxilb_lb_select_failure_shutdown_total` (counts silent TCP resets — must stay flat).
- **Inventory staleness degrades, never mis-routes:** a subscriber reconnect runs a KEEP/CLEAR
  resync decision on the first post-reconnect message — the warm inventory is KEPT when the seq
  resumes near the preserved `lastSeq` (transient blip) and CLEARED on a seq regression or large
  forward jump (publisher restart / ambiguous); a fresh subscribe backfills once from the
  engine's replay endpoint before the live loop. An empty inventory scores 0 → Tier-1.5
  `no_worker` miss → Tier 2. Per-EP inventory is FIFO-capped at `LOXILB_KV_MAX_BLOCKS`
  (default 1,000,000) with evictions counted in `loxilb_kv_inv_cap_evictions_total`.
- **Controller staleness glides to neutral:** if the external controller (§7) goes stale or its
  gRPC stream is evicted, per-EP weights decay toward the neutral 100 — capacity scaling relaxes
  back to unweighted; EPs are never zero-filled or dropped by staleness alone.

---

## 6. The single-pool (non-disaggregated) hierarchy

For a plain fullproxy pool (no `pd_disagg_mode`), the request path selects via the rule's
**selector algorithm** (the selector switch in `sockproxy_ep.c`), *before* the P/D gate.
The cache-aware members of that family:

| REST `sel` | C selector | Mechanism |
|---|---|---|
| `8` (chwbl) | `PROXY_SEL_CHWBL` | Consistent Hash with Bounded Loads over a hash ring, keyed by **prefix_hash** |
| `9` (gpuaware) | `PROXY_SEL_GPU_AWARE` | `prefix_hash % n_eps` placement only on the single-pool path (the selector switch in `sockproxy_ep.c`). The capacity-weighted 20/50/30 scoring is a **P/D Tier-2 C2** feature, not applied here |
| `10` (wrr-hash) | `PROXY_SEL_WRR_HASH` | CHWBL with endpoint **weights** folded into the ring (capacity-weighted bounded load) |

The routing key priority is identical for all three (the selector switch in `sockproxy_ep.c`):

1. **`prefix_hash`** — XXH64 over the request's extracted LLM prefix: prompt prefix + model,
   plus (per `chwbl_prefix_hash_level` and presence flags) LoRA adapter, image/audio hashes,
   `cache_salt`, tool-schema hash (`compute_prefix_hash`, `common/sockproxy_json.c`).
   Level 1 = global prefix fields only; levels 2/3 fold in progressively more context.
2. **`conv_id`** — fallback session stickiness (XXH64 of the conversation ID).
3. **RR** — last resort.

Same-prefix requests therefore hash to the same ring point and land on the same EP *while it is
under its bounded-load cap* (`chwbl_mean_load_factor`, effective default 175 ⇒ 1.75× mean —
`sockproxy_http.c` initializes the ring to 175, so this matches the Tier-1.5 ε=0.75 of §4.2),
spilling CHWBL-style when hot — the same bounded-load idea as §4.2, applied to a hash of the
prompt instead of measured block overlap.

**What single-pool does *not* give you:** exactness. `prefix_hash` is one hash of one extracted
prefix — it cannot measure *partial* overlap, cannot see vLLM's evictions, and matches only
byte-identical prefixes. It needs no vLLM-side config at all (no ZMQ events, no tokenizer
staging, no hash-contract parity), which is exactly the trade. Choose single-pool CHWBL when you
cannot run P/D disaggregation; choose the P/D ladder with Tier 1.5 when you can.

> **Legacy note:** older single-pool bring-up tooling registered rules with `kvExactMode:1`.
> That populated inventories but could not influence selection (§2), so it is now **rejected
> at rule POST time** — `kv-exact zmq mode requires pd_disagg_mode=true (use kvExactMode=3
> for a single pool)`. For a role-less pool use `kvExactMode:3` (engine-exact,
> [doc 15](15-sglang-kv-cache-aware-routing.md)) or `sel:8`/`sel:10` for approximate
> prefix-hash cache affinity.

---

## 7. The control loop above the ladder ("layer 3")

Three mechanisms retune the ladder at runtime. All are default-safe: absent/unset, the data
plane behaves byte-identically to a controller-less deployment.

### 7.1 In-process: the adaptive ε/λ law

Described in §4.4 — runs inside the selector itself, per request, no external component.

### 7.2 Out-of-process: the AI controller (`aictrl`)

An external controller binary (`cmd/loxilb-ai-controller/`, engine in `pkg/aictrl/`) that:

- **scrapes** the vLLM fleet's `/metrics` (waiting queue, `kv_cache_usage_perc`,
  `num_gpu_blocks`; optionally LMCache lookup signals) every `scrape-interval-sec` (5 s default);
- **decides** per-EP **routing weights (0–100, 100 = neutral)** and lifecycle states
  (ACTIVE/DRAINING/DISABLED) once per epoch (10 s default), smoothed by EWMA, a dead-band, and a
  max-step clamp to prevent thrash;
- **publishes** full state-of-the-world snapshots over a frozen gRPC contract
  (`loxilb.aictrl.v1`, port 18856). LoxiLB **dials out** and subscribes
  (`LOXILB_AI_CTRL_ADDR`); the applier (`pkg/loxinet/ai_ctrl_applier.go`) validates, applies to
  C-side atomics, and acks.

**Safety contract highlights:** snapshots carry *outputs only* (weight/state — never load
observations); local health always wins (a controller can never resurrect an EP the data plane
sees as down — "non-resurrection G4"); on staleness the applied influence α(t) decays linearly
from 1 (Smart) to 0 (Autonomous) over `LOXILB_AI_CTRL_DECAY_WINDOW_SEC` (30 s default), landing
byte-identical to no-controller:

```
effective_weight = round(100 + α(t)·(weight − 100))      // pkg/aictrl/decay.go
```

**How weights reach the ladder:** as **capacity scaling**. In Tier 1.5 the Go candidate
capacity is weighted (`kvWeightedCapacity`), and in Tier 2's C2 arm the controller's effective
capacity (`pd_ctrl_eff_cap`) replaces the static one — so a down-weighted EP gets a smaller
bounded-load cap and sheds traffic *proportionally*, without being removed. DISABLED state is
folded into the excluded_mask (§3 table). Observability: `loxilb_pd_ctrl_*` gauges on the
LoxiLB side, `aictrl_*` on the controller side.

### 7.3 The Expected-TTFT term (default-OFF)

A model-based refinement *inside the controller's weight computation* (no C-side counterpart;
it reaches the data plane only through the §7.2 weights). Per epoch, per EP, the controller
predicts log-TTFT from a fitted linear model over features
`{intercept, log_prompt_tokens, waiting_over_capacity, kv_cache_usage_perc, fetch_cost,
matched_prefix_sat}` (`pkg/aictrl/engine/ttft.go`), then biases the EP weight
(`engine.go`):

```
rel = clamp( mean_pred − pred_i , −1, 1 )        // lower predicted TTFT ⇒ bonus
dw  = TtftMaxPts · rel · clamp(α_ttft, 0, 1)     // capped at ±15 pts by default
```

`α_ttft` is a **confidence factor**: the controller monitors live prediction error and decays
α toward 0 on regime shift (model mistrust ⇒ neutral influence, never inverted influence).
Coefficients are fitted offline (`cmd/aictrl-ttft-fit`) from per-epoch feature snapshots and
loaded via `--ttft-coef-file`; the term is armed with `--ttft-weight` and is OFF unless both are
provided. Per-EP capacity priors come from the controller registry
(`ai-controller.yaml`: `expected_num_gpu_blocks`, `serving_throughput_prior`, and measured
`calibration.throughput_ratio` blocks gated by an environment fingerprint).

---

## 8. Concepts recap — what each layer "knows"

| Layer | Signal it trusts | Freshness | Cost per request | Wrong-signal failure mode |
|---|---|---|---|---|
| Tier 0 | its own routing history (session table) | TTL (300 s default) | O(1) lookup | pin outlives worker's cache → one cold prefill |
| Tier 1 | its own routing history (prefix trie) | LRU, 8192 entries | O(prefix) trie walk | trie says EP has prefix, vLLM evicted it → cold prefill |
| Tier 1.5 | **vLLM's actual cache state** (hash inventory) + own `active_conns` | event-driven, sub-ms | tokenize + hash + argmax (µs–ms, prompt-length-bound) | hash-contract mismatch → silent 0-overlap → Tier 2 (fail-open) |
| Tier 2 | own `active_conns + queued` | exact, instantaneous | O(n_eps) scan | none (it *is* the fallback) |
| Controller | fleet-wide vLLM metrics + models | epoch (10 s), α-decayed | zero on the request path | staleness → neutral (never worse than no controller) |

The design rule that falls out: **each layer may only refine the previous one, and every signal
of doubtful freshness must decay to the behavior of the layer below it.** That is the invariant
that lets all of this run in the serving path of production traffic.

---

## 9. Source map (developers)

| Area | Files |
|---|---|
| P/D ladder + admission + decode | `loxilb-ebpf/common/sockproxy_pd.c` (`pd_select_prefill`, `pd_select_decode`) |
| P/D gate + excluded_mask + 429/parked plumbing | `loxilb-ebpf/common/sockproxy_ep.c` |
| Tier 1.5 C side (guards, hashing, CGO) | `loxilb-ebpf/common/sockproxy_kv_exact.c`, `sockproxy_kv_exact.h` |
| Mid-request failover (prefill retry + receipt rewrite) | `loxilb-ebpf/common/sockproxy_pd_vllm.c` (`pd_retry_prefill`, `pd_receipt_rewrite`) |
| Generalized connect failover (non-P/D) | `loxilb-ebpf/common/sockproxy_ep.c` |
| Parked-FIFO drain on EP ineligibility | `loxilb-ebpf/common/sockproxy_health.c` (`pd_parked_drain_ep` → `pd_resume_parked`) |
| Unified/soft/adaptive blend + env parsing | `pkg/loxinet/ai_kv_unified.go` |
| Inventory subscribers + best-worker CGO export | `pkg/loxinet/ai_kv_subscriber.go` |
| Tokenizer pool | `pkg/loxinet/ai_kv_router.go`, `ai_kv_tokenizer_hf.go` |
| Chat-template registry (chat KV-exact) | `pkg/loxinet/ai_kv_chat_template.go` |
| Single-pool selectors (CHWBL/WRR-hash/GPU-aware) | `loxilb-ebpf/common/sockproxy_ep.c`, `sockproxy_json.c` (`compute_prefix_hash`) |
| Controller engine / proto / decay / TTFT | `pkg/aictrl/` (`engine/`, `aictrl.proto`, `decay.go`), `cmd/loxilb-ai-controller/` |
| Applier (controller → C atomics) | `pkg/loxinet/ai_ctrl_applier.go` |
| Fleet metrics scraper | `pkg/aimetrics/` |
| Rule plumbing (REST → DP) | `pkg/loxinet/rules.go`, `pkg/loxinet/dpebpf_linux.go` |
| Metrics export | `api/prometheus/sockproxy_metrics.go`, `ai_metrics.go`, `aictrl_metrics.go` |

Configuration reference and tuning playbook: [doc 11](11-hierarchical-kv-routing-config-tuning.md).

