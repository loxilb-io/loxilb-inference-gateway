# TensorRT-LLM KV-Cache-Aware Routing & P/D Disaggregation

> **Audience:** AI/LLM platform engineers running TensorRT-LLM (`trtllm-serve`)
> fleets behind LoxiLB, and developers extending the engine-dialect layer.
>
> **Prerequisites:** [doc 10](10-hierarchical-kv-routing-architecture.md)
> (the tier ladder), [doc 08](08-kv-cache-aware-routing.md) (KV-exact
> internals, guard ladder), [doc 15](15-sglang-kv-cache-aware-routing.md)
> (the SGLang sibling — the re-hash decoder and single-pool mode land on the
> same machinery).

TensorRT-LLM is the third engine LoxiLB speaks natively, joining vLLM and
SGLang. `kvEngineType: "trtllm"` selects it, and all three deployment shapes
work:

| Shape | Rule shape | What routes |
|---|---|---|
| Plain load balancing | `mode: 4` fullproxy, no `kv*` fields | Tier 2 only |
| Single pool, engine-exact | `kvExactMode: 3` + `kvEngineType: "trtllm"` | Tier 1.5 against the fleet's real prefix caches |
| P/D disaggregation | `pd_disagg_mode: true` + `kvEngineType: "trtllm"` + `kvExactMode: 1`, endpoints tagged `ep_role` 1/2 | The full P/D ladder; Tier 1.5 subscribes the CONTEXT endpoints |

The tier ladder, guard ladder, circuit breakers, and observability are the
shared machinery of docs 08/10 — this page covers only what is
TensorRT-LLM-specific: the event transport, the hash strategy, the admission
guard, and the P/D request dialect.

## 1. The KV event plane — an HTTP drain, not a ZMQ stream

vLLM and SGLang publish KV events over ZMQ. TensorRT-LLM has **no event
publisher**: events accumulate in an engine-side ring buffer and are
consumed by **destructively draining** `POST /kv_cache_events` on the
serving port. Whoever POSTs gets the buffered events; they are then gone.

LoxiLB's poller wraps this drain behind the same subscriber pipeline the
other engines use (each drained batch is re-framed as if it had arrived on
ZMQ, so sequence tracking, gap detection, and the KEEP/CLEAR resync
machinery are identical):

- **Adaptive cadence** — 5 ms floor, 20 ms idle ceiling
  (`LOXILB_KV_TRTLLM_POLL_MIN_MS` / `LOXILB_KV_TRTLLM_POLL_MAX_MS`).
- **`event_id` is the sequence** — gaps (ring overflow, a competing
  consumer) trigger the standard KEEP/CLEAR decision; a fresh engine's
  `created` event clears that endpoint's inventory outright.
- **Per-endpoint, CONTEXT-only in P/D** — generation endpoints are never
  subscribed; only prefill placement benefits from cache knowledge.

### 1.1 The sole-consumer rule (operational, non-negotiable)

Because the drain is destructive, **exactly one consumer may exist per
endpoint: the gateway.** Anything else that POSTs `/kv_cache_events` — a
second router, NVIDIA Dynamo, a curious monitoring probe — steals events and
silently degrades hit rates on that endpoint (the gateway detects the gaps
and resyncs; correctness holds, hit rate suffers). Monitoring must scrape
`/prometheus/metrics` only; `/metrics` and `/perf_metrics` on `trtllm-serve`
are also drain-on-read.

The failure is graceful by design and verified live: under a deliberate
rogue-drain loop, client traffic stayed 100% green, the degradation was
scoped to the raided endpoint, and its inventory self-healed from its own
drain once the rogue stopped.

### 1.2 Engine-side staleness after a restart

TensorRT-LLM emits its `created` (fresh-cache) event on the **first KV-cache
allocation**, i.e. the first request — not at process start. A restarted
endpoint that has not yet served anything therefore leaves its old inventory
standing in the gateway. This is fail-safe: a stale "hit" simply routes to an
endpoint that recomputes (the engine reports ~0 cached tokens), and the first
real request triggers `created` → inventory clear → rebuild.

## 2. Hash strategy — re-hash the tokens, ignore the engine's hashes

TensorRT-LLM's internal block hashes are a custom uint64 scheme that is
explicitly **not a stable wire format**. LoxiLB does not reproduce it.
Instead, stored events carry each block's **token list**, and the gateway
re-hashes those tokens with its own chained SHA-256 — the same family the
SGLang integration uses — so the engine's hash contract exits the critical
path entirely. Engine hashes serve only as short-lived translation handles
(parent-chain references, removals) inside the poller.

Blocks the re-hash cannot key consistently are **skipped, never guessed**:
partial tail blocks, token counts that do not equal `kvBlockSize`, salted or
multimodal blocks, and chains whose parent was stored before the subscriber
connected (no replay channel exists — the inventory self-heals when those
blocks are re-stored). Every skipped event still advances the sequence, so
skips can never masquerade as gaps.

The API surface calls this `kvHashAlgo: "blockhash_trtllm"`; it is the
effective default when `kvEngineType` is `"trtllm"`, so in practice you never
set it.

## 3. The admission guard — `/server_info` gates every subscription

Two silent-zero-hit landmines exist: a `kvBlockSize` that differs from the
engine's `tokens_per_block` (TensorRT-LLM's default is **32**; LoxiLB's
historical `kvBlockSize` default is 16), and an engine configured with a
non-default event-hash scheme. Both are runtime-discoverable, so LoxiLB
refuses to guess: before a poller starts, the endpoint's `/server_info` must
report `kv_cache_hash_algo: v1_block_key` and a `tokens_per_block` equal to
the rule's `kvBlockSize`. A mismatch refuses that endpoint (named reason,
re-checked every 60 s); traffic still flows — Tier-1.5 dark is a degraded
mode, not an outage. Verdicts are visible per endpoint in the KV inventory
audit API (`admission` field).

Verified live both ways: a deliberate `kvBlockSize: 16` rule against a
32-token fleet refuses every CONTEXT endpoint, keeps serving traffic at
Tier 2, records zero Tier-1.5 hits, and never opens a drain connection —
the admission gate is also what makes a misconfigured rule harmless to a
live rule's sole-consumer drains.

Engine-side prerequisite: KV events are off by default —
`kv_cache_config.event_buffer_max_size > 0` (e.g. 4096) opts in;
`enable_block_reuse` is already on by default.

## 4. The P/D dialect — sequential, context-first, early-exit

TensorRT-LLM's disaggregation is sequential context-first, the same machine
shape as vLLM's, so the dialect is a request-rewriter on the shared P/D
engine, not a new state machine:

1. **Prefill leg** — the original request is spliced with
   `"disaggregated_params": {"request_type": "context_only", ...}`, forced
   non-streaming. No `max_tokens` rewrite (the engine forces context-only to
   one step itself).
2. **Extract** — the buffered prefill response's
   `choices[0].disaggregated_params` object (the KiB-scale opaque KV-transfer
   state) is lifted out.
3. **Decode leg** — the **original prompt** plus the extracted params with
   `request_type` rewritten to `"generation_only"` goes to the selected
   generation endpoint. Keeping the original prompt (rather than substituting
   the prefill's token IDs, as NVIDIA's reference proxy does) is validated
   byte-identical: same completion text and equal `prompt_tokens` against
   `trtllm-serve disaggregated` on pinned worker pairs and across a full
   fleet.
4. **Context early-exit** — if the context leg already finished the request
   (a stop sequence or EOS in the first step: `finish_reason` other than
   `length`/`not_finished`), the gateway relays the context response to the
   client and skips the decode leg entirely — counted in
   `loxilb_pd_trt_ctx_early_exit_total`. The check is fail-safe: anything
   ambiguous proceeds to decode.

The shared P/D protections apply unchanged: origin-5xx breaker demotion (a
prefill endpoint that accepts TCP and probes healthy but errors on inference
is demoted on its error streak, with clients kept at 200 throughout), the
prefill-phase timeout, and the decode first-byte timeout (a decode endpoint
that accepts the connection but never answers gets a 504
`pd_decode_timeout` instead of parking the client).

### 4.1 Affinity oracle caveat

On the P/D path, `usage.prompt_tokens_details.cached_tokens` in the client
response **always equals `prompt_tokens`** — the client-visible usage comes
from the generation leg, which receives the full prompt KV via the transfer.
It is useless as a routing-affinity signal there. Use
`loxilb_pd_kv_tier15_hits_total` for P/D affinity; `cached_tokens` remains a
valid oracle in the single-pool (converged) shape.

## 5. Configuration

P/D rule (the method shape — 4 context + 1 generation shown):

```json
{
  "serviceArguments": {
    "externalIP": "192.0.2.10", "port": 9007, "protocol": "tcp",
    "sel": 0, "mode": 4,
    "pd_disagg_mode": true, "kvEngineType": "trtllm",
    "kvExactMode": 1, "kvBlockSize": 32,
    "sse_mode": true, "monitor": true, "cb_enable": true,
    "probetype": "http", "probeport": 8355, "probereq": "/health"
  },
  "endpoints": [
    {"endpointIP": "192.0.2.11", "targetPort": 8355, "weight": 1, "ep_role": 1},
    {"endpointIP": "192.0.2.12", "targetPort": 8355, "weight": 1, "ep_role": 1},
    {"endpointIP": "192.0.2.13", "targetPort": 8355, "weight": 1, "ep_role": 1},
    {"endpointIP": "192.0.2.14", "targetPort": 8355, "weight": 1, "ep_role": 1},
    {"endpointIP": "192.0.2.15", "targetPort": 8355, "weight": 1, "ep_role": 2}
  ]
}
```

Single-pool engine-exact: drop `pd_disagg_mode` and the `ep_role` tags, set
`kvExactMode: 3`.

Field notes:

- `kvBlockSize` **must equal** the fleet's `tokens_per_block` (default 32) —
  the admission guard refuses mismatches per endpoint, loudly.
- `kvZmqPort` is meaningless for this engine (HTTP drain on the serving
  port) and is rejected if set to anything but its defaults.
- `kvDpRankCount > 1` is rejected — TensorRT-LLM event sequences are
  per-attention-DP-rank and the current poller is single-rank.
- Rejected combinations fail at rule creation with named reasons; the
  accepted matrix is `kvExactMode ∈ {0,1,3}` with `pd_disagg_mode` requiring
  mode 0 or 1.

Engine side (`trtllm-serve`):

- P/D roles: `--server_role CONTEXT` / `--server_role GENERATION` per
  worker.
- Events on: `kv_cache_config: {event_buffer_max_size: 4096}` in the
  `--extra_llm_api_options` YAML.
- The decode first-byte budget reuses the prefill timeout (default 30 s,
  per-rule override) — raise it if your generation fleet's time-to-first-byte
  under load legitimately exceeds it.

## 6. Validation status

All of the following ran green on a live 5-GPU fleet (4 CONTEXT + 1
GENERATION, Qwen2.5-7B-Instruct, `tokens_per_block: 32`) and in the
containerized mock scenario:

| What | Result |
|---|---|
| Prompt parity vs NVIDIA's reference disagg proxy (pinned pair) | byte-identical text + equal `prompt_tokens`, 3/3 seeds |
| Prompt parity vs the reference router over the full fleet, A/B | byte-identical, 4/4 seeds; gateway arm faster on the same corpus |
| Converged Tier-1.5 affinity (repeat-prompt, cached-token oracle) | ~100% repeat cache hits; hit counter advanced exactly per repeat |
| Block-size mismatch (deliberate `kvBlockSize:16`) | all endpoints refused with named reason; traffic unaffected; zero Tier-1.5 hits; zero drain connections |
| Failure drills: paused context EP / paused generation EP | no hangs; clean 200/5xx taxonomy; automatic re-admission |
| Drain-theft (rogue consumer, 60 s) | zero client errors; endpoint-scoped degradation; self-heal |
| Engine restart | fresh-cache `created` → inventory clear → rebuild, hits recover |
| Origin-5xx demotion (health-green, inference-500 shim) | clients 200 throughout; breaker demotes; zero requests while open; standard heal re-admits |
| Mock CI scenario (tri-engine coexistence, early-exit, gap resync) | full pass, wired into CI |

## 7. See also

- [doc 10 — hierarchical routing architecture](10-hierarchical-kv-routing-architecture.md)
- [doc 08 — KV-exact internals & guard ladder](08-kv-cache-aware-routing.md)
- [doc 15 — SGLang integration](15-sglang-kv-cache-aware-routing.md) (the
  sibling engine-exact integration; shares the re-hash decoder family)
- [doc 16 — SGLang vs vLLM differences](16-sglang-vs-vllm-routing-differences.md)
- [doc 05 — REST API reference](05-rest-api-reference.md)
