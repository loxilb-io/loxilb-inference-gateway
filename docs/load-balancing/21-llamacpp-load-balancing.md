# 21 — llama.cpp load balancing

loxilb-inference-gateway supports `llama-server` (llama.cpp) fleets as a
first-class engine alongside vLLM, SGLang and TensorRT-LLM. llama.cpp is
deliberately integrated with a **shorter feature ladder** than the other
three engines, because the engine itself neither publishes KV-cache events
nor supports prefill/decode disaggregation:

| Capability | Status |
|---|---|
| L7 load balancing (`/v1/chat/completions`, `/v1/completions`, SSE) | supported |
| Session affinity (session-header / IP stickiness) | supported |
| Cache-aware prefix affinity via CHWBL (`sel: 8`) | supported — **the recommended selector** |
| Tier-1.5 KV-exact routing (`kvExactMode`) | rejected — the engine has no KV event plane |
| P/D disaggregation (`pd_disagg_mode`) | rejected — the engine has no P/D support |

## Why CHWBL is the cache-affinity tier

llama.cpp does the fine-grained cache work *inside* each server: incoming
prompts are matched to the slot holding the longest common prefix, and
evicted slot states are parked in a host-RAM prompt cache (`--cache-ram`)
and restored when the prefix family returns. What the engine cannot do is
keep a prefix family on the *same server* across a fleet — that is exactly
the gateway's CHWBL selector, which hashes the model + normalized system
prompt into a consistent-hash ring with bounded loads.

The division of labor is measurable per request: llama.cpp returns
`usage.prompt_tokens_details.cached_tokens` on every response (add
`stream_options: {"include_usage": true}` for streams), and exports a
`llamacpp:prompt_tokens_cached_total` Prometheus counter. Live-measured on
a 5-endpoint converged fleet: round-robin **never** re-lands a repeating
prefix family (fleet cached-token delta literally +0 across every run),
while CHWBL keeps families warm — repeat-prompt TTFT 92 ms vs 4.4 s at
16k-token prompts (~48×), 42 ms vs 513 ms at 1.8k (~12×). Benchmarked
against a perfect single-server co-location oracle, CHWBL captures
essentially all of the achievable affinity (within measurement noise),
including workloads where families share a common system-prompt preamble —
no finer-grained gateway tier could do measurably better.

### CHWBL keys on the SYSTEM prompt — with a bounded user-prefix fallback

The gateway's content hash is computed from the request's **system
message** (plus the model). This is deliberate: the system prompt is the
stable, shared prefix that makes cache affinity worth routing on, while
user turns diverge per request. A system prompt remains the preferred way
to shape traffic for affinity.

Chat payloads with **no system message** no longer spray: the gateway
falls back to hashing a **bounded prefix of the first user message**
(default 256 bytes, `LLB_LLM_USER_PREFIX_FALLBACK_LEN` overrides; `0`
disables the fallback and restores pure connection-spread for such
bodies). The bound is what makes multi-turn conversations co-locate:
later turns share their opening, so turn N hashes to the same endpoint
as turn 1 even as the transcript grows. Bodies with no user message at
all (empty `messages`, assistant-only) still get no content affinity.

Observability: the gateway logs a `[PREFIX_EXTRACTED]` debug receipt when
it hashes a request's content, and a `[PREFIX_USER_FALLBACK]` receipt when
the bounded user-prefix fallback supplied the hash input — the latter is
the tell that traffic is running on fallback affinity rather than a shared
system prompt.

## Deployment recipe (per endpoint)

```
llama-server -m <model.gguf> \
  --host 0.0.0.0 --port <port>   # default bind is localhost:8080 — must override
  -np <slots> -ngl 999 \
  --cache-ram <MiB>              # host-RAM prompt cache; default 8192
  --metrics                      # observability is OPT-IN — always pass this
```

**Long-context shape.** With the default split KV pool, each of the `-np`
slots gets `ctx/np` context — a `-np 4 -c 32768` server rejects any prompt
over 8192 tokens with a clean 400. To accept prompts near the full model
context while keeping slot concurrency, add `--kv-unified`:

```
llama-server ... -np 4 -c 32768 --kv-unified
```

Live-measured trade-offs of the unified shape: single-request cold prefill
throughput is identical to a split pool, warm repeats stay in the
100–130 ms range, and 4-way concurrent bursts pay roughly +16 % contention
versus split slots — a good default for fleets that must accept
long-context requests.

**Host prompt-cache limits at long context.** `--cache-ram` restores an
evicted prefix family only when enough KV cells are free up front — it
does not purge idle slots to make room. Near the full `-c`, restores fail
(the engine logs `failed to find … available cells`) and the request pays
a full recompute; short states (a few thousand tokens) restore reliably.
At long context, gateway-side CHWBL affinity is therefore not an
optimization but **the only warm path** — an endpoint switch costs a full
prefill that the host cache cannot buy back.

**`--cache-reuse` (chunk reuse) — leave off by default.** It earns its
keep only for deletion-shaped edits (dropping a middle chunk lets the
tail shift left and be reused); replacement or insertion edits still get
prefix-only reuse, because the engine only shifts matching chunks toward
lower positions. Enable it for RAG-compaction workloads; otherwise the
default (off) is correct.

Rails:

- **Never** set `--sleep-idle-seconds` on endpoints behind a VIP — a
  sleeping server pays a full model reload behind the next open request.
  The gateway's admission probe warns if it sees `is_sleeping: true`.
- Run **classic single-model mode** per endpoint. The multi-model router
  mode (`llama-server` without `-m`) double-routes behind a gateway and
  fragments slot pools.
- llama.cpp has no release branches — master is tagged per merge as
  rolling `b<N>` builds. Pin one image build/digest per fleet; the gateway
  probe warns when `build_info` differs across a rule's endpoints.
- Identical GGUF (same file, same quantization) on every endpoint of a
  rule. `POST /tokenize` through the VIP is a quick parity oracle.

## Rule configuration

Typing the rule with `kvEngineType: "llamacpp"` is optional but
recommended — it enables the loud config-time guards, the admission probe
and the `engine` metrics label. An untyped plain rule works identically at
the datapath level.

```json
{
  "serviceArguments": {
    "externalIP": "192.0.2.10", "port": 9012, "protocol": "tcp",
    "sel": 8, "mode": 4,
    "kvEngineType": "llamacpp",
    "sse_mode": true, "monitor": true, "cb_enable": true,
    "probetype": "http", "probeport": 8085, "probereq": "/health"
  },
  "endpoints": [
    {"endpointIP": "10.0.0.7", "targetPort": 8085, "weight": 1},
    {"endpointIP": "10.0.0.8", "targetPort": 8085, "weight": 1}
  ]
}
```

Guard behavior for `kvEngineType: "llamacpp"`:

- `kvExactMode` (any non-zero) → rejected: no KV event plane exists; use
  CHWBL (`sel: 8`) for prefix affinity.
- `pd_disagg_mode: true` → rejected: no P/D disaggregation exists. The
  upstream llama.cpp direction for disaggregation is internal to
  `llama-server`, so a gateway orchestration dialect will not be needed
  even when it ships.
- `kvHashAlgo`, non-default `kvZmqPort`/`kvDpRankCount`/`kvBlockSize`,
  `pdBootstrapPort` → rejected as meaningless knobs (loud beats
  silently-dead config).

## Admission probe & observability

On admission of a `llamacpp`-typed rule, the gateway probes each
endpoint's `GET /props` (retrying through the model-loading window) and
**warns — never refuses** — on fleet skew:

| Warning kind | Meaning |
|---|---|
| `model_mismatch` | endpoints of one rule serve different models |
| `build_mismatch` | mixed llama.cpp builds behind one rule (rolling-release drift) |
| `slots_mismatch` | uneven `--parallel` slot counts behind one rule |
| `sleeping` | an endpoint has sleep mode enabled behind the VIP |
| `unanswered` | an endpoint never answered `/props` within the probe deadline |

Findings are logged with the `[LCP_PROBE]` prefix and counted in
`loxilb_ai_llamacpp_probe_warnings_total{service, kind}`. The rule's
engine identity is exported as `loxilb_ai_engine_info{service, engine}`.

Engine-side dashboards can scrape each endpoint's own `/metrics`
(`llamacpp:` family) directly — llama.cpp speaks native Prometheus text,
so no adapter is needed.

## Operational notes

- `/health` answers 503 with a `"Loading model"` error body during GGUF
  load, then 200 — existing HTTP health probes gate correctly on long
  loads.
- Malformed request JSON is answered **HTTP 500** (with an OpenAI-shaped
  error object), not 400. Unknown JSON request fields are silently
  ignored (the vLLM posture).
- SSE streams end with `data: [DONE]` on the OpenAI endpoints; a request
  rejected before streaming begins (for example, prompt exceeds the
  per-slot context) returns a non-stream JSON error.
- The engine's HTTP keep-alive idle timeout is 5 seconds — idle backend
  connections churn; this is normal and handled by the proxy.
- Requests with no free slot are deferred in an unbounded engine-side
  queue (`llamacpp:requests_deferred` gauge); the gateway's admission
  gate remains the bounded backpressure layer in front of it.
- The per-endpoint circuit breaker on plain rules trips on connect-level
  failures **and on origin-computed 5xx streaks**: a configurable run of
  consecutive 5xx responses (`LLB_PD_ORIGIN_ERR_THRESHOLD`, default 3,
  `0` disables) opens the breaker (`[CB_ORIGIN]` in the dataplane log)
  and takes the endpoint out of rotation. The erroring streak itself is
  still relayed to clients as-is — demotion is not retry or masking.
  Because such an endpoint accepts TCP fine, recovery requires a
  half-open probe to draw a real origin success (status < 400); a mere
  connect success does not re-admit it. Note that 4xx responses neither
  extend nor reset the streak — this engine answers 500 (not 400) to
  malformed request JSON, so a burst of client-fault errors interleaved
  with successes cannot demote a healthy endpoint, but three back-to-back
  client-fault 500s with no interleaved success on one endpoint can; keep
  the threshold comfortably above your worst-case burst if your clients
  send malformed bodies at volume.
