# trtllm-pd-disagg — TensorRT-LLM P/D disaggregation (mock, no GPU)

Validates the TRT-LLM **sequential context-first rewriter dialect**
(`pd_dialect_trtllm`): the gateway splices
`disaggregated_params{request_type:context_only, disagg_request_id}` into the
context leg, buffers the context response, extracts
`choices[0].disaggregated_params`, re-splices it into the generation leg with
`request_type:generation_only` — or relays the context response directly when
it already finished the request (context early exit).

Two mock properties make this scenario adversarial rather than happy-path:

- **`extra="forbid"` everywhere** — any unknown request field draws a 400,
  exactly like the real engine. A vLLM `kv_transfer_params` or an SGLang
  bootstrap triple leaking into a TRT-LLM request fails loudly forever.
- **Relay-integrity pin** — the generation mock 400s any
  `encoded_opaque_state` whose magic prefix + base64 payload do not
  round-trip intact (stateless check — context/generation mocks are
  separate processes). A proxy that reconstructs (or corrupts) the
  extracted span instead of relaying it verbatim fails leg B by
  construction.

## Topology

```
l3h1  (10.10.10.1/24)  ── llb1 (loxilb, VIP 10.10.10.254/24)
l3ep1 (31.31.31.1/24)  ── llb1   trtllm CONTEXT    + sglang prefill A + vllm prefill
l3ep2 (32.32.32.1/24)  ── llb1   trtllm CONTEXT    + sglang prefill B
l3ep3 (33.33.33.1/24)  ── llb1   trtllm GENERATION + sglang decode    + vllm decode
```

Mocks per EP: `:8355` mock_trtllm (admin `127.0.0.1:9600`), `:8100`
mock_sglang_pd (admin `:9100`), `:8000` mock_vllm (admin `:9000`).

## Rules

| VIP port | Engine | Shape |
|---|---|---|
| 2040 | trtllm | `pd_disagg_mode` + `kvEngineType=trtllm` + `kvExactMode=1` + `kvBlockSize=32` (subject under test; the mode-1 KV plane polls the CONTEXT EPs' **serving ports** — sole consumer of `/kv_cache_events`) |
| 2042 | sglang | P/D coexistence (dual-dispatch machine, bootstrap `:9998`) |
| 2043 | vllm | P/D coexistence (sibling sequential machine, nixl 9001/9003/9002) |

## Run

```bash
cd cicd/trtllm-pd-disagg
./config.sh        # topology + mocks + rules   (LOXILB_DOCKER_IMAGE=<tag> to pin the image)
./validation.sh    # legs below; exits non-zero on any FAIL
./rmconfig.sh      # teardown
```

The gateway image must carry the trtllm P/D admission (leg A posts a
`kvEngineType=trtllm` + `pd_disagg_mode` rule). When validating a not-yet-
published gateway build, pin `LOXILB_DOCKER_IMAGE` to the locally-built
image — the harness default is the public tag, and a pre-flip public image
fails every leg from A1 in a way that masquerades as a total regression.

## Legs

| Leg | What it pins |
|---|---|
| A | guard flip: trtllm+pd_disagg+mode-1 accepted; kvExactMode=2 / non-default kvZmqPort / kvDpRankCount>1 still rejected |
| B | non-stream happy path; generation text proves the extracted span was relayed **verbatim** (integrity pin) and both legs ran |
| C | streaming happy path (SSE from the generation leg, `[DONE]` intact) |
| D | context early exit: scripted `finish_reason=stop` → buffered response relayed, generation leg **skipped**, `pd_trt_ctx_early_exit_total` ticks; D4 = one-chunk SSE re-frame for a streaming client |
| E | `extra="forbid"` pin: client-carried `kv_transfer_params` → engine 400 relayed (not masked, not stripped) |
| F | origin-5xx demotion: context mock 500-storm → `[CB_ORIGIN]` + `pd_cb_flips`, all client requests stay 200 via generation recompute, EP serves zero while OPEN, heal re-admits |
| G | mode-1 KV plane: exactly the CONTEXT EPs subscribed on their serving ports, `/server_info` admission verdicts, stored-event ingest, `event_id` gap(100) → resync → continued ingest |
| H | tri-engine coexistence: trtllm + sglang + vllm P/D rules serving on one gateway |
| I | metric families exported (`pd_trt`, `kv_subscriber`, `cb`) |

Deterministic early-exit and event-gap forcing live HERE (the mock scripts
`finish_reason` and `event_id`). What mocks cannot cover — parity against
a real engine and the cached-token affinity oracle — needs a live GPU
fleet running `trtllm-serve` in context/generation roles.
