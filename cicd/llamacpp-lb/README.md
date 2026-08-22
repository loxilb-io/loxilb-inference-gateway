# llamacpp-lb — llama.cpp typed plain-LB (mock, no GPU)

Validates the **fourth typed engine**'s only supported rule shape: plain L7
LB with CHWBL/session affinity — no KV event plane, no P/D disaggregation
(both rejected loudly at config time). `mock_llamacpp.py` speaks the
contract live-pinned against `b10524` on a 5-EP GPU fleet:

- **Unknown request fields silently ignored** — the vLLM-tolerant posture,
  opposite of TRT-LLM's `extra="forbid"`. A foreign dialect leaking in
  serves 200 here (and that quiet failure mode is exactly why the typed
  guards exist).
- **Malformed JSON answers HTTP 500** (with the OAI error object), not 400
  — the live-pinned taxonomy quirk; the relay must pass it through, not
  reshape it.
- **`":"` SSE ping comments** whenever generation stalls past
  `--sse-ping-interval` — the mock scripts a mid-stream stall so the
  ping-through-VIP behavior gets pinned (the real fleet's prefill outruns
  any sane interval, so only the mock can exercise this).
- **`cached_tokens` receipts from a per-process prefix store** — warm
  repeats only on the EP that served the family before, which makes the
  receipts a per-EP affinity oracle exactly like the engine's.
- **/props** (`total_slots`/`model_path`/`build_info`/`is_sleeping`) for
  the phase-1 admission warn-probe; `l3ep3` runs a scripted build mismatch
  so the probe has real fleet skew to surface.

## Topology

```
l3h1  (10.10.10.1/24)  ── llb1 (loxilb, VIP 10.10.10.254/24)
l3ep1 (31.31.31.1/24)  ── llb1   llamacpp + trtllm CONTEXT    + sglang prefill A + vllm prefill
l3ep2 (32.32.32.1/24)  ── llb1   llamacpp + trtllm CONTEXT    + sglang prefill B  + vllm prefill
l3ep3 (33.33.33.1/24)  ── llb1   llamacpp + trtllm GENERATION + sglang decode     + vllm decode
```

Mocks per EP: `:8085` mock_llamacpp (admin `127.0.0.1:9700`), plus the
trtllm/sglang/vllm mocks (`:8355`/`:8100`/`:8000`) for the
quad-coexistence leg.

## Rules

| VIP port | Engine | Shape |
|---|---|---|
| 2044 | llamacpp | typed CHWBL (`sel=8` + `kvEngineType=llamacpp`; creation fires the `/props` warn-probe) — subject under test |
| 2045 | llamacpp | RR + `session_header_name=x-session-id` (stickiness; rotation also makes hold-out legs assertable) |
| 2040/2042/2043 | trtllm/sglang/vllm | P/D coexistence rules (unchanged from their own suites) |

## Run

```bash
cd cicd/llamacpp-lb
./config.sh        # topology + mocks + rules   (LOXILB_DOCKER_IMAGE=<tag> to pin the image)
./validation.sh    # legs below; exits non-zero on any FAIL
./rmconfig.sh      # teardown
```

The gateway image must carry the llamacpp typed-engine admission (leg A
posts `kvEngineType=llamacpp` rules). When validating a not-yet-published
build, pin `LOXILB_DOCKER_IMAGE` to the locally-built image.

## Legs

| Leg | What it pins |
|---|---|
| A | typed rules accepted; every KV/P/D shape rejected for llamacpp (`kvExactMode`, `pd_disagg_mode`, non-default `kvZmqPort`/`kvDpRankCount`/`kvBlockSize`, any explicit `kvHashAlgo`) |
| B | non-stream + stream happy path with receipts and `[DONE]`; unknown fields tolerated (200); malformed JSON relayed as the engine's **500** |
| C | ping-through-VIP: `":"` comment frames relayed mid-stream during a scripted stall, stream completes |
| D | **F-LCP-2 positive**: system-prompt families pin to one EP each, warm `cached_tokens` receipts, `[PREFIX_EXTRACTED]` in the dp log |
| E | **F-LCP-2 negative**: user-only payloads → zero new extractions — the documented spray; production rail = carry a system prompt |
| F | session-header stickiness (`x-session-id` on the RR rule) |
| G | 503-`Loading model` window → health-probe hold-out (zero serves) → re-admission |
| H | origin-5xx taxonomy: engine 500s relayed intact; EP stays in rotation (plain-LB rules have **no origin-5xx demotion** — that plane is P/D-only; documented-behavior pin) |
| I | quad-engine coexistence: llamacpp + trtllm + sglang + vllm rules serving on one gateway |
| J | hygiene: `loxilb_ai_engine_info{engine="llamacpp"}` + `loxilb_ai_llamacpp_probe_warnings_total` ticked by the scripted build skew |

What mocks cannot cover — real cached-token affinity magnitudes, long-context
behavior, `--cache-ram`/`--cache-reuse` semantics — lives in the GPU-fleet
characterization (design doc §8–§8.3): CHWBL vs RR repeat-TTFT 92 ms vs
4419 ms at 16k tokens, and the T6 SLO-grid verdict that CHWBL already
captures ~100 % of achievable affinity.
