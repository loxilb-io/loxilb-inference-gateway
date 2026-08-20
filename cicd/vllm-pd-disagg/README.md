# vLLM P/D Disaggregation CICD Scenario

## Overview

Exit gate for the **vLLM sequential prefill/decode** datapath
(`pd_disagg_mode`, default engine dialect): the gateway rewrites the request
into a prefill probe (`max_tokens=1`, `stream=false`, `kv_transfer_params`),
sends it to a prefill EP, extracts `kv_transfer_params` from the prefill
response, rebuilds the original request for the decode EP, and relays the
decode response (including SSE) to the client. A prefill failure degrades
gracefully (decode recomputes, or mid-request prefill retry on a transport
death) — never a hung client.

Engines are mocked by `mock_vllm.py` (OpenAI-compatible endpoints,
`kv_transfer_params` synthesis, NIXL side-channel listeners, an admin server
with health toggles and one-shot fault knobs).

## Topology

```
l3h1 (10.10.10.1)
      │
      └── llb1 (VIP 10.10.10.254)
             ├── :2020 P/D 1P+1D    ── l3ep1 (31.31.31.1:8000) prefill, nixl 9001
             │                       └─ l3ep2 (32.32.32.1:8000) decode,  nixl 9002
             ├── :2021 non-P/D baseline (l3ep2 as a plain backend)
             ├── :2022 P/D 2P+2D    ── + l3ep3 (33.33.33.1:8000) prefill, nixl 9003
             │                       └─ + l3ep4 (34.34.34.1:8000) decode,  nixl 9004
             ├── :2023 P/D 2P+2D + pd_cache_aware_mode (Tier-1 trie)
             └── :2024 session-header stickiness (HA conversation sync)
```

## Run

```bash
cd cicd/vllm-pd-disagg
./run-pd-cicd.sh                     # config + validation + teardown, logged under logs/
./run-pd-cicd.sh --bail-on-fail      # stop at the first failing phase
./run-pd-cicd.sh --phase=D           # a single phase (see the table below)
./run-pd-cicd.sh --phase=L           # HA failover phase (auto-enables the 2-loxilb topology)
```

Or the raw scenario flow: `./config.sh` → `./validation.sh` → `./rmconfig.sh`
(`LOXILB_DOCKER_IMAGE=<tag>` pins the gateway image).

Success sentinel: `SCENARIO-vllm-pd-disagg [PASS]`.

## Tests

| Block | What it proves |
|---|---|
| T1-T9 | baseline: non-P/D passthrough, `X-Request-Id` auto-inject/preserve format, P/D completions data plane, request-id correlation, SSE streaming, LB statistics, Prometheus P/D metrics, NIXL ports (not HTTP ports) in the request-id receipt |
| Phase A | prefill body rewriting (`max_tokens=1`, `stream=false`, `kv_transfer_params` injection, Content-Length fixup) |
| Phase B | multi-EP pool routing on :2022 (prefill/decode role separation under load) |
| Phase C | the full `X-Request-Id` spec (`___prefill_addr_..___decode_addr_.._<uuid>`) |
| Phase D | failover: EP down/up transitions, prefill mid-request retry, decode re-selection |
| Phase E | concurrency + parallel load (fresh buffers per request, no cross-talk) |
| Phase F | control-plane CRUD (rule add/delete/re-add under live traffic) |
| Phase G | SSE edge cases (fragmented frames, `[DONE]` terminators, keep-alive) |
| Phase H | Prometheus observability (P/D counter families present and moving) |
| Phase I | circuit breaker on TCP-failure triggers (connect-level `failure_count`) |
| Phase J | Tier-0 conversation stickiness |
| Phase K | Tier-1 cache-aware trie routing on :2023 |
| Phase L | HA session restoration across a 2-loxilb MASTER failover (gated; `validation-convsync.sh` / `validation-xsync.sh`) |

The **origin-5xx breaker demotion** for this dialect (a prefill 5xx is
swallowed as decode-recompute, so only the origin-error streak can demote an
erroring-but-TCP-healthy prefill) is pinned by leg L of
`../sglang-pd-disagg/` — that scenario hosts both engine mocks on one
gateway, which is exactly the coexistence surface the demotion must respect.

Fault knobs on each mock (loopback admin `:9000`): `/admin/health-fail`,
`/admin/health-ok`, `/admin/fail-next` (one-shot origin 500), `/admin/reset`,
`/admin/status`; plus `--fail-every N` at process start.
