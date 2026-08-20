# SGLang P/D Disaggregation CICD Scenario

## Overview

Exit gate for the **SGLang prefill/decode dual-dispatch** datapath
(`kvEngineType=sglang`): the gateway fires the prefill and decode legs
concurrently, injects the bootstrap triple (`bootstrap_host` /
`bootstrap_port` / `bootstrap_room`) into both requests, relays only the
decode response to the client, and couples the pair's failure handling
(abort, retry-with-fresh-room, verbatim 4xx relay, origin-5xx breaker
demotion).

Engines are mocked by `mock_sglang_pd.py` (bootstrap rendezvous +
one-shot fault knobs) and `mock_vllm.py` (the coexistence rule, borrowed
from `../vllm-pd-disagg/`). Every leg self-confirms its stimulus fired
before asserting.

## Topology

```
l3h1 (10.10.10.1)
      │
      └── llb1 (VIP 10.10.10.254)
             ├── :2030 SGLang P/D  ── l3ep1 (31.31.31.1:8100) prefill ┐ bootstrap :9998
             │        kvEngineType=sglang, pdBootstrapPort=9998,      ├─ l3ep2 (32.32.32.1:8100) prefill ┘
             │        cb_enable                                        └─ l3ep3 (33.33.33.1:8100) decode
             └── :2031 vLLM P/D coexistence (default engine, cb_enable)
                      ├── l3ep1 (:8000, nixl 9001) prefill
                      ├── l3ep2 (:8000, nixl 9003) prefill
                      └── l3ep3 (:8000, nixl 9002) decode
```

Fault knobs (one-shot, armed via loopback admin servers inside each EP):
`mock_sglang_pd` on `:9100` (`fail-next` / `die-next` / `reject-next` /
`reset`), `mock_vllm` on `:9000` (`fail-next` / `reset`).

## Run

```bash
cd cicd/sglang-pd-disagg
./config.sh          # topology + mocks + rules   (LOXILB_DOCKER_IMAGE=<tag> to pin the image)
./validation.sh      # the legs; exits nonzero on any failure
./rmconfig.sh        # teardown
```

Success sentinel: `SCENARIO-sglang-pd-disagg [OK]` (48 checks, 0 FAIL).

## Legs

| Leg | What it proves |
|---|---|
| A | rule acceptance with the sglang guard + `pdBootstrapPort`-on-vLLM rejected coherently |
| B | non-streaming happy path — the bootstrap rendezvous pins DUAL dispatch (prefill blocks until decode joins the room), fresh room per request |
| C | streaming happy path — SSE relayed from the decode leg to `[DONE]` |
| D | prefill origin 5xx → pair abort (decode leg closed fast, abort counter ticks) |
| E | prefill drain-leg transport death → pair RETRY with a fresh room, client rescued to 200 |
| F | decode-leg death → graceful 5xx, the drain leg is not orphaned |
| G | coexistence — the vLLM sequential machine and SGLang dual dispatch on one gateway |
| I | prefill origin 4xx (pre-decode) relayed to the client VERBATIM (no 502 masking) |
| J | streamable JSON over the body-inspect cap on a disagg rule → fail-closed 503 pre-dispatch |
| K | three consecutive prefill 5xx → the origin-error streak opens the breaker (`[CB_ORIGIN]` dp-log marker + `pd_cb_flips`), failover holds, the tripped EP serves zero while OPEN, the heal cycle re-admits it |
| L | the same demotion on the **vLLM dialect**, where a prefill 5xx is swallowed (degrades to decode-recompute, client stays 200) — the breaker must still open, avoid the EP, and re-admit it |
| H | hygiene — zero mock-side contract violations, the `pd_sg_*` counter family exported |

Note for leg K/L debugging: the `[CB_ORIGIN]` marker is written by the C
data-plane logger to `/var/log/loxilbdp.log` **inside the container** —
`docker logs llb1` does not carry it.
