# KV-Cache-Aware Routing on AWS — P/D Disaggregation Deploy & Debug Guide

**Audience:** internal engineers deploying, operating, and debugging KV-cache-aware
(Tier-1.5) routing on a real GPU fleet with **prefill/decode (P/D) disaggregation**.

**Relationship to [`08-kv-cache-aware-routing.md`](08-kv-cache-aware-routing.md):** doc 08 is the
*mechanism/internals* deep dive (block-hash contract, guard ladder, C↔Go index translation,
sync format). **This doc is the hands-on AWS deploy + debug guide** for the P/D-disaggregated,
real-vLLM/NIXL configuration. Read 08 §4 (block-hash contract) and §5 (guard ladder) alongside the
debugging section here. Where the two overlap, 08 is authoritative on internals; this doc is
authoritative on the live wire/operational behavior observed on a real GPU fleet.

> **Verified live 2026-06-16** on a 3×prefill + 1×decode fleet (the evidence in §7/§9 is from a real
> run, not a mock). The reference AWS testbed is `cicd/vllm-loxilb-kvcache-aws-small/` (2P+1D).

---

## 1. The one thing to internalize first: KV-aware routing ONLY runs in P/D mode

loxilb's P/D prefill selector `pd_select_prefill()` (`loxilb-ebpf/common/sockproxy_pd.c`),
invoked from the P/D gate in `sockproxy_ep.c`, runs **only** when the service is a
P/D-disaggregated rule (its Tier-1.5 KV-exact stage is `pd_kv_exact_select` in
`sockproxy_kv_exact.c`):

```
tepval->pd_disagg_enabled && n_prefill_eps > 0 && n_decode_eps > 0
```

A plain single-pool fullproxy service **never** invokes KV routing, no matter what `kvExactMode`
you set. Practically:

- The rule must be `mode: 4` + `pd_disagg_mode: true`, with endpoints tagged `ep_role: 1` (prefill)
  and `ep_role: 2` (decode), at least one of each.
- The selector picks **among the prefill EPs** by KV-block overlap. **Decode EPs are never KV-selection
  candidates** — they serve the generation phase.
- **2+ prefill EPs are required** for the routing decision to be meaningful — with one prefill node the
  LB is correct by default.

This also means the backing vLLM instances must run **real disaggregation** (NIXL `kv_producer` /
`kv_consumer`) — see §4. Plain vLLM instances will not work.

---

## 2. Reference AWS topology (2P+1D)

From `cicd/vllm-loxilb-kvcache-aws-small/bench/TOPOLOGY.md`. All nodes in one `/24`, one AWS
**cluster placement group** (low-latency intra-node traffic for NIXL KV transfer + ZMQ events).

| Node  | Instance     | Role                    | Ports                                  |
|-------|--------------|-------------------------|----------------------------------------|
| llb1  | t3.medium    | loxilb LB + REST        | REST `:11111`, VIPs `:9000–9003`       |
| l3h1  | t3.small     | benchmark/client driver | —                                      |
| l3ep1 | g5.xlarge    | **Prefill-1** (kv_producer) | vLLM `:8100`, ZMQ PUB `:5557`, NIXL `:5600` |
| l3ep2 | g5.xlarge    | **Prefill-2** (kv_producer) | vLLM `:8100`, ZMQ PUB `:5557`, NIXL `:5600` |
| l3ep3 | g5.xlarge    | **Decode-1** (kv_consumer)  | vLLM `:8200`, NIXL `:5600`             |

> **BYO/on-prem fleets are identical** minus the provisioning layer — drop the terraform; supply an
> SSH inventory of `{ip, role, gpu_type, vllm_port}` and the same deploy logic applies. See
> `cicd/vllm-kvcache-routing-byo/` (`deploy-byo-pd.sh`) for the SSH-inventory port of this testbed.

**Port discipline is baked into the scripts and LB rules — do not change without updating both
sides:** prefill vLLM `:8100`, decode vLLM `:8200`, ZMQ KV events `:5557` (prefill only), NIXL
side-channel `:5600` (all GPU nodes).

---

## 3. The three planes

| Plane           | Carries                          | Path                                                   |
|-----------------|----------------------------------|--------------------------------------------------------|
| **Inventory**   | which prefix blocks each prefill EP holds | prefill vLLM → ZMQ PUB `:5557` → loxilb SUB (dials each prefill IP) |
| **Request**     | the client completion request    | client → loxilb VIP → selected prefill → (NIXL) → decode → client |
| **KV transfer** | the computed KV tensors          | prefill GPU → CPU → TCP/UCX `:5600` → CPU → decode GPU  |

The **inventory** plane is what makes routing "cache-aware"; the **KV-transfer** plane is what makes
P/D disaggregation work. They are independent — a broken inventory plane silently degrades routing to
round-robin (see §9), while a broken KV-transfer plane fails requests outright (503/timeout).

---

## 4. vLLM configuration (the part most people get wrong)

Source of truth: `cicd/vllm-loxilb-kvcache-aws-small/vllm-run-args.sh` + `vllm-run-args-kvcache.sh`
(BYO equivalent: `cicd/vllm-kvcache-routing-byo/pd_vllm_args.sh`).

### 4.1 Prefill node (kv_producer + KV-event publish)

```bash
docker run -d --name vllm --gpus all --network host \
  -e VLLM_NIXL_SIDE_CHANNEL_HOST=<this-node-private-ip> \   # MUST be the node IP, NOT 0.0.0.0
  -e VLLM_NIXL_SIDE_CHANNEL_PORT=5600 \
  -e UCX_TLS=tcp \                                          # no RDMA/GDRcopy on g5 → tcp transport
  -e UCX_NET_DEVICES=all \
  -e PYTHONHASHSEED=0 \                                     # PARITY TRIAD leg 1 (see §6)
  vllm/vllm-openai:v0.17.0 \
    --model <MODEL> --host 0.0.0.0 --port 8100 \
    --block-size 16 \                                       # PARITY TRIAD leg 2
    --prefix-caching-hash-algo sha256_cbor \                # PARITY TRIAD leg 3 (NOT the default "sha256"!)
    --enforce-eager --enable-request-id-headers \
    --kv-transfer-config '{"kv_connector":"NixlConnector","kv_role":"kv_producer","kv_buffer_device":"cpu","kv_load_failure_policy":"fail"}' \
    --kv-events-config '{"enable_kv_cache_events":true,"publisher":"zmq","endpoint":"tcp://*:5557"}'
```

### 4.2 Decode node (kv_consumer; no KV-event publish)

Identical, except `--port 8200`, `kv_role":"kv_consumer"`, and **no `--kv-events-config`** (decode
nodes don't publish; they're never KV-selection candidates).

### 4.3 Why each non-obvious flag matters

| Flag | Why | Failure if wrong |
|------|-----|------------------|
| `kv_buffer_device: "cpu"` | g5/A10G has no GDRcopy/RDMA; CUDA-aware UCX is unavailable on `UCX_TLS=tcp`. Routes KV GPU→CPU→TCP→CPU→GPU. | vLLM crashes in `nixlUcxSharedThread::run()` on the first request. |
| `UCX_TLS=tcp` | Forces the TCP transport (no RDMA fabric on these instances). | UCX init crash / hang. |
| `VLLM_NIXL_SIDE_CHANNEL_HOST=<node-ip>` | Peers must dial a reachable IP, never `0.0.0.0`. | Decode can't pull KV → request hangs/fails. |
| `--prefix-caching-hash-algo sha256_cbor` | vLLM's **default is pickle-`"sha256"`** (non-portable, NOT what loxilb computes). loxilb computes CBOR. | 0% hash intersection → every request falls through to round-robin (silent). |
| `PYTHONHASHSEED=0` | Seeds vLLM's `NONE_HASH` (first-block parent) deterministically; must match loxilb's `LLB_KV_NONE_HASH_SEED=0`. | First block never matches → broken affinity. |
| `--block-size 16` | Must equal the rule's `kvBlockSize`. | Hashes computed over different token spans → no match. |
| `--kv-events-config endpoint tcp://*:5557` | `*` binds PUB mode; `127.0.0.1` puts ZMQ in connect mode and **nothing is published**. | `loxilb_pd_kv_blocks` stays 0 forever. |

---

## 5. loxilb configuration

### 5.1 Run loxilb as a CONTAINER (native does not serve the VIP)

A natively-launched `./loxilb` process has no eBPF VIP intercept wired — `curl VIP:9003` gets
connection-refused. You **must** run the container:

```bash
docker run -u root --cap-add SYS_ADMIN --restart unless-stopped --privileged \
  --network host -dit \
  -v /etc/loxilb/tokenizers:/etc/loxilb/tokenizers \       # tokenizer for block hashing (see §6)
  -e LLB_KV_NONE_HASH_SEED=0 \                             # PARITY: must match vLLM PYTHONHASHSEED=0
  -e LOXILB_KV_MAX_BLOCKS=1000000 \                        # per-EP inventory cap (read at subscriber init)
  -e LLB_KV_HASH_DEBUG=1 \                                 # testbed-only: [KV_HASH] forensic logger
  --name loxilb ghcr.io/loxilb-io/loxilb-inference-gateway:latest -p
```

### 5.2 The LB rules — the four modes the testbed registers

Posted to `http://localhost:11111/netlox/v1/config/loadbalancer`. All P/D rules are `mode:4` +
`pd_disagg_mode:true`, endpoints `ep_role:1` (prefill) / `ep_role:2` (decode) + `nixl_port:5600`.

| VIP port | `pd_disagg_mode` | selector | Purpose |
|----------|------------------|----------|---------|
| `:9001`  | **false** (`ep_role:0`, `sse_mode:true`) | round-robin, single pool | non-P/D RR baseline |
| `:9000`  | true, `pd_cache_aware_mode:false` | **round-robin prefill** | **P/D-RR baseline** (the apples-to-apples comparison for KV-exact) |
| `:9002`  | true, `pd_cache_aware_mode:true` (`pd_cache_threshold:20`, `pd_balance_abs_threshold:3`) | heuristic cache-affinity | heuristic mode |
| `:9003`  | true, **`kvExactMode:1`** (`kvZmqPort:5557`, `kvHashAlgo:sha256_cbor`, `kvWarmupSec:60`, `kvBlockSize:16`) | **Tier-1.5 KV-exact** | the method |

The KV-exact rule body (`:9003`):

```json
{
  "serviceArguments": {
    "externalIP": "<llb-ip>", "port": 9003, "protocol": "tcp",
    "sel": 0, "mode": 4, "security": 0, "host": "<llb-ip>",
    "pd_disagg_mode": true, "probeRetries": 1,
    "kvExactMode": 1, "kvZmqPort": 5557, "kvHashAlgo": "sha256_cbor",
    "kvWarmupSec": 60, "kvBlockSize": 16
  },
  "endpoints": [
    {"endpointIP": "<prefill-1>", "targetPort": 8100, "weight": 1, "ep_role": 1, "nixl_port": 5600},
    {"endpointIP": "<prefill-2>", "targetPort": 8100, "weight": 1, "ep_role": 1, "nixl_port": 5600},
    {"endpointIP": "<decode-1>",  "targetPort": 8200, "weight": 1, "ep_role": 2, "nixl_port": 5600}
  ]
}
```

> **Field-casing trap:** `pd_disagg_mode`, `pd_cache_aware_mode`, `ep_role`, `nixl_port`, `security`
> are **snake_case**; `kvExactMode`, `kvZmqPort`, `kvHashAlgo`, `kvBlockSize`, `externalIP`,
> `targetPort` are **camelCase**. Mixing them up silently drops the field (the API does not error).

---

## 6. The block-hash parity contract (why routing silently degrades to RR)

For loxilb to match a prompt against a prefill EP's inventory, **loxilb and vLLM must compute the
identical block hash for the identical token span.** See 08 §4 for the byte-level contract. The three
load-bearing knobs — the **parity triad** — must agree on both sides:

| Leg | vLLM | loxilb |
|-----|------|--------|
| NONE_HASH seed | `PYTHONHASHSEED=0` | `LLB_KV_NONE_HASH_SEED=0` |
| hash algorithm | `--prefix-caching-hash-algo sha256_cbor` | `kvHashAlgo: "sha256_cbor"` |
| block size | `--block-size 16` | `kvBlockSize: 16` |

Plus loxilb needs the **same tokenizer** staged at
`/etc/loxilb/tokenizers/<model-slug>/tokenizer.json`, where `<model-slug>` is the model id with `/`
→ `__` (e.g. `Qwen/Qwen2.5-7B-Instruct` → `Qwen__Qwen2.5-7B-Instruct`). A missing/mismatched
tokenizer produces different token ids → different hashes → no matches. See
[08 §6.3](08-kv-cache-aware-routing.md) for how to obtain and stage the file (download commands
and container mount paths).

For `/v1/chat/completions` there is an additional prerequisite: KV-exact routing of chat requests
requires a **chat template** registered in the gateway (`pkg/loxinet/ai_kv_chat_template.go`).
v1 ships only the Qwen2.5/ChatML family (any `Qwen__*` slug); for other models, chat requests
miss at Guard E and silently route via lower tiers — `/v1/completions` is unaffected.

**If any leg disagrees, there is no error — every request just falls through to round-robin.** This is
the single most common "it's not working" cause. Detection in §9.

---

## 7. End-to-end request sequence (client → response)

Observed flow for a request whose prefix is already cached on prefill `.5` (3 prefill `.4/.5/.6`,
1 decode `.3`):

```
CLIENT            loxilb VIP :9003 (eBPF fullproxy, mode 4)        PREFILL .5:8100      DECODE .3:8200
  │  TCP SYN ───────────►│ (eBPF intercept; L7 proxy terminates)        │                   │
  │  POST /v1/completions│                                              │                   │
  │  {model,prompt} ────►│ TIER-1.5 SELECT (pd_kv_exact_select):        │                   │
  │                      │  1. tokenize(prompt) via staged tokenizer    │                   │
  │                      │  2. block-hash (cbor+sha256, blk16, seed0)   │                   │
  │                      │  3. overlap vs inventory: .4=0 .5=5 .6=0     │                   │
  │                      │     → argmax = .5  (or MISS→Tier-2 RR if 0)  │                   │
  │                      │  4. exclusion mask (down/CB-open EPs)        │                   │
  │                      │  5. pd_select_decode → .3                    │                   │
  │                      │── prefill compute (cache HIT, skip recompute)►│                  │
  │                      │                                              │── KV via NIXL ───►│
  │                      │── decode (kv_transfer_params) ──────────────────────────────────►│
  │  200 OK {id=...      │◄──────────────────── response ───────────────────────────────────│
  │  prefill_addr_.5___  │                                              │                   │
  │  decode_addr_.3} ◄───│                                              │                   │
```

**Operator gold:** loxilb stamps the chosen pair into the completion `id`:
`cmpl-___prefill_addr_192.168.0.5:5600___decode_addr_192.168.0.3:5600_…`. You can read routing
decisions per-request straight off the response — no instrumentation needed. One caveat: if the
prefill leg failed over mid-request (`pd_retry_prefill()`), the receipt is rewritten
(`pd_receipt_rewrite()`) so the `id` names the prefill EP that **actually served** — it always
reflects the true server, not the first selection.

---

## 8. Observability — the metrics that exist (and a Prometheus gotcha)

Scrape on the loxilb host (metrics port need not be exposed off-box):
`curl -s http://localhost:11111/netlox/v1/metrics | grep -E 'loxilb_(pd_kv|kv_|pd_)'`.

⚠️ **Prometheus lazy-emission gotcha:** **labelled counters are not emitted until their first non-zero
observation.** On a freshly-deployed, zero-traffic system, `loxilb_pd_kv_tier15_hits_total` and several
others are **simply absent from `/metrics`** — that does **not** mean they don't exist. Drive a few
requests first, then scrape. (This previously misled a harness assertion into concluding the hits
counter was missing.) Also note the **`loxilb_` prefix** — code/harnesses that scrape bare
`pd_kv_tier15_hits_total` will never match; the real name is `loxilb_pd_kv_tier15_hits_total`.

### 8.1 The KV / P/D metric set (live image)

```
# --- routing decisions ---
loxilb_pd_kv_tier15_hits_total{ep_idx="N"}        COUNTER  KV-exact HITS, per prefill EP index
loxilb_pd_kv_tier15_fallthrough_total                COUNTER  requests that skipped Tier-1.5 → Tier-2
loxilb_pd_kv_tier15_miss_reason_total{reason="..."}  COUNTER  misses by guard reason:
                                                           mode_off, warmup, text_empty, model_empty,
                                                           tokenize, hashes, no_worker, excluded  (08 §5)
loxilb_pd_fallback_to_normal_total                COUNTER  P/D selection failed → fell back to normal LB
loxilb_pd_cb_flips_total                          COUNTER  per-EP circuit-breaker state flips
# --- failover / endpoint death ---
loxilb_pd_prefill_ep_died_total                   COUNTER  prefill backends that died mid-request
loxilb_pd_decode_ep_died_total                    COUNTER  decode failures (connect fail / EOF before 1st byte)
loxilb_pd_decode_zero_byte_eof_total              COUNTER  decode EOF w/ zero bytes relayed (client got 502)
loxilb_pd_connect_failover_total                  COUNTER  silent successful prefill connect failovers
loxilb_lb_select_failure_shutdown_total           COUNTER  raw TCP resets on non-P/D selection failure
                                                           (tripwire — must stay flat)
# --- inventory / subscriber health ---
loxilb_pd_kv_blocks{service="<svc>",ep_idx="<ep_idx>"}   GAUGE  blocks held per prefill EP (the inventory)
loxilb_kv_subscriber_connected{service,ep}             GAUGE  1 = loxilb's ZMQ SUB is connected to that prefill EP
loxilb_kv_agent_up                                     GAUGE  KV agent liveness (present only when the
                                                              separate KV agent is deployed)
# --- P/D serving + capacity ---
loxilb_ai_pd_requests_total                       COUNTER  total P/D requests
loxilb_ai_pd_kv_params_found_total                COUNTER  requests carrying kv_transfer_params
loxilb_ai_pd_prefill_duration_seconds             HISTO    prefill-leg latency
loxilb_ai_pd_decode_ttft_seconds                  HISTO    decode TTFT
loxilb_pd_sessions_active / loxilb_pd_trie_nodes  GAUGE    session-affinity + Tier-1 trie size
loxilb_proxy_pd_kv_params_overflow_total                 COUNTER  kv_params buffer overflow (should stay 0)
```

The `ep_idx` label on `loxilb_pd_kv_blocks` (and on `tier15_hits_total`/`tier15_spills_total`) is
the **0-based absolute endpoint index** within the rule, in registration order. It is an opaque
integer — join it to an endpoint address via the info metric
`loxilb_pd_ep_info{service,ep_idx,ep}` (value always 1):
`loxilb_pd_kv_tier15_hits_total * on(ep_idx) group_left(ep) loxilb_pd_ep_info`.

### 8.2 "Is KV-exact routing engaged?" — the three checks

1. `loxilb_kv_subscriber_connected{...} == 1` for **every** prefill EP (ZMQ plane healthy), AND
2. `loxilb_pd_kv_blocks` > 0 on prefill EPs (inventory ingested ⇒ ZMQ + **parity** OK), AND
3. under same-prefix load, `loxilb_pd_kv_tier15_hits_total` **advances** while `t15_fallthrough_total`
   stays flat (the only expected miss is the first request to a *cold* prefix).

**Live reference (from the §10 probe):** `loxilb_kv_subscriber_connected=1` for all three prefill
EPs; `loxilb_pd_kv_blocks`=13 on the cached prefill EP's `ep_idx`; `tier15_hits_total`=8 on that
same `ep_idx` (the 8 same-prefix requests, all to the cached prefill EP);
`t15_fallthrough_total=8` (`no_worker=7` cold + `model_empty=1`). Hits pinned to one `ep_idx` = correct
affinity.

Log markers (with `LLB_KV_HASH_DEBUG=1`): `[KV_HASH]` (hash forensics), `[KV_T15]` /
`[KV_T15_STAGE]` (per-request routing decision + per-stage timing). See 08 §7.2.

---

## 9. Debugging playbook

| Symptom | Likely cause | Diagnosis / fix |
|---------|-------------|-----------------|
| `curl VIP:9003` → connection refused | loxilb running **natively**, not as a container | `pgrep -a loxilb`; if native, kill it and run the container (§5.1). |
| Requests succeed but **always round-robin** (`t15_fallthrough_total` climbs 1:1 with traffic) | **parity triad broken** or tokenizer missing | Confirm all 3 legs (§6) on both sides; confirm `/etc/loxilb/tokenizers/<slug>/tokenizer.json` is staged + mounted. Enable `LLB_KV_HASH_DEBUG=1`, compare `[KV_HASH]` vs a published block. |
| `loxilb_pd_kv_blocks` stays **0** for all prefill EPs | ZMQ not flowing | First check `loxilb_kv_subscriber_connected{ep=...}`: **0** ⇒ loxilb's SUB can't reach that prefill's `:5557` (security groups / netns / wrong IP). **1** but blocks still 0 ⇒ either (a) prefill `--kv-events-config endpoint` is `127.0.0.1` not `tcp://*:5557` (connect-mode, publishes nothing), or (b) all test prompts are shorter than `block_size` (16) so no full block is ever cached/published — use a ≥16-token prefix. |
| `tier15_hits_total` **absent** from `/metrics` on a fresh deploy | Prometheus lazy-emission (zero observations) | Not a fault — drive a few same-prefix requests, then re-scrape (§8 gotcha). |
| Occasional 502, or silent prefill retries in logs | prefill EP died mid-request | `pd_retry_prefill()` re-drives once against another healthy prefill EP. `loxilb_pd_prefill_ep_died_total` counts death events; `loxilb_pd_connect_failover_total` advancing means failovers are succeeding **silently** (clients see no error). Client-visible `502 pd_prefill_failed` means the one-retry budget was exhausted (multiple EPs failing per request). |
| `502 {"error":"pd_decode_backend_died"}` | decode backend died before relaying any response byte | Check the decode EP's health/NIXL plane; `loxilb_pd_decode_zero_byte_eof_total` advances 1:1 with these 502s (subset of `loxilb_pd_decode_ep_died_total`). |
| `429 pd_overloaded` | admission gate shedding (every healthy prefill EP at its in-flight cap, no park room) | Retriable by the client. Watch `loxilb_pd_admission_shed_total`; raise `LLB_PD_MAX_INFLIGHT_PER_EP` / queue depth or add capacity. |
| vLLM container **exits immediately** at startup | NIXL/UCX crash | `docker logs vllm`; ensure `kv_buffer_device:"cpu"` + `UCX_TLS=tcp` (§4.3). |
| `503 {"error":"pd_pool_unavailable"}` | no healthy prefill **or** decode | check all EP `/health`; a P/D rule needs ≥1 healthy of **each** role. |
| Decode hangs / request times out after prefill | NIXL side-channel unreachable | `VLLM_NIXL_SIDE_CHANNEL_HOST` must be the node IP (not 0.0.0.0); `:5600` open between prefill↔decode. |
| loxilb **image build fails**: `undefined reference to bpf_object__next_map/next_program` | system `libbpf-dev` (Ubuntu 22.04 = libbpf 0.5.0) hijacked the link | Do **not** install system `libbpf-dev`. loxilb vendors libbpf 1.5.0 — stage it post-`make`: `cp -a loxilb-ebpf/libbpf/src/libbpf.so* /usr/lib64/` + soname symlinks (already in `Dockerfile`). Build with `docker build --network=host` if the build container's apt DNS is flaky. |
| `kv inventory` REST query → `invalid service_id` | the inventory endpoint needs a `service_id` param | cosmetic; use the Prometheus `loxilb_pd_kv_blocks` gauge instead. |

---

## 10. Verification recipe (copy/paste)

A ~30-second probe proving the whole path. Warms one long-prefix request, then confirms same-prefix
requests pin to the cached prefill EP and inventory grew. (Full script:
`cicd/vllm-kvcache-routing-byo` history / adapt the snippet below.)

```python
# warm a ~70-token shared prefix, then 8 same-prefix follow-ups; read prefill_addr from each id.
# EXPECT: loxilb_pd_kv_blocks{<cached-ep>} jumps 0→N after warm; all 8 follow-ups route to that EP;
#         fallthrough/miss increment by exactly 1 (the cold warm request only).
```

Reference live result (3 prefill + 1 decode, Qwen2.5-7B):

```
WARM routed to prefill .5  →  loxilb_pd_kv_blocks (cached EP): 0 → 5
SAME-PREFIX routes = [.5,.5,.5,.5,.5,.5,.5,.5]   (8/8 pinned)
fallthrough_delta = 1   miss_delta = 1           (the warm request only)
```

That is the correct signature: **1 cold miss (expected), then 100% affinity to the cached EP.**

---

## 11. AWS lifecycle

`cicd/vllm-loxilb-kvcache-aws-small/`: `provision-aws-infra.sh` → `deploy-vllm.sh` (rules 9000–9002)
→ `deploy-kvcache.sh` (tokenizer + rule 9003 + KV-events) → `run-aws-cicd.sh` /
`run-aws-validation-kvcache.sh` → `teardown-aws-testbed.sh`. ~$3.08/hr (3× g5.xlarge + 2× t3).
A full sweep run is ~2–3 hrs. **Tear down after every run — these instances bill by the second.**
(BYO/on-prem: no terraform; release your own hardware + stop the containers.)

---

## See also
- [`08-kv-cache-aware-routing.md`](08-kv-cache-aware-routing.md) — mechanism/internals, block-hash
  contract (§4), guard ladder (§5), sync format, known limits (§9/§10).
- [`06-troubleshooting.md`](06-troubleshooting.md) — general LB troubleshooting.
- `cicd/vllm-loxilb-kvcache-aws-small/bench/{TOPOLOGY,MEASUREMENT_PLAN,WBS}.md` — the AWS testbed spec.
- `cicd/vllm-kvcache-routing-byo/` — the SSH-inventory (BYO) port of this testbed.
