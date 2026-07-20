# cicd/vllm-kvcache-routing-cpu — KV-cache-aware AI routing exit gate (CPU / no GPU)

A **strict, mock-driven CICD gate** that proves loxilb's Tier-1.5 KV-cache-aware AI routing path (ZMQ
KV-event subscriber → per-prefill-EP block-hash inventory → tokenize → block-hash → best-worker overlap
selection — the KV-cache-aware routing enhancements) to the **same production-quality bar as the other
CICD harnesses**: a 4-file lifecycle, a single `SCENARIO-vllm-kvcache-routing-cpu [OK]` sentinel,
`SKELETON_STRICT=1`, feature-enable-before-assert, REST readiness polling, and scoped teardown.

This is the **fast inner loop** (the functional checks, driven by a contract-faithful synthetic ZMQ publisher).
The two-tier gate pairs this with an **authoritative exit gate** that additionally runs the real
CPU vLLM contract-drift smoke — **the phase cannot go green without the real-vLLM exit-gate stage** (see
the `cicd/vllm-kvcache-routing-cpu-aws/` provisioning rig). No GPU is used anywhere.

## Topology (6 EPs, 3 prefill at NON-ADJACENT absolute indices + 3 decode)

```
            10.10.10.0/24
  l3h1 ───────────────────── llb1 (loxilb CP+DP, REST :11111, VIP=10.10.10.254)
  (client + publisher)          │   KV-exact P/D VIP 10.10.10.254:8080 (mode=4 fullproxy, pd_disagg_mode)
                                │   kvExactMode=1 kvZmqPort=5557 kvHashAlgo=sha256_cbor kvBlockSize=16
                                │
   abs idx  ep_role  ECHO_NAME  ├── 31.31.31.1:80  l3ep1  serverP0  PREFILL (EP-A, idx 0)  ep_role=1
     0        1      serverP0   ├── 32.32.32.1:80  l3ep2  serverD0  DECODE          (idx 1)  ep_role=2
     1        2      serverD0   ├── 33.33.33.1:80  l3ep3  serverP1  PREFILL (EP-B, idx 2)  ep_role=1
     2        1      serverP1   ├── 34.34.34.1:80  l3ep4  serverD1  DECODE          (idx 3)  ep_role=2
     3        2      serverD1   ├── 35.35.35.1:80  l3ep5  serverP2  PREFILL (EP-C, idx 4)  ep_role=1
     4        1      serverP2   └── 36.36.36.1:80  l3ep6  serverD2  DECODE          (idx 5)  ep_role=2
     5        2      serverD2
```

- **Prefill EPs at absolute indices 0/2/4** (non-contiguous) so the C↔Go bitmask
  index-translation is exercised. Decode EPs interleave at 1/3/5 and are **never** KV-selection
  candidates. EP-A/EP-B/EP-C = `31.31.31.1` / `33.33.33.1` / `35.35.35.1`.
- **Backends are socat reflect-echo** (`--dock-type reflect-echo`, `ECHO_NAME=serverP*/serverD*`): the
  banner `serverN` is the **delivery proof** surface (never curl, never metrics-only).
- **VIP = llb1's own IP (10.10.10.254)**, the standard fullproxy bind requirement.

## Functional check → assert map

| Check | What it proves                                                                     | Assert (validation.sh)                                                          |
| ----- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| 1  | inventory-mutation flip — re-issued identical prompt changes the winner            | flip: re-publish remaining blocks to EP-B → banner==serverP1 AND tier15_hits{2}++ |
| 2  | argmax-overlap selection (highest-overlap prefill EP serves)                       | argmax: banner==serverP0 AND tier15_hits{0}++ (dual proof)          |
| 3  | guards F/G (no_hashes / no_worker / excluded / cb_open) — C unit `make test_kv`    | C-side `test_kv_exact.c` (layered into the gate)           |
| 4  | hash parity vs the PROMOTED golden vectors for BOTH algos                          | kv_hash_parity self-check `--algo sha256_cbor` + `--algo xxhash_cbor --vectors cicd/common/kv_hash/fixtures/kv_hash_vectors.json` |
| 5  | the 9 routing counters surface non-zero deltas (miss-reason is ONE CounterVec)     | `GET /metrics` tier15_hits / t15_fallthrough / t15_miss_reason / subscriber_connected |
| 6  | subscriber liveness — publisher kill/restart → reconnect + inventory clear + replay | publisher `--kill`/restart → loxilb_kv_subscriber_reconnect_total increments     |
| 7  | feature-enable live — kvExactMode active on the rule                               | `GET /config/loadbalancer/all` shows `kvExactMode:1`                            |
| 8  | backward-compat — vllm-pd-disagg byte-for-byte unchanged on the same build         | re-run `cicd/vllm-pd-disagg` → `SCENARIO-vllm-pd-disagg [PASS]` after collision pre-clean |
| 9  | real CPU vLLM contract-drift smoke (live hash-stream parity + e2e routing)         | **exit gate only** — `cicd/vllm-kvcache-routing-cpu-aws/` |

The four **REQUIRED overlap scenarios** map onto checks 1/2 and the guard ladder:

1. **two-EP partial-overlap argmax + mutation flip** (checks 1/2).
2. **non-contiguous prefill bitmask** — best EP at abs idx 4 (EP-C) still selected.
3. **excluded / circuit-broken winner → 2nd-best PREFILL EP** (never Tier-2 RR).
4. **warmup grace + tokenize/no-worker miss → Tier-2 RR fallthrough** + `t15_miss_reason{reason}`.

Every functional assert is **HARD/FATAL** under `SKELETON_STRICT=1`. Only the inherently
non-deterministic timing windows (exact warmup-expiry moment, reconnect latency) are `soft()`.

## Fixtures + feature-enable (config.sh)

- **Tokenizer of record:** the committed `Qwen__Qwen3-0.6B/tokenizer.json` (promoted to
  `cicd/common/kv_hash/fixtures/`) is `docker cp`'d to `/etc/loxilb/tokenizers/Qwen__Qwen3-0.6B/` so
  loxilb's CGO daulet path and the publisher's HF path tokenize **identically** (genuine non-empty
  inventory intersection — the token-ID-mismatch trap).
- **Golden vectors:** `cicd/common/kv_hash/fixtures/kv_hash_vectors.json` — the parity check asserts the
  publisher's reused hash core reproduces these for both `sha256_cbor` and `xxhash_cbor`.
- **Publisher:** `kv_event_publisher.py` emits the real 3-frame `topic | seq:u64-BE | msgpack` vLLM
  v0.17.0 envelope (`BlockStored`/`BlockRemoved`/`AllBlocksCleared`) with INT block hashes, reusing the
  `kv_hash_parity.py` hash core (no re-derivation — avoids the `digest[-8:]` drift).
- **Feature-enable POST:** a single P/D fullproxy service carries `kvExactMode=1` + the five
  `kv_*` fields (`kvZmqPort` 5557, `kvHashAlgo` sha256_cbor, `kvWarmupSec`, `kvBlockSize` 16), prefill
  `ep_role=1` / decode `ep_role=2`. The subscriber auto-starts per prefill EP; `serviceID == r.ruleNum`
  (the rule ordinal, NOT the port). The POST runs **after** a `:11111` readiness poll (the eBPF load
  takes 10–20s; a POST racing it returns HTTP 000).

## Two-tier gate

| Tier | What runs | Speed | Purpose |
| ---- | --------- | ----- | ------- |
| **1 — fast inner loop** | this scenario (functional checks, mock publisher) + `make test_kv` (C guards) + go-test KV units + vllm-pd-disagg compat | seconds–minutes | `sync-and-rebuild.sh` fix-loop iteration |
| **2 — authoritative exit gate** | tier 1 **plus** the real CPU vLLM smoke | minutes (CPU vLLM) | mandatory before sign-off — catches upstream-vLLM contract drift the pinned mock cannot |

**The phase cannot go green on tier 1 alone.** The mock is pinned to vLLM v0.17.0, so only a real vLLM
run validates against upstream contract drift / real cache+scheduler behaviour.

## Drive path

```bash
# Container gate (remote Linux testbed — Docker + ip netns are NOT on macOS):
./scripts/remote-cicd.sh vllm-kvcache-routing-cpu

# Strict mode explicitly (this is the default):
SKELETON_STRICT=1 ./scripts/remote-cicd.sh vllm-kvcache-routing-cpu

# Authoritative AWS exit gate (tier 2, adds the real-vLLM smoke):
cicd/vllm-kvcache-routing-cpu-aws/pipeline-kvcache.sh

# Directly on a Linux testbed:
sudo ./config.sh && sudo ./validation.sh ; ./rmconfig.sh
```

The harness greps the exact line `SCENARIO-vllm-kvcache-routing-cpu [OK]`. The backward-compat sub-stage re-runs
`cicd/vllm-pd-disagg` on the SAME build and requires its own `SCENARIO-vllm-pd-disagg [PASS]`.

## Teardown (rmconfig.sh)

SCOPED per-container teardown (6 EPs + client + llb1) **plus** a kill of the backgrounded
`kv_event_publisher.py` by its anchored tag `kvpub80` (`exec -a kvpub80` at launch → `pkill -f kvpub80`
matches only this suite's publisher). **Never** a host-wide netns sweep or process-name `killall`
— that would reap unrelated PIDs/netns across the shared runner.
