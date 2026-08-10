# SGLang Integration — Configuration, Tuning & Troubleshooting Guide

> **Audience:** engineers deploying LoxiLB in front of SGLang fleets, and operators tuning and
> troubleshooting the SGLang KV-exact routing path.
> **Scope:** every operator-facing knob for SGLang integration — the REST rule
> fields (`kvExactMode=3`, `kvEngineType`, `kvDpRankCount`), the config-time validation guards,
> the SGLang-relevant LoxiLB environment variables, the SGLang server-side flags
> (`--kv-events-config`, `--page-size`, `--dp-size`), port planning for co-resident fleets,
> plus a tuning playbook, observability quick reference, and troubleshooting playbook.
> **Prerequisite reading:** [15 — SGLang architecture & integration](15-sglang-kv-cache-aware-routing.md)
> for what each piece does; [11 — Hierarchical KV routing config & tuning](11-hierarchical-kv-routing-config-tuning.md)
> for the shared (engine-agnostic) knob families this doc does not repeat.
> **Last verified** against the committed code (2026-07-12).

> ⚠ **Validation status (read §11 before relying on live behavior).** Every flag, default,
> bound, and error string here is verified against the committed code, but the **binding
> remote gates** and the **live SGLang fleet window** had **not yet run** at the time of
> writing (the §7.7 spill-relief screen is the one measured exception).

---

## 1. Configuration surface at a glance

The SGLang path is configured in **three planes**; each row maps to specific knobs:

| Plane | Where configured | Key knobs |
|---|---|---|
| Rule shape (single-role KV-exact) | REST rule | `mode:4` (fullproxy), `kvExactMode:3`, `sel` (the miss-path selector) |
| Engine identity | REST rule | `kvEngineType:"sglang"` (immutable), `kvHashAlgo` **omitted** (default) |
| Hash parity | REST rule + SGLang flag | `kvBlockSize` **= SGLang `--page-size`** (read back from `/get_server_info`) |
| Event feed | REST rule + SGLang flag | `kvZmqPort` + `kvDpRankCount` ⇔ `--kv-events-config` port + `--dp-size` |
| Silent-failure tripwire | LoxiLB env | `LOXILB_KV_ZERO_HIT_N` (watchdog threshold, default 50) |
| Blend law / inventory caps | LoxiLB env (shared) | `LOXILB_KV_LB_MODE`, `LOXILB_KV_MAX_BLOCKS`, … — **process-global across vLLM and SGLang VIPs** ([11 §3.1](11-hierarchical-kv-routing-config-tuning.md)) |
| SGLang server | container launch flags | `--kv-events-config`, `--page-size` (model-dependent default), `--dp-size`, `--mem-fraction-static` |
| Tokenizer staging | LoxiLB host filesystem | the served model's HF `tokenizer.json` at `/etc/loxilb/tokenizers/<model-slug>/tokenizer.json` (slug = model id with `/` → `__`) — missing ⇒ Tier 1.5 **silently off** ([08 §6.3](08-kv-cache-aware-routing.md)) |
| Co-residency (optional) | deployment tooling | SGLang publisher-port choice (free-port check with `ss -tln`), vLLM/SGLang GPU memory split, uniform `--num-gpu-blocks-override` pin |

**Environment variables are read once at process start** — changing any `LOXILB_*`/`LLB_*`
value requires recreating the LoxiLB container. REST rules can be re-posted at runtime —
**except `kvEngineType`, which is immutable after create** (§3).

What the SGLang path deliberately does **not** have (all vLLM/P/D-only — see
[15 §1/§4](15-sglang-kv-cache-aware-routing.md)):

- No `pd_disagg_mode`, no `ep_role` tags, no NIXL ports — mode 3 is **rejected** with P/D.
- No `LLB_KV_NONE_HASH_SEED` / `PYTHONHASHSEED` parity leg — SGLang block 0 has no parent hash.
- No admission gate / 429 / park logic — a Tier-1.5 miss falls to the rule's **own selector**.
- `kvWarmupSec` is accepted but **currently inert in production** (both engines).

---

## 2. REST rule fields (SGLang mode)

Endpoint: `POST http://<loxilb>:11111/netlox/v1/config/loadbalancer`. Schema:
the `kv*` fields under `serviceArguments` in `api/swagger.yml`; validation:
`pkg/loxinet/rules.go`.

There is **no loxicmd flag for any `kv*` field** — the SGLang surface is REST-only, exactly
like the vLLM `kv*` family ([11 §2](11-hierarchical-kv-routing-config-tuning.md)). All
`kv*` fields are **camelCase**; a wrong-cased field is silently dropped by the API.

### 2.1 Service-level (`serviceArguments`)

| Field | Type | Default | Values | Meaning for an SGLang rule |
|---|---|---|---|---|
| `mode` | int | 0 | must be **4** | fullproxy — **required** for `kvExactMode:3` (validated, §3) |
| `sel` | int | 0 (rr) | 0–10 | the **miss-path selector**: on a Tier-1.5 miss the rule's own selector routes (no P/D Tier-2). For cache-friendly misses pair with `sel:8` (prefix-hash CHWBL, doc 10 §6) |
| `kvExactMode` | int | 0 | 0–3 | endpoint-**topology** selector only, orthogonal to `kvEngineType`: 0 off, **1 = zmq over a role-partitioned P/D pool (any engine)**, 2 NATS (reserved), **3 = zmq over a role-less pool (any engine)** (`KV_EXACT_MODE_SINGLE_ROLE` in `sockproxy.h`) |
| `kvEngineType` | string | `"vllm"` | `"vllm"`\|`"sglang"` | KV-event engine behind this rule. **Immutable after create** (§3); drives the hash-algo default; one framework per VIP:port |
| `kvDpRankCount` | int | 1 | 1–8 (0 ⇒ 1) | SGLang data-parallel rank count. Rank N subscribes at `kvZmqPort+N`; all ranks union into **one** per-EP inventory. Must equal SGLang `--dp-size` |
| `kvBlockSize` | int | 16 | ≥1 | **Must equal SGLang `--page-size`** — which is *model-dependent*; read it back from `/get_server_info` (§5.2). A mismatch is **silent** (the watchdog is the tripwire) |
| `kvZmqPort` | int | 5557 | 1–65535 | SGLang KV-events PUB base port (rank 0). 5557 is the canonical contract port; co-resident fleets shift it (§5.3) |
| `kvHashAlgo` | string | engine-derived | **omit** (recommended) \| `"sha256_sglang"` | `"sha256_sglang"` is in the swagger enum and accepted by `kvHashAlgoValidate`; omitting takes the engine default (the engine→algo mapping in `DpLBRuleMod` maps `sglang`+unset ⇒ `kv_hash_algo=2`, `KV_HASH_SHA256_SGLANG`). A contradictory algo (`sha256_cbor`/`xxhash_cbor` on an sglang rule) is **rejected at config time** (§3) |
| `kvWarmupSec` | int | 30 | ≥0 | accepted, **currently a no-op** in production (GUARD_B has no production writer — [15 §3.3](15-sglang-kv-cache-aware-routing.md)) |
| `host` | string | — | — | host key (the reference configs set it to the VIP) |
| `probeRetries` | int | 0 | — | health-probe retries (probe state does not feed exclusion — doc 10 §5) |

### 2.2 Endpoint-level (`endpoints[]`)

| Field | Type | Meaning |
|---|---|---|
| `endpointIP` | string | SGLang backend IP |
| `targetPort` | int | SGLang OpenAI port (conventionally 30000) |
| `weight` | int | endpoint weight |
| `ep_role` | — | **do not set** — single-role EPs are role-less; mode 3 admits all EPs into the Tier-1.5 candidate mask |
| `nixl_port` | — | **do not set** — no P/D KV handoff on this path |

### 2.3 Worked example — single-role SGLang service

An example deployment shape:
VIP `10.0.0.12:9010` in front of three SGLang EPs at `:30000`, KV events at `:5561`
(co-resident port shift), page size read back from the server (here: 64).

```bash
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' -d @- <<'JSON'
{
  "serviceArguments": {
    "externalIP": "10.0.0.12", "port": 9010, "protocol": "tcp",
    "sel": 0, "mode": 4, "security": 0, "host": "10.0.0.12",
    "probeRetries": 1,
    "kvExactMode": 3,
    "kvEngineType": "sglang",
    "kvBlockSize": 64,
    "kvZmqPort": 5561,
    "kvDpRankCount": 1,
    "kvWarmupSec": 30
  },
  "endpoints": [
    {"endpointIP": "10.0.0.7", "targetPort": 30000, "weight": 1},
    {"endpointIP": "10.0.0.8", "targetPort": 30000, "weight": 1},
    {"endpointIP": "10.0.0.9", "targetPort": 30000, "weight": 1}
  ]
}
JSON
```

Notes: no `pd_disagg_mode`, no `ep_role`, `kvHashAlgo` omitted (the recommended spelling —
an explicit `"sha256_sglang"` is also accepted). `kvBlockSize: 64` is **illustrative** —
always substitute the value your own `/get_server_info` reports. Delete with:

```bash
curl -s -X DELETE \
  http://127.0.0.1:11111/netlox/v1/config/loadbalancer/externalipaddress/10.0.0.12/port/9010/protocol/tcp
```

### 2.4 Worked example — two-VIP coexistence (one gateway, both engines)

The reference shape from `cicd/sglang-loxilb-kvcache/config.sh`: **one** LoxiLB process,
**one** VIP IP, two rules keyed by port — an unmodified vLLM P/D rule beside an SGLang
single-role rule. Same-IP/different-engine is **accepted** (that IS the coexistence story)
and logs one engine-mix WARN.

```jsonc
// Rule 1 — VIP-A 10.10.10.254:8080 — the unmodified vLLM P/D shape (doc 08/11, unchanged)
{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 8080, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "10.10.10.254", "probeRetries": 1,
    "pd_disagg_mode": true,
    "kvExactMode": 1, "kvZmqPort": 5557,
    "kvHashAlgo": "sha256_cbor", "kvWarmupSec": 20, "kvBlockSize": 16
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1, "ep_role": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 80, "weight": 1, "ep_role": 2 },
    { "endpointIP": "33.33.33.1", "targetPort": 80, "weight": 1, "ep_role": 1 },
    { "endpointIP": "34.34.34.1", "targetPort": 80, "weight": 1, "ep_role": 2 }
  ]
}

// Rule 2 — VIP-B 10.10.10.254:9090 — the SGLang single-role shape (this doc)
{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 9090, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "10.10.10.254", "probeRetries": 1,
    "kvExactMode": 3, "kvEngineType": "sglang",
    "kvDpRankCount": 3, "kvZmqPort": 5561,
    "kvWarmupSec": 20, "kvBlockSize": 16
    // kvHashAlgo DELIBERATELY OMITTED — engine default => sha256_sglang
  },
  "endpoints": [
    { "endpointIP": "35.35.35.1", "targetPort": 80, "weight": 1 },
    { "endpointIP": "36.36.36.1", "targetPort": 80, "weight": 1 },
    { "endpointIP": "37.37.37.1", "targetPort": 80, "weight": 1 }
  ]
}
```

Port planning here: vLLM publishes at `:5557`; the SGLang rule's 3 DP ranks subscribe at
`:5561/:5562/:5563` per EP. Cross-VIP inventory isolation is enforced by the `kv_svc_id`
threading ([15 §6](15-sglang-kv-cache-aware-routing.md)) — no operator knob needed.

---

## 3. Config-time validation guards

Every rejection below happens at rule POST time (the `kvExactMode`/`kvEngineConfigValidate`/
`kvHashAlgoValidate` block in `AddLbRule`, plus `kvEngineImmutabilityCheck` at the
rule-exists branch — all in `pkg/loxinet/rules.go`) — before the eRule lookup, so create
**and** update are both covered. What the operator sees
is the exact error string.

| Rejected config | Exact error returned | Why it exists |
|---|---|---|
| `kvExactMode:3` + `pd_disagg_mode:true` | `kv-exact single-role mode is incompatible with pd-disagg (use kvExactMode=1 for P/D)` | mode 3 and the P/D ladder are separate entries into Tier 1.5; combining them would double-run selection. SGLang P/D (bootstrap+gRPC) is out of scope entirely |
| `kvExactMode:3` without `mode:4` | `kv-exact single-role mode requires mode=fullproxy` | Tier 1.5 lives in the sockproxy — only fullproxy rules reach it. Mode 3 must not be creatable in a topology where the seam structurally cannot run |
| `kvExactMode:1` without `pd_disagg_mode:true` | `kv-exact zmq mode requires pd_disagg_mode=true (use kvExactMode=3 for a single pool)` | the mode-3 guards' sibling. Tier 1.5 for mode 1 is reachable only from `pd_select_prefill()`, which the C selector calls only inside its `pd_disagg_enabled` branch — so on a single pool mode 1 populated inventories and held a subscriber goroutine per prefill EP while never influencing selection. Use `kvExactMode:3` for a role-less pool |
| `kvHashAlgo` contradicting `kvEngineType` | `kv-hash-algo "<algo>" is incompatible with kv-engine-type "<engine>" (omit kvHashAlgo to take the engine default "<default>")` | the C hasher picks its contract from `kv_hash_algo` alone, so an `sglang` rule pinned to `"sha256_cbor"` (or a `vllm` rule pinned to `"sha256_sglang"`) missed **every** published block, with no signal until the `[KV_ZEROHIT]` watchdog fired. Omitting `kvHashAlgo` always passes and is the recommended shape |
| `kvHashAlgo` outside {`""`,`"sha256_cbor"`,`"xxhash_cbor"`,`"sha256_sglang"`} | `kv-hash-algo must be one of "sha256_cbor", "xxhash_cbor", "sha256_sglang"` | allowlist, mirroring the engine allowlist below |
| `kvEngineType` outside {`""`,`"vllm"`,`"sglang"`} | `kv-engine-type must be one of "vllm", "sglang"` | allowlist — an unknown engine is rejected, never silently treated as vllm |
| `kvDpRankCount` > 8 | `kv-dp-rank-count must be within 1..8 (0 = default 1)` | rank N subscribes at `kvZmqPort+N` on every EP host — the cap bounds the port-range walk. 0 is accepted and defaults to 1 downstream |
| `kvEngineType` changed on a live rule (PUT/re-POST) | `lbrule-exist error: cant modify rule kv engine type (delete and recreate)` | immutability: a live engine flip would silently re-key the whole Tier-1.5 hash space. `""`≡`"vllm"` is honored (setting `"vllm"` on a default-engine rule is not a change). The check sits before the change-detect short-circuit, so an engine-only update gets this exact message — never a silent delete+re-add |
| Two rules on one VIP IP with different engines | **ACCEPTED** + one WARN naming both engines | that IS the multi-framework coexistence story (§2.4); the WARN keeps it observable |

The sanctioned way to change an engine: `DELETE` the rule, then `POST` the new one —
rule teardown already stops all `(ep, rank)` subscribers and drops the service inventory
(`KvSubscriberStopAll`).

---

## 4. LoxiLB environment variables (SGLang-relevant)

Set with `docker run -e …`; read once at startup. Full engine-agnostic table:
[11 §3](11-hierarchical-kv-routing-config-tuning.md).

| Var | Default | Accepted | Effect on an SGLang deployment |
|---|---|---|---|
| `LOXILB_KV_ZERO_HIT_N` | **50** | positive int | zero-hit watchdog threshold: N consecutive KV-exact lookups scoring zero hits against a **non-empty eligible inventory** ⇒ one `[KV_ZEROHIT]` WARN (per transition edge) + `loxilb_pd_kv_zero_hit_watchdog_total{service_id}` increments on every occurrence at/past N. Invalid/zero/negative ⇒ default 50 + one-shot WARN — the watchdog is **never disabled**. Lower it (e.g. 5) only on test rigs where you want a deliberate-mismatch leg to fire fast (the CICD scenario does exactly that) |
| `LOXILB_KV_MAX_BLOCKS` | 1,000,000 | int 1000–100,000,000 | per-EP inventory cap (FIFO eviction). Shared across engines; DP ranks union into one per-EP inventory, so a high-rank EP fills it faster — watch `loxilb_kv_inv_cap_evictions_total` (sizing guidance: [11 §6.5](11-hierarchical-kv-routing-config-tuning.md)) |
| `LOXILB_KV_LB_MODE` + ε/λ family (`LOXILB_KV_MEAN_LOAD_FACTOR`, `LOXILB_KV_LOAD_PENALTY`, `LOXILB_KV_SPILL_RELIEF`, `LOXILB_KV_CAP_SUM_MILLI`) | see doc 11 | see doc 11 | the Tier-1.5 blend law applies unchanged to the single-role path (it calls the same `llb_ai_kv_best_worker`). ⚠ **Process-global across ALL KV VIPs, vLLM and SGLang alike** — accepted limitation; per-rule override is deferred |
| `LOXILB_KV_TLOAD_LOG` | off | `1` | per-selection `[KV_INV] totalLoad=` diagnostics — works identically for mode-3 selections |
| `LLB_KV_HASH_DEBUG` | off | `1` | `[KV_HASH]` per-block forensics; the SGLang path has a dedicated emit reporting the FIRST-8 published value (testbed only) |
| `LLB_KV_NONE_HASH_SEED` | unset | — | **inert for SGLang rules** — the SGLang contract has no NONE_HASH/parent seed (block 0 hashes bare tokens). Keep it set for any co-resident vLLM rule; it does not affect algo-2 hashing |

Fixed internals worth knowing (constants, not env): subscriber reconnect backoff **5 s**
(`kvReconnectFailBackoff`), seq-gap forward tolerance **64** (`kvSeqResumeWindow`) — a gap
within the window KEEPs the warm inventory, a larger jump CLEARs it (§8).

---

## 5. SGLang server-side configuration

Keep the server-side launch a scripted, repeatable recipe — never improvise it at a
console.
Image pin: **`lmsysorg/sglang:v0.5.9`** — the nearest release to the hash-contract-pinned
sglang commit `d8ef76682e`. Do not update the image mid-deployment without re-checking the
hash contract (a drift shows up as a zero-hit watchdog fire, not a crash).

### 5.1 Enabling KV events

```bash
docker run -d --name sglang --gpus all --network host --ipc=host --shm-size 16g \
  -e PYTHONHASHSEED=0 \
  -v /root/.cache/huggingface:/root/.cache/huggingface \
  lmsysorg/sglang:v0.5.9 \
  python3 -m sglang.launch_server \
    --model-path Qwen/Qwen2.5-7B-Instruct --host 0.0.0.0 --port 30000 \
    --mem-fraction-static 0.35 \
    --kv-events-config '{"publisher":"zmq","endpoint":"tcp://*:5561"}'
```

- `--kv-events-config` is the whole feed: `publisher":"zmq"` + a `tcp://*:<port>` bind.
  Use `*` (bind mode) — a concrete local IP in connect-mode publishes nothing, silently.
- The port in the endpoint **must equal the rule's `kvZmqPort`** (rank 0).
- Gate readiness on **both** surfaces: `/health` (process up) then `/health_generate`
  (a real generation completes — model loaded, KV cache allocated).
- Self-confirm the publisher actually bound: `ss -tln | grep :5561` on the EP must show a
  listener. **This failure is otherwise silent** — make the listener check a hard
  precondition in your launch tooling.
- `PYTHONHASHSEED=0` is harmless but not load-bearing here (no NONE_HASH on the SGLang path).

### 5.2 `--page-size` parity (the deadliest knob)

`kvBlockSize` on the rule **must equal SGLang's effective page size** — and SGLang's
`--page-size` default is **model-dependent; never assume 16**. Always read it back:

```bash
curl -s http://<ep>:30000/get_server_info | grep -o '"page_size"[: ]*[0-9]*'
```

and set the rule's `kvBlockSize` to exactly that number. All EPs behind one rule must
report the **same** page size (homogeneous EPs required). A mismatch does not error
anywhere — Tier 1.5 simply never scores a hit and all traffic quietly takes the fallback
selector; watchdog (§8) is the runtime tripwire for exactly this.

### 5.3 DP attention ranks and port planning

With `--dp-size N`, SGLang publishes KV events **per DP rank**, each rank on its own
consecutive port with its own seq counter:

```
rank 0 → kvZmqPort      rank 1 → kvZmqPort+1   …   rank N−1 → kvZmqPort+N−1
```

- Set the rule's `kvDpRankCount` **equal to** `--dp-size` (bounds 1..8). LoxiLB starts one
  subscriber goroutine per `(ep, rank)`; all ranks union into one per-EP inventory.
- **Do not undercount:** ZMQ connect does not fail on a missing endpoint, so a
  too-small rank count silently drops the higher ranks' warmth (this is why auto-probing
  was rejected). Do not overcount either: extra subscribers spin on reconnect.
- **The `:5557` collision (co-resident hosts):** 5557 is the canonical KV-events contract
  port, but on a host where a vLLM KV-events publisher already runs (`--network host`),
  it is taken. Verify the chosen port — and the whole rank range `[kvZmqPort,
  kvZmqPort+N)` — is free with `ss -tln` before launch, and hard-fail if it is bound;
  a common co-residency choice is base port `5561`
  (leaving room for ranks at 5562/5563…). LoxiLB subscribes per-rule `kvZmqPort`, so any
  free port works — just keep the rule and the server config equal, and **never kill the
  vLLM publisher to free the port**.

### 5.4 Co-residency memory split (the 0.55/0.35 lesson)

An **example deployment** runs SGLang **beside** vLLM prefills on 24 GB L4-class GPUs.
The split validated there: vLLM `--gpu-memory-utilization 0.55` + SGLang
`--mem-fraction-static 0.35` (the remainder is headroom). Two coupled cautions when you
shrink a co-resident vLLM:

1. **Uniform block-count pin.** Reducing vLLM's split changes its `num_gpu_blocks`; a
   NIXL P/D mesh must agree on block count (heterogeneous counts trip the
   `num_external_tokens` assert). Probe one EP at the reduced split to learn the new
   block count, then pin the probed value **fleet-wide** via
   `--num-gpu-blocks-override`.
2. **If two weight copies don't fit,** fall back to a smaller SGLang model — and switch
   the gateway's staged tokenizer to match, or KV-exact hashing silently never matches
   (the watchdog will tell you).

Tokenizer staging is engine-agnostic and unchanged from doc 08 §6: the served model's HF
`tokenizer.json` at `/etc/loxilb/tokenizers/<model-slug>/tokenizer.json` (slug = model id
with `/` → `__`).

---

## 6. Per-layer enablement matrix

What turns each piece on, and the fastest check that it engaged
(metrics on `GET http://<loxilb>:11111/netlox/v1/metrics` unless noted):

| Layer | Enable | Verify |
|---|---|---|
| Single-role Tier 1.5 | rule: `mode:4` + `kvExactMode:3` + `kvEngineType:"sglang"` | `loxilb_pd_kv_tier15_hits_total{ep_idx}` advances on a shared-prefix burst; `[KV_SR] … single-role Tier-1.5 HIT -> EP<n>` in the C log |
| Tokenizer staging (Tier-1.5 prerequisite) | served model's HF `tokenizer.json` at `/etc/loxilb/tokenizers/<model-slug>/tokenizer.json` (slug = model id with `/` → `__`; [08 §6.3](08-kv-cache-aware-routing.md)) | no warn-once `kv-router: tokenizer not available` in the log; Guard E `tokenize` absent from `loxilb_pd_kv_tier15_miss_reason_total`. A missing tokenizer is **silent** — Tier 1.5 is quietly off |
| Hash contract | omit `kvHashAlgo` on an sglang rule | `[KV_CONFIG]` line shows the rule landing with `kv_engine_type=1`; `[KV_HASH] … algo=sha256_sglang` with `LLB_KV_HASH_DEBUG=1` |
| Event feed | SGLang `--kv-events-config` + rule `kvZmqPort` | `loxilb_kv_subscriber_connected{service,ep}` = 1 per EP; `loxilb_pd_kv_blocks{service,ep_idx}` > 0 after traffic |
| Multi-rank fan-out | `kvDpRankCount` = `--dp-size` | inventory (REST `GET /netlox/v1/config/ai/kv/inventory?service_id=<id>&ep_idx=<n>`) grows past any single rank's contribution; `kv-subscriber: ep N rank R …` lines for every rank |
| Zero-hit watchdog | always on (threshold `LOXILB_KV_ZERO_HIT_N`) | healthy: `loxilb_pd_kv_zero_hit_watchdog_total{service_id}` stays **0** |
| Blend law on misses | `LOXILB_KV_LB_MODE` (shared, doc 11 §6.1) | `loxilb_pd_kv_tier15_spills_total` under hot-prefix load |
| Cross-VIP isolation | automatic (`kv_svc_id`) | during single-VIP traffic, the *other* VIP's tier15/inventory deltas stay 0 (the CICD L3/L4 legs assert this) |

---

## 7. The SGLang parity triad + tuning playbook

### 7.1 The parity triad (must match or Tier 1.5 silently degrades to the fallback selector)

The SGLang triad is **different** from vLLM's ([11 §3.3](11-hierarchical-kv-routing-config-tuning.md)) —
no seed leg, a page-size leg instead of block-size-16, and the algo leg is an *omission*:

| SGLang setting | Must match |
|---|---|
| effective page size (from `/get_server_info`, model-dependent) | rule `kvBlockSize` — **exactly** |
| hash contract (pinned sglang `d8ef76682e`; image `lmsysorg/sglang:v0.5.9`) | rule `kvHashAlgo` **omitted** + `kvEngineType:"sglang"` (⇒ `sha256_sglang`) |
| served model's tokenizer | staged at `/etc/loxilb/tokenizers/<slug>/tokenizer.json` on the LoxiLB host |

There is **no** `PYTHONHASHSEED`/`LLB_KV_NONE_HASH_SEED` leg. There is one extra structural
leg the triad implies: `kvDpRankCount` = `--dp-size` and `kvZmqPort` = the publisher port
(a broken feed leg shows as empty inventory rather than zero hits — §9 tells them apart).

### 7.2 Page-size choice

Prefer the model's default page size and set `kvBlockSize` to the read-back value. If you
override `--page-size` for engine-side reasons, larger pages mean fewer, coarser hash
blocks — cheaper hashing and smaller inventories, but a shared prefix must be at least one
full page long to score any overlap. Whatever you choose, **change both sides together**
and re-read `/get_server_info` after any server relaunch.

### 7.3 Rank count

`kvDpRankCount` is not a tuning knob — it is a topology fact (= `--dp-size`), bounded 1..8.
Operationally relevant: `AllBlocksCleared` from **any** rank clears the **whole** shared EP
inventory (union semantics, over-clear by design) — expect brief warmth loss on DP fleets
after a single-rank restart; it re-grows in seconds under traffic.

### 7.4 Watchdog threshold (`LOXILB_KV_ZERO_HIT_N`)

- **50 (default)** is the production setting: late enough to ride out a cold start /
  post-clear rebuild, early enough to void a bad measurement window fast.
- Lower (5–10) on test rigs and CICD where you *want* a deliberate mismatch to fire within
  a handful of lookups (the coexistence scenario injects `LOXILB_KV_ZERO_HIT_N=5`).
- Raising it above 50 mainly delays detection; the streak only counts lookups against a
  **non-empty eligible inventory**, so quiet services don't creep toward the threshold.
- A single Tier-1.5 hit resets the streak and re-arms the WARN.

### 7.5 Coexistence memory split

Start from the validated 0.55 (vLLM) / 0.35 (SGLang) split on 24 GB-class GPUs (§5.4).
Shrink the SGLang fraction first if the vLLM side is the production-critical tenant; if
SGLang `/health` never comes up at your split, the model does not fit — use the fallback
model path, don't shave the fraction below what the KV cache needs (that silently guts the
radix cache and with it any routing win).

### 7.6 Miss-path selector and shared knobs

On a Tier-1.5 miss the rule's **own selector** routes. `sel:0` (RR) is a fine baseline;
`sel:8` (prefix-hash CHWBL) keeps even the miss path cache-friendly. The blend-law and
inventory-cap tuning is identical to vLLM — follow [11 §6.1/§6.5](11-hierarchical-kv-routing-config-tuning.md),
remembering those env knobs are shared by every KV VIP on the process.

### 7.7 Spill relief + saturation ε (live-validated 2026-07-14)

The numbers in this subsection were measured on a **single internal validation fleet**
(24 GB L4-class GPUs, co-resident SGLang + vLLM) — they are indicative for similar
capacity-bound shapes, not a general benchmark.

Two findings from the post-fix competitive campaign change the single-role tuning defaults:

1. **Fleet spill relief is the single-role default** (commit `7ac66196`).
   `LOXILB_KV_SPILL_RELIEF` is tri-state: unset ⇒ relief ON for `kvExactMode:3` services and
   OFF for P/D (unchanged behavior there); explicit `1`/`0` forces globally. Do NOT turn it
   off for SGLang fleets: a hot single-cached prefix produces a *singleton* candidate set that
   can never spill on its own cap at any ε — relief is the only unpin mechanism (pre-relief:
   1041/13/0 routing decisions across 3 EPs and goodput 0.21 at rate 2.0; with relief + the
   load-signal fix: hits spread 3-ways, goodput 0.78–0.95 depending on ε).

2. **At saturation, tighten ε — do not raise it.** The adaptive law raises ε with load
   (175→300), which is calibrated for cache-heavy vLLM P/D substrates where affinity at load
   is worth defending. On a **capacity-bound** substrate (small model, cheap prefill — the
   SGLang co-residency shape), the optimum is the opposite. Live screen at rate 2.0
   (goodput@10s-SLO, N=7/knob, then N=21 for the winner):

   | Config | goodput | CV |
   |---|---|---|
   | `adaptive` (ε→300 at load) | 0.776 | 0.209 |
   | `hard` ε=175 + relief | 0.864 | 0.153 |
   | `hard` ε=120 + relief | 0.950 | 0.027 |
   | **`hard` ε=100 + relief** | **0.955 → 0.929 @ N=21** | **0.019 / 0.036** |

   At ε=100 (cap = fleet mean load) loxilb **beat `sgl-model-gateway cache_aware`
   head-to-head** (0.929 vs 0.912, CI [+0.000, +0.035]) and sat within 0.04 of the RR
   balance ceiling — while keeping exact affinity active for the loads where it wins.

   **Recommendation:** for known saturation-heavy, capacity-bound SGLang fleets set
   `LOXILB_KV_LB_MODE=hard` + `LOXILB_KV_MEAN_LOAD_FACTOR=100..120`. Keep `adaptive` for
   mixed/cache-heavy workloads at rates ≤1.0 (it is parity-grade there: 0.977/0.947 vs
   cache_aware 0.983/0.975 at rates 0.5/1.0). A load-direction-aware single-role ε law is
   the recorded follow-up. Remember these env knobs are process-global (§4).

---

## 8. Observability quick reference

Metrics: `GET http://<loxilb>:11111/netlox/v1/metrics`.
Inventory snapshot: `GET /netlox/v1/config/ai/kv/inventory?service_id=<rule#>&ep_idx=<n>`.

**SGLang-relevant metric set:**

| Metric | Labels | Meaning |
|---|---|---|
| `loxilb_pd_kv_zero_hit_watchdog_total` | `service_id` | **the** silent-parity-failure signal. `service_id` = the rule number, so two-VIP setups attribute per arm. Nonzero delta during a measurement window ⇒ the window is void |
| `loxilb_pd_kv_tier15_hits_total` | `ep_idx` | Tier-1.5 hits — increments for single-role hits too. `ep_idx` is per-rule-opaque and carries **no service label**: for cross-VIP attribution, steer test traffic to numerically disjoint indexes per VIP (the CICD pattern) |
| `loxilb_pd_kv_tier15_miss_reason_total` / `loxilb_pd_kv_tier15_fallthrough_total` | `reason` / — | guard-ladder misses. On a mode-3 rule a fallthrough lands in the rule's own selector |
| `loxilb_kv_subscriber_connected` / `…_reconnect_total` / `…_recv_error_total` | `service`,`ep` | subscriber health. **All DP ranks of an EP share one label pair** — the gauge is over-conservative during a single-rank rebuild |
| `loxilb_pd_kv_blocks` | `service`,`ep_idx` | the shared per-EP union inventory size |
| `loxilb_kv_inv_cap_evictions_total` | `service`,`ep` | `LOXILB_KV_MAX_BLOCKS` cap pressure (union of all ranks) |

**Log markers (grep keys):**

| Marker | Meaning |
|---|---|
| `[KV_SR] fd=… single-role Tier-1.5 HIT -> EP<n>` | mode-3 routing decision (miss = no line; the rule's selector routes) |
| `[KV_ZEROHIT] service <id>: N consecutive KV-exact lookups scored ZERO hits against a non-empty inventory …` | WARN — one per transition edge; probable cause named in the line (page-size/algo drift) |
| `kv-subscriber: ep N rank R seq gap A -> B (missing G, no replay) decision=KEEP\|CLEAR` | mid-stream gap decision: `KEEP` = small hop within the 64-seq resume window (warm inventory retained), `CLEAR` = large jump (publisher likely restarted; stale inventory dropped) |
| `kv-subscriber: ep N rank R … resync KEEP\|CLEAR` | the post-reconnect resync decision, rank-keyed |
| `kv-subscriber: AllBlocksCleared received for ep N (rank R) — clearing shared inventory` | union over-clear (any rank clears the whole EP) |
| `[KV_CONFIG] … kv_engine_type= kv_dp_rank_count= kv_svc_id=` | the rule's KV parameters as the data plane parsed them — the first thing to check after a POST |
| `[KV_T15]` | the guard ladder A–G (doc 08 §7.2), identical on the single-role path |

⚠ **Go markers need stderr capture.** The `kv-subscriber:` and `[KV_ZEROHIT]` lines are
logrus **stderr** output; a stock `docker exec -dt` launch discards them. Relaunch with
`… loxilb >>/var/log/loxilb-go.log 2>&1` (the CICD scenario's pattern) before asserting on
any of them. C-plane markers (`[KV_SR]`, `[KV_T15]`, `[KV_CONFIG]`) go to the container's
stdout log as usual.

**The silent-degradation patterns to alert on:**

1. **Zero hits, non-empty inventory** — `zero_hit_watchdog_total` climbing (or
   `[KV_ZEROHIT]` in the log) with `blocks_total` > 0 ⇒ parity broken:
   `kvBlockSize` ≠ page-size, algo drift (explicit `kvHashAlgo` on an sglang rule), or
   wrong tokenizer. This is the SGLang-path equivalent of vLLM's "silent RR".
2. **Empty inventory, subscriber connected** — `blocks_total` = 0 with
   `kv_subscriber_connected` = 1 ⇒ the server isn't publishing (missing
   `--kv-events-config`, connect-mode endpoint, or wrong port — ZMQ SUB "connects"
   happily to nothing).
3. **Partial warmth (one rank silent)** — inventory grows but plateaus below expectation
   and one rank never logs; `kvDpRankCount` too small or a rank port collision. Compare
   per-rank `kv-subscriber: ep N rank R` lines against `--dp-size`.
4. **Repeated `decision=CLEAR`** without EP restarts — the publisher side is flapping or
   two processes fight over one port; warmth never accumulates.

---

## 9. Troubleshooting playbook

| Symptom | Likely cause | Check | Fix |
|---|---|---|---|
| Zero Tier-1.5 hits; traffic works but `tier15_hits_total` flat and `zero_hit_watchdog_total` climbing | **`kvBlockSize` ≠ SGLang `--page-size`** (the deadliest, fully silent misconfig) — or an explicit `kvHashAlgo` on the sglang rule | `curl <ep>:30000/get_server_info \| grep page_size` vs the rule; `[KV_CONFIG]` line for the algo that actually landed | recreate the rule with `kvBlockSize` = the read-back page size and `kvHashAlgo` omitted |
| Inventory empty (`blocks_total` = 0) on all EPs; subscriber connected | wrong `kvZmqPort` (ZMQ connect never fails), server launched without `--kv-events-config`, or connect-mode endpoint (`tcp://127.0.0.1:…`) | `ss -tln \| grep <port>` on the EP (must show a listener); the server's launch flags; `kv-subscriber:` lines | fix the server flag to `tcp://*:<port>` and/or set the rule `kvZmqPort` to the bound port |
| Inventory empty AND no subscribers started | rule shape wrong for the gate: `kvExactMode` ≠ 3 on a role-less rule (mode 1 subscribes only `ep_role:1` EPs — a single-role rule gets none), or mode 0 | `[KV_CONFIG]` for the mode that landed; `loxilb_kv_subscriber_connected` series count | set `kvExactMode:3` (single-role) — or add proper `ep_role` tags if you meant a vLLM P/D rule |
| One DP rank silent — warmth lower than expected, one rank never appears in the log | rank port collision on the EP host (another service owns `kvZmqPort+k`), or `kvDpRankCount` < `--dp-size` | `ss -tln` on the EP for every port in `[kvZmqPort, kvZmqPort+N)`; count distinct `rank R` log lines | move the whole base port to a free range (e.g. base port 5561) and recreate the rule to match; set `kvDpRankCount` = `--dp-size` |
| Suspected cross-VIP contamination (two KV rules on one gateway) | (should be impossible — `kv_svc_id` scoping) | drive traffic to ONE VIP only; the other VIP's `tier15_hits` (its ep_idx set) and inventory deltas must stay 0 — the CICD L3/L4 legs are the reference procedure | if a delta appears, capture logs + rule numbers and file it — that is a product bug, not a config issue |
| Rule update rejected: `lbrule-exist error: cant modify rule kv engine type (delete and recreate)` | attempted in-place `kvEngineType` change (immutability) | — expected behavior | `DELETE` the rule, then `POST` the new engine's rule (teardown cleans subscribers + inventory) |
| Rule POST rejected with a `kv-exact single-role…` or `kv-engine-type…` error | one of the §3 guards | match the exact string against the §3 table | fix the named field (`mode:4`, drop `pd_disagg_mode`, engine spelling, rank ≤ 8) |
| EP restarted; inventory dropped to 0 | **working as designed**: a large seq gap or `AllBlocksCleared` clears stale inventory instead of routing on phantom hashes | `kv-subscriber: … decision=CLEAR` or `AllBlocksCleared received for ep N` marker; inventory re-grows under fresh traffic | none — expect a brief warmth loss; alert only if it does NOT re-grow (then check the feed, row 2) |
| `[KV_ZEROHIT]` mid measurement window | parity drifted mid-run (server relaunch changed page size / model / image) | re-read `/get_server_info` on every EP; compare against the rule | fix parity, then **re-run the window** — a watchdog-fired window is void (treat this as a hard gate on any measurement window) |
| Go-side markers absent entirely (`kv-subscriber:` never appears) | stderr discarded by the container launch | `docker logs` shows only C/entrypoint output | relaunch loxilb with `>>/var/log/loxilb-go.log 2>&1` (§8) |

When results look wrong, check the harness/client first, then the §8 metrics, then the
code — the fleet's most common "routing bug" has been a broken parity leg.

---

## 10. CICD self-validation — `cicd/sglang-loxilb-kvcache/`

The two-VIP coexistence scenario is the reference configuration **and** the executable
proof. It needs a Linux host (Docker + `ip netns`; macOS only gets `bash -n`/shellcheck):

```bash
# on a Linux testbed:
cd cicd/sglang-loxilb-kvcache && sudo ./config.sh && sudo ./validation.sh ; ./rmconfig.sh
```

`config.sh` stands up the §2.4 topology (one gateway, VIP-A vLLM P/D mock `:8080` +
VIP-B SGLang single-role `:9090`, mock publishers speaking both hash contracts, tokenizer
staged, Go-log capture, `LOXILB_KV_ZERO_HIT_N=5`). `validation.sh` then proves, leg by leg
(L0 is a pre-check; L1–L7 are the seven scenario legs; sentinel on success:
`SCENARIO-sglang-loxilb-kvcache [OK]`):

| Leg | Proves |
|---|---|
| L0 publisher fidelity | both hash cores (vLLM cbor + SGLang) reproduce their golden parity vectors before any leg runs |
| L1 multi-rank union | a 3-rank publish to a virgin EP converges to the exact 3-rank union (> any single rank) in the shared inventory |
| L2 Tier-1.5 hit, both VIPs | steered hits land on disjoint `ep_idx` targets per VIP (dual proof: banner + counter delta) |
| L3 isolation both ways | VIP-A tier15/inventory deltas stay 0 while VIP-B takes traffic **and** rule churn (delete/re-add), and vice versa |
| L4 same-model negative control | same-model content planted as SGLang hashes must NOT cross-match — engineered to FAIL without the `kv_svc_id` filter (the gate runs a revert-mutation once to prove the teeth) |
| L5 engine immutability | re-POST of the SGLang rule with `kvEngineType:"vllm"` is rejected with the exact message |
| L6 EP-restart-clears + seq gap | publisher kill/high-seq restart drives `decision=CLEAR`; a small hop drives `decision=KEEP` — both markers discriminated |
| L7 zero-hit watchdog | a throwaway rule with a deliberately wrong `kvBlockSize` (32 vs the publisher's 16) fires `[KV_ZEROHIT]` exactly once + a counter delta |

Run it after any change to the KV subscriber, the hash arms, or the rule-validation code.

---

## 11. Validation status (honesty note)

Every field name, default, bound, and error string above was verified against the
committed code. However, at the time of writing:

- the **binding remote gates** — a Linux-controller `make clean && make`, the
  `test_pd`/`test_kv` rosters, the scoped `go test ./pkg/loxinet/` suites, and the §10
  coexistence scenario itself — had **not yet run**;
- the **live SGLang fleet window** — real SGLang servers, the live smoke checks
  (inventory grows under traffic, a Tier-1.5 hit fires, an EP restart clears the
  inventory), and the **full** 3-arm competitive A/B — had **not yet opened**.

**The one measured exception is §7.7**: the spill-relief / saturation-ε screen was run
live on a single internal validation fleet (L4-class GPUs) — indicative for similar
capacity-bound shapes, not a general benchmark. Everything else remains unmeasured
design intent. Treat other behavioral claims as **code-verified, not fleet-verified**,
and check [15 §10](15-sglang-kv-cache-aware-routing.md) for the current gate status
before relying on this in production.

---

## 12. See also

- [08 — KV-cache-aware routing (Tier-1.5 internals)](08-kv-cache-aware-routing.md) — the
  vLLM hash contract, guard ladder, and per-model onboarding guide (§6) this path reuses.
- [10 — Hierarchical KV routing architecture](10-hierarchical-kv-routing-architecture.md) —
  the tier ladder and the single-pool selector family that serves as the mode-3 miss fallback.
- [11 — Hierarchical KV routing config & tuning](11-hierarchical-kv-routing-config-tuning.md)
  — the engine-agnostic knob reference (blend law, inventory caps, admission, controller);
  this doc is its SGLang companion exactly as 11 is 10's.
- [15 — SGLang KV-cache-aware routing (architecture)](15-sglang-kv-cache-aware-routing.md) —
  what every knob here actually drives: the mode-3 seam, the SGLang hash contract, the
  multi-rank subscriber, `kv_svc_id` isolation, and watchdog internals.
- [16 — SGLang vs vLLM KV-routing differences](16-sglang-vs-vllm-routing-differences.md) — the
  contract-by-contract comparison behind §7.1's triad.
