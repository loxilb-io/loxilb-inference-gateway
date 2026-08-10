# SGLang vs vLLM — KV Routing Integration Differences & Optimization Guide

> **Audience:** internal loxilb engineers and users who know the vLLM Tier-1.5 integration
> (docs [08](08-kv-cache-aware-routing.md)–[11](11-hierarchical-kv-routing-config-tuning.md))
> and need to understand *exactly what changes* with SGLang — and how to run SGLang serving
> behind loxilb well.
> **Scope:** a dimension-by-dimension comparison (topology, hash contract, event stream,
> DP ranks, router ecosystem, rule config) plus the SGLang optimization playbook. This doc
> **compares and guides**; the mechanism deep-dive lives in
> [15 — SGLang KV-cache-aware routing](15-sglang-kv-cache-aware-routing.md) — cross-referenced
> per section, never duplicated here.
> **Status:** describes the committed integration. **Not yet CICD-gate-verified** — see §9.

Related: [08 — KV-cache-aware routing (vLLM Tier-1.5 internals)](08-kv-cache-aware-routing.md),
[10 — Hierarchical KV routing architecture](10-hierarchical-kv-routing-architecture.md),
[11 — Configuration & tuning](11-hierarchical-kv-routing-config-tuning.md),
[15 — SGLang KV routing architecture](15-sglang-kv-cache-aware-routing.md),
[17 — SGLang configuration & tuning](17-sglang-config-tuning.md).

> ⚠ **Validation status (read this first).** Everything here is **code-verified, not
> gate-verified**: neither the binding remote gates nor the live fleet bring-up and the
> full 3-arm competitive A/B had run when this doc was written. The one exception is the
> spill-relief / saturation-ε screen in [17 §7.7](17-sglang-config-tuning.md) — measured
> on a single internal validation fleet. Details in §9.

---

## 1. Executive summary — one row per dimension

| Dimension | vLLM (docs 08–11) | SGLang (doc 15, this doc) |
|---|---|---|
| **Serving topology** | P/D disaggregation: `ep_role:1` prefill + `ep_role:2` decode, KV handoff over vLLM's own NIXL connector | **Single-role**: one flat worker pool, no roles, no handoff (SGLang's own P/D is bootstrap-server + gRPC — out of scope) |
| **loxilb entry point** | `kvExactMode: 1` inside the P/D tier ladder (`pd_select_prefill`) | `kvExactMode: 3` (`KV_EXACT_MODE_SINGLE_ROLE`) — the sibling branch on plain fullproxy rules ([15 §3](15-sglang-kv-cache-aware-routing.md)). Note `kvExactMode` selects the endpoint **topology** only; the engine is chosen by `kvEngineType` — this column shows the conventional pairing |
| **KV event transport** | ZMQ PUB, one socket per prefill EP, conventionally `:5557`; 3-frame msgpack envelope | **Byte-identical wire format**; one PUB **per DP rank** at `kvZmqPort + rank`; port is deployment-chosen (`:5561` on the co-resident fleet — §5) |
| **Hash algorithm** | SHA-256 or XXH3-128 over **canonical CBOR** `[parent, [tokens], null]` (`sha256_cbor` / `xxhash_cbor`) | **SHA-256 only**, over **raw bytes** `parent_digest(32) ‖ token₀_LE4 ‖ token₁_LE4 …` — no CBOR envelope (`KV_HASH_SHA256_SGLANG`, algo 2) |
| **uint64 truncation** | **last** 8 digest bytes, big-endian (`digest[-8:]` — an earlier `digest[:8]` mis-slice produced 0% overlap before this fix) | **first** 8 digest bytes, big-endian (`digest[:8]`) — the exact inverse |
| **Published sign** | unsigned msgpack ints (`VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=1` required) | **signed int64** (two's-complement wrap when digest byte 0 ≥ `0x80`); `extractBlockHashes` converts bit-exact |
| **First-block parent** | `NONE_HASH` derived from `PYTHONHASHSEED` (`LLB_KV_NONE_HASH_SEED` parity leg) | **No parent at all** — block 0 hashes bare tokens; no seed machinery exists on this path |
| **Parent chaining** | parent = previous block's **full digest** (32 or 16 B) | same idea: parent = previous block's **full 32-byte digest** (raw, not hex, not truncated) |
| **Block/page granularity knob** | vLLM `--block-size` (default 16) ↔ rule `kvBlockSize` | SGLang `--page-size` — **model-dependent default, never assume 16**; read back from `/get_server_info` ↔ rule `kvBlockSize` |
| **DP ranks** | n/a (one publisher per prefill EP) | `--dp-size N` ⇒ N publishers per EP; rule `kvDpRankCount` (1..8, 0 ⇒ 1) fans out N subscribers per EP, unioned into one inventory (§6) |
| **Router ecosystem competitor** | `vllm-router` (prefix-aware / kv-aware modes) | `sgl-model-gateway` (external project; v0.3.2 at the time of comparison — no in-repo pin) — `cache_aware` (approximate router-side radix tree) / `round_robin` (§7) |
| **loxilb rule config** (conventional pairings — `kvExactMode` is topology-only and orthogonal to `kvEngineType`) | `mode:4` + `pd_disagg_mode` + `ep_role` tags + `kvExactMode:1` + `kvHashAlgo:"sha256_cbor"` | `mode:4` fullproxy + `kvExactMode:3` + `kvEngineType:"sglang"` + `kvDpRankCount` + **`kvHashAlgo` omitted** (recommended; engine default — [15 §8.1](15-sglang-kv-cache-aware-routing.md)) |

Everything not listed is **shared**: the guard ladder A–G, the tokenizer pool and staging
path, the Go inventory plane (`map[uint64]struct{}` per EP, `LOXILB_KV_MAX_BLOCKS` cap),
the unified CHWBL / adaptive ε/λ blend of [doc 10 §4](10-hierarchical-kv-routing-architecture.md),
and the miss-reason / hit metrics of [doc 08 §7](08-kv-cache-aware-routing.md).

---

## 2. Topology: P/D ladder vs single-role pool

### 2.1 What each shape is

**vLLM** deployments that use Tier 1.5 are P/D-disaggregated ([doc 10 §2](10-hierarchical-kv-routing-architecture.md)):
prefill workers (`ep_role:1`, `kv_producer`) compute the prompt KV and hand it to decode
workers (`ep_role:2`, `kv_consumer`) over vLLM's NIXL connector. loxilb's KV-exact decision
picks the **prefill** EP; decode selection is a separate ladder stage. Only prefill EPs
publish KV events and hold scored inventories.

**SGLang** workers behind loxilb are **single-role**: every EP serves the whole request
(prefill + decode in one process, radix cache local to it). There are no `ep_role` tags, no
NIXL, no decode-selection stage. The integration opened `kvExactMode=3` precisely because
[doc 10 §2](10-hierarchical-kv-routing-architecture.md)'s load-bearing constraint — *Tier 1.5
is reachable only inside the P/D ladder* — would otherwise have left SGLang with nothing but
the approximate prefix-hash CHWBL family. How the three gates opened (C selection mode, Go
subscriber gate, single-role `active_conns` accounting) is [15 §3](15-sglang-kv-cache-aware-routing.md).

### 2.2 Which tiers apply in each shape

The [doc 10 §3](10-hierarchical-kv-routing-architecture.md) ladder is a **P/D structure**;
mode 3 deliberately does **not** clone it (design decision). Remember that `kvExactMode`
selects the endpoint topology only — mode 1 = zmq over a role-partitioned P/D pool (any
engine), mode 3 = zmq over a role-less pool (any engine); the columns below are the
conventional engine pairings:

| Ladder stage (doc 10) | vLLM P/D (`kvExactMode=1`) | SGLang single-role (`kvExactMode=3`) |
|---|---|---|
| Health/CB exclusion mask | ✅ seeds every tier | ✅ same mask built before the single-role branch |
| Controller fold-in | ✅ | ✅ (weights reach the blend as capacity scaling) |
| Admission gate (park / 429) | ✅ (opt-in) | ❌ P/D-only — no park, no 429 on this path |
| Tier 0 session stickiness | ✅ | ❌ (use the rule's own selector for stickiness) |
| Tier 1 radix-trie heuristic | ✅ (`pd_cache_aware_mode`) | ❌ |
| **Tier 1.5 KV-exact + blend** | ✅ | ✅ — the same `pd_kv_exact_select` → `llb_ai_kv_best_worker` leaves, over **all** healthy EPs |
| Tier 2 min-load fallback | ✅ | ❌ — a Tier-1.5 **miss falls to the rule's own configured selector** (CHWBL `sel:8`, RR, …) |
| Decode selection | ✅ | ❌ (nothing to select — one EP serves everything) |

Two operational consequences:

1. **A single-role Tier-1.5 miss is not "Tier-2 RR".** It lands in whatever `sel` the rule
   carries. For cache-friendly behavior on the miss path, pair mode 3 with `sel:8`
   (prefix-hash CHWBL, [doc 10 §6](10-hierarchical-kv-routing-architecture.md)) —
   [15 §11](15-sglang-kv-cache-aware-routing.md) item 10.
2. **The blend still needs live load.** The lesson (a load-blind blend resurrects the
   hot-prefix herd) is why mode 3 ships its own `active_conns` increment/single-owner-release
   lifecycle ([15 §3.3](15-sglang-kv-cache-aware-routing.md)) — the unified CHWBL cap,
   adaptive ε/λ, and controller weights all apply to SGLang exactly as to vLLM.

**Coexistence is per-VIP, never per-rule.** One gateway serves a vLLM P/D rule (`:9003`)
and an SGLang single-role rule (`:9010`) simultaneously; cross-VIP inventory isolation is
the `kv_svc_id` threading of [15 §6](15-sglang-kv-cache-aware-routing.md). A single rule
carries exactly one `kvEngineType` — mixing engines behind one rule is structurally
impossible (§8.5).

---

## 3. The hash contract, side by side (the centerpiece)

This is the part engineers get wrong. Both engines content-address KV blocks with a chained
hash, both publish only hashes — but **every step of the recipe differs**. Any confusion
between the two arms produces 0% overlap and a *silent* fallback (§4).

| Step | vLLM v0.17.0 (`sha256_cbor` / `xxhash_cbor`) — [08 §4](08-kv-cache-aware-routing.md) | SGLang @ `d8ef76682e` (`sha256_sglang`) — [15 §4](15-sglang-kv-cache-aware-routing.md) |
|---|---|---|
| 1. Block input | canonical CBOR (RFC 7049 §3.9) of `[parent_hash, [token_ids…], null]` | raw bytes: `parent_digest(32B, only if present) ‖ token₀ as 4-byte LE ‖ token₁ LE4 ‖ …` — **no envelope** |
| 2. Digest | SHA-256 (32 B) or XXH3-128 (16 B) | SHA-256 (32 B), always |
| 3. First block's parent | `NONE_HASH` — derived from `PYTHONHASHSEED` via `init_none_hash`; loxilb mirrors it with `LLB_KV_NONE_HASH_SEED` | **nothing** — block 0 hashes bare tokens; no seed, no zero-bytes placeholder |
| 4. Chaining | parent for block *i+1* = block *i*'s **full digest** | same — full 32-byte digest, raw |
| 5. uint64 truncation | `BE(digest[-8:])` — **last** 8 bytes (`memcpy(out, digest_full + len - 8, 8)`) | `int(hexdigest[:16], 16)` — **first** 8 bytes BE (`memcpy(out, digest_full, 8)`) |
| 6. Wire value | unsigned msgpack int (`VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=1` mandatory) | **signed int64**: `v − 2⁶⁴ if v ≥ 2⁶³ else v` — negative whenever digest byte 0 ≥ `0x80` |
| loxilb C implementation | CBOR encoder + algo 0/1 arms in `kv_compute_block_hashes` (`sockproxy_kv_exact.c`) | dedicated `kv_hash_sglang_block()` loop (algo 2) that early-returns **before** the `NONE_HASH` seed — the CBOR arms are textually untouched |

### 3.1 Worked example — real committed vector values

From the committed parity vectors (`chain3_bs16`, derived from the pinned sglang
checkout `d8ef76682e` via `cicd/vllm-kvcache-routing-cpu/sglang_hash_core.py`; asserted
bit-for-bit in `test_sglang_parity_vectors()` in `loxilb-ebpf/common/test_kv_exact.c` and
in `pkg/loxinet/ai_kv_subscriber_hash_vectors_test.go`).

Tokens `1..48`, page size 16 ⇒ 3 full blocks. The **SGLang** side computes:

```
block 0:  SHA256( 01000000 02000000 … 10000000 )                # 16 tokens, LE4 each, NO parent
          digest = 77d735ce838418aa 151bd96b5b1e78ee …          # full 32 bytes
          published int64 = 8635429971592222890                 # first 16 hex chars, positive
          loxilb stores uint64 0x77d735ce838418aa

block 1:  SHA256( <block-0 full 32-byte digest> ‖ 11000000 … 20000000 )
          digest = 1170426cf2449ceb f4d17f087ce5bb43 …
          published int64 = 1256577331724852459  → uint64 0x1170426cf2449ceb

block 2:  SHA256( <block-1 full digest> ‖ 21000000 … 30000000 )
          published int64 = 5689809685380680247  → uint64 0x4ef643c350b14a37
```

The **signed-wrap teeth** (`negative_int64_bs16`, single token `[0]`): the digest starts
`0xdf3f619804a92fdb…` — byte 0 ≥ `0x80`, so SGLang publishes **−2360060374177730597** on the
wire; Go's `extractBlockHashes` int64→uint64 cast must land on exactly
`0xdf3f619804a92fdb`, or Tier 1.5 silently never intersects. A `chain2_bs32` vector pins
page-size-32 independence (block 1 also negative: `0xb9e5c32b50351992` ↔
−5051416816229475950), and `le_teeth_bs16` pins the 4-byte-LE token encoding with ids
65537 / 2147483646 / 2147483647 / 2147483648 / 4294967295.

**The same 48 tokens under the vLLM contract** produce entirely different values: block 0's
input is the CBOR array `[NONE_HASH, [1,2,…,16], null]` (where `NONE_HASH` depends on
`PYTHONHASHSEED`), and the published uint64 is the **last** 8 bytes of that digest. There
is no numeric relationship between the two contracts — which is the point: a vLLM-armed
rule scoring an SGLang inventory (or vice versa) scores **zero, forever, silently**.

### 3.2 The three classic mis-implementations

1. **Last-8 vs first-8.** A classic vLLM-side bug was `digest[:8]` where `digest[-8:]` was
   required (it produced 0% overlap); SGLang is the exact inversion. The C parity test self-checks per block that
   `BE(digest[-8:])` *differs* from the SGLang published value, so a wrong-end slice cannot
   pass any committed vector.
2. **Seeding block 0.** Carrying vLLM's `NONE_HASH` habit into the SGLang arm (any parent
   bytes on block 0 — even 32 zero bytes) changes every digest in the chain.
   `LLB_KV_NONE_HASH_SEED` / `PYTHONHASHSEED` parity is a **vLLM-only** concern; setting
   them has no effect on algo 2.
3. **Treating the wire int as unsigned.** SGLang's negative int64s are not errors and not
   sentinel values — they are the published hash. Reject-on-negative or abs() both destroy
   parity for roughly half of all blocks.

---

## 4. The SGLang parity triad (mirror of doc 11 §3.3)

[Doc 11 §3.3](11-hierarchical-kv-routing-config-tuning.md) defines the vLLM parity triad
(seed / block size / algo+version). The SGLang triad is *smaller but sneakier* — there is
no seed leg, but the block-size leg has a model-dependent default:

| # | SGLang / loxilb setting | Must match | Failure mode if wrong |
|---|---|---|---|
| 1 | SGLang `--page-size` (effective value — **model-dependent default, never assume 16**; read `GET /get_server_info` back) | rule `kvBlockSize` | **Silent.** loxilb chunks tokens at the wrong stride → every hash wrong → 0 overlap → all traffic takes the fallback selector while labeled "KV-exact" |
| 2 | The model's HF `tokenizer.json` + chat template staged for the exact model string clients send (`/etc/loxilb/tokenizers/<slug>/`, [08 §6.3/§6.5](08-kv-cache-aware-routing.md)) | what SGLang tokenizes server-side | Missing ⇒ loud-ish (Guard E `tokenize` misses); **wrong-but-loading** (e.g. swapping to a fallback model without switching the staged tokenizer) ⇒ silent 0 overlap |
| 3 | rule `kvEngineType: "sglang"` with **`kvHashAlgo` omitted** (recommended) | default at the single dpebpf mapping site (the `kv_hash_algo`/`kv_engine_type` mapping block in `DpLBRuleMod`, `pkg/loxinet/dpebpf_linux.go`): `algo=="" && engine=="sglang"` ⇒ `kv_hash_algo=2` | `sha256_sglang` is in the swagger enum and an explicit `"sha256_sglang"` is accepted; an algo that *contradicts* the engine (`"sha256_cbor"`/`"xxhash_cbor"` on an sglang rule) is **rejected at config time** by `kvHashAlgoValidate` — it can no longer be silently honored ([15 §8.1](15-sglang-kv-cache-aware-routing.md)) |

**What silent failure looks like** (identical symptom signature to
[doc 11 §7.1](11-hierarchical-kv-routing-config-tuning.md) pattern 1): `tier15_hits_total`
flat, `tier15_miss_reason{reason="no_worker"}` climbing request-for-request,
`loxilb_pd_kv_blocks` **non-empty** — the inventory is real, your computed hashes just never
touch it. Requests keep completing (fail-open), latency looks "fine-ish", and an A/B run in
this state would *measure the fallback selector and call it KV-exact*.

**The upgrade: the failure is no longer detectable only by manual checks.** The zero-hit
watchdog ([15 §7](15-sglang-kv-cache-aware-routing.md)) counts consecutive zero-hit lookups
against a non-empty eligible inventory; at `LOXILB_KV_ZERO_HIT_N` (default 50) it emits one
`[KV_ZEROHIT]` WARN per transition edge and increments
`loxilb_pd_kv_zero_hit_watchdog_total{service_id}` on every at-or-past-threshold lookup.
Treat this as a **HARD per-window gate** in any comparative measurement: the window is
valid only if the `loxilb_pd_kv_tier15_hits_total` delta ≠ 0 AND the
`loxilb_pd_kv_zero_hit_watchdog_total` delta == 0; otherwise the arm is VOID.
The watchdog is engine-agnostic — it retro-covers the vLLM path too, which never had a
runtime tripwire for this class.

---

## 5. Event stream differences

**The wire format is the one thing that did NOT change.** SGLang publishes the same
3-frame ZMQ multipart (`topic | seq u64 BE | msgpack KVEventBatch`) with the same
`BlockStored` / `BlockRemoved` / `AllBlocksCleared` vocabulary — loxilb's decoder needed
zero changes ([15 §1](15-sglang-kv-cache-aware-routing.md)). Everything *around* the wire
differs:

| Aspect | vLLM | SGLang |
|---|---|---|
| Port convention | `:5557` (the canonical contract port, one PUB per prefill EP) | `kvZmqPort + rank` per DP rank; the base port is free-form (see the collision note) |
| Publisher count per EP | 1 | `--dp-size` N (rank N binds base+N) |
| Seq counters | one per EP | **one per rank**, independent — the reason for per-rank seq state ([15 §5.2](15-sglang-kv-cache-aware-routing.md)) |
| Hash wire type | unsigned ints (with `VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=1`) | signed int64s (§3) |
| Enable flag | `--kv-events-config '{"enable_kv_cache_events":true,"publisher":"zmq","endpoint":"tcp://*:5557"}'` | `--kv-events-config '{"publisher":"zmq","endpoint":"tcp://*:<port>"}'` |

### 5.1 The `:5557` co-residency collision

In a co-resident example deployment, SGLang lands on the **same `--network host` boxes**
as the vLLM prefills — and vLLM already owns `:5557` there. Pick a distinct SGLang
publisher port (e.g. `:5561`), **verify it is free with `ss -tln` before launch and
hard-fail if it is bound**, and create the rule with the matching `kvZmqPort` (e.g.
`kvZmqPort: 5561`). Rules of thumb:

- loxilb subscribes per-rule `kvZmqPort` — **any free port works**; there is no magic in
  5557 beyond convention.
- Never free the port by killing the vLLM publisher (that starves the `:9003` rule's
  subscribers).
- With DP ranks, the *whole consecutive range* `[kvZmqPort, kvZmqPort+N−1]` must be free.

### 5.2 Seq gaps, replay, and decision

The subscriber's replay hook (`kvZmqReplayRequester`) exists for vLLM's paired
replay/ROUTER socket, but **production passes `replay=nil` for both engines** — the earlier
loop therefore *silently ignored* mid-stream seq gaps, leaving phantom hashes after missed
`BlockRemoved`/`AllBlocksCleared` events (the long-standing "subscriber does not recover
from EP restart" defect). The staleness fix closes this for both engines, per rank
([15 §5.3](15-sglang-kv-cache-aware-routing.md)): a gap within the forward tolerance
(`kvSeqResumeWindow = 64`) **KEEPs** the warm inventory (stale entries are harmless by
construction — [08 §3.5](08-kv-cache-aware-routing.md)); a larger jump **CLEARs** (the
publisher likely restarted). Both decisions emit a structured
`kv-subscriber: ep N rank R seq gap A -> B … decision=KEEP|CLEAR` marker — the CICD and
live-check anchor (assert it on a real SGLang EP restart as part of any live bring-up).

---

## 6. Multi-DP-rank: what it means for routing

SGLang's `--dp-size N` runs N data-parallel attention workers inside one server process:
**one OpenAI-facing port, N KV pools, N event publishers** (base+rank), each with its own
seq counter. Two facts shape loxilb's design:

1. **loxilb routes to the EP, not to a rank.** The request lands on `host:30000` and
   SGLang's internal scheduler picks the rank. So the *routable* cache-warmth signal is
   "does this EP hold the blocks **anywhere**" — which is exactly what the per-EP **union
   inventory** expresses: all ranks' `BlockStored`/`BlockRemoved` merge into one hash set
   per `epIdx` ([15 §5.1](15-sglang-kv-cache-aware-routing.md)). Rank-partitioned
   inventories were rejected as complexity without a proven need.
2. **Rule `kvDpRankCount` must equal the server's `--dp-size`** (valid 1..8, `0 ⇒ 1`;
   values > 8 are rejected at config time). Too small ⇒ some ranks' events are never
   subscribed (invisible warmth, depressed hit-rate); too large ⇒ dead subscribers
   endlessly retrying non-existent ports (noise, no correctness impact). Drive both
   values from one variable in your deployment tooling so they cannot drift.

Union semantics to expect in operation ([15 §5.4](15-sglang-kv-cache-aware-routing.md)):
`AllBlocksCleared` from **any** rank clears the **whole** shared EP inventory (over-clear
by design — a brief warmth loss beats phantom hashes), and all ranks share one
`(service, ep)` metrics identity, so `kv_subscriber_connected` is over-conservative during
a single-rank rebuild. `kvDpRankCount: 1` (or 0) reproduces the vLLM-era single-subscriber
behavior byte-identically — vLLM deployments are untouched by the fan-out machinery.

---

## 7. Router ecosystem: loxilb vs `sgl-model-gateway`

The honest 3-arm framing for any competitive comparison:

| Arm | Router | Cache signal | Trust model |
|---|---|---|---|
| **loxilb Tier 1.5** (`kvExactMode=3`) | L4/L7 gateway, C data plane + Go inventory | **Exact block hashes published by the servers themselves** (`--kv-events-config` ZMQ events) — a mirror of the radix cache's real content, including evictions | Routes **unmodified servers** — no SGLang patches, no router-side model of the cache; needs the parity triad (§4) configured right |
| **`sgl-model-gateway` `cache_aware`** (v0.3.2, from the same pinned checkout `d8ef76682e`) | standalone Rust router | **Approximate router-side radix tree** built from the *prompts it has routed* — **no event subscription**; it cannot see server-side evictions, cache resets, or traffic that bypassed it | Zero server-side configuration; the approximation is the trade |
| **`round_robin`** | same binary | none | the floor both cache-aware arms must beat |

Structural (not measured — §9) expectations for when each wins:

- **loxilb's edge is exactness under churn**: after evictions, `/flush_cache`, EP restarts
  (CLEAR → honest cold routing), or multi-router/mixed-entry traffic, the event-driven
  inventory stays truthful while a router-side tree goes stale in the optimistic direction
  (routing to warmth that no longer exists). It also inherits the whole load-bounded blend
  (unified CHWBL, adaptive ε/λ, controller weights — [doc 10 §4/§7](10-hierarchical-kv-routing-architecture.md)),
  where `cache_aware` is a different balancing philosophy entirely.
- **`cache_aware`'s edge is zero integration cost**: no ZMQ config, no page-size parity, no
  tokenizer staging. On a stable fleet with all traffic through one router and low eviction
  pressure, its approximation degrades least.
- **RR wins only when there is nothing to win** — negligible shared prefixes, or a
  cache-aware arm misconfigured into silence (which is why the §4 watchdog gate exists:
  a voided arm is neither a win nor a loss).

The differentiator statement: *`cache_aware` is an
approximate router-side radix tree with no event subscription — loxilb's exact-hash,
event-driven routing over unmodified servers is what arm A must demonstrate.* Whether it
does is a measurement question, not this document's (§9).

### 7.1 The three radix trees — and why "syncing" them is the wrong integration

The recurring source of confusion when engineers first study this integration: there are
**three** radix-tree-shaped structures in the system, and it is tempting to conclude they
must be synchronized. They must not — each answers a different question, and the one
transfer of state that matters already happens through the block-hash event stream.

| Tree | Lives where | Answers | Failure mode if trusted alone |
|---|---|---|---|
| loxilb **Tier-1 prefix trie** ([doc 10 §3.3](10-hierarchical-kv-routing-architecture.md)) | loxilb, per service | "where did **I** route this prefix recently?" | self-referential — assumes past routing implies present cache; blind to evictions and other traffic entrances |
| SGLang **RadixAttention** tree | inside each worker's scheduler | "what is **actually** in my GPU KV cache right now?" | ground truth, but server-local — no router can query it per-request at line rate |
| `sgl-model-gateway` **`cache_aware` tree** | the router process | "what do I **think** each worker has, judging by what I sent it?" | optimistic drift — cannot see LRU evictions, `/flush_cache`, restarts, or bypass traffic |

**Why loxilb does not sync (or simulate) the worker's tree:**

1. **There is no sync protocol to adopt.** SGLang exposes no radix-tree export; even its
   own router simulates rather than syncs. Any "tree sync" would have to be invented, and
   would immediately face the staleness problem in the third row above.
2. **The chained hash IS the serialized tree.** Each published page hash is
   `SHA256(parent_digest ‖ tokens)` (§3) — hash at depth *k* encodes the entire prefix
   path to the root. An inventory of chained block hashes is the radix tree flattened into
   its set of node-paths, which is precisely the query routing needs ("longest cached
   prefix for this request, per EP"). Syncing tree *structure* on top would transfer zero
   additional routing information, in a bulkier format.
3. **Events beat snapshots on the axis that decides A/B outcomes: eviction truth.**
   `BlockRemoved`/`AllBlocksCleared` arrive as the worker prunes RadixAttention leaves, so
   the Tier-1.5 inventory tracks cache *departures*, not just arrivals. This is the
   structural edge over any simulated tree (§7 table) and the reason loxilb treats an
   unexplained seq gap as a KEEP/CLEAR decision rather than trusting stale state.

**The equivalence worth internalizing:** loxilb's Tier-1 trie is, in spirit, what
`sgl-model-gateway cache_aware` is — a router-local, zero-cooperation approximation.
loxilb keeps it as the **fallback layer** (cold inventory, reconnect windows, broken
parity) and adds Tier 1.5 as the exact layer above it. So the integration question is
never "how do the trees stay consistent?" — it is "is the parity triad (§4) intact so the
inventory mirrors RadixAttention faithfully?" That is a *configuration* invariant, watched
at runtime by zero-hit watchdog, not a synchronization protocol.

**vLLM backward compatibility:** none of this changed for vLLM. The Tier-1 trie is
engine-agnostic and untouched; the exact layer differs per engine only in the
hash contract (§3) selected by `kvEngineType`; and `kv_svc_id` isolation
([doc 15 §6](15-sglang-kv-cache-aware-routing.md)) keeps a vLLM VIP and an SGLang VIP on
one gateway from cross-matching inventories. Trees never needed reconciling across engines
either.

---

## 8. Optimizing SGLang behind loxilb

All of this is configuration guidance grounded in the shipped mechanism — **not**
measured tuning (§9; the one measured exception is the spill-relief screen in
[17 §7.7](17-sglang-config-tuning.md)). The operator-facing knob reference
is [doc 17](17-sglang-config-tuning.md); this section is the *reasoning*.

### 8.1 Page size (`--page-size` ↔ `kvBlockSize`)

The iron rule first: **`kvBlockSize` must equal the server's *effective* page size, read
back from `/get_server_info`** — the default is model-dependent and the mismatch is silent
(§4). If you control the server-side value, the trade-off (structural, mirrors
[08 §10.2](08-kv-cache-aware-routing.md) economics):

- **Smaller pages (e.g. 16):** finer-grained overlap detection — partial prefix reuse shows
  up as more matched blocks, so scoring resolution is better; but more hash computations
  per request on loxilb (a 10k-token prompt at 16 = 625 SHA-256 chains), more events, and
  bigger inventories.
- **Larger pages (e.g. 32):** half the hash/event/inventory cost, but coarser matching — a
  shared prefix that ends mid-page contributes nothing for that page, and short shared
  preambles may round down to zero scored blocks. The `chain2_bs32` parity vector exists
  precisely so 32 is a first-class, contract-safe choice.
- Whatever you choose, **all EPs behind one rule must agree** — verify every EP reports
  the same page size before creating the rule, and hard-fail your deployment tooling on a
  cross-EP mismatch (homogeneous EPs required).

### 8.2 DP rank count

Set `kvDpRankCount` = `--dp-size`, always, and prefer driving both from one variable
in your deployment tooling. When *choosing* `--dp-size`: more ranks = more
independent KV pools per EP, which **dilutes per-rank warmth while the union inventory
still reports the block as present** — loxilb can route to the right EP and SGLang's
scheduler can still land the request on a cold rank. Tier-1.5's signal is therefore
sharpest at `dp=1` per EP; scale out with more EPs rather than more ranks when cache
affinity is the goal, and treat high-DP EPs as coarser routing targets.

### 8.3 Co-residency memory split (the 0.55/0.35 lesson)

An **example deployment** runs SGLang **beside** the vLLM prefills on 24 GB L4-class
GPUs: `--gpu-memory-utilization 0.55` (vLLM, down from 0.90) + `--mem-fraction-static
0.35` (SGLang), image `lmsysorg/sglang:v0.5.9`, same model
(`Qwen/Qwen2.5-7B-Instruct`). What the split teaches:

- **Reducing the vLLM split changes `num_gpu_blocks`** — the NIXL mesh needs a *uniform*
  `--num-gpu-blocks-override` pin (heterogeneous block counts trip the
  `num_external_tokens` assert), and the ai-controller's calibration fingerprints then
  **mismatch by design** (prior fallback fires visibly; never suppress, never recalibrate
  mid-window).
- **If two weight copies don't fit**, a practical fallback is a smaller model
  (e.g. `Qwen/Qwen2.5-1.5B-Instruct`) — and the gateway's tokenizer/chat-template config is
  MODEL-specific: switch it too, or hashing silently never matches (the watchdog fires).
- Gate readiness on **both** `/health` (process up) and `/health_generate` (a real
  generation completed — model loaded, KV cache allocated); `/health` alone passes long
  before the cache exists.

### 8.4 Watchdog threshold

`LOXILB_KV_ZERO_HIT_N` (default **50**, never disabled — invalid values fall back with a
one-shot WARN). 50 consecutive zero-hit lookups against a non-empty inventory is already
far beyond what honest cold traffic produces on a warm fleet; **lower it (e.g. 20) for
short A/B windows** where 50 requests is a meaningful fraction of a block, raise it only if
your workload genuinely alternates long cold phases against populated inventories. Alert on
any nonzero `loxilb_pd_kv_zero_hit_watchdog_total` delta — it is the authoritative silent
parity-failure signal (§4).

### 8.5 What NOT to do

| Anti-pattern | What happens |
|---|---|
| Mixing engines behind one rule | Structurally impossible — a rule carries exactly one `kvEngineType`. Split frameworks across rules/VIPs (that *is* the coexistence design; two same-VIP rules with different engines are accepted with a WARN) |
| PUT-ing a different `kvEngineType` onto a live rule | Rejected with the exact error `lbrule-exist error: cant modify rule kv engine type (delete and recreate)` — the engine is **immutable**; delete and recreate the rule |
| Setting an engine-incoherent `kvHashAlgo` on an SGLang rule | **Rejected at config time** (`kvHashAlgoValidate`): `sha256_cbor`/`xxhash_cbor` on an sglang rule returns the exact `kv-hash-algo … is incompatible with kv-engine-type …` error instead of being silently honored. Omit the field (recommended) or set `"sha256_sglang"` explicitly (§4 leg 3) |
| Unknown engine strings (`"sgl"`, `"SGLang "`, …) | Rejected at config time (allowlist `""`/`"vllm"`/`"sglang"`) — never silently treated as vLLM |
| `kvExactMode: 3` + `pd_disagg_mode`, or without `mode:4` | Both rejected at config time with exact messages ([15 §3.2](15-sglang-kv-cache-aware-routing.md)) |
| Assuming `kvWarmupSec` protects the cold window | GUARD_B warmup is currently **inert in production** on both paths ([15 §3.3](15-sglang-kv-cache-aware-routing.md)) — don't design procedures around it |
| Designing around per-rule blend knobs | The `LOXILB_KV_*` env family (mode, ε/λ, caps) is **process-global across all KV VIPs**, vLLM and SGLang alike ([15 §8.3](15-sglang-kv-cache-aware-routing.md)) |

---

## 9. Validation status — almost no numbers exist yet

**Be precise about this when quoting the doc.** As of writing:

- The changes are committed; the local, non-binding gates passed (single-TU C
  harness 153/153, `gofmt`, shellcheck, mock-publisher self-checks —
  [15 §10.1](15-sglang-kv-cache-aware-routing.md)).
- The **binding** gates — a Linux `make clean && make`, the `test_pd`/`test_kv`
  rosters, scoped `go test`, and the two-VIP coexistence CICD scenario
  (`cicd/sglang-loxilb-kvcache/`) — are listed in
  [doc 15 §10.2](15-sglang-kv-cache-aware-routing.md); run them on your build.
- The **full 3-arm competitive A/B has not been run** — it requires a live GPU fleet.
  The only measured data published anywhere in the tree is the **spill-relief /
  saturation-ε screen in [17 §7.7](17-sglang-config-tuning.md)**, measured on a single
  internal validation fleet (L4-class GPUs) — indicative, not a general benchmark.
  Beyond that there are **no measured hit-rates, no TTFT/goodput numbers, and no
  win/loss verdicts** for loxilb-vs-`sgl-model-gateway`. §7's "when each wins" is
  structural reasoning, and §8 is mechanism-grounded guidance — neither is a benchmark
  result.

If you run such an A/B yourself, use a pooled methodology (N≥3 blocks, CV≤10%,
per-window self-confirm gates); publish any verdict only with the SLO stated and the §4
gate evidence attached.

---

## 10. See also

- [08 — KV-cache-aware routing (Tier-1.5 internals)](08-kv-cache-aware-routing.md) — the
  vLLM hash contract (§4), guard ladder (§5), and configuration/onboarding guide (§6)
  this doc contrasts against.
- [10 — Hierarchical KV routing architecture](10-hierarchical-kv-routing-architecture.md) —
  the P/D tier ladder and single-pool selector family; §2's deployment shapes are the
  vLLM column of §2 here.
- [11 — Configuration & tuning](11-hierarchical-kv-routing-config-tuning.md) — the vLLM
  parity triad (§3.3) that §4 here mirrors, and the process-global knob reference.
- [15 — SGLang KV-cache-aware routing](15-sglang-kv-cache-aware-routing.md) — the
  mechanism deep-dive behind every SGLang-side row in this doc (gates, hash arm,
  multi-rank subscriber, svc-id isolation, watchdog, source map).
- [17 — SGLang configuration & tuning](17-sglang-config-tuning.md) — the operator-facing
  knob-by-knob companion to §8.
