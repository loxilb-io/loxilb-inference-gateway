# SGLang KV-Cache-Aware Routing — Architecture & Integration Deep Dive

> **Audience:** internal loxilb engineers and advanced users who already know the vLLM
> Tier-1.5 integration ([doc 08](08-kv-cache-aware-routing.md)) and the selection hierarchy
> ([doc 10](10-hierarchical-kv-routing-architecture.md)).
> **Scope:** the SGLang integration — the
> Tier-1.5 decouple from P/D (`kvExactMode=3`, `KV_EXACT_MODE_SINGLE_ROLE`), the SGLang
> block-hash contract (`KV_HASH_SHA256_SGLANG`), per-rule engine config
> (`kvEngineType`/`kvDpRankCount`), the `KvEventSource` multi-DP-rank subscriber fan-out
> with its staleness fix, cross-VIP isolation (`kv_svc_id` threading), the zero-hit
> watchdog, and the two-VIP coexistence CICD scenario.
> **Status:** code complete (all committed). **Not yet
> CICD-gate-verified** — see the admonition below and §10.

Related: [08 — KV-cache-aware routing (Tier-1.5 internals)](08-kv-cache-aware-routing.md)
(the vLLM hash contract and guard ladder this doc builds on),
[10 — Hierarchical KV routing architecture](10-hierarchical-kv-routing-architecture.md)
(the tier ladder and the P/D-only constraint this integration relaxes),
[11 — Configuration & tuning](11-hierarchical-kv-routing-config-tuning.md).

> ⚠ **Validation status (read this first).** Everything documented here landed with
> **local gates only**: the single-TU C unit harness (153/153 PASS on darwin — a
> toolchain sanity run, *not* the binding gate), `gofmt`, `bash -n`/`shellcheck`, and the
> mock-publisher self-checks. The **binding** gates — a Linux `make clean && make`,
> the `test_pd`/`test_kv` rosters, the scoped `go test` suites, and the two-VIP coexistence
> CICD scenario — are listed in §10.2; run them on your build before relying on the
> behavioral claims. The live SGLang GPU-fleet bring-up and the 3-arm competitive A/B
> remain outstanding (§10.3). Full breakdown in §10.

---

## 1. What it is and where it sits

SGLang, like vLLM, keeps a prefix cache (its **radix cache**, in **pages** of `--page-size`
tokens) and publishes **KV cache events** (`BlockStored` / `BlockRemoved` /
`AllBlocksCleared`) on a ZMQ PUB socket (`--kv-events-config`). The wire format is
**byte-identical** to vLLM's (3-frame multipart, msgpack `KVEventBatch`) — loxilb's decoder
(`decodeKVEventBatch`) needed **zero changes**. What differs is everything around it:

| Difference | vLLM (doc 08) | SGLang (this doc) |
|---|---|---|
| Deployment shape | P/D disaggregation (`ep_role` 1/2, NIXL) | **Single-role** converged pool (this doc). SGLang's own P/D disaggregation is ALSO supported — `pd_disagg_mode` + `kvEngineType:"sglang"` runs a concurrent dual-dispatch orchestrator (bootstrap triple injection, drain leg, pair retry); Tier-1.5 then subscribes the prefill EPs with the same hash contract described here |
| Block hash | SHA-256/XXH3 over canonical **CBOR** `[parent, tokens, extra]` | SHA-256 over **raw** `parent‖tokens_LE4`, no CBOR (§4) |
| First-block parent | `NONE_HASH` seeded from `PYTHONHASHSEED` | **No parent at all** — block 0 hashes bare tokens |
| uint64 truncation | **last** 8 digest bytes, BE | **first** 8 digest bytes, BE (§4) |
| Published hash sign | unsigned msgpack ints (`VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=1`) | **signed int64** (two's-complement wrap) — `extractBlockHashes` already converts |
| Event publishers per EP | one ZMQ PUB `:5557` | one PUB **per DP rank** at `kvZmqPort+rank` (§5) |

The load-bearing constraint this integration removes: doc 10 §2's rule that *Tier 1.5 is
reachable only inside the P/D ladder*. SGLang serves single-role, so the integration opened a
**second, additive entry** into KV-exact selection: `kvExactMode=3`
(`KV_EXACT_MODE_SINGLE_ROLE` in `loxilb-ebpf/common/sockproxy.h`). Note that `kvExactMode`
selects the **endpoint topology only** (role-partitioned P/D pool vs role-less pool); it is
orthogonal to `kvEngineType`, which selects the engine — the pairings shown throughout this
doc (mode 1 + vLLM, mode 3 + SGLang) are the conventional ones, not a coupling. A plain `mode:4`
fullproxy rule — no `pd_disagg_mode`, no `ep_role` tags — now reaches `pd_kv_exact_select`
and the full unified-CHWBL / adaptive-ε/λ blend of doc 10 §4, while the vLLM P/D mode-1
path stays **byte-identical** (purely-additive diffs, mutation-proven mask test — §3).

Selection semantics at mode 3:

```
kvExactMode=3 rule, per request:
  single-role Tier-1.5 (pd_kv_exact_select over ALL healthy EPs)
      HIT  → route to the KV winner (+ active_conns hold)
      MISS → the rule's OWN configured selector (CHWBL / sel:8 / RR …)
```

There is deliberately **no Tier-0/1/2 ladder duplication** (design decision): on a
Tier-1.5 miss the single-role branch leaves `algorithm_selection` untouched, so the
selector switch that already ran for the rule (doc 10 §6) is the natural fallback. No 429/
park/admission logic exists on this path — those are P/D-only features.

**One framework per VIP by design.** A single gateway serves a vLLM P/D VIP and an SGLang
single-role VIP simultaneously (different rules, same or different VIP IP); mixing engines
*behind one rule* is structurally impossible (a rule carries exactly one `kvEngineType`,
immutable after create — §8.3).

---

## 2. Architecture

Two rules, one gateway, one shared Go inventory plane — the vLLM side is exactly doc 08's
architecture, untouched:

```
                       ┌───────────────────────── one loxilb gateway ─────────────────────────┐
 vLLM clients ──HTTP──▶ VIP-A :9003   rule: mode 4 + pd_disagg, kvExactMode=1, engine=vllm     │
                       │   P/D tier ladder (UNTOUCHED — doc 10 §3)                             │
                       │     └─ pd_select_prefill → Tier 0/1/1.5/2 → decode select             │──▶ vLLM prefill/decode EPs
                       │           └── pd_kv_exact_select ────────────┐                        │      (ZMQ PUB :5557 per prefill)
 SGLang clients ─HTTP─▶ VIP-B :9010   rule: mode 4 fullproxy, kvExactMode=3, engine=sglang     │
                       │   single-role sibling branch (proxy_sel_ep, sockproxy_ep.c)           │──▶ SGLang EPs (example) :30000
                       │     └─ health/CB exclusion mask → pd_kv_exact_select                  │      (ZMQ PUB :zmqPort..+N-1 per EP,
                       │          HIT  → EP + active_conns hold        │                       │       N = kvDpRankCount)
                       │          MISS → rule's own selector (CHWBL/RR)▼                       │
                       │              llb_ai_kv_best_worker(…, kv_svc_id)   ← one CGO crossing │
                       │              svc-scoped inventory scan → overlap argmax               │
                       │              → unified CHWBL / adaptive ε/λ blend (doc 10 §4)         │
                       └────────────────────▲──────────────────────────────────────────────────┘
                                            │ per-EP kvInventory (ONE per epIdx, union of DP ranks)
                       Go: KvSubscriberStartRank(svc, epIdx, rank) ← ZMQ SUB tcp://EP:(kvZmqPort+rank)
                           BlockStored / BlockRemoved / AllBlocksCleared
                           per-rank seq state · reconnect + KEEP/CLEAR resync · gap decision
```

| Layer | Code | What was added |
|---|---|---|
| **Request decision** (C) | `loxilb-ebpf/common/sockproxy_ep.c` (the single-role branch in `proxy_sel_ep()`), `sockproxy_kv_exact.c` | Sibling else-if beside the P/D block; SGLang hash arm; candidate-mask widening; `kv_svc_id` at the CGO call |
| **Inventory ingest** (Go) | `pkg/loxinet/ai_kv_subscriber.go` | `KvEventSource` seam, `(epIdx, rank)`-keyed lifecycle, per-rank seq state, gap decision, watchdog |
| **Rule plumbing** (Go) | `pkg/loxinet/rules.go`, `dpebpf_linux.go` | Mode-3 subscriber gate, config-time validation, `kvEngineType`/`kvDpRankCount` 10-hop chain, engine→hash-algo defaulting |
| **Contract fixtures** | `cicd/vllm-kvcache-routing-cpu/sglang_hash_core.py` | ONE Python hash source of record + committed parity vectors pinned to sglang `d8ef76682e` |
| **Coexistence gate** | `cicd/sglang-loxilb-kvcache/` | Two-VIP mock scenario, 7 assertion legs (§10.2) |

Key design properties (all inherited or strengthened from doc 08):

- **The vLLM path is provably untouched.** Every C and Go seam landed as a *sibling branch
  attached at the existing block's closing brace* — the diffs are purely additive (0
  deletions in the hot-path files), and the mode-1 candidate mask is locked by a
  mutation-proven unit test (`test_mask_mode1_byte_identity`: forcing the widening
  disjunct always-on fails with `mask=0xf want 0x9`).
- **The single-role path inherits the whole modern selection stack.** Because it calls the
  same `pd_kv_exact_select` → `llb_ai_kv_best_worker` leaves, unified CHWBL hard caps,
  adaptive ε/λ, capacity normalization, and controller weights all apply — *provided the
  load feed is live*, which is exactly gate 3 of §3.
- **Hash parity is still the whole game**, but the contract is a different one (§4), and
  this integration adds a runtime tripwire for silent parity failure (§7) that doc 08's
  vLLM path never had.

### 2.1 Relationship to SGLang's RadixAttention — why there is no tree sync

A question every engineer asks on first contact: SGLang manages its KV cache as a radix
tree (RadixAttention), loxilb already has a radix-trie prefix layer (Tier 1,
[doc 10 §3.3](10-hierarchical-kv-routing-architecture.md)) — so does the integration sync
the trees? **No. Nothing syncs a tree, by design.**

The block-hash event stream already carries the radix tree's information in a flat, exact
form. Because of parent chaining — each page hash is `SHA256(parent_digest ‖ tokens)`
(§4) — a block hash at depth *k* encodes its **entire prefix**. Matching a request's
leading block hashes against an EP's inventory *is* a radix-path match: **the chained hash
is a serialized radix path.** The per-EP inventory is therefore a flattened, eviction-aware
mirror of exactly the part of each worker's RadixAttention state that routing needs —
`BlockRemoved`/`AllBlocksCleared` events propagate SGLang's LRU leaf evictions, which is
the one thing a synced *snapshot* or a router-side *simulation* of the tree structurally
cannot keep up with.

Three trees, one question each:

| Tree | Lives where | Answers | Nature |
|---|---|---|---|
| loxilb Tier-1 prefix trie | loxilb, per service | "where did **I** route this prefix recently?" | heuristic, from loxilb's own routing history — engine-agnostic, unchanged |
| SGLang RadixAttention | inside each worker | "what is **actually** in my GPU cache?" | ground truth; local; constantly evicting |
| loxilb Tier-1.5 inventory | loxilb Go heap | "what has each worker **published** as cached?" | exact mirror via KV events — the flattened radix state |

The Tier-1 trie is **not** displaced by mode 3: it remains the resilience floor under the
ladder (§1) — cold inventory right after subscriber start, reconnect windows, or a broken
parity triad all fall through Tier 1.5 to the trie before reaching min-load. The layers are
complementary, not competing mechanisms to reconcile. The full comparison with
`sgl-model-gateway`'s router-side simulated tree — the design loxilb deliberately did NOT
adopt — is [doc 16 §7.1](16-sglang-vs-vllm-routing-differences.md).

---

## 3. The three gates that had to open

"Decouple Tier 1.5 from P/D" turned out to be not one gate but **three** —
and the third was invisible until a hot-spot post-mortem. All three are now open.

### 3.1 Gate 1 — the C selection-mode gate

Historically `pd_kv_exact_select` was reachable only through `pd_select_prefill`, which
runs only when `tepval->pd_disagg_enabled && n_prefill_eps > 0 && n_decode_eps > 0`
(the `pd_select_prefill()` call site in `sockproxy_ep.c`, doc 10 §2). The integration
attached a **sibling** `else if` at that block's closing brace in `proxy_sel_ep()`:

```c
} else if (tepval->kv_exact_mode == KV_EXACT_MODE_SINGLE_ROLE && pfe) {
    /* build the same health/CB exclusion mask the P/D ladder builds */
    uint32_t sr_excl = 0;
    for (int pe = 0; pe < tepval->n_eps && pe < 32; pe++)
        if (tepval->eps[pe].inv ||
            tepval->circuit_breakers[pe].state == CB_STATE_OPEN)
            sr_excl |= (1u << (unsigned)pe);
    if (pd_kv_exact_select(tepval, pfe, &kv_sr_ep, sr_excl) == 0 && ...) {
        ...  /* HIT: route + load hold; MISS: fall through untouched */
    }
}
```

The `&& pfe` guard is load-bearing: `pd_kv_exact_select` dereferences `pfe`
unconditionally past GUARD_A, and Tier 1.5 is meaningless without request text anyway.

Inside `pd_kv_exact_select` exactly one guarded change was needed — the `prefill_mask`
build in `pd_kv_exact_select()` (`sockproxy_kv_exact.c`) admits **all** EPs at mode 3
(single-role services have no roles; `ep_role[]` is all-zero):

```c
for (int i = 0; i < tepval->n_eps && i < 32; i++) {
    if (tepval->ep_role[i] == 1 ||
        tepval->kv_exact_mode == KV_EXACT_MODE_SINGLE_ROLE)
        prefill_mask |= (1u << (unsigned)i);
}
```

At mode 1 the new disjunct is provably never true — the P/D mask build is byte-identical.
The guard ladder A–G (doc 08 §5), tokenize, hash, and the Go argmax are mode-agnostic and
run unchanged. Note the mode value: **3**, not 2 — `kv_exact_mode == 2` remains the
documented NATS reservation (`sockproxy.h` comments: `0=off, 1=zmq(P/D), 2=nats(reserved),
3=zmq single-role `); the *hash* enum is a different enum where 2 was free (§4).

### 3.2 Gate 2 — the Go subscriber-start gate

`rules.go`'s subscriber gate started KV subscribers **only for `epRole==1`** endpoints at
mode 1 — a single-role rule got no subscribers and therefore permanently empty
inventories. The fix is again a sibling branch (the mode-3 arm of the subscriber gate in
`rules.go`), fanning out through a pure, unit-testable contract function:

```go
// kvSubscriberTargets in rules.go — the fan-out contract
func kvSubscriberTargets(mode uint8, endPoints []ruleLBEp) []int
//   mode 0 / 2 (reserved) → none
//   mode 1                → epRole==1 only   (pinned semantic twin of the verbatim loop)
//   mode 3                → ALL endpoint indexes
```

The mode-1 loop stays textually verbatim; `KvExactModeSingleRole uint8 = 3`
(`rules.go`) mirrors the C define. Teardown is already generic and service-scoped —
rule delete calls `KvSubscriberStopAll(uint32(rule.ruleNum))` in `rules.go` for both
modes.

Two **config-time validations** land beside the gate (the mode-3/mode-1/engine/hash-algo
validations in `AddLbRule`, placed before the eRule lookup so they cover create *and*
update):

| Rejected config | Exact error |
|---|---|
| `kvExactMode=3` + `PDDisaggMode` | `kv-exact single-role mode is incompatible with pd-disagg (use kvExactMode=1 for P/D)` |
| `kvExactMode=3` without fullproxy | `kv-exact single-role mode requires mode=fullproxy` |
| `kvExactMode=1` without `PDDisaggMode` | `kv-exact zmq mode requires pd_disagg_mode=true (use kvExactMode=3 for a single pool)` |
| `kvHashAlgo` contradicting `kvEngineType` | `kv-hash-algo "<algo>" is incompatible with kv-engine-type "<engine>" (omit kvHashAlgo to take the engine default "<default>")` |

The last two are the **mode-1 sibling guards**. `kvExactMode=1` without pd-disagg used to be
accepted and silently inert (Tier 1.5 for mode 1 is reachable only from `pd_select_prefill()`,
which the C selector calls only inside its `pd_disagg_enabled` branch), so it populated
inventories and held a subscriber goroutine per prefill EP while never influencing selection.
The hash-algo guard closes the mirror-image trap: the C hasher picks its contract from
`kv_hash_algo` alone, so `kvEngineType:"sglang"` pinned to `"sha256_cbor"` missed **every**
published block with no config-time signal — only the `[KV_ZEROHIT]` watchdog eventually warned.
Omitting `kvHashAlgo` (the recommended shape) always passes; the engine default is derived by
`kvHashAlgoEffective`, which mirrors `dpebpf_linux.go`'s resolution order exactly.

The second one exists because the Tier-1.5 hot path lives in the sockproxy, which only
fullproxy rules reach — mode 3 must never be creatable in a topology where the seam
structurally cannot run. (Mode 1 inherits the same precondition transitively through the
P/D validation; mode 3 has no P/D block to inherit from, so it is mirrored explicitly.)

### 3.3 Gate 3 — single-role `active_conns` accounting (the hidden gate)

The lesson: `llb_ai_kv_best_worker`'s blend keys on
`pd_ep_loads[i].active_conns`, and those counters were incremented **only inside the P/D
block**. A single-role service would have passed all-zero loads → the bounded-load cap
never binds → pure overlap argmax → the shared-prefix hot-spot — the same failure class
previously seen when a dead metrics feed made the blend run blind.

The single-role branch therefore adds a full load lifecycle:

- **Increment on hit** (the `[KV_SR]` hit block in `sockproxy_ep.c`):
  `atomic_fetch_add(&pd_ep_loads[kv_sr_ep].active_conns, 1)` plus
  `pfe->kv_sr_load_held = 1`, `pfe->kv_sr_ep_idx = kv_sr_ep`.
- **A second increment site** exists on the mid-cycle failover re-claim path (the LB
  mid-cycle failover block in `sockproxy_ep.c`): when a connect failover re-selects an EP
  mid-cycle, the hold is re-claimed there (`kv_sr_load_held = 1` for the new EP), so the
  load accounting survives failover.
- **Single-owner atomic-claim decrement**: exactly one of two owners releases the hold by
  claiming the flag via `__atomic_exchange_n(&pfe->kv_sr_load_held, 0, __ATOMIC_ACQ_REL)`:
  - the **backend connect-failure release** in `sockproxy_ep.c`, or
  - **`pd_cleanup()`** at generic teardown (`sockproxy_http.c`) — the *same*
    single owner that runs the P/D lifecycle decrements (close, error, keep-alive request
    boundary). No second decrement owner exists, so failed connects cannot leak load and
    concurrent teardown races cannot double-decrement.

The `pfe` fields are append-only growth (`kv_sr_load_held`/`kv_sr_ep_idx`,
`sockproxy.h`); zero-init means "not held", so P/D and mode-0/1 connections are a no-op in
the release paths.

> **Related finding:** `kv_warmup_start` has **no production writer** anywhere
> (only `test_kv_exact.c` stamps it) — GUARD_B warmup is **inert in production for both
> the P/D and single-role paths** today. Documented at the `kv_warmup_start` declaration
> in `sockproxy.h`; deliberately *not* stamped, because stamping would change
> shipped vLLM P/D behavior. `kvWarmupSec` is accepted config but currently a no-op.

---

## 4. The SGLang block-hash contract

The single source of truth is the pinned sglang checkout **`d8ef76682e`**
(`python/sglang/srt/mem_cache/utils.py` `get_hash_str`/`hash_str_to_int64` +
`mem_cache/cpp_utils/hash_binding.cpp` `hash_page`, lines 62–75), re-derived as ONE
pure-Python source of record: `cicd/vllm-kvcache-routing-cpu/sglang_hash_core.py`
(stdlib-`hashlib`-only — sglang's own module chain hard-imports torch-heavy kernels and a
compiled pybind module, so it is never imported; every consumer, including the mock
publisher, imports *this* module so vectors and publisher can never drift).

| Contract element | Definition | loxilb implementation |
|---|---|---|
| Block input | raw bytes `[32-byte parent digest, ONLY if present] ‖ token0_LE4 ‖ token1_LE4 ‖ …` per `--page-size` tokens — **no CBOR envelope** (`hash_binding.cpp` hashes the page's uint32 words directly; x86_64 memory order == 4-byte LE per token) | `kv_hash_sglang_block()` (`sockproxy_kv_exact.c`): `SHA256_Update(parent, 32)` iff `has_parent`, then per-token LE4 bytes |
| Hash algorithm | SHA-256 (32-byte digest), always | `KV_HASH_SHA256_SGLANG 2` (`sockproxy_kv_exact.h`) — value 2 is free in the *hash* enum; the NATS "2" reservation is on the *mode* enum only |
| First-block parent | **NONE** — block 0 hashes bare tokens. There is no `NONE_HASH`, no seed, no zero-parent bytes. Contrast vLLM: `NONE_HASH` derived from `PYTHONHASHSEED` (doc 08 §4) — the whole `LLB_KV_NONE_HASH_SEED` machinery does not exist on this path | `has_parent=false` skips the parent update entirely (the dedicated SGLang arm of `kv_compute_block_hashes`) |
| Parent chaining | parent for block *i>0* = block *i−1*'s **full 32-byte digest** (raw bytes, not hex, not truncated) | `parent_hash` carries the full digest between iterations |
| Published value | `hash_str_to_int64`: `v = int(hexdigest[:16], 16)` — the **FIRST 8 digest bytes as a big-endian uint64** — then signed-int64 wrap: `v - 2^64 if v >= 2^63 else v` | `memcpy(out, digest_full, 8)` (**first** 8, in the `kv_compute_block_hashes` SGLang arm) — the exact **inverse** of the vLLM `digest[-8:]` slice. The C parity test self-checks per block that `BE(digest[-8:])` *differs* from the published value, so a last-8 mis-implementation cannot silently pass any vector |
| Wire encoding | msgpack **signed int64** (negative when digest byte 0 ≥ `0x80`) | `extractBlockHashes` already handles int64→uint64 bit-exact conversion — zero Go-side change |
| Block size | must equal SGLang `--page-size` — **model-dependent default, never assume 16**; read it back from `/get_server_info` | `kvBlockSize` REST field; a mismatch is *silent* — watchdog (§7) exists precisely for this |
| Hash stride | 32-byte slots (same as sha256_cbor) | the existing stride selector already yields 32 for algo 2 — no change |

The dedicated SGLang loop inside `kv_compute_block_hashes` (`sockproxy_kv_exact.c`)
early-returns before the vLLM `kv_compute_none_hash` seed, so the algo-0/1 CBOR code paths
are textually byte-identical (whole-plan C diff: 0 deletions). `[KV_HASH]` debug on this
path uses a dedicated emit — the shared `kv_hash_debug_emit`'s hash field is contractually
`BE(digest[-8:])` (vLLM) and would misreport the SGLang published value.

### 4.1 Parity vectors

Committed constants, derived **once** from the pinned checkout via
`cicd/vllm-kvcache-routing-cpu/sglang_hash_core.py` (the single hash source of record —
no digest arithmetic exists anywhere else; the pin commit is stamped in every consumer's
header — do not hand-edit, do not update the checkout between regenerations). Five vectors:

| Vector | Pins |
|---|---|
| `single_block_bs16_noparent` | block-0 no-parent rule (first-8 `4c816952ba53cc36`) |
| `chain3_bs16` | full-digest parent propagation across a 3-block chain |
| `le_teeth_bs16` | LE byte-order teeth: tokens 65537 / 2147483646 / 2147483647 / 2147483648 / 4294967295 |
| `negative_int64_bs16` | signed wrap: digest starts `0xdf` → published int64 **−2360060374177730597** |
| `chain2_bs32` | **page size 32** (block-size independence); block 1 also negative (first-8 `b9e5c32b50351992` → **−5051416816229475950**) |

Each vector is asserted at **both** layers:

- **C** — `test_sglang_parity_vectors()` in `loxilb-ebpf/common/test_kv_exact.c`: hand-
  chained `kv_hash_sglang_block` full digests AND the production
  `kv_compute_block_hashes(KV_HASH_SHA256_SGLANG, …)` output slots (first-8-BE uint64 +
  zero-pad tail + the last-8-must-differ guard). Local single-TU harness: 153/153
  (107 baseline + 42 SGLang asserts + 4 svc-id asserts).
- **Go** — `TestKvSGLangHashVectors_Int64ToUint64`
  (`pkg/loxinet/ai_kv_subscriber_hash_vectors_test.go`): feeds the *signed* published
  int64s through `extractBlockHashes` (the exact msgpack decode type) and asserts bit-exact
  uint64 equality with the C references; structural guards fail the test if the committed
  set ever loses its negative-int64 or bs32 coverage.

The mock publisher (`kv_event_publisher.py --algo sha256_sglang`, §10.2) imports the same
core and self-checks against `chain3_bs16` + `negative_int64_bs16` —
one-source-of-record pattern that prevents the `digest[:8]`-vs-`digest[-8:]` drift
class from ever having two implementations to drift between.

---

## 5. KvEventSource + multi-DP-rank fan-out

SGLang with data parallelism publishes KV events **per DP rank**, each rank on its own
consecutive port with its own independent seq counter. The multi-rank fan-out wraps —
never rewrites — the shipped subscriber of doc 08 §3.2/§3.5:

### 5.1 The seam and the fan-out

- **`KvEventSource`** (`ai_kv_subscriber.go`) is the transport-agnostic interface the
  loop consumes; it *embeds* the existing `kvZmqSubscriber` seam (so every pre-existing
  reconnect test still mock-injects unchanged). `newKvEventSource(ctx, engine, addr)` is
  the engine→transport factory: `""`, `"vllm"`, and `"sglang"` all resolve to the same
  pure-Go ZMQ source (the wire format is byte-identical); the factory is the named
  admission point for a future non-ZMQ engine (TensorRT-LLM REST polling — deferred).
- **`KvSubscriberStartRank(serviceID, epIdx, rank, epIP, port, algo)`** is the
  shipped `KvSubscriberStart` body parameterized by rank: same initial-connect retry
  (5 s backoff — a rule may pre-date the server), same metrics identity, but dedup/cancel
  keyed by **`kvEpRankKey{epIdx, rank}`** so N rank goroutines get N cancels
  (`KvSubscriberStopAll` iterates the composite keys; teardown-clean test pins
  zero leaked goroutines). `KvSubscriberStart` survives as a thin rank-0 wrapper
  — every existing caller is byte-identical.
- **Rank ports:** `rules.go` wraps *both* gate paths (mode-1 and mode-3) in
  `for rank := 0; rank < dpRanks; rank++ { KvSubscriberStartRank(…, zmqPort+rank, …) }`
  (the per-rank `KvSubscriberStartRank` loops), with `dpRanks = kvDpRankCount; 0 ⇒ 1`. Default 1
  reproduces today's single call exactly — vLLM deployments are untouched.
- **One inventory per EP, shared across ranks:** the first rank creates
  `svc.inventories[epIdx]`; later ranks look it up. All ranks' `BlockStored`/
  `BlockRemoved` union into that one hash set — which is what the selector scores. The
  per-EP `LOXILB_KV_MAX_BLOCKS` cap applies to the shared inventory.

### 5.2 Per-rank sequence state

The earlier model kept `lastSeq` on the shared inventory — N ranks with independent seq
counters interleaving into one detector would false-"gap" on every cross-rank hop and
spuriously clear. Now:

- `rankLastSeq` is **goroutine-local** per rank (`runKvSubscriberLoopRank` in
  `ai_kv_subscriber.go`). Rank 0 seeds from `inv.lastSeq` (back-compat with pre-seeded
  test baselines) and mirrors progress back; ranks > 0 start at −1 and never touch the
  shared field.
- The reconnect KEEP/CLEAR resync (`kvResyncDecision`; forward tolerance
  `kvSeqResumeWindow = 64`) keys on the rank's **own** state — a rank-1 blip cannot
  clear warmth rank 0 built (the `TestKvMultiRankIsolatedResync` regression).

### 5.3 The staleness fix

The shipped loop reacted to a mid-stream seq gap only when a replay requester existed —
and production passes `nil`, so missed `BlockRemoved`/`AllBlocksCleared` events silently
left **phantom hashes** in the inventory (the long-standing "KV subscriber does not
recover from EP restart" defect). The fix closes it: a gap with `replay == nil` now runs
the same conservative decision and emits a **structured marker** (in
`runKvSubscriberLoopRank`):

```
kv-subscriber: ep 2 rank 1 seq gap 117 -> 224 (missing 106, no replay) decision=CLEAR — large forward jump; clearing stale inventory
kv-subscriber: ep 2 rank 0 seq gap 117 -> 121 (missing 3, no replay) decision=KEEP — small resume within window; warm inventory retained (size=482)
```

A small forward hop within `kvSeqResumeWindow` KEEPs (transient loss; stale entries are
harmless by construction — doc 08 §3.5); a large jump CLEARs (the publisher likely
restarted). `justResynced` suppresses the gap decision on the first post-reconnect
message — resync decision already ran on the same pair; a double decision would
double-log and double-clear. The `replay != nil` arm (vLLM's replay buffer) is
byte-identical.

### 5.4 `AllBlocksCleared` under union (over-clear by design)

The union inventory carries no rank tag, so `AllBlocksCleared` from **any** rank clears
the **whole** shared EP inventory (handled in `runKvSubscriberLoopRank`):

```
kv-subscriber: AllBlocksCleared received for ep 1 (rank 2) — clearing shared inventory
```

Over-clearing degrades to the fallback selector (a perf cost, recoverable in seconds);
under-clearing would leave phantom hashes (a correctness bug). Rank-partitioned
inventories were rejected as complexity without a proven need — revisit only if live
measurement shows measurable warmth loss.

**Metric identity note:** all ranks of an EP share the `(service, ep)` label pair, so
`loxilb_kv_subscriber_connected` is over-conservative during a single-rank rebuild
(acceptable; per-rank labels would multiply cardinality without a consumer).

---

## 6. Cross-VIP isolation — `kv_svc_id` threading

**The bug coexistence would have hit:** `llb_ai_kv_best_worker` historically iterated
**all** registered KV services, scoring every service's inventories with the *caller's*
masks and load arrays indexed by epIdx. Two same-engine, same-model VIPs on one gateway
could cross-match content and return an epIdx that is valid in the *wrong* rule's EP space
— VIP-A's `tier15_hits` moving while only VIP-B receives traffic. Single-service
deployments never exposed it.

**The fix is identity threading with zero new plumbing.** The rule number already
arrives in the C data plane — it just wasn't stored where the selector could see it:

```
Go r.ruleNum ──(the dat.ca.cidx assignment in DpLBRuleMod — dpebpf_linux.go)──▶ pval->_id
    ──(llb_conv_nat2proxy)──▶ proxy_add_entry arg->_id
    ──(stamped at BOTH proxy_add_entry copy sites, sockproxy_http.c)──▶ tepval->kv_svc_id
    ──(the CGO call in pd_kv_exact_select, sockproxy_kv_exact.c)──▶ llb_ai_kv_best_worker(..., svcID)
    ──(Go, kvSvcScanTargets — ai_kv_subscriber.go)──▶ kvServices[svcID] single lookup
```

`kvServices` is keyed by `uint32(r.ruleNum)` (`serviceID := uint32(r.ruleNum)` in
`rules.go`) — exactly the value that arrives. The CGO signature change was twin-lockstep
(the Go `//export llb_ai_kv_best_worker` in `ai_kv_subscriber.go`, the C prototype in
`sockproxy_ai_gw.h`, the call site, and both stubs in ONE commit).

Semantics:

- **`svcID != 0`** → the Go scan scores **only** `kvServices[svcID]`'s inventories; an
  unknown ID is a Tier-1.5 miss (no cross-service iteration is even reachable).
- **`svcID == 0`** → "no identity": the **legacy all-services loop, textually unchanged**.
  LB rule markers allocate from 1, so zero-init/legacy C structs can never collide with a
  real rule — the seam is independently default-off, regression-locked by
  `TestKvSvcFilterLegacyAllServices`.

The coexistence CICD scenario carries a same-model **negative control** (leg L4, §10.2)
engineered to FAIL without this filter — and the scenario runs a one-shot revert-mutation
check proving exactly that.

---

## 7. The zero-hit watchdog

**Why it exists:** the deadliest SGLang misconfiguration is silent. If `kvBlockSize` ≠
SGLang `--page-size` (or the hash algo drifts), loxilb's computed hashes simply never
match the inventory — Tier 1.5 never fires, every request quietly takes the fallback
selector, and a competitive A/B would *silently measure the fallback* while labeled
"KV-exact". vLLM has the same failure class (doc 08 §6.5's silent-failure decoder), but
this integration makes it a first-class runtime signal instead of a manual checklist
item. The watchdog is engine-agnostic — it also catches vLLM parity misconfig.

**Mechanism** (`kvZeroHitWatchdog` in `ai_kv_subscriber.go`, evaluated once per scanned
service on the selector exit path in `kvSvcScanInventories`):

- Per-service **consecutive-zero-hit streak**, counted only when that service had an
  **eligible non-empty inventory** this lookup (mask-passing, non-excluded EPs — a service
  whose EPs are all excluded this lookup is an expected miss, not a parity signal).
- The streak resets on the **per-service** best score, not the global one — in a legacy
  `svcID==0` scan, another service's hit must not mask a broken service's streak.
- At streak == N: **one WARN per transition edge** (transition-log shape), and the
  Prometheus counter increments on **every** occurrence at-or-past N (the WARN carries the
  edge, the counter carries the volume — log-flood-proof, test-locked at 1 WARN per 100
  zero-hits). A single hit resets the streak AND re-arms the WARN.
- Threshold: `LOXILB_KV_ZERO_HIT_N`, parse-or-default **50**, never disabled (invalid/zero/
  negative ⇒ default + one-shot WARN).

The WARN:

```
[KV_ZEROHIT] service 7: 50 consecutive KV-exact lookups scored ZERO hits against a
non-empty inventory (14382 eligible blocks) — probable cause: kvBlockSize/page-size
mismatch or hash-algo drift; Tier-1.5 is effectively OFF for this service
```

The metric: `loxilb_pd_kv_zero_hit_watchdog_total{service_id}` (lazy CounterVec in
`api/prometheus/sockproxy_metrics.go`; `service_id` = the rule number, keeping two-VIP
scenarios attributable per arm; increment via `IncKvZeroHitWatchdog`, test getter
`KvZeroHitWatchdogValue`). No backend HTTP call anywhere — the watchdog is
data-path-only by decision.

**Operational contract for any comparative measurement:** treat this as a HARD
per-window gate for the loxilb arm — the window is valid only if the
`loxilb_pd_kv_tier15_hits_total` delta ≠ 0 **AND** the
`loxilb_pd_kv_zero_hit_watchdog_total` delta == 0; otherwise the arm is VOID
(every experiment self-confirms that Tier 1.5 actually fired).

---

## 8. Configuration

### 8.1 REST surface (additive fields — the `kv*` block of `serviceArguments` in `api/swagger.yml`)

```jsonc
{
  "serviceArguments": {
    "mode": 4,                     // fullproxy — REQUIRED for kvExactMode 3 (validated)
    "kvExactMode": 3,              // TOPOLOGY only (orthogonal to kvEngineType): 0=off, 1=zmq role-partitioned P/D pool, 2=nats(reserved), 3=zmq role-less pool
    "kvEngineType": "sglang",      // "vllm" (default) | "sglang"; IMMUTABLE after create
    "kvDpRankCount": 2,            // 1..8 (0⇒1); rank N subscribes at kvZmqPort+N
    "kvBlockSize": 64,             // MUST equal SGLang --page-size (read back from /get_server_info)
    "kvZmqPort": 5561,             // SGLang --kv-events-config port (5557 canonical; co-resident fleets shift)
    // "kvHashAlgo" OMITTED on purpose — see below
  },
  "endpoints": [                   // role-less: NO epRole tags
    { "endpointIP": "10.0.0.7", "targetPort": 30000 },
    { "endpointIP": "10.0.0.8", "targetPort": 30000 },
    { "endpointIP": "10.0.0.9", "targetPort": 30000 }
  ]
}
```

**The `kvHashAlgo` omission is deliberate and recommended — but not the only legal
spelling:** the swagger enum is `["sha256_cbor", "xxhash_cbor", "sha256_sglang"]`, and
`kvHashAlgoValidate` accepts an explicit `"sha256_sglang"` on an sglang rule. The rule at
the single dpebpf mapping site (the `kv_hash_algo`/`kv_engine_type` mapping in
`DpLBRuleMod`, `dpebpf_linux.go`) does the defaulting work:
`KvHashAlgo == "" && KvEngineType == "sglang"` ⇒ `kv_hash_algo = 2`
(`KV_HASH_SHA256_SGLANG`). An algo that *contradicts* the engine (e.g. `xxhash_cbor` +
sglang) is rejected at config time (§3.2), so it can no longer be silently honored.
Engine mapping: `"sglang"` ⇒ `kv_engine_type = 1`; rank `0 ⇒ 1`.

**Tokenizer prerequisite (Tier 1.5 does not run without it):** stage the served model's
HuggingFace `tokenizer.json` at `/etc/loxilb/tokenizers/<model-slug>/tokenizer.json`
(slug = the model id with `/` replaced by `__`). A missing tokenizer fails **silently**:
a warn-once log `kv-router: tokenizer not available`, Guard E `tokenize` misses, and
Tier 1.5 quietly off. See [08 §6.3](08-kv-cache-aware-routing.md) for the staging
procedure.

### 8.2 SGLang side (must match)

```bash
# per EP (per DP rank when dp > 1 — consecutive ports):
python -m sglang.launch_server --model <MODEL> --port 30000 \
  --kv-events-config '{"publisher":"zmq","endpoint":"tcp://*:5561"}'
# page size: read /get_server_info and set the rule's kvBlockSize to EXACTLY that value.
# SGLang's --page-size default is MODEL-DEPENDENT — never assume 16 (§7).
```

Make the launch a scripted, repeatable recipe rather than an improvised console session.
The required end state per EP: the chosen ZMQ port range verified free with `ss -tln`
before launch (on hosts co-resident with a vLLM publisher, `:5557` is usually taken —
hence e.g. `:5561`); a GPU memory split that leaves both engines' KV caches viable;
readiness gated on **both** `/health` and `/health_generate`; and the rule's
`kvBlockSize` set to the page size read back from `/get_server_info`.

### 8.3 The engine guards

| Guard | Behavior | Where |
|---|---|---|
| Engine allowlist | `kvEngineType` ∈ {`""`, `"vllm"`, `"sglang"`} — unknown strings are **rejected**, never silently vllm | `kvEngineConfigValidate` in `rules.go` |
| Rank bounds | `kvDpRankCount` ≤ 8 (caps the port-range walk); violation returns `kv-dp-rank-count must be within 1..8 (0 = default 1)` | same |
| **Immutability** | engine change on a live rule ⇒ `RuleExistsErr` + exact message `lbrule-exist error: cant modify rule kv engine type (delete and recreate)`; `""`≡`"vllm"` equivalence honored. Deliberately **absent** from the change-detect OR-chain — a change must REJECT, never trigger a ruleChg delete+re-add; the check sits *before* the `!ruleChg` short-circuit so an engine-only PUT gets the exact message | `kvEngineImmutabilityCheck` in `rules.go`, wired at the rule-exists branch of `AddLbRule` |
| Same-VIP mix | two rules on one VIP IP with different engines are **ACCEPTED** (that *is* the coexistence story) + one WARN naming both engines | `kvEngineMixDetect` in `rules.go`, wired in `AddLbRule` |

> **Accepted limitation (documented in the swagger description):** the `LOXILB_KV_*` env
> knobs — unified mode, ε/λ, `LOXILB_KV_CAP_SUM_MILLI`, `LOXILB_KV_MAX_BLOCKS` — are
> **process-global and shared across all KV VIPs**, vLLM and SGLang alike. Per-rule
> override is a deferred follow-up.

---

## 9. Observability — log markers & metrics quick table

### 9.1 Log markers (grep keys)

| Prefix / marker | Source | What it traces |
|---|---|---|
| `[KV_SR]` | C, `sockproxy_ep.c` | single-role Tier-1.5 decision: `fd=%d single-role Tier-1.5 HIT -> EP%d` (miss = no line; the rule's own selector routes) |
| `[KV_T15]` | C, `sockproxy_kv_exact.c` | the guard ladder A–G, unchanged from doc 08 §7.2 — fires identically on the single-role path |
| `[KV_ZEROHIT]` | Go, `kvZeroHitWatchdog` in `ai_kv_subscriber.go` | watchdog WARN (once per transition edge) — the silent-parity-failure tripwire |
| `[KV_CONFIG]` | C, the emit in `proxy_add_entry` (`sockproxy_http.c`) | rule config landing in the data plane, now incl. `kv_engine_type= kv_dp_rank_count= kv_svc_id=` |
| `kv-subscriber: ep N rank R seq gap A -> B (missing G, no replay) decision=KEEP\|CLEAR` | Go | mid-stream gap decision (§5.3) — the CICD anchor |
| `kv-subscriber: ep N rank R … resync KEEP\|CLEAR` | Go | post-reconnect decision, now rank-keyed |
| `kv-subscriber: AllBlocksCleared received for ep N (rank R) — clearing shared inventory` | Go | union over-clear (§5.4) |
| `[KV_HASH]` … `algo=sha256_sglang` | C (needs `LLB_KV_HASH_DEBUG=1`) | per-block parity forensics — dedicated SGLang emit reporting the FIRST-8 published value |

```bash
# single-role routing decisions + guard misses
grep -E '\[KV_SR\]|\[KV_T15\]' loxilb.log
# multi-rank subscriber lifecycle + decisions
grep -E 'kv-subscriber:.*(rank|decision=|clearing shared inventory)' loxilb.log
# the parity tripwire
grep '\[KV_ZEROHIT\]' loxilb.log
```

⚠ The Go markers are **logrus stderr** lines — in the stock container launch that stream
is discarded; the CICD scenario relaunches loxilb with stderr captured
to `/var/log/loxilb-go.log` before asserting on any of them.

### 9.2 Metrics

| Metric | Labels | Type | Meaning |
|---|---|---|---|
| `loxilb_pd_kv_zero_hit_watchdog_total` | `service_id` | counter | lookups at-or-past the consecutive-zero-hit threshold against a non-empty inventory. Nonzero = the authoritative silent hash-parity-failure signal |
| `loxilb_pd_kv_tier15_hits_total` | `ep_idx` | counter | unchanged — increments for single-role hits too (labels are opaque per-rule ep indexes; the coexistence scenario attributes VIPs by *disjoint* index steering) |
| `loxilb_pd_kv_tier15_miss_reason_total` / `loxilb_pd_kv_tier15_fallthrough_total` | `reason` / — | counter | unchanged guard-ladder misses (doc 08 §7.1) — on a single-role rule a fallthrough lands in the rule's own selector, not P/D Tier 2 |
| `loxilb_kv_subscriber_connected` / `reconnect_total` / `recv_error_total` | `service`,`ep` | gauge/counter | unchanged identity — all DP ranks of an EP share the label pair (§5.4 note) |
| `loxilb_pd_kv_blocks` | `service`,`ep_idx` | gauge | unchanged — reports the shared per-EP union inventory |

Env knobs added: `LOXILB_KV_ZERO_HIT_N` (watchdog threshold, default 50, never disabled).

---

## 10. Test & validation status — what is and is NOT proven

**Be precise about this.** The changes are authored and
committed, but the project's binding gates for CGO code run **only** on a Linux
controller (darwin cannot compile `pkg/loxinet`, and the local C harness is a single-TU
sanity build). At the time of writing, **none of the binding gates have run**.

### 10.1 What HAS run (local, non-binding)

| Gate | Result |
|---|---|
| Single-TU C unit harness (`test_kv_exact`, darwin clang + homebrew OpenSSL) | **153/153 PASS** — 107 baseline + SGLang parity vectors + svc-id threading; mode-1 mask byte-identity **mutation-proven** (forced widening ⇒ FAIL `mask=0xf want 0x9`) |
| `gofmt` on every touched Go file; structural greps | clean / PASS |
| `bash -n` + `shellcheck -S error` on all CICD scripts | PASS |
| Mock-publisher self-checks (`--self-check --algo sha256_sglang` 2/2; vLLM mode 8/8 unchanged) | PASS |
| Parity-vector regen reproducibility (bit-exact re-run) + independent core-free cross-check | PASS |
| Dockerized swagger regen executed (not skipped) | PASS |

### 10.2 Binding gate checklist

1. `make clean && make` RC=0 on a Linux build host (full CGO build — the twin-lockstep
   CGO signature change and the new C struct fields compile through the chain).
2. `make test_pd` — the full 9-binary P/D byte-identity roster.
3. `make -C loxilb-ebpf/common test_kv` — including the SGLang parity vectors, the mask
   byte-identity/admits-all cases, and the svc-id threading case.
4. Scoped `go test ./pkg/loxinet/` — `TestKvSingleRole*`, `TestKvMultiRank*`,
   `TestKvEngine*`, `TestKvSvcFilter*`, `TestKvZeroHit*`, plus the untouched
   `TestKvReconnect*`/`TestKvResyncDecision` roster staying green (the "wrap, don't
   rewrite" proof).
5. Execute the **two-VIP coexistence scenario** `cicd/sglang-loxilb-kvcache/`
   (`config.sh && validation.sh && rmconfig.sh`) green: one gateway, VIP-A `:8080` =
   unmodified vLLM P/D mock (kvExactMode=1, cbor, `:5557`), VIP-B `:9090` = SGLang
   single-role (kvExactMode=3, engine=sglang, kvDpRankCount=3, ports `:5561-5563`,
   kvHashAlgo omitted ⇒ default). Seven legs: L0 publisher fidelity, L1 multi-rank
   union (== `blocks_total` AND > max single rank), L2 Tier-1.5 hits on BOTH VIPs
   (disjoint ep_idx attribution), L3 isolation both ways across traffic + rule churn,
   L4 same-model negative control (must FAIL without the §6 svc-id filter — runs
   the revert-mutation once to prove the teeth), L5 engine-immutability (exact
   message), L6 restart-clears + `decision=CLEAR`/`decision=KEEP` discrimination,
   L7 zero-hit watchdog (WARN exactly once + counter delta). Sentinel:
   `SCENARIO-sglang-loxilb-kvcache [OK]`.
6. Byte-identity re-run of the untouched `vllm-kvcache-routing-cpu` scenario (the shared
   mock publisher's default modes must stay green), plus the strict-gate checks
   (inventory-grows, tier15-hit fires, EP-restart-clears).

### 10.3 Remaining live-fleet validation

Still owed on a real GPU fleet: SGLang co-resident beside the vLLM prefill workers, a live
`kvExactMode=3` rule, the live equivalents of the strict-gate checks (inventory-grows,
tier15-hit fires, EP-restart-clears on markers), then a **3-arm competitive A/B** —
loxilb KV-exact vs `sgl-model-gateway --policy cache_aware` (an *approximate* router-side
radix tree with **no** event subscription — the differentiator) vs `round_robin`, with a
pooled-N methodology (N≥3, CV≤10%).

Until that lands, treat every behavioral claim in this document as
**code-verified but not yet live-gate-verified** on a GPU fleet.

---

## 11. Known limits & operational gotchas

1. **`kvBlockSize` ≠ `--page-size` fails silently** — Tier 1.5 never fires, traffic takes
   the fallback selector. Watch `loxilb_pd_kv_zero_hit_watchdog_total` and `[KV_ZEROHIT]`
   (§7); read the page size back from `/get_server_info`, never assume 16.
2. **Omit `kvHashAlgo` on SGLang rules (recommended)** — the engine default derives
   `sha256_sglang` automatically; an explicit `"sha256_sglang"` is also accepted (it is in
   the swagger enum), while a contradictory algo is rejected at config time (§8.1).
3. **`kvEngineType` is immutable** — change = delete + recreate; a PUT returns the exact
    rejection, never a silent re-add (§8.3).
4. **GUARD_B warmup is inert in production** (both paths — §3.3 note):
   `kvWarmupSec` is accepted but currently a no-op; don't design procedures around it.
5. **`AllBlocksCleared` from any rank clears the whole EP inventory** — expected brief
   warmth loss on DP fleets (§5.4).
6. **`LOXILB_KV_*` knobs are process-global** across vLLM and SGLang VIPs (§8.3 note).
7. **Go log markers need stderr capture** — the stock container launch discards logrus
   output (§9.1).
8. **No NONE_HASH machinery on the SGLang path** — `LLB_KV_NONE_HASH_SEED` and
   `PYTHONHASHSEED` parity are vLLM-only concerns; setting them has no effect on algo 2.
9. **Contract frozen at sglang `d8ef76682e`** — the parity vectors pin that commit; a
   future SGLang hash change shows up as a zero-hit watchdog fire, not a gate failure
   (there is no SGLang drift stage yet, unlike vLLM's `KV_CONTRACT_DRIFT.md`).
10. **Single-role miss ≠ P/D Tier 2** — the fallback is the rule's *configured* selector;
    for cache-friendly single-pool behavior on the miss path, pair mode 3 with `sel:8`
    (prefix-hash CHWBL, doc 10 §6).
11. **The tokenizer must be staged, or Tier 1.5 is silently off** — stage the served
    model's HuggingFace `tokenizer.json` at
    `/etc/loxilb/tokenizers/<model-slug>/tokenizer.json` (slug = model id with `/` →
    `__`). A missing tokenizer produces only a warn-once
    `kv-router: tokenizer not available` log and Guard E `tokenize` misses — no error,
    no fallback tokenizer ([08 §6.3](08-kv-cache-aware-routing.md), §8.1 here).

---

## 12. Source map (developers)

| Area | Files (roles) |
|---|---|
| Mode/enum constants + struct fields | `loxilb-ebpf/common/sockproxy.h` — `KV_EXACT_MODE_SINGLE_ROLE 3`, `kv_engine_type`/`kv_dp_rank_count` in BOTH structs, `kv_svc_id`, the warmup-inert note at the `kv_warmup_start` declaration, pfe `kv_sr_*` fields |
| Single-role selection branch + load lifecycle | `loxilb-ebpf/common/sockproxy_ep.c` — the sibling branch in `proxy_sel_ep()`, the `[KV_SR]` inc-on-hit block, the mid-cycle failover re-claim, the connect-fail release |
| Teardown decrement (single owner) | `loxilb-ebpf/common/sockproxy_http.c` — the `pd_cleanup()` release; `kv_svc_id`/engine/rank stamped at both `proxy_add_entry` copy sites + `[KV_CONFIG]` log |
| SGLang hash arm + mask widening + svc-id call | `loxilb-ebpf/common/sockproxy_kv_exact.c` — `kv_hash_sglang_block`, the dedicated SGLang arm of `kv_compute_block_hashes` (FIRST-8 truncation), the `prefill_mask` disjunct and the `llb_ai_kv_best_worker` CGO call in `pd_kv_exact_select`; enum in `sockproxy_kv_exact.h` |
| CGO prototype (twin-lockstep) | the `llb_ai_kv_best_worker` prototype in `loxilb-ebpf/common/sockproxy_ai_gw.h` (+ stubs `sockproxy_ai_gw_stub.c`, `test_kv_exact.c`) |
| C unit + parity vectors | `loxilb-ebpf/common/test_kv_exact.c` — `test_sglang_parity_vectors`, `test_mask_mode1_byte_identity`, `test_mask_mode3_single_role_admits_all`, `test_kv_svc_id_threading` |
| Go gate + engine guards | `pkg/loxinet/rules.go` — `KvExactModeSingleRole`, `kvSubscriberTargets`, `kvEngineConfigValidate`/`kvEngineImmutabilityCheck`/`kvEngineMixDetect`, the `AddLbRule` validations, the per-rank `KvSubscriberStartRank` loops, `KvSubscriberStopAll` |
| Subscriber: KvEventSource / multi-rank / staleness fix / watchdog / svc filter | `pkg/loxinet/ai_kv_subscriber.go` — `kvResyncDecision`, `kvEpRankKey`, `kvSvcScanTargets`, `KvEventSource` + `newKvEventSource`, `runKvSubscriberLoopRank` (`rankLastSeq` + decision markers), `KvSubscriberStartRank`, `kvZeroHitWatchdog` + env parsing, the `kvSvcScanInventories` scan exit, `//export llb_ai_kv_best_worker` |
| Go unit suites | `pkg/loxinet/ai_kv_single_role_test.go`, `ai_kv_multirank_test.go`, `rules_kv_engine_test.go`, `ai_kv_svcfilter_test.go`, `ai_kv_subscriber_hash_vectors_test.go` (SGLang int64 vectors) |
| Config chain (REST → DP) | the `kv*` block of `serviceArguments` in `api/swagger.yml`, `api/restapi/handler/loadbalancer.go`, `common/common.go`, `pkg/loxinet/dpbroker.go`, the `kv_hash_algo`/`kv_engine_type` mapping in `DpLBRuleMod` (`pkg/loxinet/dpebpf_linux.go` — the ONE mapping site) |
| Metrics | `api/prometheus/sockproxy_metrics.go` — `loxilb_pd_kv_zero_hit_watchdog_total`, `IncKvZeroHitWatchdog`, `KvZeroHitWatchdogValue` |
| Hash source of record | `cicd/vllm-kvcache-routing-cpu/sglang_hash_core.py` (pinned `d8ef76682e`) |
| Mock publisher + coexistence scenario | `cicd/vllm-kvcache-routing-cpu/kv_event_publisher.py` (`--algo sha256_sglang`, `--dp-ranks`, `--seq-jump-rank`), `cicd/sglang-loxilb-kvcache/{config,rmconfig,validation}.sh` |

---

## 13. See also

- [08 — KV-cache-aware routing (Tier-1.5 internals)](08-kv-cache-aware-routing.md) — the
  vLLM block-hash contract, guard ladder A–G, and ZMQ inventory plane this integration
  reuses; read its §4 side-by-side with §4 here.
- [10 — Hierarchical KV routing architecture](10-hierarchical-kv-routing-architecture.md)
  — the P/D tier ladder and the single-pool selector family that serves as the mode-3
  miss fallback; its §2 "P/D-only" constraint is what §1/§3 here relax.
- [11 — Configuration & tuning](11-hierarchical-kv-routing-config-tuning.md) — the
  process-global `LOXILB_KV_*` knob reference (shared across engines, §8.3 note).
- [16 — SGLang vs vLLM KV-routing differences](16-sglang-vs-vllm-routing-differences.md) — the
  contract-by-contract comparison this doc's §1/§4 tables summarize.
- [17 — SGLang configuration & tuning](17-sglang-config-tuning.md) — the operator-facing
  companion to §8 (page-size discovery, DP-rank sizing, co-residency splits).
- [20 — TensorRT-LLM KV-cache-aware routing & P/D](20-tensorrt-llm-kv-cache-aware-routing.md)
  — the third engine, which lands on the same subscriber/decoder machinery via an
  HTTP-drain event source and a token re-hash of the same chained-SHA-256 family
  this doc's §4 defines.
- [21 — llama.cpp load balancing](21-llamacpp-load-balancing.md) — the fourth engine,
  which deliberately has NONE of this machinery: no event plane, no P/D, no Tier-1.5 —
  its cache-affinity tier is CHWBL over the system prompt, and the typed guards reject
  every `kv*`/`pd*` rule shape.
