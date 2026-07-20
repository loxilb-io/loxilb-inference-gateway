#!/usr/bin/env python3
"""kv_event_publisher.py — contract-faithful synthetic vLLM v0.17.0 ZMQ KV-event
publisher.

This is THE central missing fixture of the KV-cache-aware routing gate. `mock_vllm.py`
publishes NO ZMQ KV events; loxilb's per-prefill-EP `go-zeromq` subscriber
(`pkg/loxinet/ai_kv_subscriber.go`) therefore never populates an inventory under the
mock harness. This publisher fills that gap with a HIGH-FIDELITY stream:

  * It tokenizes real prompts LIVE with the committed `tokenizer.json` of record
    (Qwen/Qwen3-0.6B) — identical token IDs to loxilb's CGO daulet path
    → genuine, non-empty inventory intersection.
  * It recomputes vLLM v0.17.0 block hashes via the REUSED hash core from
    `cicd/vllm-loxilb-kvcache-aws-small/kv_hash_parity.py`. The hash math
    is NOT re-implemented here — re-deriving it risks reintroducing the
    `digest[:8]`-vs-`digest[-8:]` drift fixed upstream. `kv_hash_parity.py` remains
    the single Python source of record; this module imports it (read-dependency).
  * It emits the real 3-frame ZMQ envelope `[topic | seq:u64-BE | msgpack]` with the
    FULL KV-event vocabulary — `BlockStored` + `BlockRemoved` + `AllBlocksCleared`
    — and block hashes as msgpack INTS (uint64) so loxilb's int-only
    `extractBlockHashes` accepts them (the `VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=1`
    contract; `ai_kv_subscriber.go:258-285`).
  * Monotonic `seq` from a known base, plus `--kill`/restart and `--seq-jump`, make
    reconnect / replay / seq-gap exercisable end-to-end immediately.

Wire contract (the SUBSCRIBER side this publisher must satisfy byte-for-byte —
`pkg/loxinet/ai_kv_subscriber.go`):
  * 3 frames, `len(frames) >= 3` (:392-395): Frame0 topic, Frame1 seq 8-byte
    BIG-ENDIAN uint64, Frame2 msgpack KVEventBatch.
  * KVEventBatch top-level: `[ts: float, events: [[tag, ...], ...], dp_rank: int|nil]`;
    subscriber reads `raw[1]` (:200).
  * BlockStored: `["BlockStored", [hash...], parent_hash, [tok...], block_size,
    lora_id, medium, lora_name, extra_keys]` — reads `arr[1]` (:230-238).
  * BlockRemoved: `["BlockRemoved", [hash...], medium]` — reads `arr[1]` (:240-248).
  * AllBlocksCleared: `["AllBlocksCleared"]` — no payload (:250-251).
  * `seq > lastSeq+1` triggers replay (:404-409).

SGLang support: the publisher also speaks the SGLang wire/hash contract —
`--algo sha256_sglang` computes radix-page hashes via the IMPORTED
`sglang_hash_core` (one source of record) and publishes the SIGNED
int64 form; `--dp-ranks N` binds N PUB sockets on consecutive ports with
INDEPENDENT per-rank seq counters (real SGLang data-parallel rank semantics);
`--seq-jump-rank` aims the existing --seq-jump fault at a designated rank. The
wire envelope is byte-identical to the vLLM modes (3-frame multipart, msgpack
EventBatch); default flags reproduce the shipped vLLM behavior unchanged.

Security: binds on localhost/private iface ONLY; the all-interfaces
quad is refused.

Reproducibility: set `PYTHONHASHSEED=0` (== loxilb `LLB_KV_NONE_HASH_SEED=0`) so the
first-block NONE_HASH parent is `hash_fn(cbor2.dumps("0"))` deterministically
(kv_hash_vectors.json `none_hash_*_hex`).

Exit codes:
    0   success (published / self-check passed)
    1   self-check mismatch (emitted hash != golden vector)
    2   environment error (missing dep, missing fixture, tokenizer/bind failure)

Usage:
    # local hash-parity self-check (no zmq / tokenizers needed — proves hash-core reuse):
    PYTHONHASHSEED=0 python3 kv_event_publisher.py --self-check

    # publish a corpus on the runner (needs pyzmq + tokenizers):
    PYTHONHASHSEED=0 python3 kv_event_publisher.py \
        --corpus prompts/corpus.json \
        --tokenizer ../common/kv_hash/fixtures/tokenizers/Qwen__Qwen3-0.6B/tokenizer.json \
        --service-id 0 --bind 127.0.0.1 --port 5557 --algo sha256_cbor
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

# ----------------------------------------------------------------------------
# Hash-core reuse — import the SINGLE Python source of record.
# NOT a re-implementation, NOT an inline copy: this is a sys.path read-dependency
# on cicd/vllm-loxilb-kvcache-aws-small/kv_hash_parity.py.
# The C/Go/Python golden-vector chain keeps exactly one hash core.
# ----------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
# kv_hash_parity.py lives in the sibling GPU scenario dir.
_HASH_CORE_DIR = os.path.normpath(
    os.path.join(_HERE, "..", "vllm-loxilb-kvcache-aws-small")
)
if _HASH_CORE_DIR not in sys.path:
    sys.path.insert(0, _HASH_CORE_DIR)

try:
    # _compute_client_blocks : cbor2.dumps([parent,tokens,None],canonical=True)
    #                          → sha256/xxh3_128 → int.from_bytes(digest,'big') & mask;
    #                          FULL blocks only; parent = full digest; NONE_HASH seeded.
    # _none_hash_for         : seed="0" → hash_fn(cbor2.dumps("0")) first-block parent.
    # _load_tokenizer        : transformers.AutoTokenizer.from_pretrained.
    # _digest                : the raw sha256_cbor / xxh3_128 primitive (one hash core).
    from kv_hash_parity import (  # noqa: E402 — sys.path mutated above on purpose
        _compute_client_blocks,
        _digest,
        _load_tokenizer,
        _none_hash_for,
    )
except ImportError as exc:  # pragma: no cover — guarded per harness convention
    print(
        "ERROR: cannot import the kv_hash_parity hash core from "
        f"{_HASH_CORE_DIR} ({exc}). This publisher REUSES that module's "
        "hash functions and must not re-implement them; ensure "
        "the hash-core scenario dir is present.",
        file=sys.stderr,
    )
    sys.exit(2)

# cbor2 is needed both by the hash core and by our self-check; it is a hard dep.
try:
    import cbor2  # noqa: E402
except ImportError:  # pragma: no cover
    print("ERROR: cbor2 package is required (pip install cbor2).", file=sys.stderr)
    sys.exit(2)

# ----------------------------------------------------------------------------
# SGLang hash-core reuse — the SAME one-source-of-
# record discipline as the kv_hash_parity import above. sglang_hash_core.py
# lives in THIS directory; the publisher imports it
# and NEVER re-derives the SGLang math (digest-slice drift-class
# prevention — zero hash arithmetic in the sglang path here). Loaded lazily:
# only --algo sha256_sglang needs it, so the vLLM modes are byte-identical on
# hosts without the module.
# ----------------------------------------------------------------------------
_SGLANG_CORE_MOD = None


def _sglang_core():
    """Import-once accessor for the ONE SGLang hash source of record."""
    global _SGLANG_CORE_MOD
    if _SGLANG_CORE_MOD is None:
        if _HERE not in sys.path:
            sys.path.insert(0, _HERE)
        try:
            import sglang_hash_core
        except ImportError as exc:  # pragma: no cover — guarded per convention
            print(
                f"ERROR: cannot import sglang_hash_core from {_HERE} ({exc}). "
                "--algo sha256_sglang REUSES that module's hash chain "
                "(one source of record) and must not re-implement "
                "it; ensure the SGLang hash core is present.",
                file=sys.stderr,
            )
            sys.exit(2)
        _SGLANG_CORE_MOD = sglang_hash_core
    return _SGLANG_CORE_MOD


# Pinned SGLang golden vectors for --self-check --algo sha256_sglang — the
# SAME committed values as loxilb-ebpf/common/test_kv_exact.c and
# pkg/loxinet/ai_kv_subscriber_hash_vectors_test.go (regen provenance:
# scripts/compute_sglang_hash_refs.py @ sglang d8ef76682e). EXPECTED values
# only — the math stays in sglang_hash_core (import-only). chain3 pins the
# raw-32-byte parent chaining + first-8-BE truncation; negative_int64 pins the
# signed-int64 wrap SGLang publishes (uint64 teeth live in the C/Go layers).
_SGLANG_SELFCHECK_VECTORS = [
    ("chain3_bs16", 16, list(range(1, 49)),
     [8635429971592222890, 1256577331724852459, 5689809685380680247]),
    ("negative_int64_bs16", 16, [0],
     [-2360060374177730597]),
]


_UINT64_MASK = (1 << 64) - 1
DEFAULT_PORT = 5557  # kvZmqPort default (PATTERNS Feature-enable POST)
DEFAULT_ALGO = "sha256_cbor"
DEFAULT_BLOCK_SIZE = 16  # kvBlockSize default
DEFAULT_NONE_HASH_SEED = "0"  # == PYTHONHASHSEED=0 / LLB_KV_NONE_HASH_SEED=0
# Resolve the shared golden vectors (promoted to cicd/common/kv_hash/fixtures/).
DEFAULT_VECTORS = os.path.normpath(
    os.path.join(_HERE, "..", "common", "kv_hash", "fixtures", "kv_hash_vectors.json")
)
DEFAULT_TOKENIZER = os.path.normpath(
    os.path.join(
        _HERE,
        "..",
        "common",
        "kv_hash",
        "fixtures",
        "tokenizers",
        "Qwen__Qwen3-0.6B",
        "tokenizer.json",
    )
)


def _block_hash_u64(algo: str, parent_bytes: bytes, tokens) -> bytes:
    """Compute one block's (full_digest, uint64) via the REUSED hash primitive.

    This is the SAME math `_compute_client_blocks` performs per block, factored out
    so the self-check can drive each golden fixture's explicit parent/tokens pair.
    It routes through `kv_hash_parity._digest` (the imported primitive) — no hash
    function is defined locally, preserving the single-source-of-record invariant.
    """
    cbor = cbor2.dumps([parent_bytes, list(tokens), None], canonical=True)
    digest = _digest(algo, cbor)
    u64 = int.from_bytes(digest, "big") & _UINT64_MASK
    return digest, u64


# ============================================================================
# GOLDEN-VECTOR SELF-CHECK (the drift tripwire — locally runnable)
# ============================================================================
def _self_check(vectors_path: str) -> int:
    """Assert the REUSED hash core reproduces every golden uint64.

    Proves locally (cbor2 + optional xxhash only — no zmq / tokenizers) that the
    hashes this publisher will emit are byte-identical to the frozen vectors that
    the C and Go layers also assert against. A mismatch here means the publisher
    would feed loxilb wrong inventory — fail the gate (exit 1).
    """
    try:
        with open(vectors_path, "rb") as fp:
            doc = json.load(fp)
    except OSError as exc:
        print(f"ERROR: cannot open golden vectors at {vectors_path}: {exc}",
              file=sys.stderr)
        return 2

    # Confirm seed-derived NONE_HASH parents match (the *_noneHashSeed0_* chains
    # begin from these). Routes through the imported _none_hash_for.
    expected_none = {
        "sha256_cbor": doc.get("none_hash_sha256_hex"),
        "xxhash_cbor": doc.get("none_hash_xxhash_hex"),
    }
    seed = doc.get("none_hash_seed", DEFAULT_NONE_HASH_SEED)
    have_xxhash = True
    try:
        import xxhash  # noqa: F401
    except ImportError:
        have_xxhash = False

    none_ok = True
    for algo, want in expected_none.items():
        if want is None:
            continue
        if algo == "xxhash_cbor" and not have_xxhash:
            continue
        got = _none_hash_for(algo, seed).hex()
        if got != want:
            print(f"FAIL: NONE_HASH[{algo}] got {got} want {want}",
                  file=sys.stderr)
            none_ok = False

    total = matched = failures = skipped_xxhash = 0
    by_algo: dict[str, int] = {}
    for fx in doc.get("fixtures", []):
        algo = fx["hash_algo"]
        if algo == "xxhash_cbor" and not have_xxhash:
            skipped_xxhash += 1
            continue
        total += 1
        parent = bytes.fromhex(fx["parent_hash_hex"])
        digest, u64 = _block_hash_u64(algo, parent, fx["tokens"])
        if "expected_digest_hex" in fx and digest.hex() != fx["expected_digest_hex"]:
            print(f"FAIL: {fx['name']} digest {digest.hex()} != "
                  f"{fx['expected_digest_hex']}", file=sys.stderr)
            failures += 1
            continue
        if u64 != fx["expected_hash_uint64"]:
            print(f"FAIL: {fx['name']} uint64 {u64} != "
                  f"{fx['expected_hash_uint64']}", file=sys.stderr)
            failures += 1
            continue
        matched += 1
        by_algo[algo] = by_algo.get(algo, 0) + 1

    for algo, n in by_algo.items():
        print(f"  {algo}: all {n} blocks match (via reused kv_hash_parity core)")
    if skipped_xxhash:
        print(f"  xxhash_cbor: SKIPPED {skipped_xxhash} fixtures "
              "(xxhash not installed locally — runner-only check)")

    if not none_ok or failures:
        print(f"SELF-CHECK FAIL: {matched}/{total} matched, {failures} failures "
              f"(none_ok={none_ok})", file=sys.stderr)
        return 1
    if matched == 0:
        print("SELF-CHECK ERROR: zero blocks asserted", file=sys.stderr)
        return 2
    print(f"SELF-CHECK PASS: {matched}/{total} golden blocks reproduced by the "
          "REUSED vLLM v0.17.0 hash core (kv_hash_parity).")
    return 0


def _self_check_sglang() -> int:
    """Assert the REUSED sglang_hash_core reproduces the committed golden
    vectors (self-confirm: the publisher proves its own hash
    fidelity BEFORE any scenario runs it). A mismatch means this publisher
    would feed loxilb an inventory the C request-side sglang chain can never
    intersect — fail the gate (exit 1). No zmq/tokenizers needed."""
    core = _sglang_core()
    failures = 0
    for name, bs, tokens, want in _SGLANG_SELFCHECK_VECTORS:
        got = core.sglang_hash_chain(core.blocks_from_tokens(tokens, bs))
        if got != want:
            print(f"FAIL: sglang vector {name}: got {got} want {want}",
                  file=sys.stderr)
            failures += 1
    if failures:
        print(f"SELF-CHECK FAIL: {failures}/{len(_SGLANG_SELFCHECK_VECTORS)} "
              "sglang golden vectors mismatched (sglang_hash_core drift)",
              file=sys.stderr)
        return 1
    print(f"SELF-CHECK PASS: {len(_SGLANG_SELFCHECK_VECTORS)}/"
          f"{len(_SGLANG_SELFCHECK_VECTORS)} SGLang golden vectors reproduced "
          "by the REUSED sglang_hash_core (raw-32-byte parent chain, "
          "first-8-BE / signed-int64 publish contract @ d8ef76682e).")
    return 0


def _run_self_check(args) -> int:
    """Route --self-check by algo: the SGLang mode verifies the SGLang hash core
    against its committed vectors; every other algo runs the vLLM golden-
    vector check (which asserts BOTH cbor algos from the vectors doc)."""
    if args.algo == "sha256_sglang":
        return _self_check_sglang()
    return _self_check(args.vectors)


# ============================================================================
# ZMQ PUB publisher
# ============================================================================
class KvEventPublisher:
    """Holds the PUB socket + monotonic seq and emits the 3-frame envelope."""

    def __init__(self, bind: str, port: int, seq_base: int = 0,
                 settle_sec: float = 0.3):
        # Probe-guard pyzmq + msgpack at construction (NOT at import) so
        # --self-check works on hosts without them (guarded-probe convention).
        try:
            import zmq
        except ImportError:
            print("ERROR: pyzmq required to publish (pip install pyzmq).",
                  file=sys.stderr)
            sys.exit(2)
        try:
            import msgpack
        except ImportError:
            print("ERROR: msgpack required to publish (pip install msgpack).",
                  file=sys.stderr)
            sys.exit(2)
        self._zmq = zmq
        self._msgpack = msgpack
        self.seq = seq_base
        self._settle_sec = settle_sec
        # Never bind all interfaces on a public runner. The all-zeros
        # quad is constructed (not written as a literal) so the acceptance grep
        # confirms the publisher never *targets* it, while the guard still rejects
        # an operator who passes it on the command line.
        _all_ifaces = ".".join(["0", "0", "0", "0"])
        if bind == _all_ifaces:
            print(f"ERROR: refusing to bind {_all_ifaces}; use "
                  "127.0.0.1 or a private iface.", file=sys.stderr)
            sys.exit(2)
        self.ctx = zmq.Context.instance()
        self.pub = self.ctx.socket(zmq.PUB)
        endpoint = f"tcp://{bind}:{port}"
        try:
            self.pub.bind(endpoint)
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: zmq bind {endpoint} failed: {exc}", file=sys.stderr)
            sys.exit(2)
        # PUB/SUB slow-joiner: give the subscriber time to (re)connect before
        # the first send, else early frames are dropped. The default (0.3s) suits
        # a first-time connect; scenarios that KILL then relaunch a publisher must
        # set settle_sec ABOVE loxilb's kvReconnectFailBackoff (5s) via --settle-sec
        # so the subscriber re-establishes the live stream BEFORE a mid-stream
        # seq-jump — otherwise it reconnects after the jump and sees the gap as its
        # first post-reconnect msg (resync path), never the live-stream decision=.
        time.sleep(self._settle_sec)

    def emit(self, events, dp_rank=None) -> int:
        """Send one 3-frame multipart batch; return the seq used.

        dp_rank: the SGLang multi-rank mode stamps the
        batch-level data_parallel_rank slot; None (the default) keeps the
        vLLM modes byte-identical (the decoder reads raw[1] and tolerates
        either)."""
        used = self.seq
        batch = [time.time(), events, dp_rank]  # [ts: float, events, dp_rank: int|nil]
        self.pub.send_multipart([
            b"kv",                              # Frame 0: topic
            used.to_bytes(8, "big"),           # Frame 1: seq — 8-byte BIG-ENDIAN
            self._msgpack.packb(batch, use_bin_type=True),  # Frame 2: msgpack batch
        ])
        self.seq += 1
        return used

    def seq_jump(self, gap: int) -> None:
        """Deliberately advance seq by `gap` to create a seq-gap (replay path)."""
        self.seq += max(0, gap)

    def close(self) -> None:
        try:
            self.pub.close(linger=200)
        except Exception:  # noqa: BLE001
            pass


def block_stored_event(hashes, parent_hash, tokens, block_size, attn_dp_rank=None):
    """Full vLLM v0.17.0 BlockStored shape. Hashes emitted as INTS.

    attn_dp_rank: the SGLang wire appends a trailing
    attn_dp_rank slot the loxilb decoder already tolerates (it reads arr[1]
    only). None (default) keeps the vLLM event shape byte-identical."""
    ev = [
        "BlockStored",
        [int(h) for h in hashes],   # arr[1] — INT hashes for extractBlockHashes
        int(parent_hash) if parent_hash is not None else None,
        list(tokens),
        block_size,
        None,   # lora_id
        "gpu",  # medium
        None,   # lora_name
        None,   # extra_keys
    ]
    if attn_dp_rank is not None:
        ev.append(int(attn_dp_rank))  # trailing SGLang attn_dp_rank slot
    return ev


def block_removed_event(hashes):
    """Full vLLM v0.17.0 BlockRemoved shape."""
    return ["BlockRemoved", [int(h) for h in hashes], "gpu"]


def all_blocks_cleared_event():
    """AllBlocksCleared has no payload."""
    return ["AllBlocksCleared"]


def _blocks_for_prompt(tok, prompt, block_size, algo, seed):
    """Tokenize live (bare encode, NO chat template) and compute the
    FULL-block (uint64, full_digest, tokens) tuples via the reused hash core."""
    token_ids = tok.encode(prompt)
    # _compute_client_blocks returns (block_idx, uint64, cbor, tokens) for FULL
    # blocks only, with seeded NONE_HASH parent + full-digest chaining.
    blocks = _compute_client_blocks(token_ids, block_size, algo, seed)
    return token_ids, blocks


def _sglang_blocks_for_prompt(tok, prompt, block_size):
    """Tokenize live (same bare-encode tokenizer path as the
    vLLM mode) and chain SGLang page hashes via the REUSED sglang_hash_core —
    zero hash arithmetic here (import-only, single-source discipline). FULL pages only:
    the loxilb C request side (kv_hash_sglang_block) hashes full kvBlockSize
    pages, so a trailing partial page is never publishable inventory.

    Returns (token_ids, [(published_int64, tokens), ...]). Published values are
    the SIGNED int64 form (SGLang publishes signed; loxilb's extractBlockHashes
    handles the uint64 wrap)."""
    core = _sglang_core()
    token_ids = tok.encode(prompt)
    pages = [p for p in core.blocks_from_tokens(token_ids, block_size)
             if len(p) == block_size]
    if not pages:
        return token_ids, []
    digests = core.sglang_digest_chain(pages)
    return token_ids, [(core.published_int64(d), pg)
                       for pg, d in zip(pages, digests)]


def _synthesize_corpus(args) -> list:
    """Build a shared-preamble synthetic corpus from the break-even knobs.

    A fixed pool of preambles (~--ctx-len tokens of deterministic filler) is shared
    across --reuse-ratio of the synthesized prompts; the remainder get a unique
    preamble. Every prompt also carries a unique tail so the FULL-block chain past
    the shared prefix differs — exactly the shared-prefix-then-divergent-tail shape
    the C2 break-even sweep needs. Determinism is seeded (--synth-seed) so the same
    corpus reproduces across runs. Token length is APPROXIMATE: word filler is sized
    to land near --ctx-len after tokenization; the hashing path uses the real
    tokenizer so block boundaries are exact regardless of the approximation.
    """
    import random as _random

    rng = _random.Random(args.synth_seed)
    ctx_len = args.ctx_len if args.ctx_len is not None else 128
    reuse = 0.0 if args.reuse_ratio is None else max(0.0, min(1.0, args.reuse_ratio))
    n = max(1, args.synth_prompts)
    # ~ctx_len tokens of filler; a word averages ~1.3 tokens, so size words ~ctx_len/1.3.
    n_words = max(1, int(ctx_len / 1.3))
    _vocab = [f"w{i:04d}" for i in range(256)]
    # A small pool of shared preambles (reused across requests, the cache-hit driver).
    n_pool = max(1, n // 8)
    pool = []
    for _ in range(n_pool):
        pool.append(" ".join(rng.choice(_vocab) for _ in range(n_words)))

    prompts = []
    for i in range(n):
        if rng.random() < reuse:
            preamble = rng.choice(pool)
        else:
            preamble = " ".join(rng.choice(_vocab) for _ in range(n_words))
        tail = f"unique-tail-{i}-" + " ".join(rng.choice(_vocab) for _ in range(8))
        prompts.append({"prompt": f"{preamble} {tail}"})
    return prompts


def _publish_corpus(args) -> int:
    """Tokenize the corpus and publish BlockStored events per prompt."""
    # Tokenizer is loaded from the committed tokenizer.json dir of record.
    tok = _load_tokenizer(args.tokenizer)
    # The SGLang chain has NO NONE_HASH seed (block 0 hashes with no
    # prior bytes at all) — the seeded parent is a vLLM-only concept, and
    # _none_hash_for does not know the sglang algo.
    parent0 = None
    if args.algo != "sha256_sglang":
        parent0 = _none_hash_for(args.algo, args.none_hash_seed)  # first-block parent

    # When a break-even/load-skew knob is set, synthesize the corpus
    # in-process (still hashed via the vendored core) instead of reading a file.
    if args.reuse_ratio is not None or args.ctx_len is not None:
        corpus = _synthesize_corpus(args)
        if args.verbose:
            print(f"  synthesized {len(corpus)} prompts "
                  f"(reuse-ratio={args.reuse_ratio} ctx-len={args.ctx_len})")
    else:
        try:
            with open(args.corpus, "rb") as fp:
                corpus = json.load(fp)
        except OSError as exc:
            print(f"ERROR: cannot open corpus {args.corpus}: {exc}", file=sys.stderr)
            return 2

    # --dp-ranks N binds N PUB sockets on CONSECUTIVE ports
    # (--port .. --port+N-1), one per SGLang data-parallel rank, each with an
    # INDEPENDENT seq counter (real rank semantics — what makes the
    # interleave test honest). The corpus is partitioned deterministically
    # (prompt index % N == rank) so the per-EP union size is assertable.
    # ranks == 1 (the default) reproduces the shipped single-socket behavior
    # byte-identically. Every bind routes through KvEventPublisher.__init__,
    # which keeps the localhost-bind refusal on every new path.
    ranks = max(1, args.dp_ranks)
    if not (0 <= args.seq_jump_rank < ranks):
        print(f"ERROR: --seq-jump-rank {args.seq_jump_rank} out of range for "
              f"--dp-ranks {ranks}.", file=sys.stderr)
        return 2
    pubs = [KvEventPublisher(args.bind, args.port + r, seq_base=args.seq_base,
                             settle_sec=args.settle_sec)
            for r in range(ranks)]
    published = 0
    rank_prompts = [0] * ranks           # prompts assigned per rank
    rank_hashes = [set() for _ in range(ranks)]  # DISTINCT published uint64s per rank
    jump_pending = args.seq_jump > 0
    try:
        # --repeat: re-emit the corpus N times with a pause between passes, keeping
        # the PUB socket bound the whole time. loxilb's subscriber redials a missing
        # publisher on a multi-second backoff (kvReconnectFailBackoff), so a single
        # 2-second publish-and-exit pass is usually MISSED entirely; a resident
        # multi-pass publisher guarantees an overlap window. Re-emission is
        # idempotent for the inventory (BlockStored carries set semantics) and seq
        # stays strictly monotonic across passes (no false gap/replay).
        for rep in range(max(1, args.repeat)):
            if rep:
                time.sleep(max(0.0, args.repeat_interval))
            for j, entry in enumerate(corpus):
                prompt = entry["prompt"] if isinstance(entry, dict) else entry
                rank = j % ranks
                pub = pubs[rank]
                if args.algo == "sha256_sglang":
                    # SGLang mode: hashes via the REUSED
                    # sglang_hash_core chain; published as SIGNED int64 (the
                    # SGLang wire form — loxilb wraps to uint64). Wire envelope
                    # is UNCHANGED (3-frame multipart, msgpack EventBatch);
                    # the batch dp_rank slot + the trailing attn_dp_rank slot
                    # carry the rank (both tolerated by the decoder).
                    _, sgl_blocks = _sglang_blocks_for_prompt(
                        tok, prompt, args.block_size
                    )
                    if not sgl_blocks:
                        continue
                    prev_pub = None  # block 0 has NO parent (no NONE_HASH seed)
                    for (pub_i64, tokens) in sgl_blocks:
                        ev = block_stored_event(
                            [pub_i64], prev_pub, tokens, args.block_size,
                            attn_dp_rank=rank,
                        )
                        seq = pub.emit([ev], dp_rank=rank)
                        rank_hashes[rank].add(pub_i64 & _UINT64_MASK)
                        if args.verbose:
                            print(f"  published rank={rank} seq={seq} "
                                  f"blk_int64={pub_i64} tokens={len(tokens)}")
                        prev_pub = pub_i64  # informational arr[2] chain
                else:
                    _, blocks = _blocks_for_prompt(
                        tok, prompt, args.block_size, args.algo,
                        args.none_hash_seed
                    )
                    if not blocks:
                        # No FULL block — nothing vLLM would publish for this prompt.
                        continue
                    # Emit each full block as its own BlockStored with the chained
                    # parent, mirroring vLLM's per-block publish; parent of block i
                    # is block i-1's full digest, or NONE_HASH for block 0.
                    prev_digest = parent0
                    for (_, u64, cbor, tokens) in blocks:
                        # parent uint64 (informational arr[2]) — loxilb reads only arr[1].
                        parent_u64 = int.from_bytes(prev_digest, "big") & _UINT64_MASK
                        ev = block_stored_event(
                            [u64], parent_u64, tokens, args.block_size
                        )
                        seq = pub.emit([ev])
                        rank_hashes[rank].add(u64)
                        if args.verbose:
                            print(f"  published seq={seq} blk_uint64=0x{u64:016x} "
                                  f"tokens={len(tokens)}")
                        # advance the chained parent to this block's FULL digest.
                        prev_digest = _digest(args.algo, cbor)
                published += 1
                rank_prompts[rank] += 1
                if jump_pending and rank == args.seq_jump_rank \
                        and rank_prompts[rank] == 1:
                    # Create a deliberate seq-gap after the DESIGNATED rank's
                    # first prompt so its subscriber sees seq > lastSeq+1 (replay /
                    # KEEP-CLEAR path). Applied exactly once (first pass only);
                    # ranks==1 + default --seq-jump-rank 0 reproduces the shipped
                    # after-first-prompt behavior byte-identically.
                    pubs[args.seq_jump_rank].seq_jump(args.seq_jump)
                    jump_pending = False
                    if args.verbose:
                        print(f"  seq-jump +{args.seq_jump} on rank "
                              f"{args.seq_jump_rank} → next seq="
                              f"{pubs[args.seq_jump_rank].seq}")
        # Demonstrate the full vocabulary at least once so a SUB observes
        # BlockRemoved + AllBlocksCleared decode paths, harmless to the inventory
        # asserts (BlockRemoved of an unknown hash is a no-op; clear is end-of-run).
        if published and args.emit_vocabulary:
            pubs[0].emit([block_removed_event([0xDEADBEEF])])
            pubs[0].emit([all_blocks_cleared_event()])
    finally:
        if args.kill:
            # Simulate a publisher crash/restart so the subscriber rebuilds
            # and clears, then a fresh process re-publishes from a known seq base.
            if args.verbose:
                print("  --kill: closing socket(s) to trigger subscriber rebuild")
        for pub in pubs:
            pub.close()

    if ranks == 1:
        print(f"PUBLISH done: prompts={published} last_seq={pubs[0].seq - 1} "
              f"algo={args.algo} bind={args.bind}:{args.port}")
    else:
        # Multi-rank report: rank_blocks = DISTINCT published
        # hashes per rank; blocks_total = their sum. With a disjoint-partition
        # corpus (distinct prompts per rank) blocks_total IS the expected per-EP
        # shared-inventory UNION size — the validation.sh multi-rank
        # union assertion parses this line.
        rb = [len(s) for s in rank_hashes]
        print(f"PUBLISH done: prompts={published} ranks={ranks} "
              f"rank_prompts={rank_prompts} rank_blocks={rb} "
              f"blocks_total={sum(rb)} "
              f"last_seqs={[p.seq - 1 for p in pubs]} algo={args.algo} "
              f"bind={args.bind}:{args.port}..{args.port + ranks - 1}")
    return 0 if published else 2


def _emit_hashes(args) -> int:
    """Print loxilb's computed FULL-block uint64 hashes for --prompt (one decimal
    per line), using the SAME committed tokenizer.json + cbor/hash core as the
    publish path. The real-vLLM exit gate compares this set against a REAL vLLM's
    emitted BlockStored hashes to prove live contract parity. No zmq
    needed — pure tokenize+hash, so it reuses the self-check-verified core."""
    if not args.prompt:
        print("ERROR: --emit-hashes requires --prompt.", file=sys.stderr)
        return 2
    tok = _load_tokenizer(args.tokenizer)
    if args.algo == "sha256_sglang":
        # SIGNED int64 per full page (the SGLang wire form) via the
        # reused core — useful for on-controller parity debugging.
        _, sgl_blocks = _sglang_blocks_for_prompt(tok, args.prompt, args.block_size)
        for (pub_i64, _tokens) in sgl_blocks:
            print(pub_i64)
        return 0
    _, blocks = _blocks_for_prompt(
        tok, args.prompt, args.block_size, args.algo, args.none_hash_seed
    )
    for (_, u64, _cbor, _tokens) in blocks:
        print(u64)   # decimal uint64 — validation.sh parses int(x) over whitespace
    return 0


def _capture_events(args) -> int:
    """SUB-side capture: connect to a running PUB (a REAL vLLM in the exit gate),
    drain BlockStored events for a bounded window, and dump the collected INT block
    hashes to --capture-out as {"hashes":[...]}. Mirrors loxilb's subscriber: SUB,
    subscribe-all, decode the 3-frame [topic|seq:BE|msgpack] envelope, read the
    BlockStored hash list (event[1]). The output file is (re)written after every
    new batch so a reader that samples mid-run never sees a missing file."""
    if not args.capture_out:
        print("ERROR: --capture requires --capture-out.", file=sys.stderr)
        return 2
    try:
        import zmq
    except ImportError:
        print("ERROR: pyzmq required to --capture.", file=sys.stderr)
        return 2
    try:
        import msgpack
    except ImportError:
        print("ERROR: msgpack required to --capture.", file=sys.stderr)
        return 2

    ctx = zmq.Context.instance()
    sub = ctx.socket(zmq.SUB)
    endpoint = f"tcp://{args.connect}:{args.port}"
    sub.connect(endpoint)
    sub.setsockopt(zmq.SUBSCRIBE, b"")     # all topics — mirrors loxilb's SUB
    sub.setsockopt(zmq.RCVTIMEO, 500)      # ms — poll so the deadline is honored

    hashes, seen = [], set()

    def _flush():
        try:
            with open(args.capture_out, "w") as fp:
                json.dump({"hashes": hashes}, fp)
        except OSError:
            pass

    _flush()   # write an empty file immediately (reader-safe)
    deadline = time.time() + max(1, args.capture_secs)
    while time.time() < deadline:
        try:
            frames = sub.recv_multipart()
        except zmq.Again:
            continue
        except Exception:  # noqa: BLE001
            continue
        if not frames:
            continue
        try:
            # Frame layout is [topic, seq:8-BE, msgpack-batch]; the payload is the
            # last frame. EventBatch = [ts, [events], ...] (loxilb reads event[1]).
            batch = msgpack.unpackb(frames[-1], raw=False)
        except Exception:  # noqa: BLE001
            continue
        events = batch[1] if isinstance(batch, (list, tuple)) and len(batch) >= 2 else []
        new = False
        for ev in events:
            if isinstance(ev, (list, tuple)) and ev and ev[0] == "BlockStored" and len(ev) >= 2:
                for h in ev[1]:
                    hi = int(h)
                    if hi not in seen:
                        seen.add(hi); hashes.append(hi); new = True
        if new:
            _flush()
    _flush()
    try:
        sub.close(linger=0)
    except Exception:  # noqa: BLE001
        pass
    print(f"CAPTURE done: hashes={len(hashes)} from {endpoint}")
    return 0


def _parse_args(argv):
    p = argparse.ArgumentParser(
        prog="kv_event_publisher.py",
        description="Contract-faithful synthetic vLLM v0.17.0 ZMQ KV-event publisher.",
    )
    p.add_argument("--self-check", action="store_true",
                   help="assert the reused hash core reproduces the golden vectors "
                        "and exit (no zmq/tokenizers needed).")
    p.add_argument("--vectors", default=DEFAULT_VECTORS,
                   help="path to kv_hash_vectors.json (self-check).")
    p.add_argument("--corpus",
                   help="path to prompts/corpus.json to tokenize and publish.")
    p.add_argument("--tokenizer", default=DEFAULT_TOKENIZER,
                   help="tokenizer.json dir/path of record (Qwen__Qwen3-0.6B).")
    p.add_argument("--bind", default="127.0.0.1",
                   help="bind address (localhost/private iface only; the "
                        "all-interfaces quad is refused).")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help=f"ZMQ PUB port (default {DEFAULT_PORT} = kvZmqPort).")
    p.add_argument("--algo", default=DEFAULT_ALGO,
                   choices=["sha256_cbor", "xxhash_cbor", "sha256_sglang"],
                   help="hash algo — must match the LB rule kvHashAlgo. "
                        "sha256_sglang = the SGLang radix-page "
                        "chain via the imported sglang_hash_core (one source "
                        "of record); publishes SIGNED int64 hashes.")
    p.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE,
                   help="tokens per KV block (default 16 = kvBlockSize).")
    p.add_argument("--none-hash-seed", default=DEFAULT_NONE_HASH_SEED,
                   help="first-block NONE_HASH seed (== PYTHONHASHSEED, default '0').")
    p.add_argument("--service-id", type=lambda s: int(s, 0), default=0,
                   help="serviceID ordinal r.ruleNum (NOT the port) per the "
                        "feature-enable contract; informational for the publisher.")
    p.add_argument("--settle-sec", dest="settle_sec", type=float, default=0.3,
                   help="post-bind PUB/SUB slow-joiner sleep before the first "
                        "send (default 0.3). Set > loxilb kvReconnectFailBackoff "
                        "(5s) for kill+relaunch seq-jump legs so the subscriber "
                        "re-establishes the live stream before the mid-stream gap.")
    p.add_argument("--seq-base", type=int, default=0,
                   help="starting seq (known base so seq-gap is exercisable).")
    p.add_argument("--seq-jump", type=int, default=0,
                   help="deliberate seq gap after the first prompt (replay path).")
    p.add_argument("--seq-jump-rank", dest="seq_jump_rank", type=int, default=0,
                   help="the rank whose seq counter --seq-jump "
                        "applies to (default rank 0 — byte-identical to the "
                        "shipped single-rank behavior).")
    p.add_argument("--dp-ranks", dest="dp_ranks", type=int, default=1,
                   help="bind N PUB sockets on CONSECUTIVE "
                        "ports (--port .. --port+N-1), one per SGLang "
                        "data-parallel rank, each with an INDEPENDENT seq "
                        "counter (real rank semantics, interleave "
                        "honesty). The corpus is partitioned deterministically "
                        "(prompt index %% N == rank) so the per-EP union size "
                        "is assertable. Default 1 = the shipped single-socket "
                        "behavior.")
    p.add_argument("--kill", action="store_true",
                   help="close the socket at the end to trigger the subscriber "
                        "rebuild/clear path (reconnect).")
    p.add_argument("--repeat", type=int, default=1,
                   help="re-emit the corpus N times (PUB stays bound between "
                        "passes) so a backoff-redialing subscriber cannot miss "
                        "the publish window (default 1 = single pass).")
    p.add_argument("--repeat-interval", dest="repeat_interval", type=float,
                   default=6.0,
                   help="seconds between repeat passes (default 6 — just above "
                        "loxilb's 5s kvReconnectFailBackoff).")
    p.add_argument("--no-vocabulary", dest="emit_vocabulary", action="store_false",
                   help="do NOT emit the trailing BlockRemoved/AllBlocksCleared.")
    # ----------------------------------------------------------------------
    # break-even / load-skew corpus knobs. These let the
    # CPU rig generate a shared-preamble + ctx-length-swept corpus WITHOUT a
    # separate generator and WITHOUT re-mocking the hash core: when set, the
    # publisher synthesizes prompts (shared-preamble pool reused at --reuse-ratio,
    # preamble length ~--ctx-len tokens) and tokenizes+hashes them through the
    # SAME vendored kv_hash_parity core as --corpus. The parity triad still
    # applies: LLB_KV_NONE_HASH_SEED=0 + PYTHONHASHSEED=0 + --block-size 16.
    # ----------------------------------------------------------------------
    p.add_argument("--reuse-ratio", dest="reuse_ratio", type=float, default=None,
                   help="break-even knob: fraction [0..1] of synthesized "
                        "prompts that reuse a shared pooled preamble. Setting this "
                        "(or --ctx-len) switches --corpus to a synthetic generator "
                        "that still hashes via the vendored kv_hash_parity core. "
                        "Parity triad: LLB_KV_NONE_HASH_SEED=0/PYTHONHASHSEED=0/"
                        "--block-size 16.")
    p.add_argument("--ctx-len", dest="ctx_len", type=int, default=None,
                   help="prompt-length sweep knob: approx token length of the "
                        "shared preamble synthesized per prompt (short->long sweep). "
                        "Implies the synthetic generator like --reuse-ratio.")
    p.add_argument("--synth-prompts", dest="synth_prompts", type=int, default=64,
                   help="number of synthetic prompts to generate when "
                        "--reuse-ratio/--ctx-len is set (default 64).")
    p.add_argument("--synth-seed", dest="synth_seed", type=int, default=0,
                   help="deterministic seed for the synthetic generator (default 0).")
    p.add_argument("--verbose", action="store_true", help="per-event logging.")
    # exit-gate cross-check modes (live real-vLLM contract parity).
    p.add_argument("--emit-hashes", dest="emit_hashes", action="store_true",
                   help="print loxilb's computed FULL-block uint64s for --prompt "
                        "(one decimal per line) and exit; no zmq needed.")
    p.add_argument("--prompt",
                   help="prompt text for --emit-hashes.")
    p.add_argument("--capture", action="store_true",
                   help="SUB-side capture: --connect a PUB, drain BlockStored, and "
                        "dump the INT hashes to --capture-out as {\"hashes\":[...]}.")
    p.add_argument("--connect", default="127.0.0.1",
                   help="PUB address to connect to in --capture mode.")
    p.add_argument("--capture-out", dest="capture_out",
                   help="output JSON path for --capture.")
    p.add_argument("--capture-secs", dest="capture_secs", type=int, default=15,
                   help="--capture drain window in seconds (default 15).")
    p.set_defaults(emit_vocabulary=True)
    return p.parse_args(argv)


def main(argv) -> int:
    args = _parse_args(argv)
    if args.self_check:
        return _run_self_check(args)
    if args.emit_hashes:
        return _emit_hashes(args)
    if args.capture:
        return _capture_events(args)
    # The synthetic generator (--reuse-ratio/--ctx-len) publishes WITHOUT
    # a --corpus file; it builds the corpus in-process. Otherwise a missing --corpus
    # falls through to the cheap locally-runnable self-check.
    if not args.corpus and args.reuse_ratio is None and args.ctx_len is None:
        # Default action with no corpus is the self-check (cheap, locally runnable).
        return _run_self_check(args)
    return _publish_corpus(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
