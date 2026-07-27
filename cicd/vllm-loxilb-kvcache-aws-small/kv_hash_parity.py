#!/usr/bin/env python3
"""kv_hash_parity.py — client-side three-way KV-hash parity harness.

Reference implementation: vLLM v0.17.0 module-level ``hash_block_tokens`` +
``maybe_convert_block_hash`` (vllm/v1/core/kv_cache_utils.py:71-74,532-559;
NONE_HASH seed via ``init_none_hash`` L91-106). v0.17.0 exposes these as
module-level functions (no wrapper class); the literal vendored copy lives
at cicd/common/kv_hash/vllm_v0_17_0_blockhash.py. The uint64
truncation is the LOW 64 bits of the full digest interpreted big-endian (i.e.
``digest[-8:]`` BE), NOT ``digest[:8]`` BE — the latter is what loxilb-C
produced pre-44-04 and caused the TK27 parity diff (see 44-04 diagnosis).

    cbor_bytes = cbor2.dumps([parent_hash_bytes, token_ids, None], canonical=True)
    digest     = hashlib.sha256(cbor_bytes).digest()         # or XXH3_128bits(...)
    hash_u64   = int.from_bytes(digest, 'big') & ((1 << 64) - 1)

This script drives the three-layer regression gate for:

    1. vLLM v0.17.0 hash_block_tokens (source of truth, published via ZMQ).
    2. loxilb C-side ``kv_compute_block_hashes`` in sockproxy_kv_exact.c.
    3. This Python re-computation from prompt text + HF tokenizer.

Any divergence between layers = parity FAIL with a first-mismatch diff.

Runbook: execute on the AWS test client (l3h1 / $CLIENT_PUB) after the
target LB rule is configured and the ZMQ warmup window has elapsed.
A vLLM minor/patch bump REQUIRES re-running this harness (or the TK27
wrapper in run-aws-validation-kvcache.sh --parity) to confirm the C, Go,
and Python layers still agree; see 44-CONTEXT.md requirement P44-R8.

The diff is byte-exact per block, computed as multiset equality between
client-computed uint64s and the loxilb Admin API inventory uint64s —
Admin API ``block_idx`` is a synthetic map-iteration index, not semantic
block position, so positional tuple compare is not architecturally
possible against today's ``map[uint64]struct{}`` inventory. See
44-CONTEXT.md "Diff tightness" for the rationale.

Exit codes:
    0   All blocks match byte-exact.
    1   Mismatch (first-mismatch details on stderr).
    2   Client-side error (tokenizer load failure, Admin API unreachable,
        malformed response, missing xxhash package when requested, etc.).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import List, Tuple

try:
    import cbor2
except ImportError:  # pragma: no cover
    print(
        "ERROR: cbor2 package is required (pip install cbor2).",
        file=sys.stderr,
    )
    sys.exit(2)

try:
    import requests
except ImportError:  # pragma: no cover
    print(
        "ERROR: requests package is required (pip install requests).",
        file=sys.stderr,
    )
    sys.exit(2)


ZERO_PARENT_SHA256 = bytes(32)  # 32 zero bytes — sha256_cbor block-0 parent (legacy fallback)
ZERO_PARENT_XXHASH = bytes(16)  # 16 zero bytes — xxhash_cbor block-0 parent (legacy fallback)
INVENTORY_PATH = "/netlox/v1/config/ai/kv/inventory"


def _parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="kv_hash_parity.py",
        description=(
            "Compare KV-hash uint64s between a client-side reference "
            "(tokenize+CBOR+hash) and the loxilb Admin API inventory."
        ),
    )
    p.add_argument(
        "--llb-url",
        required=True,
        help="Base URL of the loxilb Admin API, e.g. http://10.0.0.5:11111",
    )
    p.add_argument(
        "--service-id",
        required=True,
        type=lambda s: int(s, 0),
        help="serviceID (uint32) that owns the KV inventory",
    )
    p.add_argument(
        "--ep-idx",
        required=True,
        type=int,
        help="endpoint index (int) within the service",
    )
    p.add_argument(
        "--model",
        required=True,
        help="HuggingFace model id (used for tokenizer load)",
    )
    p.add_argument(
        "--algo",
        required=True,
        choices=["sha256_cbor", "xxhash_cbor"],
        help="Hash algorithm — must match the LB rule's kvHashAlgo field",
    )
    p.add_argument(
        "--prompt",
        required=True,
        help="Prompt string to tokenize and hash",
    )
    p.add_argument(
        "--block-size",
        type=int,
        default=16,
        help="Tokens per KV block (default 16; matches LB rule kvBlockSize)",
    )
    p.add_argument(
        "--none-hash-seed",
        default="0",
        help=(
            "Seed for first-block NONE_HASH parent. Must match vLLM's "
            "PYTHONHASHSEED and loxilb's LLB_KV_NONE_HASH_SEED. Default '0' "
            "matches deploy-kvcache.sh testbed pinning. Pass empty string "
            "to fall back to all-zero parent (legacy pre-44-04 behaviour)."
        ),
    )
    p.add_argument(
        "--json-output",
        action="store_true",
        help="Emit a machine-readable JSON summary on stdout",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-block details even on PASS",
    )
    return p.parse_args(argv)


def _load_tokenizer(model: str):
    """Load a HuggingFace tokenizer; exit(2) with a clear error on failure."""
    try:
        from transformers import AutoTokenizer, PreTrainedTokenizerFast
    except ImportError:
        print(
            "ERROR: transformers package is required (pip install transformers).",
            file=sys.stderr,
        )
        sys.exit(2)
    try:
        # A path to a standalone tokenizer.json must be loaded as a fast-tokenizer
        # FILE: AutoTokenizer.from_pretrained expects a repo id ('ns/name') or a
        # directory containing tokenizer_config.json — NOT the tokenizer.json file
        # itself (which raises "Repo id must be in the form ..."). The committed
        # fixture is a bare tokenizer.json, so load it directly. Both paths return a
        # transformers tokenizer whose .encode(text) yields List[int] (caller contract).
        if os.path.isfile(model) and model.endswith(".json"):
            return PreTrainedTokenizerFast(tokenizer_file=model)
        return AutoTokenizer.from_pretrained(model)
    except Exception as exc:  # noqa: BLE001 — want to surface any tokenizer error
        print(
            f"ERROR: tokenizer load failed for model={model!r}: {exc}",
            file=sys.stderr,
        )
        sys.exit(2)


def _chunk_tokens(token_ids: List[int], block_size: int) -> List[List[int]]:
    """Chunk token_ids into blocks of block_size; last block may be short.

    Matches C-side kv_compute_block_hashes (sockproxy_kv_exact.c:189-193) which
    processes the tail of a prompt whose length is not a multiple of block_size
    by truncating the last block to the remaining tokens.
    """
    if block_size <= 0:
        raise ValueError(f"block_size must be positive, got {block_size}")
    return [
        token_ids[i : i + block_size]
        for i in range(0, len(token_ids), block_size)
    ]


def _digest(algo: str, cbor_bytes: bytes) -> bytes:
    """Run sha256 or xxhash128 on cbor_bytes, returning the raw digest."""
    if algo == "sha256_cbor":
        return hashlib.sha256(cbor_bytes).digest()
    if algo == "xxhash_cbor":
        try:
            import xxhash
        except ImportError:
            print(
                "ERROR: xxhash package is required for --algo xxhash_cbor "
                "(pip install xxhash); do not auto-install on the testbed.",
                file=sys.stderr,
            )
            sys.exit(2)
        # XXH3_128 — vLLM uses xxhash.xxh3_128_digest which returns big-endian bytes.
        return xxhash.xxh3_128_digest(cbor_bytes)
    raise ValueError(f"unsupported algo {algo!r}")


def _zero_parent_for(algo: str) -> bytes:
    if algo == "sha256_cbor":
        return ZERO_PARENT_SHA256
    if algo == "xxhash_cbor":
        return ZERO_PARENT_XXHASH
    raise ValueError(f"unsupported algo {algo!r}")


def _none_hash_for(algo: str, seed: str) -> bytes:
    """Compute first-block NONE_HASH from seed, mirroring vLLM init_none_hash.

    vLLM v0.17.0 kv_cache_utils.py:92-106 — when ``PYTHONHASHSEED`` is set:
        NONE_HASH = hash_fn(seed_str)
    where ``hash_fn`` is ``sha256_cbor`` or ``xxhash_cbor`` (cbor2.dumps(obj,
    canonical=True) → digest). An empty ``seed`` returns the legacy all-zero
    parent (44-04 backwards-compat path — requires loxilb env unset AND vLLM
    PYTHONHASHSEED unset; non-deterministic on vLLM side, discouraged).
    """
    if not seed:
        return _zero_parent_for(algo)
    return _digest(algo, cbor2.dumps(seed, canonical=True))


_UINT64_MASK = (1 << 64) - 1


def _compute_client_blocks(
    token_ids: List[int], block_size: int, algo: str, none_hash_seed: str
) -> List[Tuple[int, int, bytes, List[int]]]:
    """Reference computation — returns list of (block_idx, uint64, cbor, tokens).

    ONLY FULL BLOCKS are returned. vLLM v0.17.0
    ``kv_cache_utils.py:574-576`` (``get_request_block_hasher``) publishes KV
    events for full blocks only — the partial trailing block is never hashed
    nor ZMQ-published. The parity diff must mirror this, otherwise a prompt
    whose token count is not a multiple of ``block_size`` causes a spurious
    length_mismatch against the Admin API inventory. Parent-chaining still
    walks full blocks in order; we simply do not emit the partial tail.

    uint64 truncation matches vLLM v0.17.0 ``maybe_convert_block_hash``:
    ``int.from_bytes(full_digest, 'big') & ((1 << 64) - 1)`` (equivalently
    the low 64 bits = ``digest[-8:]`` interpreted big-endian). Keep the full
    ``digest`` for parent chaining — only the external uint64 is truncated.

    First-block parent is ``hash_fn(none_hash_seed)`` when seed is non-empty,
    mirroring vLLM init_none_hash under PYTHONHASHSEED. Empty seed falls back
    to all-zero parent (legacy pre-44-04 path — requires both vLLM and
    loxilb to be zero-parent; non-deterministic on vLLM side).
    """
    parent = _none_hash_for(algo, none_hash_seed)
    chunks = _chunk_tokens(token_ids, block_size)
    results: List[Tuple[int, int, bytes, List[int]]] = []
    for i, tokens in enumerate(chunks):
        cbor = cbor2.dumps([parent, tokens, None], canonical=True)
        digest = _digest(algo, cbor)
        u64 = int.from_bytes(digest, "big") & _UINT64_MASK
        # Only full blocks are published by vLLM — skip partial trailing block.
        if len(tokens) == block_size:
            results.append((i, u64, cbor, tokens))
        parent = digest  # chain (full digest, not truncation)
    return results


def _fetch_inventory(
    llb_url: str, service_id: int, ep_idx: int
) -> dict:
    url = llb_url.rstrip("/") + INVENTORY_PATH
    params = {"service_id": service_id, "ep_idx": ep_idx}
    try:
        r = requests.get(url, params=params, timeout=10)
    except requests.RequestException as exc:
        print(f"ERROR: Admin API GET {url} failed: {exc}", file=sys.stderr)
        sys.exit(2)
    if r.status_code != 200:
        print(
            f"ERROR: Admin API GET {url} returned HTTP {r.status_code}: {r.text[:500]}",
            file=sys.stderr,
        )
        sys.exit(2)
    try:
        return r.json()
    except ValueError as exc:
        print(
            f"ERROR: Admin API response not JSON-parseable: {exc}; body={r.text[:500]!r}",
            file=sys.stderr,
        )
        sys.exit(2)


def _emit_json_summary(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True))


def main(argv: List[str]) -> int:
    args = _parse_args(argv)

    tok = _load_tokenizer(args.model)
    try:
        token_ids = tok.encode(args.prompt)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: tokenizer.encode failed: {exc}", file=sys.stderr)
        return 2

    client_blocks = _compute_client_blocks(
        token_ids, args.block_size, args.algo, args.none_hash_seed
    )
    client_keys = sorted(b[1] for b in client_blocks)

    inv = _fetch_inventory(args.llb_url, args.service_id, args.ep_idx)
    if not isinstance(inv, dict) or "blocks" not in inv:
        print(
            f"ERROR: Admin API response missing 'blocks' field: keys={list(inv.keys()) if isinstance(inv, dict) else type(inv).__name__}",
            file=sys.stderr,
        )
        return 2

    # Admin API field is "hash_algo" (see ai_kv_subscriber.go HandleKvInventory).
    # Fall back to "algo" for forward-compat if the API schema evolves.
    llb_algo = inv.get("hash_algo", inv.get("algo", "<missing>"))
    if llb_algo != args.algo:
        print(
            f"WARNING: algo mismatch — client={args.algo}, loxilb reports {llb_algo!r}. "
            "Continuing diff, but results may be meaningless.",
            file=sys.stderr,
        )

    llb_hashes = []
    for b in inv["blocks"]:
        try:
            llb_hashes.append(int(b["hash_uint64"]))
        except (KeyError, TypeError, ValueError) as exc:
            print(
                f"ERROR: malformed block entry {b!r}: {exc}",
                file=sys.stderr,
            )
            return 2
    llb_keys = sorted(llb_hashes)

    total_client = len(client_keys)
    total_llb = len(llb_keys)

    # Strict rule: multiset equality via sorted-list compare (see CONTEXT 'Diff tightness').
    passed = client_keys == llb_keys

    if args.verbose or not passed:
        for idx, u64, cbor, tokens in client_blocks:
            sys.stderr.write(
                f"[client] blk={idx} tokens={tokens} cbor_len={len(cbor)} "
                f"uint64=0x{u64:016x}\n"
            )

    if not passed:
        # First-mismatch detail.
        diff_at = None
        for i in range(min(total_client, total_llb)):
            if client_keys[i] != llb_keys[i]:
                diff_at = i
                break
        if diff_at is not None:
            mismatch_client = client_keys[diff_at]
            mismatch_llb = llb_keys[diff_at]
            sys.stderr.write(
                f"FAIL first_mismatch_sorted_idx={diff_at} "
                f"client=0x{mismatch_client:016x} llb=0x{mismatch_llb:016x}\n"
            )
            # Find the source block for the client uint64 to dump cbor + tokens.
            for idx, u64, cbor, tokens in client_blocks:
                if u64 == mismatch_client:
                    sys.stderr.write(
                        f"  client_block_idx={idx} tokens={tokens} cbor_hex={cbor.hex()}\n"
                    )
                    break
        else:
            sys.stderr.write(
                f"FAIL length_mismatch client={total_client} llb={total_llb}\n"
            )

        sys.stderr.write(
            "client_keys=" + ",".join(f"0x{k:016x}" for k in client_keys) + "\n"
        )
        sys.stderr.write(
            "llb_keys=" + ",".join(f"0x{k:016x}" for k in llb_keys) + "\n"
        )

        summary = {
            "status": "fail",
            "algo": args.algo,
            "service_id": args.service_id,
            "ep_idx": args.ep_idx,
            "blocks_client": total_client,
            "blocks_llb": total_llb,
            "first_mismatch_sorted_idx": diff_at,
        }
        if args.json_output:
            _emit_json_summary(summary)
        return 1

    ok_msg = (
        f"PASS blocks_matched={total_client}/{total_client} "
        f"algo={args.algo} service_id={args.service_id} ep_idx={args.ep_idx}"
    )
    print(ok_msg)
    if args.json_output:
        _emit_json_summary(
            {
                "status": "pass",
                "algo": args.algo,
                "service_id": args.service_id,
                "ep_idx": args.ep_idx,
                "blocks_matched": total_client,
                "blocks_total": total_client,
            }
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
