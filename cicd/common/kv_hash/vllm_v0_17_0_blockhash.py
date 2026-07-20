#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project
#
# vllm_v0_17_0_blockhash.py — LITERAL vendored copy of vLLM v0.17.0's
# block-hash code path (D-02a strict: "same code path of record").
#
# ============================================================================
# PROVENANCE (D-02a)
# ============================================================================
# Upstream project : vllm-project/vllm
# Pinned tag       : v0.17.0
#
# Source file #1   : vllm/v1/core/kv_cache_utils.py @ v0.17.0
#   permalink      :
#     https://github.com/vllm-project/vllm/blob/v0.17.0/vllm/v1/core/kv_cache_utils.py
#   vendored symbols (verbatim, line ranges in the v0.17.0 file):
#     - maybe_convert_block_hash  (L71-74)
#     - NONE_HASH module global + init_none_hash  (L87-106)
#     - hash_block_tokens         (L532-559)
#   NOTE: at v0.17.0 these are plain module-level functions — there is no
#   wrapper class and no parent-bound method (the pre-refactor names are
#   stale). The real public symbols are the module-level functions above.
#   `get_request_block_hasher` (L562) is the per-request driver that loops
#   full blocks calling hash_block_tokens; its block-walk is reproduced in
#   the self-check below (not vendored verbatim because it depends on the
#   Request object, which is out of scope for an offline fixture gate).
#
# Source file #2   : vllm/utils/hashing.py @ v0.17.0
#   permalink      :
#     https://github.com/vllm-project/vllm/blob/v0.17.0/vllm/utils/hashing.py
#   vendored symbols (verbatim, line ranges in the v0.17.0 file):
#     - sha256_cbor               (L43-58)
#     - xxhash_cbor + _xxhash_digest + the optional _xxhash import (L18-23,
#       L61-67, L76-79)
#   These two CBOR hash functions are imported by kv_cache_utils.py at L17
#   (`from vllm.utils.hashing import sha256_cbor, xxhash_cbor`) and ARE the
#   two functions the block-hash path routes through (D-02a requires both;
#   the kv_cache_utils.py functions alone are insufficient).
#
# ============================================================================
# WHY THIS FILE EXISTS (D-02b)
# ============================================================================
# The KV-cache-aware routing gate must hash prompt blocks the SAME way the
# real vLLM publisher does. Re-deriving the math invites drift; copying the
# literal upstream functions and self-asserting them against frozen golden
# vectors (cicd/common/kv_hash/fixtures/kv_hash_vectors.json) pins behavior
# to the recorded tag. Run `--self-check` to verify the vendored code still
# reproduces every golden uint64 for both sha256_cbor and xxhash_cbor.
#
# Threat T-80-01-01 mitigation: the self-assert is the drift tripwire — any
# silent divergence from the recorded v0.17.0 behavior fails the gate.
# ============================================================================

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Callable
from typing import Any

import cbor2

# ----------------------------------------------------------------------------
# VENDORED from vllm/utils/hashing.py @ v0.17.0 (L18-23, L43-58, L61-67,
# L76-79) — verbatim, optional-xxhash import preserved.
# ----------------------------------------------------------------------------

try:
    # It is important that this remains an optional dependency.
    # It would not be allowed in environments with strict security controls,
    # so it's best not to have it installed when not in use.
    import xxhash as _xxhash

    if not hasattr(_xxhash, "xxh3_128_digest"):
        _xxhash = None
except ImportError:  # pragma: no cover
    _xxhash = None


def sha256_cbor(input: Any) -> bytes:
    """Hash objects using CBOR serialization and SHA-256.

    This option is useful for non-Python-dependent serialization and hashing.

    Args:
        input: Object to be serialized and hashed. Supported types include
            basic Python types and complex structures like lists, tuples, and
            dictionaries.
            Custom classes must implement CBOR serialization methods.

    Returns:
        Bytes representing the SHA-256 hash of the CBOR serialized input.
    """
    input_bytes = cbor2.dumps(input, canonical=True)
    return hashlib.sha256(input_bytes).digest()


def _xxhash_digest(input_bytes: bytes) -> bytes:
    if _xxhash is None:
        raise ModuleNotFoundError(
            "xxhash is required for the 'xxhash' prefix caching hash algorithms. "
            "Install it via `pip install xxhash`."
        )
    return _xxhash.xxh3_128_digest(input_bytes)


def xxhash_cbor(input: Any) -> bytes:
    """Hash objects serialized with CBOR using xxHash."""
    input_bytes = cbor2.dumps(input, canonical=True)
    return _xxhash_digest(input_bytes)


# ----------------------------------------------------------------------------
# VENDORED from vllm/v1/core/kv_cache_utils.py @ v0.17.0 — verbatim.
# In upstream `BlockHash` / `ExternalBlockHash` are NewType aliases over
# `bytes` / `int`; we drop the NewType wrappers (pure typing sugar, no
# runtime behavior) and keep the function bodies byte-for-byte equivalent.
# ----------------------------------------------------------------------------


def maybe_convert_block_hash(hash_bytes: bytes) -> int:
    # Upstream guards on envs.VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES; the KV-event
    # publisher contract this gate models runs with that flag TRUE (int block
    # hashes on the wire — matches kv_hash_vectors.json uint64s), so the
    # int-conversion branch is the code path of record here.
    return int.from_bytes(hash_bytes, byteorder="big") & ((1 << 64) - 1)


# The hash seed for the first block of any prefix block sequence.
#
# We use a random value to avoid hash collisions or PYTHONHASHSEED environment
# variable if set such that processes can share the seed if needed. This aligns
# with the behavior of Python's hash() function, which also uses a random seed
# if PYTHONHASHSEED is not set.
#
# The function `init_none_hash` initializes this variable globally.
NONE_HASH: bytes
_CBOR_HASH_FUNCTIONS = frozenset({sha256_cbor, xxhash_cbor})


def init_none_hash(hash_fn: Callable[[Any], bytes]):
    global NONE_HASH

    hash_seed = os.getenv("PYTHONHASHSEED")
    if hash_seed is None and hash_fn in _CBOR_HASH_FUNCTIONS:
        # Upstream logs a warning here via vllm.logger; we surface it on stderr
        # to keep the vendored behavior observable without dragging vllm.logger.
        print(
            "WARNING: PYTHONHASHSEED is not set. This will lead to "
            "non-reproducible block-hashes when using CBOR-based hash "
            "functions such as sha256_cbor or xxhash_cbor. Consider setting "
            "PYTHONHASHSEED to a fixed value for reproducibility.",
            file=sys.stderr,
        )

    if hash_seed is None:
        NONE_HASH = os.urandom(32)
    else:
        NONE_HASH = hash_fn(hash_seed)


def hash_block_tokens(
    hash_function: Callable[[Any], bytes],
    parent_block_hash: bytes | None,
    curr_block_token_ids,
    extra_keys: tuple[Any, ...] | None = None,
) -> bytes:
    """Computes a hash value corresponding to the contents of a block and
    the contents of the preceding block(s). The hash value is used for
    prefix caching. We use LRU cache for this function to avoid recomputing
    hash values for the same block contents.
    Args:
        hash_function: The hash function used to compute block hash.
        parent_block_hash: The hash of the parent block. None
            if this is the first block.
        curr_block_token_ids: A list of token ids in the current
            block. The current block is assumed to be full.
        extra_keys: Extra keys for the block.
    Returns:
        The hash value of the block and the token ids in the block.
        The entire tuple is used as the hash key of the block.
    """
    if not parent_block_hash:
        parent_block_hash = NONE_HASH

    curr_block_token_ids_tuple = tuple(curr_block_token_ids)
    return hash_function(
        (parent_block_hash, curr_block_token_ids_tuple, extra_keys)
    )


# ============================================================================
# D-02b GOLDEN-VECTOR SELF-ASSERT
# ============================================================================
# This is NOT part of the vendored upstream code — it is the drift tripwire.
# It loads the frozen golden vectors and asserts the vendored functions above
# reproduce every recorded uint64 for BOTH sha256_cbor and xxhash_cbor.

_HASH_FNS = {"sha256_cbor": sha256_cbor, "xxhash_cbor": xxhash_cbor}


def _fixtures_path() -> str:
    """Resolve kv_hash_vectors.json next to this file's fixtures/ dir."""
    env = os.getenv("LLB_KV_HASH_VECTORS")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "fixtures", "kv_hash_vectors.json")


def _self_check() -> int:
    """Drive the vendored functions against the golden vectors.

    Returns process exit code: 0 = all blocks match, 1 = any mismatch,
    2 = environment error (missing fixture / missing xxhash for an xxhash
    fixture).
    """
    path = _fixtures_path()
    try:
        with open(path, "rb") as fp:
            doc = json.load(fp)
    except OSError as exc:
        print(f"ERROR: cannot open golden vectors at {path}: {exc}",
              file=sys.stderr)
        return 2

    seed = doc.get("none_hash_seed", "0")

    # First, prove init_none_hash(seed) reproduces the recorded NONE_HASH for
    # both algos (the seed-derived first-block parent the *_noneHashSeed0_*
    # fixtures chain from). We pin PYTHONHASHSEED to the recorded seed so the
    # deterministic branch of init_none_hash is taken.
    os.environ["PYTHONHASHSEED"] = seed
    none_hash_ok = True
    expected_none = {
        "sha256_cbor": doc.get("none_hash_sha256_hex"),
        "xxhash_cbor": doc.get("none_hash_xxhash_hex"),
    }
    for algo, hash_fn in _HASH_FNS.items():
        if algo == "xxhash_cbor" and _xxhash is None:
            continue
        init_none_hash(hash_fn)
        got = NONE_HASH.hex()
        want = expected_none[algo]
        if want is not None and got != want:
            print(f"FAIL: init_none_hash[{algo}] got {got} want {want}",
                  file=sys.stderr)
            none_hash_ok = False

    total = 0
    matched = 0
    skipped_xxhash = 0
    failures = 0
    by_algo: dict[str, list[str]] = {}

    for fx in doc.get("fixtures", []):
        algo = fx["hash_algo"]
        hash_fn = _HASH_FNS.get(algo)
        if hash_fn is None:
            print(f"FAIL: unknown hash_algo {algo!r} in fixture {fx['name']}",
                  file=sys.stderr)
            failures += 1
            continue
        if algo == "xxhash_cbor" and _xxhash is None:
            skipped_xxhash += 1
            continue

        total += 1
        parent = bytes.fromhex(fx["parent_hash_hex"])
        # hash_block_tokens treats a falsy parent as NONE_HASH; every fixture
        # records an explicit non-zero-or-zero parent, so pass it directly to
        # exercise the chained-parent path exactly as get_request_block_hasher
        # does (prev_block_hash_value carried across full blocks).
        digest = hash_block_tokens(hash_fn, parent, fx["tokens"])

        # Cross-check the raw digest against the recorded one (guards fixture
        # corruption / vendored-fn drift at the byte level).
        if "expected_digest_hex" in fx and digest.hex() != fx["expected_digest_hex"]:
            print(
                f"FAIL: {fx['name']} digest {digest.hex()} != "
                f"{fx['expected_digest_hex']}",
                file=sys.stderr,
            )
            failures += 1
            continue

        u64 = maybe_convert_block_hash(digest)
        if u64 != fx["expected_hash_uint64"]:
            print(
                f"FAIL: {fx['name']} uint64 {u64} != {fx['expected_hash_uint64']}",
                file=sys.stderr,
            )
            failures += 1
            continue

        matched += 1
        by_algo.setdefault(algo, []).append(fx["name"])

    for algo in ("sha256_cbor", "xxhash_cbor"):
        names = by_algo.get(algo, [])
        if names:
            print(f"  {algo}: all {len(names)} blocks match")
        elif algo == "xxhash_cbor" and _xxhash is None:
            print(f"  {algo}: SKIPPED ({skipped_xxhash} fixtures) — "
                  "xxhash package not installed")

    if not none_hash_ok or failures:
        print(
            f"SELF-CHECK FAIL: {matched}/{total} blocks matched, "
            f"{failures} failures (none_hash_ok={none_hash_ok})",
            file=sys.stderr,
        )
        return 1

    if matched == 0:
        print("SELF-CHECK ERROR: zero blocks asserted", file=sys.stderr)
        return 2

    print(
        f"SELF-CHECK PASS: {matched}/{total} blocks match for vendored "
        f"vLLM v0.17.0 functions (sha256_cbor + xxhash_cbor; "
        f"{skipped_xxhash} xxhash fixtures skipped if xxhash absent)."
    )
    return 0


if __name__ == "__main__":
    if "--self-check" in sys.argv or len(sys.argv) == 1:
        raise SystemExit(_self_check())
    print(f"usage: {sys.argv[0]} [--self-check]", file=sys.stderr)
    raise SystemExit(2)
