#!/usr/bin/env python3
"""sglang_hash_core.py — a single pure-Python reference for the SGLang
KV-cache block (radix page) hash math.

Reference: SGLang's python/sglang/srt/mem_cache/cpp_utils/hash_binding.cpp
(hash_page). This module re-derives the ~15 lines of reference math directly
rather than importing sglang: sglang's mem_cache/utils.py hard-imports
torch-heavy kernels plus the compiled cpp_utils pybind module, which we do not
want as a dependency for a lightweight CI hash-parity check.

The math (hash_binding.cpp hash_page):

    digest_i = SHA256( [32-byte RAW prior digest, ONLY if present] ||
                       token0_LE4 || token1_LE4 || ... )

  * Block 0 has NO prior bytes at all — unlike vLLM's NONE_HASH seed.
  * The prior for block i>0 is block i-1's FULL 32-byte digest (raw bytes,
    not hex, not truncated).
  * Tokens are hashed as a raw uint32 buffer == 4-byte little-endian per
    token on x86_64 (hash_binding.cpp hashes the page's uint32 words
    directly).

Published value (SGLang get_hash_str -> hash_str_to_int64):

    v = int(hexdigest[:16], 16)          # FIRST 16 hex chars == FIRST 8 bytes
    published = v - 2**64 if v >= 2**63 else v   # signed-int64 wrap

⚠ FIRST-8 truncation — NOT vLLM's last-8 (maybe_convert_block_hash). This is
exactly the digest[:8]-vs-digest[-8:] drift class, inverted for SGLang;
the committed parity vectors pin it in C (test_kv_exact.c) and Go
(ai_kv_subscriber_hash_vectors_test.go).

Consumers:
  * scripts/compute_sglang_hash_refs.py — parity-vector regen.
  * kv_event_publisher.py --engine sglang (mock publisher) — imports
    this module so publisher and vectors can never drift.

Stdlib-only: hashlib. No third-party imports, ever.
"""

import hashlib

# Pinned upstream provenance — quoted by every consumer's header.
SGLANG_PIN_COMMIT = "d8ef76682e"
SGLANG_PIN_SOURCE = "python/sglang/srt/mem_cache/cpp_utils/hash_binding.cpp"

_INT64_MIN_WRAP = 2 ** 63
_UINT64_MOD = 2 ** 64


def sglang_block_digest(tokens, prior=None):
    """Full 32-byte digest for ONE block.

    tokens: iterable of token ids (uint32 range).
    prior:  None for block 0, else the previous block's FULL 32-byte digest.
    """
    if prior is not None and len(prior) != 32:
        raise ValueError("prior digest must be exactly 32 bytes")
    h = hashlib.sha256()
    if prior is not None:
        h.update(prior)  # raw 32 bytes — NOT hex
    for t in tokens:
        if not (0 <= t <= 0xFFFFFFFF):
            raise ValueError("token id does not fit in uint32: %r" % (t,))
        h.update(t.to_bytes(4, "little"))
    return h.digest()


def sglang_digest_chain(blocks, prior=None):
    """Chained FULL 32-byte digests for a block sequence.

    blocks: list of token-id lists (one entry per block).
    prior:  optional 32-byte digest seeding block 0 (None == SGLang root).
    Returns list[bytes] — one 32-byte digest per block.
    """
    out = []
    for toks in blocks:
        prior = sglang_block_digest(toks, prior)
        out.append(prior)
    return out


def hash_str_to_int64(hexdigest):
    """SGLang hash_str_to_int64: signed int64 of the FIRST 16 hex chars."""
    v = int(hexdigest[:16], 16)
    return v - _UINT64_MOD if v >= _INT64_MIN_WRAP else v


def published_int64(digest):
    """Signed int64 SGLang publishes for a full 32-byte digest."""
    return hash_str_to_int64(digest.hex())


def published_uint64(digest):
    """uint64 loxilb stores: FIRST 8 digest bytes big-endian.

    Bit-identical to uint64(published_int64) — the Go extractBlockHashes
    int64→uint64 cast and the C first-8-BE memcpy meet exactly here.
    """
    return int.from_bytes(digest[:8], "big")


def sglang_hash_chain(blocks, prior=None):
    """Published signed-int64 chain — the RESEARCH reference signature.

    blocks: list of token-id lists; prior: optional 32-byte seed digest.
    Returns list[int] of signed int64 published values, one per block.
    """
    return [published_int64(d) for d in sglang_digest_chain(blocks, prior)]


def blocks_from_tokens(tokens, block_size):
    """Split a flat token list into SGLang pages (last block may be partial)."""
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    return [tokens[i:i + block_size] for i in range(0, len(tokens), block_size)]
