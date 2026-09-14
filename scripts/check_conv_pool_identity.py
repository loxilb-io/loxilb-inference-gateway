#!/usr/bin/env python3
"""Static gate: conversation stickiness names the pool its index belongs to.

ent->val.conv_map is one table per VIP:port, but a stored ep_idx indexes ONE
proxy_epval_t's eps[], and every model pool on a service starts its index
space at 0. Two pools on one VIP therefore collide on a single row: one pool
consumes the other's binding (and so never stores its own), or overwrites it,
sending that conversation to a different member of its own pool and losing the
affinity the binding existed for. is_endpoint_healthy() does not catch it,
because an in-range index naming a live endpoint passes. The model served is
always correct; the STICKINESS is what breaks.

This replaces a grep-based version of the same check that had three holes,
each demonstrated against the pinned datapath before this file was written:

* A cast swallowed the argument.  The ERE ``(FNS)\\([^;]*?\\)`` stops at the
  first ``)``, which for ``(const proxy_epval_t *)pfe->learn_epv`` is the
  CAST's paren -- so the pool never entered the matched text and a literal
  ``(const proxy_epval_t *)NULL`` passed.
* The per-file floor counted DECLARATIONS.  Renaming all three real calls in
  sockproxy_h2.c while leaving its two forward declarations kept the file
  "covered" and the gate green.
* The pool arm passed VACUOUSLY on pre-fix source.  Before the pool argument
  existed there was no NULL to find and no pfe->epv to find, so the gate
  reported "ok at all 14 call sites" against a tree that had no pool identity
  at all.  A gate that passes on the unfixed source is worth less than none.

So this file matches CALLS and only calls, reads the whole argument list by
paren matching rather than by regex, and asserts each call's ARITY -- which is
what makes it impossible to pass on a tree where the pool argument is absent.
"""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
EBPF = ROOT / "loxilb-ebpf/common"

# Every conv_map accessor, with the argument count it must be called with.
# The pool is the LAST argument of each. Asserting the count is what stops
# this gate from passing on a tree whose helpers take no pool at all.
CONV_FNS = {
    "lookup_conversation_endpoint": 4,   # ent, conv_id, &ep_idx, epv
    "get_conversation_mapping": 3,       # ent, conv_id, epv
    "update_conversation_validation": 5, # ent, conv_id, version, healthy, epv
    "store_conversation_endpoint": 4,    # ent, conv_id, ep_idx, epv
}

# Files that must each keep at least one real call, so a rename or a move
# cannot quietly drop one out of view while the total stays healthy.
CONV_FILES = ("sockproxy_ep.c", "sockproxy_h2.c", "sockproxy_http.c")

# A pool argument that names nothing. Stored, it writes a row no lookup can
# match; read, it asks for a lookup that always misses.
NULL_POOLS = {"NULL", "0", "nullptr", "(void *)0"}


def mask(text: str) -> str:
    """Blank comments and literal contents, preserving every byte offset.

    Offsets must survive so brace depth, regex matches and slices all agree.
    Masking rather than deleting is what lets a '}' or a ')' inside a string
    be ignored without shifting anything after it.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        two = text[i : i + 2]
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif text[i] in "\"'":
            quote = text[i]
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            for k in range(i + 1, min(j - 1, n) + 1):
                if k < n and out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def depth_at(masked: str, index: int) -> int:
    """Brace depth immediately before `index`.

    Depth 0 is file scope, where a prototype and a definition's own header
    live. A CALL is always inside a function body, so depth >= 1 is exactly
    the discriminator the grep version lacked.
    """
    return masked.count("{", 0, index) - masked.count("}", 0, index)


def argument_list(masked: str, open_paren: int) -> tuple[str, int]:
    """Text between the matching parens, plus the offset just past the close."""
    depth = 0
    for i in range(open_paren, len(masked)):
        if masked[i] == "(":
            depth += 1
        elif masked[i] == ")":
            depth -= 1
            if depth == 0:
                return masked[open_paren + 1 : i], i + 1
    raise AssertionError(f"unbalanced call at offset {open_paren}")


def split_args(args: str) -> list[str]:
    """Split on top-level commas only: casts, calls and indices may nest."""
    parts, depth, current = [], 0, []
    for char in args:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    tail = "".join(current).strip()
    if tail or parts:
        parts.append(tail)
    return parts


def strip_casts(expr: str) -> str:
    """Reduce '(const proxy_epval_t *) (NULL)' to 'NULL'.

    The grep version's whole failure was that a cast hid the argument; here
    casts and redundant parens are peeled until an actual expression remains.
    """
    previous = None
    expr = expr.strip()
    while expr != previous:
        previous = expr
        # A leading cast: (identifier/keyword/star sequence) with nothing else.
        match = re.match(r"^\(\s*[A-Za-z_][A-Za-z0-9_\s*]*\)\s*(.+)$", expr, re.S)
        if match:
            expr = match.group(1).strip()
            continue
        # A wholly parenthesised expression.
        if expr.startswith("(") and expr.endswith(")"):
            inner, end = argument_list(expr, 0)
            if end == len(expr):
                expr = inner.strip()
    return re.sub(r"\s+", " ", expr)


def calls(masked: str, name: str) -> list[tuple[int, list[str]]]:
    """Every CALL to `name`: (offset, arguments). Declarations excluded."""
    found = []
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", masked):
        open_paren = match.end() - 1
        if depth_at(masked, match.start()) < 1:
            continue  # prototype or definition header, not a call
        args, _ = argument_list(masked, open_paren)
        found.append((match.start(), split_args(args)))
    return found


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def main() -> int:
    failures: list[str] = []
    per_file: dict[str, int] = {}
    total = 0

    for filename in CONV_FILES:
        path = EBPF / filename
        if not path.exists():
            failures.append(f"{filename}: missing -- the datapath moved, update this gate")
            per_file[filename] = 0
            continue
        masked = mask(path.read_text(encoding="utf-8"))
        count = 0
        for name, arity in CONV_FNS.items():
            for offset, args in calls(masked, name):
                count += 1
                where = f"{filename}:{line_of(masked, offset)} {name}()"

                # ARITY. A tree whose helpers take no pool cannot satisfy this,
                # which is what stops the check passing on pre-fix source.
                if len(args) != arity:
                    failures.append(
                        f"{where}: takes {len(args)} arguments, expected {arity} "
                        f"-- the pool argument is missing or the signature changed"
                    )
                    continue

                pool = strip_casts(args[-1])

                # A pool that names nothing, however many casts wrap it.
                if pool in NULL_POOLS:
                    failures.append(
                        f"{where}: pool argument is {args[-1]!r} -- a row stored "
                        f"without a pool can never be matched again"
                    )

                # HTTP/2 must pass the STREAM's pool. One H2 connection
                # multiplexes streams of several pools, so pfe->epv is
                # connection-scoped last-write state that on a multi-model
                # connection names a different pool than this stream's.
                if filename == "sockproxy_h2.c" and pool in ("pfe->epv", "npfe->epv"):
                    failures.append(
                        f"{where}: pool argument is {pool!r} -- HTTP/2 must pass "
                        f"the stream's resolved pool (tepval / stream->route_epv)"
                    )
        per_file[filename] = count
        total += count

    # Per-file floor on CALLS, not on declarations: a rename that moves one
    # file's call sites out of view must not leave the gate watching nothing
    # while a global total still looks healthy.
    for filename, count in per_file.items():
        if count == 0:
            failures.append(
                f"{filename}: no conversation-map calls found -- helpers renamed "
                f"or moved, and this gate is no longer watching this file"
            )

    # The row must carry the identity, and a store without one must be refused
    # rather than written as a row nothing can ever match.
    header = (EBPF / "sockproxy.h").read_text(encoding="utf-8")
    ep_source = (EBPF / "sockproxy_ep.c").read_text(encoding="utf-8")
    if "uint64_t pool_tag;" not in mask(header):
        failures.append("sockproxy.h: conversation_mapping_t must carry a pool_tag field")
    if "CONV_POOL_TAG_UNKNOWN" not in mask(ep_source):
        failures.append(
            "sockproxy_ep.c: store_conversation_endpoint must refuse "
            "CONV_POOL_TAG_UNKNOWN rather than store an unmatchable row"
        )

    if failures:
        print("FAIL: conversation stickiness must name the pool its endpoint index belongs to")
        for failure in failures:
            print(f"  {failure}")
        return 1

    detail = ", ".join(f"{name} {count}" for name, count in per_file.items())
    print(f"PASS: conversation stickiness names its pool at all {total} call sites ({detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
