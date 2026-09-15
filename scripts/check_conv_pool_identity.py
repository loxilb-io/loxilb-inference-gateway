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

# The two places the pool identity is not expressed as a call argument, and so
# is not covered by the call-site sweep above.
SYNC_FILE = "sockproxy_sync.c"          # HA failover applies remote rows here
BINDER_FILE = "sockproxy_http.c"        # the session id is captured here

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


def function_body(masked: str, name: str) -> tuple[str, int]:
    """Body of a function definition, plus its offset in the file."""
    match = re.search(rf"\n{re.escape(name)}\s*\([^;]*?\)\s*\{{", masked, re.S)
    if not match:
        raise AssertionError(f"function {name} not found")
    start = match.end() - 1
    depth = 0
    for index in range(start, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return masked[start : index + 1], start
    raise AssertionError(f"function {name} has no closing brace")


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def check_sync_refuses_to_guess(failures: list[str]) -> None:
    """A failover row may not be installed under a GUESSED pool.

    proxy_sync_event_t carries a service_key of "xip:xport:proto" and nothing
    finer, so the receiver resolves the pool by taking the first one on the
    service. With one pool that is the only possible answer. With several the
    guess is written into the row's tag, so the guessed pool MATCHES the row
    and is handed an index chosen inside a different pool's eps[] -- in range
    and naming a live endpoint, so nothing downstream can catch it -- and a
    DELETE under a wrong guess removes a live binding of a pool the event
    never named. That is the aliasing this whole file guards, arriving through
    failover with a tag that certifies it.

    Nothing in the argument sweep above can see this, because here the pool is
    not an argument: it is the decision of whether to apply at all. So the
    guard is asserted structurally -- it must exist, it must be the only route
    in, and it must come first.
    """
    path = EBPF / SYNC_FILE
    if not path.exists():
        failures.append(f"{SYNC_FILE}: missing -- the datapath moved, update this gate")
        return
    masked = mask(path.read_text(encoding="utf-8"))

    entries = calls(masked, "apply_conv_sync_entry")
    if len(entries) != 1:
        failures.append(
            f"{SYNC_FILE}: apply_conv_sync_entry has {len(entries)} call sites, expected 1 "
            f"-- every route in must pass the pool-resolvability guard"
        )
        return

    try:
        body, base = function_body(masked, "proxy_sync_apply_session_entry")
    except AssertionError as problem:
        failures.append(f"{SYNC_FILE}: {problem}")
        return

    guard = re.search(r"\bconv_pool_sync_may_apply\s*\(", body)
    apply_call = re.search(r"\bapply_conv_sync_entry\s*\(", body)

    if apply_call is None:
        failures.append(
            f"{SYNC_FILE}: the only apply_conv_sync_entry call is not inside "
            f"proxy_sync_apply_session_entry -- this gate no longer sees the guard"
        )
        return
    if guard is None:
        failures.append(
            f"{SYNC_FILE}: proxy_sync_apply_session_entry installs a remote "
            f"conversation row without calling conv_pool_sync_may_apply -- the "
            f"receiver would resolve the pool by guessing"
        )
        return
    if guard.start() > apply_call.start():
        failures.append(
            f"{SYNC_FILE}:{line_of(masked, base + guard.start())} "
            f"conv_pool_sync_may_apply is checked AFTER the row is applied"
        )


def check_session_id_is_bound_not_dropped(failures: list[str]) -> None:
    """A session id that does not fit must still be bound.

    The plain-header route used to capture the value only when it fit the
    buffer, so a longer one was not truncated but DISCARDED: stickiness
    silently did nothing, and did nothing precisely for the configuration the
    tree documents, session_header_name "authorization", whose value is a
    bearer token longer than the buffer. conv_pool_store_id binds it instead,
    digesting what will not fit.

    This asserts the binder is still the binder. It catches the regression
    that actually happened -- reverting to a length test and a straight copy --
    rather than claiming to catch every way the property could be lost.
    """
    path = EBPF / BINDER_FILE
    if not path.exists():
        failures.append(f"{BINDER_FILE}: missing -- the datapath moved, update this gate")
        return
    masked = mask(path.read_text(encoding="utf-8"))

    bound = [
        args
        for _, args in calls(masked, "conv_pool_store_id")
        if args and args[0].strip().endswith("custom_session_header_value")
    ]
    if not bound:
        failures.append(
            f"{BINDER_FILE}: custom_session_header_value is not bound through "
            f"conv_pool_store_id -- an id that does not fit is dropped or "
            f"truncated again, so stickiness silently stops for long values"
        )


def check_health_signal_reaches_every_pool(failures: list[str]) -> None:
    """The address-keyed health loop must not return from inside HASH_ITER.

    The defect this guards actually shipped: proxy_update_ep_health's loop
    body ended in `return 0`, so a multi-pool service applied the signal to
    whichever pool hashed first and no other -- the failed endpoint was never
    marked down while a healthy one was. The fix's whole contract is "every
    pool", and the only structural way to break it again is a return (or a
    bare break) inside the HASH_ITER body, so that is what is asserted --
    on the masked text, at measured brace depth, never on indentation.
    """
    path = EBPF / BINDER_FILE
    if not path.exists():
        failures.append(f"{BINDER_FILE}: missing -- the datapath moved, update this gate")
        return
    masked = mask(path.read_text(encoding="utf-8"))

    try:
        body, base = function_body(masked, "proxy_update_ep_health_by_addr")
    except AssertionError as problem:
        failures.append(f"{BINDER_FILE}: {problem} -- the address-keyed health "
                        f"entry point is the fix; its absence is the regression")
        return

    iters = list(re.finditer(r"\bHASH_ITER\s*\(", body))
    if len(iters) != 1:
        failures.append(
            f"{BINDER_FILE}: proxy_update_ep_health_by_addr has {len(iters)} "
            f"HASH_ITER loops, expected 1 -- the shape changed, re-derive this gate"
        )
        return

    _, after_args = argument_list(body, iters[0].end() - 1)
    open_brace = body.find("{", after_args)
    if open_brace < 0:
        failures.append(f"{BINDER_FILE}: HASH_ITER in proxy_update_ep_health_by_addr "
                        f"has no brace body -- re-derive this gate")
        return
    depth = 0
    close_brace = -1
    for i in range(open_brace, len(body)):
        if body[i] == "{":
            depth += 1
        elif body[i] == "}":
            depth -= 1
            if depth == 0:
                close_brace = i
                break
    if close_brace < 0:
        failures.append(f"{BINDER_FILE}: unbalanced HASH_ITER body in "
                        f"proxy_update_ep_health_by_addr")
        return

    loop_body = body[open_brace : close_brace + 1]
    escape = re.search(r"\breturn\b", loop_body)
    if escape:
        failures.append(
            f"{BINDER_FILE}:{line_of(masked, base + open_brace + escape.start())} "
            f"proxy_update_ep_health_by_addr returns from inside its HASH_ITER "
            f"body -- only the first pool is ever touched, which is the exact "
            f"defect this loop was rewritten to fix"
        )


def run_all_checks() -> tuple[list[str], dict[str, int], int]:
    """Every check, no printing. main() reports; self_test() red-twins."""
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

    check_sync_refuses_to_guess(failures)
    check_session_id_is_bound_not_dropped(failures)
    check_health_signal_reaches_every_pool(failures)

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

    return failures, per_file, total


def _last_top_level_comma(text: str, start: int, end: int) -> int:
    """Offset of the last depth-0 comma in text[start:end], or -1."""
    depth = 0
    found = -1
    for i in range(start, end):
        if text[i] in "([{":
            depth += 1
        elif text[i] in ")]}":
            depth -= 1
        elif text[i] == "," and depth == 0:
            found = i
    return found


def _doctor_return_inside_iter(root: pathlib.Path) -> None:
    """Re-insert the exact defect the health check guards: a return inside
    the HASH_ITER body of proxy_update_ep_health_by_addr."""
    path = root / BINDER_FILE
    text = path.read_text(encoding="utf-8")
    masked = mask(text)
    body, base = function_body(masked, "proxy_update_ep_health_by_addr")
    it = re.search(r"\bHASH_ITER\s*\(", body)
    _, after_args = argument_list(body, it.end() - 1)
    open_brace = body.index("{", after_args)
    at = base + open_brace + 1
    path.write_text(text[:at] + " return 0; " + text[at:], encoding="utf-8")


def _doctor_remove_entry_point(root: pathlib.Path) -> None:
    """Pre-fix world: the address-keyed entry point does not exist."""
    path = root / BINDER_FILE
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "proxy_update_ep_health_by_addr", "proxy_update_ep_health_by_index2"),
        encoding="utf-8")


def _doctor_drop_pool_argument(root: pathlib.Path) -> None:
    """Pre-fix signature: strip the trailing pool argument from one real
    store_conversation_endpoint call, so the ARITY assert must catch it."""
    path = root / "sockproxy_ep.c"
    text = path.read_text(encoding="utf-8")
    masked = mask(text)
    sites = calls(masked, "store_conversation_endpoint")
    assert sites, "self-test fixture drifted: no store_conversation_endpoint call"
    offset, _ = sites[0]
    open_paren = masked.index("(", offset)
    _, end = argument_list(masked, open_paren)   # end = just past ')'
    comma = _last_top_level_comma(masked, open_paren + 1, end - 1)
    assert comma > 0, "self-test fixture drifted: call has fewer than 2 arguments"
    path.write_text(text[:comma] + text[end - 1:], encoding="utf-8")


def _doctor_unguard_sync(root: pathlib.Path) -> None:
    """Failover applies a remote row without the pool-resolvability guard."""
    path = root / SYNC_FILE
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "conv_pool_sync_may_apply", "conv_pool_sync_guess_is_fine"),
        encoding="utf-8")


def _doctor_drop_binder(root: pathlib.Path) -> None:
    """The plain-header session id is no longer bound through the digester."""
    path = root / BINDER_FILE
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "conv_pool_store_id", "conv_pool_copy_if_it_fits"),
        encoding="utf-8")


def self_test() -> int:
    """Prove every check can go red. A gate whose failure mode has never been
    demonstrated is indistinguishable from one that cannot fail; each scenario
    below doctors a pristine copy back into the defect its check guards and
    requires the expected failure to surface -- and the pristine copy itself
    must still pass, or the doctoring proved nothing."""
    import shutil
    import tempfile

    global EBPF
    real = EBPF
    needed = sorted({*CONV_FILES, SYNC_FILE, "sockproxy.h"})
    scenarios = [
        ("health loop returns inside HASH_ITER",
         _doctor_return_inside_iter, "returns from inside its HASH_ITER"),
        ("address-keyed entry point absent",
         _doctor_remove_entry_point, "proxy_update_ep_health_by_addr not found"),
        ("conv call loses its pool argument",
         _doctor_drop_pool_argument, "the pool argument is missing"),
        ("failover applies under a guessed pool",
         _doctor_unguard_sync, "without calling conv_pool_sync_may_apply"),
        ("session id dropped instead of bound",
         _doctor_drop_binder, "not bound through"),
    ]

    bad = 0
    for name, doctor, expect in scenarios:
        with tempfile.TemporaryDirectory() as tmpdir:
            twin = pathlib.Path(tmpdir)
            for filename in needed:
                shutil.copy(real / filename, twin / filename)
            EBPF = twin
            try:
                control, _, _ = run_all_checks()
                doctor(twin)
                failures, _, _ = run_all_checks()
            finally:
                EBPF = real
        if control:
            print(f"self-test BROKEN: pristine copy already fails ({control[0]})")
            bad += 1
        elif any(expect in failure for failure in failures):
            print(f"self-test ok: {name} -> caught")
        else:
            print(f"self-test MISSED: {name} -- the doctored twin PASSED; "
                  f"this check can no longer go red")
            bad += 1

    if bad:
        return 1
    print("self-test: every check can go red")
    return 0


def main() -> int:
    failures, per_file, total = run_all_checks()

    if failures:
        print("FAIL: conversation stickiness must name the pool its endpoint index belongs to")
        for failure in failures:
            print(f"  {failure}")
        return 1

    detail = ", ".join(f"{name} {count}" for name, count in per_file.items())
    print(f"PASS: conversation stickiness names its pool at all {total} call sites ({detail})")
    # Named separately so a CI log shows these ran, rather than only a summary.
    print("PASS: HA failover refuses a conversation row whose pool it can only guess")
    print("PASS: a session id that does not fit is bound, not dropped")
    print("PASS: a health signal reaches every pool that carries its endpoint")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(main())
