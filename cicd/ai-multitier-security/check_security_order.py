#!/usr/bin/env python3
"""Static admission-order gate for the AI Gateway HTTP data planes.

This is deliberately narrow.  It does not claim that a source match proves
runtime behaviour; the C unit and remote runtime probes provide those layers.
Its job is to make three security-sensitive wiring regressions impossible to
hide in a large sockproxy diff:

* HTTP/2 captures X-Api-Key in per-stream state.
* HTTP/2 evaluates the mandatory admission gate before any L7, model, tier, or
  fallback endpoint selection.
* A declared AI credential is removed after optional L7 header mutation and
  before nghttp2 submits the request to a backend.
* HTTP/1 and HTTP/2 header ownership is derived only from api_key_auth. SSE/P/D
  may arm accounting but cannot consume a backend-owned X-Api-Key on an
  undeclared service.

The HTTP/1 denial escape hatch is retained as a fourth invariant: a callback
denial must leave the read loop before setup_proxy_path() can dispatch it.
"""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
H2 = ROOT / "loxilb-ebpf/common/sockproxy_h2.c"
H1 = ROOT / "loxilb-ebpf/common/sockproxy_http.c"
SECURITY = ROOT / "loxilb-ebpf/common/sockproxy_ai_security.c"


def function_body(text: str, name: str) -> str:
    match = re.search(rf"\n{name}\s*\([^;]*?\)\s*\{{", text, re.S)
    if not match:
        raise AssertionError(f"function {name} not found")
    start = match.end() - 1
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError(f"function {name} has no closing brace")


def ordered(body: str, *needles: str) -> None:
    positions = []
    for needle in needles:
        position = body.find(needle)
        if position < 0:
            raise AssertionError(f"missing required call or token: {needle}")
        positions.append(position)
    if positions != sorted(positions):
        pairs = ", ".join(f"{needle}@{pos}" for needle, pos in zip(needles, positions))
        raise AssertionError(f"security-sensitive operations are out of order: {pairs}")


def code_only(text: str) -> str:
    """Remove comments so prose cannot satisfy or reorder a call invariant."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def main() -> int:
    h2 = H2.read_text(encoding="utf-8")
    h1 = H1.read_text(encoding="utf-8")
    security = SECURITY.read_text(encoding="utf-8")

    header = code_only(function_body(h2, "proxy_h2_on_header_callback"))
    if 'HEADER_MATCHES("x-api-key")' not in header:
        raise AssertionError("HTTP/2 does not capture x-api-key into stream state")
    if "ai_security_copy_api_key" not in header:
        raise AssertionError("HTTP/2 x-api-key capture does not use the bounded helper")

    forward = code_only(function_body(h2, "proxy_h2_forward_to_backend"))
    admission = forward.find("ai_security_admit")
    if admission < 0:
        raise AssertionError("HTTP/2 forward path has no AI security admission gate")
    for call in re.findall(r"log_[a-z]+\s*\(.*?\);", forward, flags=re.S):
        if "x_api_key_raw" in call and "x_api_key_raw[0]" not in call:
            raise AssertionError("HTTP/2 logs credential bytes instead of presence only")
    selectors = {
        token: forward.find(token)
        for token in ("l7_route_dispatch", "find_endpoint_lpm", "chwbl_ring_lookup")
        if forward.find(token) >= 0
    }
    late = {token: pos for token, pos in selectors.items() if pos < admission}
    if late:
        raise AssertionError(f"HTTP/2 selector(s) execute before admission: {late}")

    ordered(
        forward,
        "proxy_h2_build_l7_req_headers",
        "ai_security_filter_h2_headers",
        "nghttp2_submit_request",
    )

    strip_h2 = code_only(function_body(security, "ai_security_filter_h2_headers"))
    if "ai_security_should_strip_api_key(policy)" not in strip_h2:
        raise AssertionError("HTTP/2 header filter bypasses the shared policy-ownership predicate")
    if "ai_gw_mode" in strip_h2:
        raise AssertionError("HTTP/2 header ownership still depends on ai_gw_mode")

    strip_h1 = code_only(function_body(h1, "ai_strip_upstream_api_key"))
    if "ai_security_should_strip_api_key(node->val.ephash->apikey_auth)" not in strip_h1:
        raise AssertionError("HTTP/1 header strip bypasses the shared policy-ownership predicate")
    if "ai_gw_mode" in strip_h1:
        raise AssertionError("HTTP/1 header ownership still depends on ai_gw_mode")

    if "security_ai_mode" in forward:
        raise AssertionError("HTTP/2 forwarding still keys credential stripping on ai_gw_mode")

    # The H1 parser callback marks ai_gw_denied; the read loop must consume the
    # marker and return before its malformed-HTTP compatibility dispatch.
    denied = h1.find("else if (pfe->ai_gw_denied)")
    if denied < 0:
        raise AssertionError("HTTP/1 denial marker branch is missing")
    tail = code_only(h1[denied : denied + 5000])
    ordered(tail, "return -1", "setup_proxy_path")

    print("PASS: mandatory admission order and policy-owned H1/H2 credential stripping")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
