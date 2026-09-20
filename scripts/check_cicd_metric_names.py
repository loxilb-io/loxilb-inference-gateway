#!/usr/bin/env python3
"""Static gate: a cicd assert may not name a metric family that does not exist.

An assert that greps for a family no build ever exported cannot match. It does
not fail — it takes the other branch, silently, forever. cicd/vllm-pd-disagg
carried one for two months: TH5 counted `endpoint_ip=` labels on
`loxilb_ai_pd_prefill_duration_per_ep_seconds`, a family that has never been
registered by any build (no AI P/D family carries an endpoint label at all), so
the primary branch was dead from the day it was written and an unrelated
control-plane readback in the `else` arm scored in its place under the per-EP
name. The scenario is gated by ai-gateway-sanity, so CI reported the phase
green on a claim it had never once evaluated.

A name that does not exist is the cheapest possible thing to check, and it is
the only half of that defect a static gate can see, so it is checked here.

The rule, and why it is shaped this way: cicd scripts are shell, and shell is
full of `loxilb_`-prefixed things that are not metrics — `loxilb_ip`,
`loxilb_config`, `loxilb_pid`, and grep prefixes like `loxilb_ai_token_quota_`.
Flagging those would make the gate noise and the gate would be turned off. So a
token is reported only when it is unmistakably reaching for a metric: it is not
a bare prefix, it is not a real family (after stripping the suffixes Prometheus
appends), and its first three underscore-separated segments name a namespace
that real families do live in. Over the whole tree that rule has exactly one
hit, the defect above, and no false positives.

Usage:
    scripts/check_cicd_metric_names.py
    scripts/check_cicd_metric_names.py --self-test
"""

import json
import os
import re
import subprocess
import sys

MANIFEST = "deploy/monitoring/manifest/metric-manifest.json"

# What Prometheus appends to a family name in the exposition format. A scenario
# legitimately greps for any of these.
SUFFIXES = ("_bucket", "_sum", "_count", "_created", "_total", "_info")

TOKEN = re.compile(r"loxilb_[a-z0-9_]+")


def repo_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load_families(path: str = MANIFEST) -> set:
    with open(path) as fh:
        return {f["name"] for f in json.load(fh)["families"]}


def namespaces(families: set) -> set:
    """The three-segment prefixes real families live under."""
    return {"_".join(n.split("_")[:3]) for n in families if n.count("_") >= 2}


def is_real(token: str, families: set) -> bool:
    if token in families:
        return True
    for suf in SUFFIXES:
        if token.endswith(suf) and token[: -len(suf)] in families:
            return True
    return False


def scan_text(text: str, families: set, ns: set) -> list:
    """Return [(lineno, token)] for every unreal family name in a file body.

    Whole-line shell comments are skipped: naming a family that was removed, or
    one that never existed, is exactly what a comment explaining the removal has
    to do. An assert cannot live in a comment.
    """
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for token in TOKEN.findall(line):
            if token.endswith("_"):          # a grep prefix, not a family
                continue
            if is_real(token, families):
                continue
            if "_".join(token.split("_")[:3]) not in ns:
                continue                     # not in any metric namespace
            out.append((lineno, token))
    return out


def cicd_files(root: str) -> list:
    listing = subprocess.run(
        ["git", "ls-files", "cicd/"], cwd=root, capture_output=True, text=True
    )
    return [p for p in listing.stdout.split("\n") if p]


def run(root: str) -> list:
    families = load_families(os.path.join(root, MANIFEST))
    ns = namespaces(families)
    findings = []
    for rel in cicd_files(root):
        path = os.path.join(root, rel)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except (IsADirectoryError, FileNotFoundError):
            continue
        for lineno, token in scan_text(text, families, ns):
            findings.append((rel, lineno, token))
    return findings


def self_test() -> int:
    """Red-twin every arm: a gate that cannot go red is worth less than none."""
    families = {
        "loxilb_ai_pd_prefill_duration_seconds",
        "loxilb_ai_pd_requests_total",
        "loxilb_kv_subscriber_reconnect_total",
    }
    ns = namespaces(families)

    clean = """
VAL=$(echo "$M" | grep 'loxilb_ai_pd_prefill_duration_seconds_count{')
REQ=$(echo "$M" | grep 'loxilb_ai_pd_requests_total{')
# loxilb_ai_pd_prefill_duration_per_ep_seconds never existed -- see the comment
PFX=$(echo "$M" | grep 'loxilb_ai_pd_')
loxilb_ip="10.0.0.1"
loxilb_config=/etc/loxilb
"""
    if scan_text(clean, families, ns):
        print("self-test BROKEN: the clean fixture already fails "
              f"({scan_text(clean, families, ns)})")
        return 1
    print("self-test ok: clean fixture passes")

    twins = {
        "unreal family in a live namespace":
            "H=$(grep 'loxilb_ai_pd_prefill_duration_per_ep_seconds' <<<\"$M\")",
        "unreal family with a real suffix":
            "H=$(grep 'loxilb_ai_pd_tokens_emitted_total' <<<\"$M\")",
        "typo inside a label selector":
            "H=$(grep 'loxilb_kv_subscriber_reconnects_total{ep=\"1\"}' <<<\"$M\")",
    }
    failed = 0
    for name, body in twins.items():
        if scan_text(body, families, ns):
            print(f"self-test ok: {name} -> caught")
        else:
            print(f"self-test MISSED: {name} -- the doctored twin PASSED")
            failed = 1

    # The comment skip must be a skip, not a blind spot for real asserts.
    commented = "# H=$(grep 'loxilb_ai_pd_prefill_duration_per_ep_seconds')"
    if scan_text(commented, families, ns):
        print("self-test MISSED: a whole-line comment was reported")
        failed = 1
    else:
        print("self-test ok: whole-line comment -> skipped")

    print("self-test: every check can go red" if not failed
          else "self-test: a check cannot go red")
    return failed


def main() -> int:
    root = repo_root()
    findings = run(root)
    if not findings:
        print("  ok    every metric family named in cicd/ exists in the manifest")
        return 0
    for rel, lineno, token in findings:
        print(f"  FAIL  {rel}:{lineno} names {token}, which no build exports")
    print(f"  FAIL  {len(findings)} cicd reference(s) to a non-existent metric family")
    return 1


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(main())
