#!/usr/bin/env python3
"""gen_longctx.py — deterministic long-context coding-assistant corpus generator.

The long-context legs (validation.sh scenario 5) need prompts that look like what
a coding assistant actually sends — kilobytes of source code full of newlines,
tabs, and quotes — NOT the short single-line escape-clean strings the base corpus
deliberately restricted itself to (before the escape-parity fix the selector
tokenized RAW JSON-escaped bytes, so any escape broke publisher parity; the base
corpus dodged that; these prompts exist to PIN the fix).

Everything here is a pure function of the constants below (no randomness, no
time), so the publisher (which tokenizes the text it reads from the generated
corpus) and the request path (which POSTs the same text as a JSON "prompt")
always agree byte-for-byte.

Subcommands:
  --emit-corpus BASE OUT   merge BASE (the checked-in corpus.json) + the two
                           generated long-context prompts into OUT.
  --emit-oversize-body N OUT --model M
                           write a complete /v1/completions request body
                           {"model": M, "prompt": <~N bytes of code>,
                            "max_tokens": 8} to OUT. Used by the oversize
                           fail-open leg only — never published (its point is
                           that inspection is SKIPPED and Tier-2 serves it).
"""

import argparse
import json
import sys

# Distinct preambles: each long-context prompt must be unique within its first
# ~511 DECODED bytes (MAX_PREFIX_LEN window) — that window is the entire routing
# signal for /v1/completions, so two prompts sharing it are indistinguishable to
# the selector (by design; see the README's long-context notes).
#
# CRITICAL detection property: the preambles open with CODE — a JSON escape
# (`\n`, `\"`) lands INSIDE the very first 16-token block. Before the
# escape-parity fix the
# selector tokenized RAW escaped bytes, so block 1 already mismatched the
# publisher chain -> ZERO overlap -> no_worker -> silent Tier-2 RR (the clean
# A/B FAIL signature). A prose-only opening would leave the first ~3 blocks
# escape-free and still partially match, masking the defect (live-proven on the
# pre-fix image: prose preamble -> tier15 hit with a 3-block overlap).
PREAMBLE_REVIEW = (
    "// FILE: pkg/loxinet/rules.go\n"
    "// REVIEW-REQUEST tier=1 owner=\"netops\" ci=\"pre-merge\"\n"
    "You are an expert Go code-review assistant embedded in a CI pipeline for an "
    "eBPF load balancer. Review the following control-plane source listing for "
    "correctness, races, and API misuse. Cite line tags in your findings.\n"
)
PREAMBLE_DEEP = (
    "// FILE: pkg/loxinet/ai_kv_subscriber.go\n"
    "// MIGRATION-PLAN scope=\"module\" breaking=\"no\"\n"
    "You are a repository-scale refactoring assistant. The full module source "
    "follows; produce a migration plan that renames the legacy KV inventory API "
    "without breaking the CGO bridge or the subscriber resync contract.\n"
)


def code_block(tag, i):
    """One deterministic ~200-byte Go-ish function with newlines/tabs/quotes."""
    return (
        f"// {tag} block {i:04d} — synthetic but realistic reviewer input\n"
        f"func {tag}Handler{i:04d}(w http.ResponseWriter, r *http.Request) {{\n"
        f"\tkey := r.Header.Get(\"X-Api-Key\")\n"
        f"\tif key == \"\" {{\n"
        f"\t\thttp.Error(w, \"missing key {i:04d}\", http.StatusUnauthorized)\n"
        f"\t\treturn\n"
        f"\t}}\n"
        f"\tmetrics.Observe(\"{tag}_latency_{i:04d}\", time.Since(start))\n"
        f"}}\n\n"
    )


def gen_prompt(preamble, tag, target_bytes):
    parts = [preamble]
    size = len(preamble)
    i = 0
    while size < target_bytes:
        b = code_block(tag, i)
        parts.append(b)
        size += len(b)
        i += 1
    parts.append(f"\nEnd of listing ({i} blocks). Provide the review now.\n")
    return "".join(parts)


def emit_corpus(base_path, out_path):
    with open(base_path) as f:
        doc = json.load(f)
    doc["prompts"] = list(doc["prompts"]) + [
        {
            "id": "longctx-code-review",
            "scenario": [5],
            "prompt": gen_prompt(PREAMBLE_REVIEW, "review", 12 * 1024),
            "drives": (
                "Scenario 5a/5b (long-context hit + slow-writer). ~12KB of real "
                "code text (newlines/tabs/quotes throughout — the escape-parity "
                "regression detector) published to EP-B; the selector must still "
                "match via its decoded, escape/UTF-8-safe truncated prefix, over "
                "a request body that spans many TCP segments."
            ),
        },
        {
            "id": "longctx-deep-context",
            "scenario": [5],
            "prompt": gen_prompt(PREAMBLE_DEEP, "deep", 40 * 1024),
            "drives": (
                "Scenario 5c (deep-context truncation parity). ~40KB prompt: the "
                "publisher hashes the FULL token chain, loxilb hashes only the "
                "MAX_PREFIX_LEN-truncated head — the leading blocks must still "
                "match (BPE prefix stability) and route to the publisher EP."
            ),
        },
    ]
    with open(out_path, "w") as f:
        json.dump(doc, f)
    print(f"emitted merged corpus -> {out_path} "
          f"({len(doc['prompts'])} prompts)")


def emit_oversize(nbytes, model, out_path):
    prompt = gen_prompt(
        "OVERSIZE CONTEXT WINDOW DUMP (never published — fail-open leg).\n",
        "oversize", nbytes)
    body = {"model": model, "prompt": prompt, "max_tokens": 8}
    with open(out_path, "w") as f:
        json.dump(body, f)
    print(f"emitted oversize request body -> {out_path} "
          f"({len(prompt)} prompt bytes)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit-corpus", nargs=2, metavar=("BASE", "OUT"))
    ap.add_argument("--emit-oversize-body", nargs=2, metavar=("NBYTES", "OUT"))
    ap.add_argument("--model", default="Qwen/Qwen3-0.6B")
    args = ap.parse_args()
    if args.emit_corpus:
        emit_corpus(args.emit_corpus[0], args.emit_corpus[1])
    elif args.emit_oversize_body:
        emit_oversize(int(args.emit_oversize_body[0]), args.model,
                      args.emit_oversize_body[1])
    else:
        ap.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
