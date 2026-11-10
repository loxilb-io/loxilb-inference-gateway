#!/usr/bin/env python3
"""Gate govulncheck (-format json) output: fail CI only on vulnerabilities that
are reachable from this module AND have an available upstream fix.

Advisories with no fixed version (govulncheck reports "Fixed in: N/A") are printed
for visibility but do NOT fail the build — there is nothing to bump to. Example:
GO-2026-4736 (GoBGP NEXT_HOP DoS), which has no fix in any gobgp major version.

Usage: govulncheck-gate.py <govulncheck.json>
Exit:  0 = no reachable+fixable vulns (may still print ignored no-fix advisories)
       1 = at least one reachable+fixable vuln (must be bumped)
       2 = could not read/parse govulncheck output (treat as failure)
"""
import json
import sys
import argparse

MODULE = "github.com/loxilb-io/loxilb"


def iter_messages(text):
    """govulncheck -format json emits a stream of pretty-printed JSON objects
    (not line-delimited, sometimes wrapped in a top-level array). Decode
    concatenated JSON values robustly, flattening any arrays."""
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        obj, i = dec.raw_decode(text, i)
        if isinstance(obj, list):
            yield from obj
        else:
            yield obj


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("--binary", action="store_true", help="gate symbols present in an actual binary, including non-gateway modules")
    args = parser.parse_args()
    try:
        with open(args.report) as fh:
            objs = list(iter_messages(fh.read()))
    except (OSError, json.JSONDecodeError) as e:
        print(f"govulncheck-gate: cannot read/parse output: {e}", file=sys.stderr)
        return 2
    if not objs:
        print("govulncheck-gate: empty govulncheck output (scan did not run)",
              file=sys.stderr)
        return 2
    configs = [o.get("config") for o in objs if isinstance(o, dict) and "config" in o]
    expected = "binary" if args.binary else "source"
    if len(configs) != 1 or not isinstance(configs[0], dict) or configs[0].get("scan_mode") != expected:
        print(f"govulncheck-gate: expected one {expected} scan configuration", file=sys.stderr)
        return 2
    if configs[0].get("scan_level") != "symbol":
        print("govulncheck-gate: symbol-level scan required for the callable/present-symbol gate", file=sys.stderr)
        return 2

    fixable = {}       # osv -> fixed_version
    nofix = set()      # osv reachable but with no upstream fix
    for obj in objs:
        if not isinstance(obj, dict):
            print("govulncheck-gate: invalid message", file=sys.stderr)
            return 2
        if "finding" not in obj:
            continue
        fd = obj["finding"]
        if not isinstance(fd, dict) or not isinstance(fd.get("osv"), str) or not fd["osv"]:
            print("govulncheck-gate: invalid finding", file=sys.stderr)
            return 2
        osv = fd["osv"]
        trace = fd.get("trace") or []
        if not isinstance(trace, list) or any(not isinstance(fr, dict) for fr in trace):
            print("govulncheck-gate: invalid trace", file=sys.stderr)
            return 2
        # Reachable from our code: some trace frame is a function in this module.
        reachable = any(
            fr.get("function") and (args.binary or (fr.get("module") or "").startswith(MODULE))
            for fr in trace
        )
        if not reachable:
            continue
        fv = fd.get("fixed_version") or ""
        if not isinstance(fv, str):
            print("govulncheck-gate: invalid fixed version", file=sys.stderr)
            return 2
        if fv:
            fixable[osv] = fv
        else:
            nofix.add(osv)

    if nofix:
        kind = "binary-symbol" if args.binary else "reachable"
        print(f"govulncheck-gate: ignoring {kind} advisories with NO upstream "
              "fix: " + ", ".join(sorted(nofix)))
    if fixable:
        kind = "vulnerable binary symbols" if args.binary else "reachable vulnerabilities"
        print(f"govulncheck-gate: {kind} WITH an available fix "
              "(bump required):")
        for osv, fv in sorted(fixable.items()):
            print(f"  {osv}  -> fixed in {fv}")
        return 1
    kind = "fixable vulnerable binary symbols" if args.binary else "reachable, fixable vulnerabilities"
    print(f"govulncheck-gate: OK - no {kind}"
          + (f" ({len(nofix)} unfixable advisory ignored)" if nofix else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
