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
    if len(sys.argv) != 2:
        print("usage: govulncheck-gate.py <govulncheck.json>", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1]) as fh:
            objs = list(iter_messages(fh.read()))
    except (OSError, json.JSONDecodeError) as e:
        print(f"govulncheck-gate: cannot read/parse output: {e}", file=sys.stderr)
        return 2
    if not objs:
        print("govulncheck-gate: empty govulncheck output (scan did not run)",
              file=sys.stderr)
        return 2

    fixable = {}       # osv -> fixed_version
    nofix = set()      # osv reachable but with no upstream fix
    for obj in objs:
        fd = obj.get("finding")
        if not fd:
            continue
        osv = fd.get("osv")
        if not osv:
            continue
        trace = fd.get("trace") or []
        # Reachable from our code: some trace frame is a function in this module.
        reachable = any(
            fr.get("function") and (fr.get("module") or "").startswith(MODULE)
            for fr in trace
        )
        if not reachable:
            continue
        fv = fd.get("fixed_version") or ""
        if fv:
            fixable[osv] = fv
        else:
            nofix.add(osv)

    if nofix:
        print("govulncheck-gate: ignoring reachable advisories with NO upstream "
              "fix: " + ", ".join(sorted(nofix)))
    if fixable:
        print("govulncheck-gate: reachable vulnerabilities WITH an available fix "
              "(bump required):")
        for osv, fv in sorted(fixable.items()):
            print(f"  {osv}  -> fixed in {fv}")
        return 1
    print("govulncheck-gate: OK - no reachable, fixable vulnerabilities"
          + (f" ({len(nofix)} unfixable advisory ignored)" if nofix else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
