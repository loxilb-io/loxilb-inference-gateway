#!/usr/bin/env python3
"""Gate for a run of ai-ha-failover-bfd in CI.

usage: verdict_gate.py <verdicts.tsv> <known-fail.tsv>

validation.sh reports what the product does and exits non-zero on any FAIL
or NOT_RUN. This gate compares the run with known-fail.tsv, the list of
verdicts that are known not to pass on the product as it is

    <verdict id> <TAB> <FAIL | NOT_RUN> <TAB> <why>

and exits 0 only when the two agree exactly:

  - a FAIL or NOT_RUN that is not on the list fails the job (a regression,
    a new finding, or a check that could not run and so proves nothing);
  - a listed verdict that reports anything other than what the list says
    fails the job too: the product changed, and the entry has to be changed
    or removed in the same change;
  - a listed verdict that is absent from the run fails the job.

A NOT_RUN entry is for an oracle that refuses to judge for a stated reason
(its precondition cannot be met on this product), never for a flaky check.

Matching is exact: one verdict per entry. A fault the run cannot catch every
time (shorter than the sampling interval) is not a known-fail entry; the case
reports it as RECORDED instead of judging it.
"""
import sys


def main():
    verdicts = {}
    for ln in open(sys.argv[1]):
        p = ln.rstrip("\n").split("\t")
        if len(p) >= 2:
            verdicts[p[0]] = p[1]
    known = {}
    for ln in open(sys.argv[2]):
        if ln.strip() and not ln.startswith("#"):
            p = ln.rstrip("\n").split("\t")
            if len(p) < 2 or p[1] not in ("FAIL", "NOT_RUN"):
                print("known-fail.tsv: bad line: %r" % ln)
                return 1
            known[p[0]] = p[1]
    bad = []
    for vid, v in sorted(verdicts.items()):
        if v in ("FAIL", "NOT_RUN") and vid not in known:
            bad.append("UNLISTED %-7s %s" % (v, vid))
    for vid, want in sorted(known.items()):
        got = verdicts.get(vid)
        if got is None:
            bad.append("LISTED, ABSENT   %s (the case did not report)" % vid)
        elif got != want:
            bad.append("LISTED %s, NOW %s: %s (change known-fail.tsv in the same change)" % (want, got, vid))
    count = {}
    for v in verdicts.values():
        count[v] = count.get(v, 0) + 1
    print("verdicts: %s; known-fail entries: %d" % (", ".join("%s=%d" % kv for kv in sorted(count.items())), len(known)))
    for b in bad:
        print("  " + b)
    print("gate: %s" % ("FAIL" if bad else "PASS (the run matches the known-fail list exactly)"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
