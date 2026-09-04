#!/usr/bin/env python3
"""Check a live kvexactstatus body against the published status vocabulary.

The gateway serves attestation-ladder states and reason codes as open
strings (they are published as x-extensions in api/swagger.yml rather than
schema enums, so a new ladder state cannot brick an old client). Nothing in
the generated server therefore validates a served value against the
published vocabulary -- this script closes that loop from the outside.

It reads the two x-blocks out of the swagger file, then walks a
kvexactstatus response body and reports every desiredState, enforcedState,
enforcement.desired, enforcement.enforced and reasonCodes entry that is not
in the vocabulary. Exit status is non-zero when anything is out of vocab,
so it can be dropped straight into a validation leg.

  usage: kv_status_vocab_check.py [--swagger PATH] [BODY.json]
         (body is read from stdin when no file is given)

The unit-layer twin is TestKvStatusVocabularySync in pkg/loxinet, which
pins the Go constants against the same x-blocks. This script covers the
other direction: what a live gateway actually put on the wire.
"""

import argparse
import json
import sys

STATES_KEY = "x-kv-status-states"
REASONS_KEY = "x-kv-status-reason-codes"
FAULTS_KEY = "x-kv-status-fault-codes"


def collect(node, key, acc):
    """Collect every value stored under `key` anywhere in the document."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                acc.append(v)
            collect(v, key, acc)
    elif isinstance(node, list):
        for v in node:
            collect(v, key, acc)
    return acc


def load_vocabulary(path):
    import yaml

    with open(path) as fh:
        spec = yaml.safe_load(fh)
    states = {s for group in collect(spec, STATES_KEY, []) for s in group}
    reasons = {r for group in collect(spec, REASONS_KEY, []) for r in group}
    faults = {f for group in collect(spec, FAULTS_KEY, []) for f in group}
    if not states or not reasons:
        sys.exit("%s: status vocabulary x-blocks are missing or empty" % path)
    return states, reasons, faults


def check(body, states, reasons, faults):
    """Return (out_of_vocab, unpublished_faults).

    out_of_vocab holds (entry index, field, value) triples for values that
    contradict a vocabulary that exists. unpublished_faults holds the
    enforcement.fault values seen while no fault vocabulary is published at
    all -- KvExactEnforcement.fault is declared only as "Last enforcement
    fault reason", so a client has nothing to render it against. The values
    are emitted as bare literals in pkg/loxinet/ai_kv_dataplane.go, which is
    also why the Go-constant sync test cannot see them.
    """
    bad = []
    unpublished = []
    for i, entry in enumerate(body.get("kvExactStatusAttr") or []):
        for field in ("desiredState", "enforcedState"):
            value = entry.get(field)
            if value is not None and value not in states:
                bad.append((i, field, value))
        enforcement = entry.get("enforcement") or {}
        for field in ("desired", "enforced"):
            value = enforcement.get(field)
            if value is not None and value not in states:
                bad.append((i, "enforcement." + field, value))
        # reasonCodes is required and always present: [] means "no
        # qualifying reason", never "unknown".
        for value in entry.get("reasonCodes") or []:
            if value not in reasons:
                bad.append((i, "reasonCodes[]", value))
        fault = enforcement.get("fault")
        if fault:
            if faults:
                if fault not in faults:
                    bad.append((i, "enforcement.fault", fault))
            else:
                unpublished.append((i, "enforcement.fault", fault))
    return bad, unpublished


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("body", nargs="?", help="kvexactstatus JSON (default: stdin)")
    ap.add_argument("--swagger", default="../../api/swagger.yml")
    args = ap.parse_args()

    states, reasons, faults = load_vocabulary(args.swagger)
    raw = open(args.body).read() if args.body else sys.stdin.read()
    try:
        body = json.loads(raw)
    except ValueError as exc:
        sys.exit("body is not JSON: %s" % exc)

    entries = body.get("kvExactStatusAttr") or []
    bad, unpublished = check(body, states, reasons, faults)

    print("vocabulary: %d states, %d reason codes, %d fault codes%s"
          % (len(states), len(reasons), len(faults),
             " (none published)" if not faults else ""))
    print("checked   : %d status entr%s" % (len(entries), "y" if len(entries) == 1 else "ies"))
    for i, field, value in bad:
        print("OUT-OF-VOCAB entry[%d].%s = %r" % (i, field, value))
    for i, field, value in unpublished:
        print("UNPUBLISHED entry[%d].%s = %r (no fault vocabulary in swagger)"
              % (i, field, value))
    if not entries:
        print("RESULT: no entries to check")
        return 0
    print("RESULT: %s" % ("PASS" if not bad else "FAIL (%d out of vocabulary)" % len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
