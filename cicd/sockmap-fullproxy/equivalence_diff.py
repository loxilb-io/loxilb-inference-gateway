#!/usr/bin/env python3
"""equivalence_diff.py - compares two runs of request_path_client.py's echo mode.

The invariant under test: on a rule that qualifies for acceleration the proxy
modifies no byte of any request or response, so what the client and the backend
observe must be identical with acceleration on and off. This tool is that
comparison.

Only values that differ because the two arms are DIFFERENT RULES are normalized:

  * the Host header the backend saw, and the authority in any response header,
    carry the VIP port, which is per rule -> the candidate's port is rewritten to
    the baseline's;
  * response headers listed with --drop (Date by default) change per request.

Nothing else is normalized. In particular no request header is exempt: a header
the proxy injects or strips on one arm and not the other is a difference, and the
absence of an exemption list is deliberate — inject_forwarded_headers,
l7_inject_req_headers_h1, ai_strip_upstream_api_key and the Set-Cookie and HSTS
injectors are all either HTTPS-gated or gated on a rule shape that acceleration
refuses, so a qualifying rule has nothing to inject.

  equivalence_diff.py --baseline off.jsonl --candidate both.jsonl \
                      --baseline-port 2080 --candidate-port 2083
"""
import argparse
import json
import sys

DEFAULT_DROP = ['date']


def load(path):
    records = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if not line.startswith('{'):
                # The client prints "FAIL ..." instead of records when the run
                # broke; surface that rather than reporting an empty diff.
                raise ValueError('not a record: %s' % line[:120])
            records.append(json.loads(line))
    return records


def normalize(rec, from_port, to_port, drop):
    port_from, port_to = ':%d' % from_port, ':%d' % to_port
    out = json.loads(json.dumps(rec))          # deep copy
    rhdr = out.get('rhdr') or {}
    for name in drop:
        rhdr.pop(name, None)
    for name, value in list(rhdr.items()):
        if isinstance(value, str):
            rhdr[name] = value.replace(port_from, port_to)
    bhdr = (out.get('backend') or {}).get('headers') or {}
    for name, value in list(bhdr.items()):
        if isinstance(value, str):
            bhdr[name] = value.replace(port_from, port_to)
    return out


def diff_record(base, cand):
    """Returns a list of human readable differences between two records."""
    out = []
    for key in ('req', 'sent', 'status'):
        if base.get(key) != cand.get(key):
            out.append('%s: %r != %r' % (key, base.get(key), cand.get(key)))

    bh, ch = base.get('rhdr') or {}, cand.get('rhdr') or {}
    for name in sorted(set(bh) | set(ch)):
        if bh.get(name) != ch.get(name):
            out.append('response header %s: %r != %r' % (name, bh.get(name), ch.get(name)))

    bb, cb = base.get('backend') or {}, cand.get('backend') or {}
    for key in ('name', 'method', 'path', 'len', 'sha256'):
        if bb.get(key) != cb.get(key):
            out.append('backend %s: %r != %r' % (key, bb.get(key), cb.get(key)))
    bbh, cbh = bb.get('headers') or {}, cb.get('headers') or {}
    for name in sorted(set(bbh) | set(cbh)):
        if bbh.get(name) != cbh.get(name):
            out.append('request header the backend saw, %s: %r != %r'
                       % (name, bbh.get(name), cbh.get(name)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--baseline', required=True)
    ap.add_argument('--candidate', required=True)
    ap.add_argument('--baseline-port', type=int, required=True)
    ap.add_argument('--candidate-port', type=int, required=True)
    ap.add_argument('--drop', action='append', default=None,
                    help='response header to ignore (default: %s)' % ','.join(DEFAULT_DROP))
    ap.add_argument('--max-report', type=int, default=8)
    args = ap.parse_args()
    drop = [d.lower() for d in (args.drop if args.drop is not None else DEFAULT_DROP)]

    try:
        base = load(args.baseline)
        cand = load(args.candidate)
    except (OSError, ValueError) as exc:
        print('DIFF unreadable: %s' % exc)
        return 1

    if not base or not cand:
        print('DIFF empty: baseline %d records, candidate %d' % (len(base), len(cand)))
        return 1
    if len(base) != len(cand):
        print('DIFF record count: baseline %d, candidate %d' % (len(base), len(cand)))
        return 1

    problems = []
    for b, c in zip(base, cand):
        b = normalize(b, args.baseline_port, args.baseline_port, drop)
        c = normalize(c, args.candidate_port, args.baseline_port, drop)
        for line in diff_record(b, c):
            problems.append('request %s (%s): %s' % (b.get('i'), b.get('req'), line))

    if problems:
        shown = problems[:args.max_report]
        extra = len(problems) - len(shown)
        print('DIFF %d difference(s): %s%s'
              % (len(problems), ' | '.join(shown), ' | +%d more' % extra if extra else ''))
        return 1

    print('OK %d records identical' % len(base))
    return 0


if __name__ == '__main__':
    sys.exit(main())
