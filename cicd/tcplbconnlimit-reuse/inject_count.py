#!/usr/bin/env python3
"""Reads a `bpftool map dump name nat_ep_map -j` on stdin, finds the one rule
index whose live connection count is HAVE, and prints the bpftool arguments
that rewrite that entry with the count set to WANT:

  inject_count.py HAVE WANT   ->   key <4 bytes> value <bytes>

The count's position in the raw value is located by matching the decoded
conc_conns and total_conns against the raw bytes, and must be unambiguous;
otherwise nothing is printed and the exit status is 1."""
import json
import sys


def main():
    have, want = int(sys.argv[1]), int(sys.argv[2])
    hits = [e for e in json.load(sys.stdin)
            if e['formatted']['value']['conc_conns'] == have]
    if len(hits) != 1:
        print('%d rule indexes count %d' % (len(hits), have), file=sys.stderr)
        return 1
    raw = bytes(int(b, 16) for b in hits[0]['value'])
    total = hits[0]['formatted']['value']['total_conns']
    pair = have.to_bytes(4, sys.byteorder) + total.to_bytes(4, sys.byteorder)
    at = [o for o in range(0, len(raw) - 7, 4) if raw[o:o + 8] == pair]
    if len(at) != 1:
        print('count found at %d offsets' % len(at), file=sys.stderr)
        return 1
    new = raw[:at[0]] + want.to_bytes(4, sys.byteorder) + raw[at[0] + 4:]
    print('key %s value %s' % (' '.join(hits[0]['key']),
                               ' '.join('0x%02x' % b for b in new)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
