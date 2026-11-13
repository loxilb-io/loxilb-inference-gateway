#!/usr/bin/env python3
"""Reads a `bpftool map dump name nat_ep_map -j` on stdin, finds the one rule
index that counts per-endpoint sessions, and prints the bpftool arguments that
rewrite that entry with the session count of endpoint slot SLOT changed from
HAVE to WANT:

  inject_sessions.py SLOT HAVE WANT   ->   key <4 bytes> value <bytes>

The session counts sit directly in front of the live connection count in the
raw value. That position is located by matching the decoded conc_conns and
total_conns against the raw bytes, must be unambiguous, and the bytes in front
of it must decode to exactly the session counts bpftool printed; otherwise
nothing is printed and the exit status is 1."""
import json
import sys


def main():
    slot, have, want = (int(a) for a in sys.argv[1:4])
    hits = [e for e in json.load(sys.stdin)
            if any(e['formatted']['value']['active_sess'])]
    if len(hits) != 1:
        print('%d rule indexes count sessions' % len(hits), file=sys.stderr)
        return 1
    v = hits[0]['formatted']['value']
    sess = list(v['active_sess'])
    if sess[slot] != have:
        print('slot %d counts %d, not %d' % (slot, sess[slot], have), file=sys.stderr)
        return 1
    raw = bytes(int(b, 16) for b in hits[0]['value'])
    pair = (v['conc_conns'].to_bytes(4, sys.byteorder) +
            v['total_conns'].to_bytes(4, sys.byteorder))
    at = [o for o in range(0, len(raw) - 7, 4) if raw[o:o + 8] == pair]
    if len(at) != 1:
        print('count found at %d offsets' % len(at), file=sys.stderr)
        return 1
    start = at[0] - 2 * len(sess)
    if start < 0 or [int.from_bytes(raw[start + 2 * i:start + 2 * i + 2], sys.byteorder)
                     for i in range(len(sess))] != sess:
        print('session counts not found in front of the count', file=sys.stderr)
        return 1
    o = start + 2 * slot
    new = raw[:o] + want.to_bytes(2, sys.byteorder) + raw[o + 2:]
    print('key %s value %s' % (' '.join(hits[0]['key']),
                               ' '.join('0x%02x' % b for b in new)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
