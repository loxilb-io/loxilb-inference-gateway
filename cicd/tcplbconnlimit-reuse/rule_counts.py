#!/usr/bin/env python3
"""Reads a `bpftool map dump name nat_ep_map -j` on stdin and prints what the
datapath counts for the rules that have counted anything, one line per rule
index, without the index itself:

  conc=<live connections> total=<connections ever> in=<bytes> out=<bytes> sess=<a,b,...>

sess is the per-endpoint session count least-connections selection reads, up
to the last endpoint slot that is not zero. Two prints are equal exactly when
none of these counters moved."""
import json
import sys


def main():
    for e in json.load(sys.stdin):
        v = e['formatted']['value']
        sess = list(v['active_sess'])
        while sess and sess[-1] == 0:
            sess.pop()
        if not (v['conc_conns'] or v['total_conns'] or v['cum_bytes_in'] or
                v['cum_bytes_out'] or sess):
            continue
        print('conc=%d total=%d in=%d out=%d sess=%s' % (
            v['conc_conns'], v['total_conns'], v['cum_bytes_in'],
            v['cum_bytes_out'], ','.join(str(n) for n in sess)))


if __name__ == '__main__':
    main()
