#!/usr/bin/env python3
"""capture_kv_wire.py — bank a live KV-event wire capture.

Subscribes a ZMQ SUB socket to an engine's KV-event publisher and writes
every multipart message verbatim (raw frame hex) PLUS a best-effort msgpack
decode, so the banked file proves the wire shape byte-for-byte and stays
human-readable. Written for the live validation legs after the 2026-08-31 recon
banked an EMPTY capture while its record claimed a decoded shape — a
capture run is only evidence when the file is non-empty AND self-verifying,
so this tool FAILS (rc 2) when nothing arrives.

Usage:
  python3 capture_kv_wire.py --endpoint tcp://10.0.0.7:5557 \
      --out sglang-kvwire-<runid>.json [--messages 4] [--timeout 60]

Output JSON:
  {"endpoint","captured_at_epoch","messages":[
     {"frames_hex":[...], "frame_count":N,
      "decoded":{"seq":N,"batch":<msgpack-decode or error string>}}]}
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import msgpack
import zmq


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--endpoint", required=True, help="tcp://host:port")
    ap.add_argument("--out", required=True)
    ap.add_argument("--messages", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=60,
                    help="overall seconds to wait for --messages messages")
    args = ap.parse_args()

    ctx = zmq.Context.instance()
    sub = ctx.socket(zmq.SUB)
    sub.connect(args.endpoint)
    sub.setsockopt(zmq.SUBSCRIBE, b"")

    got = []
    deadline = time.time() + args.timeout
    while len(got) < args.messages and time.time() < deadline:
        remaining_ms = max(1, int((deadline - time.time()) * 1000))
        if not sub.poll(remaining_ms):
            break
        frames = sub.recv_multipart()
        entry = {
            "frames_hex": [f.hex() for f in frames],
            "frame_count": len(frames),
            "decoded": {},
        }
        try:
            if len(frames) >= 3:
                entry["decoded"]["seq"] = int.from_bytes(frames[1], "big")
                entry["decoded"]["batch"] = msgpack.unpackb(frames[2], raw=False)
            else:
                entry["decoded"]["error"] = f"{len(frames)} frames (expected 3)"
        except Exception as exc:  # keep the raw hex either way
            entry["decoded"]["error"] = f"msgpack decode failed: {exc}"
        got.append(entry)
        print(f"captured message {len(got)}/{args.messages} "
              f"({len(frames)} frames)", flush=True)

    doc = {"endpoint": args.endpoint,
           "captured_at_epoch": int(time.time()),
           "messages": got}
    with open(args.out, "w") as f:
        json.dump(doc, f, indent=1)

    if not got:
        print(f"FAIL: zero messages within {args.timeout}s — an empty "
              "capture is NOT evidence", file=sys.stderr)
        return 2
    print(f"banked {len(got)} message(s) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
