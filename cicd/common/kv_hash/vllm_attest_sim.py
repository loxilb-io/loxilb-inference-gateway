#!/usr/bin/env python3
"""vllm_attest_sim.py — a contract-faithful vLLM attestation endpoint for
GPU-free suites.

Serves exactly the surface the gateway's vLLM attestation adapter probes,
plus the KV-event publish the echo challenge watches for:

  POST /tokenize        {"model","prompt"} -> {"count","tokens","max_model_len"}
                        (tokenizers lib, add_special_tokens=True — the same
                        convention gen_probe_fixtures.py pins the committed
                        expect files with)
  GET  /version         {"version": --engine-version}
  GET  /v1/models       {"data":[{"id": --model}]}
  POST /v1/completions  tokenizes the prompt with the kv_hash_parity core
                        (the proven-parity twin of the gateway's CGO path),
                        computes the full-block chained hashes and publishes
                        ONE BlockStored batch on the ZMQ PUB socket in the
                        tagged-map (map-v2) wire family:
                          frames [topic | seq:u64-BE | msgpack([ts, [event...], dp_rank])]
                          event = {"type":"BlockStored","block_hashes":[u64...],
                                   "token_ids":[...]}
                        then answers a minimal completions body.

Fault injection for red twins:
  --fail tokenize-drift   /tokenize flips the last token id (token_mismatch)
  --fail no-echo          /v1/completions answers but publishes NOTHING
                          (challenge_timeout)
  --fail wrong-echo       publishes a corrupted hash chain (hash mismatch)

Hash math is IMPORTED from kv_hash_parity.py (the single Python source of
record) — never re-implemented here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from kv_hash_parity import (  # noqa: E402
    _compute_client_blocks,
    _load_tokenizer,
)

try:
    import msgpack  # noqa: E402
    import zmq  # noqa: E402
except ImportError as exc:  # pragma: no cover - environment guard
    print(f"ERROR: pyzmq + msgpack are required ({exc})", file=sys.stderr)
    sys.exit(2)

try:
    from tokenizers import Tokenizer  # noqa: E402
except ImportError as exc:  # pragma: no cover - environment guard
    print(f"ERROR: tokenizers package is required ({exc})", file=sys.stderr)
    sys.exit(2)


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tokenizer", required=True, help="path to tokenizer.json")
    p.add_argument("--model", required=True, help="served model name")
    p.add_argument("--bind", default="0.0.0.0", help="HTTP+ZMQ bind address")
    p.add_argument("--http-port", type=int, default=80)
    p.add_argument("--zmq-port", type=int, default=5557)
    p.add_argument("--block-size", type=int, default=16)
    p.add_argument("--algo", default="sha256_cbor")
    p.add_argument("--none-hash-seed", default="0")
    p.add_argument("--engine-version", default="0.28.0")
    p.add_argument("--max-model-len", type=int, default=40960)
    p.add_argument("--topic", default="")
    p.add_argument("--fail", choices=["tokenize-drift", "no-echo", "wrong-echo"],
                   default=None)
    return p.parse_args(argv)


class Publisher:
    """ZMQ PUB socket emitting the 3-frame map-v2 envelope."""

    def __init__(self, bind, port, topic):
        ctx = zmq.Context.instance()
        self.sock = ctx.socket(zmq.PUB)
        self.sock.bind(f"tcp://{bind}:{port}")
        self.topic = topic.encode()
        self.seq = 0
        self.lock = threading.Lock()
        time.sleep(0.3)  # PUB/SUB slow-joiner guard

    def emit_block_stored(self, hashes, token_ids):
        event = {
            "type": "BlockStored",
            "block_hashes": [int(h) for h in hashes],
            "token_ids": [int(t) for t in token_ids],
        }
        batch = [time.time(), [event], None]
        with self.lock:
            frames = [
                self.topic,
                self.seq.to_bytes(8, "big"),
                msgpack.packb(batch, use_bin_type=True),
            ]
            self.sock.send_multipart(frames)
            self.seq += 1


def main(argv):
    args = parse_args(argv)

    fixture_tok = Tokenizer.from_file(args.tokenizer)
    parity_tok = _load_tokenizer(args.tokenizer)
    pub = Publisher(args.bind, args.zmq_port, args.topic)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):  # quiet
            pass

        def _json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/version":
                self._json(200, {"version": args.engine_version})
            elif self.path == "/v1/models":
                self._json(200, {"data": [{"id": args.model}]})
            elif self.path == "/healthz":
                self._json(200, {"status": "ok"})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n)
            try:
                req = json.loads(raw)
            except Exception:
                self._json(400, {"error": "bad json"})
                return

            if self.path == "/tokenize":
                ids = fixture_tok.encode(req.get("prompt", ""),
                                         add_special_tokens=True).ids
                if args.fail == "tokenize-drift" and ids:
                    ids = ids[:-1] + [ids[-1] ^ 1]
                self._json(200, {"count": len(ids), "tokens": ids,
                                 "max_model_len": args.max_model_len})
            elif self.path == "/v1/completions":
                prompt = req.get("prompt", "")
                token_ids = parity_tok.encode(prompt)
                blocks = _compute_client_blocks(
                    token_ids, args.block_size, args.algo, args.none_hash_seed)
                hashes = [u64 for (_idx, u64, _cbor, _toks) in blocks]
                if args.fail == "wrong-echo":
                    hashes = [h ^ 0xDEAD for h in hashes]
                if args.fail != "no-echo" and hashes:
                    pub.emit_block_stored(hashes, token_ids)
                self._json(200, {
                    "id": "cmpl-sim", "object": "text_completion",
                    "model": args.model,
                    "choices": [{"index": 0, "text": " ok",
                                 "finish_reason": "length"}],
                    "usage": {"prompt_tokens": len(token_ids),
                              "completion_tokens": 1,
                              "total_tokens": len(token_ids) + 1},
                })
            else:
                self._json(404, {"error": "not found"})

    srv = ThreadingHTTPServer((args.bind, args.http_port), Handler)
    print(f"vllm-attest-sim: model={args.model} http={args.bind}:{args.http_port} "
          f"zmq={args.zmq_port} algo={args.algo} fail={args.fail}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main(sys.argv[1:])
