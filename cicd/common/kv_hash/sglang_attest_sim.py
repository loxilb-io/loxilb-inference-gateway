#!/usr/bin/env python3
"""sglang_attest_sim.py — a contract-faithful SGLang attestation endpoint
for GPU-free suites (SGLang twin of vllm_attest_sim.py).

Serves exactly the surface the gateway's SGLang attestation adapter probes,
plus the per-rank KV-event publish the page-hash echo challenge watches
for:

  GET  /get_server_info  {"version", "revision", "page_size", "kv_events":
                          {"publisher","endpoint_host","endpoint_port_base",
                           "topic","block_size","dp_size"}, ...noise}
                         (SGLang serves NO /version route — identity and
                         geometry both come from here, as on the live
                         v0.5.18 tuple)
  GET  /get_model_info   {"model_path","served_model_name","is_generation"}
  POST /v1/tokenize      {"model","prompt"} -> {"tokens","count",
                         "max_model_len"} (tokenizers lib,
                         add_special_tokens=True — same convention the
                         committed expect files pin; identical either way
                         for the BOS-less Qwen3 tokenizer)
  POST /v1/completions   tokenizes the prompt, computes the sha256_sglang
                         page chain via the IMPORTED sglang_hash_core (one
                         source of record — zero hash arithmetic here),
                         picks the serving rank round-robin, publishes ONE
                         BlockStored batch on THAT rank's ZMQ PUB socket
                         (port base + rank) in the tagged-ARRAY rank wire
                         family, then answers a minimal completions body.

Wire shape (sglang-kv-tagged-array-rank-v1):
    frames [topic | seq:u64-BE | msgpack([ts, [event...], dp_rank])]
    event  ["BlockStored", [hash_i64...], parent, [token_id...],
            block_size, lora_id, medium, lora_name, extra_keys]
Hashes ride as SIGNED int64 (SGLang's hash_str_to_int64 published form).
NOTE: the 2026-08-31 recon banked an EMPTY wire capture, so this
shape is pinned from in-image code reading + the Go decoder contract; the
live converged leg re-verifies it against a real banked capture before
the tuple promotes.

DP ranks: --dp-ranks N binds N PUB sockets at consecutive ports. Each
completions request is served by exactly one rank (round-robin), so a
DP-coverage leg needs >= N challenges — the same property the adapter's
bounded per-rank challenge loop is built for.

Fault injection for red twins:
  --fail tokenize-drift  /v1/tokenize flips the last token id (rung-1
                         token_mismatch; completions hashes stay CORRECT)
  --fail no-echo         completions answers but publishes NOTHING
                         (challenge_timeout)
  --fail wrong-echo      publishes a corrupted hash chain (hash mismatch)
  --fail rank-lie        publishes on the serving rank's socket but the
                         batch's dp_rank field claims the NEXT rank — the
                         subscriber's socket-rank==payload-rank check must
                         reject it (rank-identity gate), starving the challenge
  --fail rank-split      one challenge's blocks published half from rank 0,
                         half from rank 1 (needs --dp-ranks >= 2) — the
                         adapter's single-rank attribution check must
                         refuse the split echo
  --fail geometry-lie    /get_server_info reports page_size + 16 (typed
                         engine_geometry_mismatch BEFORE any nonce is
                         spent)
  --fail revision-lie    /get_server_info reports a wrong model revision
                         (identity_mismatch when the manifest pins one)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
# sglang_hash_core is the single Python source of record for the SGLang
# page-hash math (same import-only discipline kv_event_publisher.py pins).
sys.path.insert(0, os.path.join(_HERE, "..", "..", "vllm-kvcache-routing-cpu"))

try:
    import sglang_hash_core  # noqa: E402
except ImportError as exc:  # pragma: no cover - environment guard
    print(f"ERROR: cannot import sglang_hash_core ({exc}) — the sim REUSES "
          "its hash chain; re-implementing here would defeat drift "
          "prevention", file=sys.stderr)
    sys.exit(2)

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

FAIL_MODES = ["tokenize-drift", "no-echo", "wrong-echo", "rank-lie",
              "rank-split", "geometry-lie", "revision-lie"]


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tokenizer", required=True, help="path to tokenizer.json")
    p.add_argument("--model", required=True, help="served model alias")
    p.add_argument("--model-path", default=None,
                   help="model_path identity (default: --model)")
    p.add_argument("--bind", default="0.0.0.0", help="HTTP+ZMQ bind address")
    p.add_argument("--http-port", type=int, default=80)
    p.add_argument("--zmq-port", type=int, default=5557,
                   help="rank-0 PUB port (rank N publishes at +N)")
    p.add_argument("--dp-ranks", type=int, default=1)
    p.add_argument("--block-size", type=int, default=16,
                   help="radix page size (server_info page_size)")
    p.add_argument("--engine-version", default="0.5.18")
    p.add_argument("--revision", default="c1899de289a04d12100db370d81485cdf75e47ca")
    p.add_argument("--max-model-len", type=int, default=131072)
    p.add_argument("--topic", default="")
    p.add_argument("--fail", choices=FAIL_MODES, default=None)
    return p.parse_args(argv)


class RankPublisher:
    """One ZMQ PUB socket per DP rank, tagged-array rank-v1 envelope."""

    def __init__(self, bind, base_port, dp_ranks, topic):
        ctx = zmq.Context.instance()
        self.topic = topic.encode()
        self.socks = []
        self.seqs = []
        self.lock = threading.Lock()
        for r in range(dp_ranks):
            s = ctx.socket(zmq.PUB)
            s.bind(f"tcp://{bind}:{base_port + r}")
            self.socks.append(s)
            self.seqs.append(0)
        time.sleep(0.3)  # PUB/SUB slow-joiner guard

    def emit_block_stored(self, rank, hashes_i64, token_ids, block_size,
                          claim_rank=None):
        # Tagged-ARRAY event, field order pinned by the gateway decoder:
        # [tag, hashes, parent, token_ids, block_size, lora_id, medium,
        #  lora_name, extra_keys]. Hashes are SIGNED int64 published values.
        event = [
            "BlockStored",
            [int(h) for h in hashes_i64],
            None,                      # parent (chain root only)
            [int(t) for t in token_ids],
            int(block_size),
            None,                      # lora_id
            "GPU",                     # medium
            None,                      # lora_name
            None,                      # extra_keys
        ]
        rank_field = rank if claim_rank is None else claim_rank
        batch = [time.time(), [event], int(rank_field)]
        with self.lock:
            frames = [
                self.topic,
                self.seqs[rank].to_bytes(8, "big"),
                msgpack.packb(batch, use_bin_type=True),
            ]
            self.socks[rank].send_multipart(frames)
            self.seqs[rank] += 1


def main(argv):
    args = parse_args(argv)
    if args.fail == "rank-split" and args.dp_ranks < 2:
        print("ERROR: --fail rank-split needs --dp-ranks >= 2", file=sys.stderr)
        sys.exit(2)

    tok = Tokenizer.from_file(args.tokenizer)
    pub = RankPublisher(args.bind, args.zmq_port, args.dp_ranks, args.topic)
    model_path = args.model_path or args.model
    rr = {"next": 0}
    rr_lock = threading.Lock()

    def server_info():
        page = args.block_size + (16 if args.fail == "geometry-lie" else 0)
        rev = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" \
            if args.fail == "revision-lie" else args.revision
        return {
            "version": args.engine_version,
            "revision": rev,
            "page_size": page,
            "model_path": model_path,
            "tokenizer_path": model_path,
            # unconsumed launch-config noise — the adapter's pinned decoder
            # must tolerate the real response's hundreds of fields
            "mem_fraction_static": 0.8,
            "schedule_policy": "fcfs",
            "chunked_prefill_size": 2048,
            "kv_events": {
                "publisher": "zmq",
                "endpoint_host": "*",
                "endpoint_port_base": args.zmq_port,
                "topic": args.topic,
                "block_size": page,
                "dp_size": args.dp_ranks,
            },
        }

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
            if self.path == "/get_server_info":
                self._json(200, server_info())
            elif self.path == "/get_model_info":
                self._json(200, {"model_path": model_path,
                                 "served_model_name": args.model,
                                 "is_generation": True})
            elif self.path == "/health":
                self._json(200, {})
            else:
                self._json(404, {"detail": "Not Found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n)
            try:
                req = json.loads(raw)
            except Exception:
                self._json(400, {"detail": "bad json"})
                return

            if self.path == "/v1/tokenize":
                ids = tok.encode(req.get("prompt", ""),
                                 add_special_tokens=True).ids
                if args.fail == "tokenize-drift" and ids:
                    ids = ids[:-1] + [ids[-1] ^ 1]
                self._json(200, {"tokens": ids, "count": len(ids),
                                 "max_model_len": args.max_model_len})
            elif self.path == "/v1/completions":
                prompt = req.get("prompt", "")
                token_ids = tok.encode(prompt, add_special_tokens=True).ids
                bs = args.block_size
                full = (len(token_ids) // bs) * bs
                blocks = sglang_hash_core.blocks_from_tokens(
                    token_ids[:full], bs)
                hashes = sglang_hash_core.sglang_hash_chain(blocks)
                if args.fail == "wrong-echo":
                    hashes = [h ^ 0xDEAD for h in hashes]
                with rr_lock:
                    rank = rr["next"] % args.dp_ranks
                    rr["next"] += 1
                if hashes and args.fail != "no-echo":
                    if args.fail == "rank-split" and len(hashes) >= 2:
                        pub.emit_block_stored(0, hashes[:1],
                                              token_ids[:bs], bs)
                        pub.emit_block_stored(1, hashes[1:],
                                              token_ids[bs:full], bs)
                    elif args.fail == "rank-lie":
                        pub.emit_block_stored(
                            rank, hashes, token_ids[:full], bs,
                            claim_rank=(rank + 1) % max(args.dp_ranks, 2))
                    else:
                        pub.emit_block_stored(rank, hashes,
                                              token_ids[:full], bs)
                self._json(200, {
                    "id": "cmpl-sgl-sim", "object": "text_completion",
                    "model": args.model,
                    "choices": [{"index": 0, "text": " ok",
                                 "finish_reason": "length"}],
                    "usage": {"prompt_tokens": len(token_ids),
                              "completion_tokens": 1,
                              "total_tokens": len(token_ids) + 1},
                })
            else:
                self._json(404, {"detail": "Not Found"})

    srv = ThreadingHTTPServer((args.bind, args.http_port), Handler)
    print(f"sglang-attest-sim: model={args.model} http={args.bind}:"
          f"{args.http_port} zmq={args.zmq_port}+{args.dp_ranks}ranks "
          f"page={args.block_size} fail={args.fail}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main(sys.argv[1:])
