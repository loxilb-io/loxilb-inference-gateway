#!/usr/bin/env python3
"""
mock_inference.py — an OpenAI-compatible backend whose token usage the
caller chooses.

The audit-data scenario asserts that a record's tokens_in / tokens_out are
the numbers that were actually charged. A backend with fixed counts cannot
prove that: a record hard-coded to the same constants would pass. So the
counts come from the request, and every arm asks for different ones.

Endpoints:
  POST /v1/chat/completions   non-streaming, or SSE when the body asks
  GET  /health                readiness
  GET  /__receipts/<nonce>    how many requests carried that X-Test-Nonce

The receipt count is the only honest oracle for a refused request. From the
client side a refusal and a forwarded request whose answer was discarded
look identical; the count is read from inside the backend's own namespace,
never through the gateway, so it answers what actually arrived.

Query parameters:
  pt=N        prompt_tokens to report     (default 10)
  ct=N        completion_tokens to report (default 5)
  split=1     write the non-streaming body in two TCP writes, cutting it
              mid-usage-object. This is the "split non-streaming body" the
              token-accounting test names: the gateway must charge what the
              reassembled body says, not what the first segment happened to
              contain.
  chunks=N    SSE content chunks before the final one (default 3)

A streaming request is one whose JSON body carries "stream": true. When it
also carries stream_options.include_usage, the stream ends with a usage
chunk before [DONE], which is where a streamed response's counts come from.
"""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

# How many requests arrived carrying each X-Test-Nonce. Guarded because the
# server is threaded.
RECEIPTS = {}
RECEIPTS_LOCK = threading.Lock()


class Server(ThreadingMixIn, HTTPServer):
    # The scenario drives several requests at once from more than one
    # sockproxy worker; a single-threaded mock would serialise them and the
    # per-producer assertions would never see two producers.
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.1: chunked transfer encoding is required for SSE.
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    # ── helpers ────────────────────────────────────────────────────────────
    def _q(self):
        return parse_qs(urlparse(self.path).query)

    def _int_param(self, name, default):
        try:
            return int(self._q().get(name, [default])[0])
        except (TypeError, ValueError):
            return default

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, UnicodeDecodeError):
            return {}

    def _usage(self, pt, ct):
        return {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct}

    def _send_json(self, obj):
        payload = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _note_arrival(self):
        nonce = self.headers.get("X-Test-Nonce")
        if not nonce:
            return
        with RECEIPTS_LOCK:
            RECEIPTS[nonce] = RECEIPTS.get(nonce, 0) + 1

    # ── routes ─────────────────────────────────────────────────────────────
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._send_json({"status": "ok"})
            return
        if path.startswith("/__receipts/"):
            nonce = path[len("/__receipts/"):]
            with RECEIPTS_LOCK:
                self._send_json({"nonce": nonce, "count": RECEIPTS.get(nonce, 0)})
            return
        self.send_error(404)

    def do_POST(self):
        if urlparse(self.path).path != "/v1/chat/completions":
            self.send_error(404)
            return

        # Counted before anything can fail, so a request that arrived is
        # never reported as one that did not.
        self._note_arrival()
        body = self._body()
        pt = self._int_param("pt", 10)
        ct = self._int_param("ct", 5)
        model = body.get("model") or "audit-model"

        if body.get("stream"):
            include_usage = bool((body.get("stream_options") or {}).get("include_usage"))
            self._stream(model, pt, ct, include_usage, self._int_param("chunks", 3))
        else:
            self._complete(model, pt, ct, self._int_param("split", 0) == 1)

    def _complete(self, model, pt, ct, split):
        payload = json.dumps({
            "id": "cmpl-audit",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }],
            "usage": self._usage(pt, ct),
        }).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()

        if not split:
            self.wfile.write(payload)
            return

        # Cut inside the usage object, so a reader that parses only the
        # first segment sees no counts at all rather than wrong ones.
        cut = payload.find(b'"usage"')
        cut = (cut + 12) if cut > 0 else (len(payload) // 2)
        self.wfile.write(payload[:cut])
        self.wfile.flush()
        time.sleep(0.25)
        self.wfile.write(payload[cut:])

    def _stream(self, model, pt, ct, include_usage, chunks):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def sse(obj):
            self.wfile.write(b"data: " + json.dumps(obj).encode() + b"\n\n")
            self.wfile.flush()

        base = {"id": "cmpl-audit", "object": "chat.completion.chunk", "model": model}
        for i in range(max(chunks, 1)):
            sse(dict(base, choices=[{"index": 0, "delta": {"content": f"t{i} "}}]))
            time.sleep(0.05)
        sse(dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}]))

        if include_usage:
            # The usage chunk carries no choices, which is how a client
            # tells it apart from content; the counts here are the ones the
            # gateway charges for a streamed response.
            sse(dict(base, choices=[], usage=self._usage(pt, ct)))

        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


if __name__ == "__main__":
    Server(("0.0.0.0", PORT), Handler).serve_forever()
