#!/usr/bin/env python3
"""Backend for the cases of ai-ha-failover-bfd that need a witness on the
backend side. Standard library only.

It answers like cicd/ai-jwtauth/hdr_echo.py (label first, a usage object
last, a receipt per X-Test-Nonce) and adds what that echo does not have:

  - a paced SSE stream when the request body says "stream": true
      X-Test-Chunks: N       content chunks (default 40)
      X-Test-Pace-Ms: N      gap between chunks (default 250)
  - X-Test-Delay-Ms: N       hold a non-stream request open (max 60000)
  - X-Test-Usage-Tokens: N   total_tokens the answer reports (default 12)
  - its own count of requests in flight, and the peak of that count
  - a record per nonce of how the request ended as THIS process saw it:
    completed, or the chunk at which a write failed

Control endpoints (never proxied, asked from inside this namespace):
  GET  /__receipts/<nonce>   number of requests seen carrying the nonce
  GET  /__state              {"inflight", "peak", "ended": {nonce: {...}}}
  POST /__reset-peak         peak := inflight
"""
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LABEL = sys.argv[1] if len(sys.argv) > 1 else "server"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8081

_lock = threading.Lock()
_receipts = {}
_ended = {}
_inflight = 0
_peak = 0


def now_ms():
    return int(time.time() * 1000)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _int_header(self, name, default, top):
        try:
            return min(max(int(self.headers.get(name) or default), 0), top)
        except ValueError:
            return default

    def _plain(self, body, status=200):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.startswith("/__receipts/"):
            with _lock:
                n = _receipts.get(self.path[len("/__receipts/"):], 0)
            self._plain(str(n))
        elif self.path == "/__state":
            with _lock:
                body = json.dumps({"inflight": _inflight, "peak": _peak, "ended": _ended,
                                   "t": now_ms()}, sort_keys=True)
            self._plain(body)
        else:
            self._plain("%s|ready" % LABEL)

    def do_POST(self):
        global _inflight, _peak
        if self.path == "/__reset-peak":
            with _lock:
                _peak = _inflight
            self._plain("ok")
            return
        nonce = self.headers.get("X-Test-Nonce") or ""
        try:
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        except (ValueError, OSError):
            raw = b""
            self.close_connection = True
        try:
            stream = bool(json.loads(raw or b"{}").get("stream"))
        except ValueError:
            stream = False
        with _lock:
            if nonce:
                _receipts[nonce] = _receipts.get(nonce, 0) + 1
            _inflight += 1
            _peak = max(_peak, _inflight)
        end = {"t_start": now_ms(), "stream": stream}
        try:
            if stream:
                self._stream(end)
            else:
                delay = self._int_header("X-Test-Delay-Ms", 0, 60000)
                if delay:
                    time.sleep(delay / 1000.0)
                total = self._int_header("X-Test-Usage-Tokens", 12, 1000000)
                self._plain('%s|{"usage":{"prompt_tokens":5,"completion_tokens":%d,"total_tokens":%d}}'
                            % (LABEL, max(total - 5, 0), total))
                end["how"] = "completed"
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            end.setdefault("how", "write_failed")
            end["error"] = type(e).__name__
            self.close_connection = True
        finally:
            end["t_end"] = now_ms()
            with _lock:
                _inflight -= 1
                if nonce:
                    _ended[nonce] = end

    def _stream(self, end):
        chunks = self._int_header("X-Test-Chunks", 40, 100000)
        pace = self._int_header("X-Test-Pace-Ms", 250, 60000)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def put(obj):
            data = ("data: %s\n\n" % (obj if isinstance(obj, str) else json.dumps(obj))).encode()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
            self.wfile.flush()

        end["chunks_written"] = 0
        end["how"] = "write_failed"
        for i in range(chunks):
            put({"id": "hafo", "object": "chat.completion.chunk", "model": LABEL,
                 "choices": [{"index": 0, "delta": {"content": "t%d " % i}}]})
            end["chunks_written"] = i + 1
            time.sleep(pace / 1000.0)
        put({"id": "hafo", "object": "chat.completion.chunk", "model": LABEL,
             "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
             "usage": {"prompt_tokens": 5, "completion_tokens": chunks, "total_tokens": 5 + chunks}})
        put("[DONE]")
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        end["how"] = "completed"


ThreadingHTTPServer.allow_reuse_address = True
ThreadingHTTPServer.daemon_threads = True
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
