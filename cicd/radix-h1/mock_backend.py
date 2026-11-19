#!/usr/bin/env python3
"""mock_backend.py - an OpenAI-style chat backend for the radix-h1 scenario.

One process per endpoint container. It answers POST /v1/chat/completions
(JSON, or SSE when the body asks for "stream": true) and records one receipt
per request: request id, endpoint name, receive time, status. It never
records or prints request text.

Usage: mock_backend.py <endpoint-name> <port> <receipts-file>

Control (GET):
  /health                      200
  /admin/status/<code>/<n>     the next <n> inference requests are answered <code>
  /admin/interim/<n>           the next <n> answers are preceded by "100 Continue"
  /admin/close/<n>             the next <n> answers carry "Connection: close" and
                               the backend closes the connection after them
  /admin/delay/<ms>/<n>        the next <n> inference answers wait <ms> first
  /admin/answer64/<0|1>        answer every inference request with a 64-byte
                               JSON body (cost measurement)
  /admin/reset                 clear the three arms above
"""
import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = sys.argv[1]
PORT = int(sys.argv[2])
RECEIPTS = sys.argv[3]

lock = threading.Lock()
arms = {"status": [], "interim": 0, "close": 0, "delay": []}
answer64 = [False]


def take_arms():
    with lock:
        status = arms["status"].pop(0) if arms["status"] else 200
        interim = arms["interim"] > 0
        if interim:
            arms["interim"] -= 1
        close = arms["close"] > 0
        if close:
            arms["close"] -= 1
        delay = arms["delay"].pop(0) if arms["delay"] else 0
    return status, interim, close, delay


def record(rid, status):
    line = json.dumps({"rid": rid, "ep": NAME, "t": time.time(), "status": status})
    with lock:
        with open(RECEIPTS, "a") as f:
            f.write(line + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        # head and body leave in separate writes: without this, Nagle and the
        # peer's delayed ACK add about 40 ms to every keep-alive answer
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def handle_one_request(self):
        # ACK at once: a peer that sends head and body in two writes would
        # otherwise wait for this side's delayed ACK (40 ms) on the second
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        except (AttributeError, OSError):
            pass
        super().handle_one_request()

    def log_message(self, fmt, *args):  # no access log: it could carry paths only, but stay quiet
        pass

    def _send(self, code, body, ctype="application/json", close=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = self.path.strip("/").split("/")
        if parts == ["health"]:
            return self._send(200, b'{"status":"ok"}')
        if len(parts) == 4 and parts[:2] == ["admin", "status"]:
            with lock:
                arms["status"] += [int(parts[2])] * int(parts[3])
            return self._send(200, b"{}")
        if len(parts) == 3 and parts[:2] == ["admin", "interim"]:
            with lock:
                arms["interim"] = int(parts[2])
            return self._send(200, b"{}")
        if len(parts) == 3 and parts[:2] == ["admin", "close"]:
            with lock:
                arms["close"] = int(parts[2])
            return self._send(200, b"{}")
        if len(parts) == 3 and parts[:2] == ["admin", "answer64"]:
            answer64[0] = parts[2] == "1"
            return self._send(200, b"{}")
        if len(parts) == 4 and parts[:2] == ["admin", "delay"]:
            with lock:
                arms["delay"] += [int(parts[2])] * int(parts[3])
            return self._send(200, b"{}")
        if parts == ["admin", "reset"]:
            with lock:
                arms.update(status=[], interim=0, close=0, delay=[])
            return self._send(200, b"{}")
        return self._send(404, b"{}")

    def _read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = b""
            while True:
                size = int(self.rfile.readline().strip().split(b";")[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return data
                data += self.rfile.read(size)
                self.rfile.readline()
        n = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(n) if n else b""

    def do_POST(self):
        body = self._read_body()
        rid = self.headers.get("X-Request-Id", "-")
        status, interim, close, delay = take_arms()
        if delay:
            time.sleep(delay / 1000.0)
        record(rid, status)
        if interim:
            self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        if status != 200:
            return self._send(status, json.dumps({"error": {"code": status, "ep": NAME}}).encode(),
                              close=close)
        if answer64[0]:
            out = json.dumps({"ep": NAME, "id": rid[:8]}).encode()
            return self._send(200, out + b" " * max(0, 64 - len(out)))
        stream = False
        try:
            stream = bool(json.loads(body).get("stream"))
        except Exception:
            pass
        if stream:
            ev = []
            for piece in ("ok", " from ", NAME):
                ev.append("data: " + json.dumps({"id": rid, "ep": NAME,
                                                  "choices": [{"delta": {"content": piece}}]}))
            ev.append("data: [DONE]")
            return self._send(200, ("\n\n".join(ev) + "\n\n").encode(), "text/event-stream", close)
        out = {"id": rid, "object": "chat.completion", "ep": NAME,
               "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop"}]}
        return self._send(200, json.dumps(out).encode(), close=close)


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
