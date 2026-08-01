#!/usr/bin/env python3
"""
mock_sse_server.py — Minimal OpenAI-compatible SSE mock for LoxiLB AI Gateway tests.

Endpoints:
  POST /v1/chat/completions  — SSE stream with optional delay_secs query param
  GET  /never-done           — Infinite SSE stream (never sends [DONE])
  GET  /health               — Health check

Query params for POST /v1/chat/completions:
  delay_secs=N   Wait N seconds before streaming (default 0). Sends keepalive
                 comments every second during the delay.
  frag_done=1    Split "data: [DONE]\\n\\n" across two TCP writes at byte 8
                 to test proxy fragmentation handling.

Usage:
  python3 mock_sse_server.py          # default port 8080
"""

import sys
import time
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080


class MockHandler(BaseHTTPRequestHandler):
    # Use HTTP/1.1 — BaseHTTPRequestHandler defaults to HTTP/1.0 which does not
    # support Transfer-Encoding: chunked and causes curl error 56.
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # suppress default access log

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if parsed.path == "/never-done":
            self._handle_never_done()
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        # Read and discard request body
        clen = int(self.headers.get("Content-Length", 0))
        if clen:
            self.rfile.read(clen)

        delay_secs = int(qs.get("delay_secs", ["0"])[0])
        frag_done = qs.get("frag_done", ["0"])[0] == "1"

        # Plain-JSON (non-SSE) response path — the error shape OpenAI-compatible
        # backends return even for streaming requests. Lets scenarios validate
        # that non-SSE responses on an AI rule are recorded in the AI request
        # metrics (cicd/monitoring) without a separate mock.
        if parsed.path == "/v1/error":
            status = int(qs.get("status", ["500"])[0])
            body = json.dumps({"error": {"message": "mock backend error",
                                         "type": "server_error"}}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        # Wait the requested delay before streaming
        if delay_secs > 0:
            for _ in range(delay_secs):
                try:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                time.sleep(1)

        # Send the content chunk
        chunk = json.dumps({"choices": [{"delta": {"content": "hello"}, "index": 0}]})
        try:
            self.wfile.write(("data: " + chunk + "\n\n").encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return

        # Send [DONE] terminator — optionally fragmented
        try:
            if frag_done:
                # Split "data: [DONE]\n\n" at byte 8: "data: [D" + "ONE]\n\n"
                self.wfile.write(b"data: [D")
                self.wfile.flush()
                time.sleep(0.1)  # force TCP segment boundary
                self.wfile.write(b"ONE]\n\n")
                self.wfile.flush()
            else:
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _handle_never_done(self):
        """Streams data: {"choices":[]}\n\n every 5 seconds indefinitely."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        chunk = json.dumps({"choices": []})
        while True:
            try:
                self.wfile.write(("data: " + chunk + "\n\n").encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
            time.sleep(5)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), MockHandler)
    print(f"[mock] SSE server listening on :{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
