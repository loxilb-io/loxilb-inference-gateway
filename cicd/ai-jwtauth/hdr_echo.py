#!/usr/bin/env python3
"""Backend that reports, in its own response body, what actually arrived.

The upstream-hygiene contract is about headers the BACKEND sees, so the
backend has to be the witness. Everything the assertions need travels back
in the response body, which keeps this scenario off shared /tmp files that
a previous root-owned run can poison.

Body shape (one line, stable field order):
  <label>|authz=<yes|no>|apikey=<yes|no>|xauth_tenant=<value|->|xauth_user=<value|->
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LABEL = sys.argv[1] if len(sys.argv) > 1 else "server"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep the scenario output readable
        pass

    def _hdr(self, name):
        v = self.headers.get(name)
        return v if v else "-"

    def _drain_identity(self, n):
        while n > 0:
            chunk = self.rfile.read(min(n, 65536))
            if not chunk:
                return
            n -= len(chunk)

    def _drain_chunked(self):
        while True:
            line = self.rfile.readline(65536)
            if not line:
                return
            size = int(line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while True:  # trailers, up to the blank line
                    trailer = self.rfile.readline(65536)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        return
            self._drain_identity(size)
            self.rfile.read(2)  # the CRLF after each chunk

    def _respond(self):
        # Drain the body so keep-alive framing stays intact for the next
        # request on this connection. A chunked body has no Content-Length,
        # so reading only that length would leave the body in the socket and
        # the next request on this connection would parse body bytes as its
        # request line. On a malformed body, stop reusing the connection
        # rather than answer from a stream we have lost our place in.
        encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        try:
            if "chunked" in encoding:
                self._drain_chunked()
            else:
                self._drain_identity(int(self.headers.get("Content-Length") or 0))
        except (ValueError, OSError):
            self.close_connection = True

        body = "%s|authz=%s|apikey=%s|xauth_tenant=%s|xauth_user=%s" % (
            LABEL,
            "yes" if self.headers.get("Authorization") else "no",
            "yes" if self.headers.get("X-Api-Key") else "no",
            self._hdr("X-Auth-Tenant"),
            self._hdr("X-Auth-User"),
        )
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _respond
    do_POST = _respond


ThreadingHTTPServer.allow_reuse_address = True
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
