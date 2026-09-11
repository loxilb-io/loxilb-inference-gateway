#!/usr/bin/env python3
"""Backend that reports, in its own response body, what actually arrived,
and independently records that it arrived at all.

Two oracles live here, and they answer different questions.

The RESPONSE BODY answers "what did the backend see" for the
upstream-hygiene contract: the headers are about what reaches the backend,
so the backend has to be the witness. Everything the assertions need
travels back in the body, which keeps this scenario off shared /tmp files
that a previous root-owned run can poison.

The RECEIPT COUNTER answers "did the request reach the backend at all",
which the response body cannot answer for a denied request. A denial's
client response never contains the backend's label whether the gateway
refused the request or forwarded it and discarded the answer, so asserting
the label's absence cannot tell a working gate from a leaking one. Each
request carries a unique nonce; the count for a nonce is read back
out-of-band from inside the backend's own namespace, never through the
gateway, so the number cannot be produced by the path under test.

Body shape (one line, stable field order):
  <label>|authz=<yes|no>|apikey=<yes|no>|xauth_tenant=<value|->|xauth_user=<value|->

Control endpoint (not counted, never proxied):
  GET /__receipts/<nonce>  ->  the number of requests seen carrying it
"""
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LABEL = sys.argv[1] if len(sys.argv) > 1 else "server"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

RECEIPTS_PREFIX = "/__receipts/"
NONCE_HEADER = "X-Test-Nonce"

_receipts = {}
_lock = threading.Lock()


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

    def _send(self, body, status=200):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _serve_receipts(self):
        # The readout must never count as traffic: it is asked for from
        # inside this namespace, so counting it would make every delta wrong
        # by one and would make a leak look like a clean run.
        nonce = self.path[len(RECEIPTS_PREFIX):]
        with _lock:
            count = _receipts.get(nonce, 0)
        self._send(str(count))

    def _respond(self):
        if self.path.startswith(RECEIPTS_PREFIX):
            self._serve_receipts()
            return

        # Record before drainage: what matters is that the request arrived,
        # not that it was well-formed enough to finish.
        nonce = self.headers.get(NONCE_HEADER)
        if nonce:
            with _lock:
                _receipts[nonce] = _receipts.get(nonce, 0) + 1

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

        self._send("%s|authz=%s|apikey=%s|xauth_tenant=%s|xauth_user=%s" % (
            LABEL,
            "yes" if self.headers.get("Authorization") else "no",
            "yes" if self.headers.get("X-Api-Key") else "no",
            self._hdr("X-Auth-Tenant"),
            self._hdr("X-Auth-User"),
        ))

    do_GET = _respond
    do_POST = _respond


ThreadingHTTPServer.allow_reuse_address = True
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
