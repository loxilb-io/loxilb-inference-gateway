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

    def _respond(self):
        # Drain the body so keep-alive framing stays intact for the next
        # request on this connection.
        n = int(self.headers.get("Content-Length") or 0)
        if n > 0:
            remaining = n
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)

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
