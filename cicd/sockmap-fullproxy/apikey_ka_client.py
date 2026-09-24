#!/usr/bin/env python3
"""apikey_ka_client.py - one client, a DIFFERENT credential per request.

curl cannot express this: it sends the same headers on every request of a reused
connection, so it can never ask the question this client exists to ask -- does
request N get its credential checked, or did request 1 buy the rest a pass?

Every request is admitted on its own only while the request direction stays on
the userspace relay. An accelerated request direction would skip admission from
the second keep-alive request on, and this client would see the 401s turn into
200s. A refused request is answered by the gateway itself with Connection: close,
so the client reconnects for the request after it; how many connections the run
took is reported, not hidden.

Usage:
  apikey_ka_client.py <host> <port> <spec> [<spec> ...]

A spec is the credential for one request, in order:
  key:<value>   send X-Api-Key: <value>
  none          send no X-Api-Key header at all

Prints one JSON object per line, in order:
  {"i": 0, "status": 200, "backend_saw_key": false, "backend": "resp-subject", "conn": 1}
where "conn" numbers the TCP connection the request went over (1 = the first),
"backend_saw_key" is true/false when a 200 carried a parsable backend echo and
null otherwise, and a request that drew no response at all is reported with
"status": null and an "error". The last line is a summary:
  {"summary": true, "requested": N, "completed": k, "connections": c,
   "closed_by_server": m}
"completed" counts requests that got a response, "closed_by_server" the responses
the gateway ended the connection after.

Exit status is 0 when every request got a response, 2 otherwise -- the
ASSERTIONS live in the caller, not here.
"""

import json
import socket
import sys


class ServerClosed(Exception):
    pass


def read_exactly(sock, buf, n):
    while len(buf) < n:
        chunk = sock.recv(65536)
        if not chunk:
            raise ServerClosed("connection closed mid-response")
        buf += chunk
    return buf


def read_response(sock, buf):
    """Returns (status, headers, body, leftover). Content-Length framing only,
    which is what request_path_server.js and the gateway's own denials emit."""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise ServerClosed("connection closed before response headers")
        buf += chunk
    head, _, buf = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0") or 0)
    buf = read_exactly(sock, buf, length)
    return status, headers, buf[:length], buf[length:]


def main():
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    host, port, specs = sys.argv[1], int(sys.argv[2]), sys.argv[3:]

    sock = None
    buf = b""
    connections = 0
    completed = 0
    closed_by_server = 0

    def connect():
        nonlocal sock, buf, connections
        sock = socket.create_connection((host, port), timeout=20)
        buf = b""
        connections += 1

    for i, spec in enumerate(specs):
        headers = [
            "GET /echo HTTP/1.1",
            "Host: %s:%d" % (host, port),
            "Connection: keep-alive",
        ]
        if spec.startswith("key:"):
            headers.append("X-Api-Key: %s" % spec[4:])
        elif spec != "none":
            print("bad spec %r" % spec, file=sys.stderr)
            return 2
        wire = ("\r\n".join(headers) + "\r\n\r\n").encode()

        record = {"i": i, "status": None, "backend_saw_key": None,
                  "backend": None, "conn": None}
        try:
            if sock is None:
                connect()
            record["conn"] = connections
            sock.sendall(wire)
            status, resp_headers, body, buf = read_response(sock, buf)
        except (OSError, ServerClosed) as exc:
            record["error"] = str(exc)
            print(json.dumps(record), flush=True)
            try:
                sock.close()
            except OSError:
                pass
            sock = None
            continue

        completed += 1
        record["status"] = status
        # Only a 200 carries the backend's echo; a 401 is the gateway's own
        # answer and never reached a backend at all.
        if status == 200:
            try:
                echo = json.loads(body.decode("utf-8"))
                record["backend_saw_key"] = "x-api-key" in echo.get("headers", {})
                record["backend"] = echo.get("name")
            except (ValueError, AttributeError):
                pass
        print(json.dumps(record), flush=True)

        if resp_headers.get("connection", "").lower() == "close":
            closed_by_server += 1
            sock.close()
            sock = None

    if sock is not None:
        sock.close()
    print(json.dumps({"summary": True, "requested": len(specs),
                      "completed": completed, "connections": connections,
                      "closed_by_server": closed_by_server}), flush=True)
    return 0 if completed == len(specs) else 2


if __name__ == "__main__":
    sys.exit(main())
