#!/usr/bin/env python3
"""apikey_ka_client.py - one keep-alive connection, a DIFFERENT credential per request.

curl cannot express this: it sends the same headers on every request of a reused
connection, so it can never ask the question this scenario exists to ask -- does
request N of a connection get its credential checked, or did request 1 buy the
whole connection a pass?

That question is the whole point of accelerating only the RESPONSE direction of an
api_key_auth service. With the request direction still on the userspace relay, every
request is admitted on its own; if it were accelerated, request 2 onward would skip
admission and this client would see the 401s turn into 200s.

Usage:
  apikey_ka_client.py <host> <port> <spec> [<spec> ...]

A spec is the credential for one request, in connection order:
  key:<value>   send X-Api-Key: <value>
  none          send no X-Api-Key header at all

Prints one JSON object per line, in order:
  {"i":0,"status":200,"backend_saw_key":false,"backend":"resp-accel"}
and finally a summary object with "reused":true when every request went over the
same TCP connection (which is what makes the result meaningful at all).

Exit status is 0 if every request got a response, 2 on a connection or framing
error -- the ASSERTIONS live in the caller, not here.
"""

import json
import socket
import sys


def read_exactly(sock, buf, n):
    while len(buf) < n:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("backend closed mid-response")
        buf += chunk
    return buf


def read_response(sock, buf):
    """Returns (status, body, leftover). Content-Length framing only, which is
    what request_path_server.js always emits for the JSON echo."""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed before response headers")
        buf += chunk
    head, _, buf = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])

    length = 0
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "content-length":
            length = int(value.strip())
    buf = read_exactly(sock, buf, length)
    return status, buf[:length], buf[length:]


def main():
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    host, port, specs = sys.argv[1], int(sys.argv[2]), sys.argv[3:]

    sock = socket.create_connection((host, port), timeout=20)
    local = sock.getsockname()
    buf = b""
    try:
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
            sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())

            status, body, buf = read_response(sock, buf)

            # Only a 200 carries the backend's echo; a 401 is the gateway's own
            # answer and never reached a backend at all.
            saw_key, backend = None, None
            if status == 200:
                try:
                    echo = json.loads(body.decode("utf-8"))
                    saw_key = "x-api-key" in echo.get("headers", {})
                    backend = echo.get("name")
                except Exception:
                    saw_key, backend = None, None
            print(json.dumps({"i": i, "status": status,
                              "backend_saw_key": saw_key, "backend": backend}),
                  flush=True)
    except (OSError, RuntimeError) as exc:
        print(json.dumps({"error": str(exc)}), flush=True)
        return 2
    finally:
        # Same local port throughout means one connection; the caller asserts on it,
        # because a client that silently reconnected would test nothing.
        print(json.dumps({"summary": True, "reused": sock.getsockname() == local,
                          "requests": len(specs)}), flush=True)
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
