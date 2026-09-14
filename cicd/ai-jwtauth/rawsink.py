#!/usr/bin/env python3
"""Raw-socket recorder: the forwarding oracle for the H2 gate red twin.

An HTTP backend cannot answer HTTP/2, so on a denial leg its silence proves
nothing — the client-side reset looks the same whether the gateway refused
the request or forwarded it into a parser that choked. This recorder accepts
any connection, appends whatever arrives to a file, and answers nothing.
"Was the request forwarded" becomes "do the recorded bytes contain the
request's nonce", which no client-visible outcome can fake.

Usage: rawsink.py <port> <outfile>
"""

import socket
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8091
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/ai-jwtauth-rawsink.out"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", PORT))
server.listen(16)
out = open(OUT, "ab", 0)
print(f"rawsink listening on :{PORT} -> {OUT}", flush=True)

while True:
    conn, addr = server.accept()
    conn.settimeout(3)
    data = b""
    try:
        while len(data) < 65536:
            chunk = conn.recv(8192)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError):
        pass
    out.write(b"=== CONNECTION %d bytes ===\n" % len(data))
    out.write(data + b"\n")
    conn.close()
