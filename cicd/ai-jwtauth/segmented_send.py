#!/usr/bin/env python3
"""Send one request with the header block split across many small writes.

llhttp is fed per socket read and keeps parser state between calls, so a
single header VALUE reaches the callback as several fragments whenever it
spans a read boundary. A role-carrying access token is large enough for
that to happen on a normal network; here it is forced deterministically so
the leg is not a coin flip.

The chunk size and the pause matter: writes must land in separate reads,
which is what a small chunk plus a flush gap buys. Prints the raw response
(status line included) on stdout.

usage: segmented_send.py <host> <port> <token-file> [chunk] [delay-ms]
"""
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
token = open(sys.argv[3]).read().strip()
chunk = int(sys.argv[4]) if len(sys.argv) > 4 else 200
delay = (int(sys.argv[5]) if len(sys.argv) > 5 else 15) / 1000.0

body = b'{"model":"llama-70b","messages":[{"role":"user","content":"hi"}]}'
head = (
    "POST /v1/chat/completions HTTP/1.1\r\n"
    "Host: %s:%d\r\n"
    "Content-Type: application/json\r\n"
    "Authorization: Bearer %s\r\n"
    "Content-Length: %d\r\n"
    "Connection: close\r\n"
    "\r\n" % (host, port, token, len(body))
).encode()

req = head + body

s = socket.create_connection((host, port), timeout=15)
try:
    for off in range(0, len(req), chunk):
        s.sendall(req[off:off + chunk])
        time.sleep(delay)
    s.shutdown(socket.SHUT_WR)
    resp = b""
    s.settimeout(15)
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        resp += d
finally:
    s.close()

sys.stdout.write(resp.decode("latin1", "replace"))
sys.stderr.write("sent %d bytes in %d-byte writes (token %d chars)\n"
                 % (len(req), chunk, len(token)))
