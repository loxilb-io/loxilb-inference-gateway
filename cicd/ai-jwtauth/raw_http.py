#!/usr/bin/env python3
"""Send one hand-framed HTTP/1.1 request and print the raw response.

The chunked and CL+TE legs cannot be driven with curl: curl normalizes
framing, will not put Content-Length next to Transfer-Encoding, and picks
its own header spellings. Each mode here sends exactly the bytes its leg
needs and nothing else.

modes:
  chunked        Transfer-Encoding: chunked, canonical casing, one chunk
  chunked-mixed  the same request spelled "Transfer-Encoding: Chunked" —
                 field values are case-insensitive (RFC 9112), so neither
                 the verdict nor the identity contract may change with it
  cl-te          BOTH Content-Length and Transfer-Encoding: chunked — the
                 request-smuggling ambiguity; must never reach a backend

The nonce rides X-Test-Nonce so the caller's receipt oracle is THIS
request's, not whatever an earlier leg minted.

usage: raw_http.py <host> <port> <mode> <token> <nonce>
"""
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
mode = sys.argv[3]
token = sys.argv[4]
nonce = sys.argv[5]

body = b'{"model":"llama-70b","messages":[{"role":"user","content":"hi"}]}'
chunked_body = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)

te_line = {
    "chunked":       b"Transfer-Encoding: chunked\r\n",
    "chunked-mixed": b"Transfer-Encoding: Chunked\r\n",
    "cl-te":         b"Transfer-Encoding: chunked\r\n",
}[mode]

head = (b"POST /v1/chat/completions HTTP/1.1\r\n"
        b"Host: " + ("%s:%d" % (host, port)).encode() + b"\r\n"
        b"Content-Type: application/json\r\n"
        b"X-Test-Nonce: " + nonce.encode() + b"\r\n")
# An empty token means "send no credential at all" — the K5 bypass probe:
# a Bearer with an empty value is a different thing from no Authorization.
if token:
    head += b"Authorization: Bearer " + token.encode() + b"\r\n"
if mode == "cl-te":
    # The ambiguity under test: a Content-Length measuring the DECODED body
    # beside chunked framing. A hop that honors CL reads chunk metadata as
    # body bytes; one that honors TE de-chunks — two readings of one
    # request is the smuggling primitive, so the gate must refuse, not pick.
    head += b"Content-Length: %d\r\n" % len(body)
head += te_line + b"Connection: close\r\n\r\n"

req = head + chunked_body

resp = b""
try:
    s = socket.create_connection((host, port), timeout=12)
except OSError:
    sys.exit(0)   # no connection at all: the caller reads an empty response
try:
    try:
        s.sendall(req)
    except OSError:
        pass      # an RST mid-send is a legitimate refusal shape for cl-te
    s.settimeout(12)
    while True:
        try:
            d = s.recv(65536)
        except (socket.timeout, OSError):
            break
        if not d:
            break
        resp += d
finally:
    s.close()

sys.stdout.write(resp.decode("latin1", "replace"))
