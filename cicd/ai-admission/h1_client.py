#!/usr/bin/env python3
"""h1_client.py — the HTTP/1.1 shapes curl cannot drive.

  disconnect <host> <port> --n K --after-s S [--nonce-prefix P]
      K connections, each with one request the backend holds; after S
      seconds every socket is destroyed with a TCP RST (no FIN, nothing
      read). The gateway sees the client vanish while the request executes.

  kept <host> <port> --signal <file> [--nonce-prefix P] [--timeout S]
      ONE keep-alive connection: a full request, then a wait until <file>
      exists (the caller fills the pool meanwhile), then a SECOND request on
      the SAME socket. Reports both statuses and the second's headers, so
      the caller can see whether the kept backend leg was re-gated. With
      --second-no-rid the second request carries no X-Request-Id of its own:
      whatever ID its answer names is then the gateway's, and must not be the
      first request's.

  shed_keepalive <host> <port> --signal <file> [--nonce-prefix P] [--timeout S]
      ONE connection whose FIRST request is sent against a full pool: the
      refusal must arrive with the connection kept open. Then a wait until
      <file> exists (the caller frees the pool), then a SECOND request on the
      SAME socket, which must be admitted. Reports both statuses and whether
      the refusal closed the connection.

  kept_bad <host> <port> [--nonce-prefix P]
      ONE keep-alive connection: a full request with X-Request-Id
      <P>-first, answered by the backend; then a SECOND request on the SAME
      socket that cannot be framed (Content-Length together with
      Transfer-Encoding: chunked) and carries no X-Request-Id. The gateway
      refuses it before it has an ID of its own. Reports both statuses and
      the refusal's headers.

  pipelined <host> <port> --after-s S [--nonce-prefix P] [--timeout S]
      ONE connection: a full request with X-Request-Id <P>-first that the
      backend holds and then resets without answering (X-Test-Hold,
      X-Test-Reset); S seconds later, while it is unanswered, the first
      lines of a NEXT request with X-Request-Id <P>-next (no end of head).
      The caller releases the backend. Reports the one answer the
      connection gets: it is the first request's.

  pipelined_full <host> <port> --after-s S [--nonce-prefix P] [--timeout S]
      As pipelined, but the NEXT request is sent whole, so the gateway
      hands it to the backend under the first one's pending answer. The
      caller releases the backend, which resets. Reports the one answer the
      connection gets: positionally the first request's, and the gateway
      cannot tell which of the two it answers.

  kept_partial <host> <port> --close-after-ms M [--nonce-prefix P] [--timeout S]
      ONE keep-alive connection: a full request with X-Request-Id <P>-first,
      answered by a backend that closes its kept connection M ms later
      (X-Test-Close-After-Ms); right after the answer, the first lines of a
      NEXT request with X-Request-Id <P>-next (no end of head). The backend
      connection ends while that request is still being read. Reports both
      answers: the second is the next request's.

Every mode prints one JSON line per request and a final "summary" line.
"""
import argparse
import json
import os
import socket
import struct
import sys
import time


# What a caller reads of an answer's head: the admission family, the refusal
# mark (the stage and the request ID the gateway echoes) and Retry-After.
def gw_headers(h):
    return {k: v for k, v in h.items()
            if k.startswith("x-loxilb-admission-") or k.startswith("x-loxilb-refusal-")
            or k in ("retry-after", "x-request-id")}


def request(host, nonce, model, hold=False, rid=None, send_rid=True, extra=""):
    # The rules match on the VIP as the host, so the header names it the way
    # curl does (host:port).
    body = json.dumps({"model": model,
                       "messages": [{"role": "user", "content": nonce}]}).encode()
    hdr = ("POST /v1/chat/completions HTTP/1.1\r\n"
           "Host: %s\r\n"
           "Content-Type: application/json\r\n"
           "Content-Length: %d\r\n"
           "X-Test-Nonce: %s\r\n" % (host, len(body), nonce))
    if send_rid:
        hdr += "X-Request-Id: %s\r\n" % (rid or nonce)
    if hold:
        hdr += "X-Test-Hold: 1\r\n"
    hdr += extra
    return hdr.encode() + b"\r\n" + body


def read_response(sock, timeout):
    """Read one HTTP/1.1 response (status, headers, body by Content-Length).
    Returns (status, headers dict, body bytes, closed)."""
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65535)
        if not chunk:
            return ("CLOSED", {}, b"", True)
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin1").split("\r\n")
    status = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "?"
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    body = rest
    clen = int(headers.get("content-length") or 0)
    while len(body) < clen:
        chunk = sock.recv(65535)
        if not chunk:
            break
        body += chunk
    closed = headers.get("connection", "").lower() == "close"
    return (status, headers, body[:clen] if clen else body, closed)


def hard_close(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def mode_disconnect(args):
    host = "%s:%d" % (args.host, args.port)
    socks = []
    for i in range(args.n):
        nonce = "%s-%d" % (args.nonce_prefix, i)
        s = socket.create_connection((args.host, args.port), timeout=10)
        s.sendall(request(host, nonce, args.model, hold=True))
        socks.append((nonce, s))
    time.sleep(args.after_s)
    for nonce, s in socks:
        hard_close(s)
        print(json.dumps({"nonce": nonce, "action": "rst"}), flush=True)
    print(json.dumps({"summary": "disconnect", "n": len(socks)}), flush=True)
    return 0


def mode_kept(args):
    host = "%s:%d" % (args.host, args.port)
    s = socket.create_connection((args.host, args.port), timeout=30)
    n1 = args.nonce_prefix + "-first"
    s.sendall(request(host, n1, args.model))
    st1, h1, b1, closed1 = read_response(s, 30)
    print(json.dumps({"nonce": n1, "status": st1, "closed": closed1}), flush=True)
    if closed1 or st1 != "200":
        print(json.dumps({"summary": "kept", "first": st1, "second": "NOT_SENT",
                          "reused": False}), flush=True)
        return 1
    deadline = time.monotonic() + args.timeout
    while not os.path.exists(args.signal):
        if time.monotonic() > deadline:
            print(json.dumps({"summary": "kept", "first": st1, "second": "NO_SIGNAL",
                              "reused": False}), flush=True)
            return 1
        time.sleep(0.2)
    n2 = args.nonce_prefix + "-second"
    s.sendall(request(host, n2, args.model, send_rid=not args.second_no_rid))
    st2, h2, b2, closed2 = read_response(s, 30)
    print(json.dumps({"nonce": n2, "status": st2, "closed": closed2,
                      "headers": gw_headers(h2),
                      "body": b2.decode("utf8", "replace")[:200]}), flush=True)
    print(json.dumps({"summary": "kept", "first": st1, "second": st2, "reused": True}),
          flush=True)
    return 0


def mode_shed_keepalive(args):
    host = "%s:%d" % (args.host, args.port)
    s = socket.create_connection((args.host, args.port), timeout=30)
    n1 = args.nonce_prefix + "-first"
    s.sendall(request(host, n1, args.model))
    st1, h1, b1, closed1 = read_response(s, 30)
    print(json.dumps({"nonce": n1, "status": st1, "closed": closed1,
                      "connection": h1.get("connection", ""),
                      "headers": gw_headers(h1)}),
          flush=True)
    if closed1:
        print(json.dumps({"summary": "shed_keepalive", "first": st1, "first_closed": True,
                          "second": "NOT_SENT", "reused": False}), flush=True)
        return 1
    deadline = time.monotonic() + args.timeout
    while not os.path.exists(args.signal):
        if time.monotonic() > deadline:
            print(json.dumps({"summary": "shed_keepalive", "first": st1, "first_closed": False,
                              "second": "NO_SIGNAL", "reused": False}), flush=True)
            return 1
        time.sleep(0.2)
    n2 = args.nonce_prefix + "-second"
    s.sendall(request(host, n2, args.model))
    st2, h2, b2, closed2 = read_response(s, 30)
    print(json.dumps({"nonce": n2, "status": st2, "closed": closed2}), flush=True)
    print(json.dumps({"summary": "shed_keepalive", "first": st1, "first_closed": False,
                      "second": st2, "reused": True}), flush=True)
    return 0


def mode_kept_bad(args):
    host = "%s:%d" % (args.host, args.port)
    s = socket.create_connection((args.host, args.port), timeout=30)
    n1 = args.nonce_prefix + "-first"
    s.sendall(request(host, n1, args.model))
    st1, h1, b1, closed1 = read_response(s, 30)
    print(json.dumps({"nonce": n1, "status": st1, "closed": closed1}), flush=True)
    if closed1 or st1 != "200":
        print(json.dumps({"summary": "kept_bad", "first": st1, "second": "NOT_SENT"}), flush=True)
        return 1
    n2 = args.nonce_prefix + "-second"
    # Content-Length and Transfer-Encoding together: the parser refuses the
    # pair, so the request never reaches the point where an ID is minted.
    bad = ("POST /v1/chat/completions HTTP/1.1\r\n"
           "Host: %s\r\n"
           "Content-Type: application/json\r\n"
           "Content-Length: 5\r\n"
           "Transfer-Encoding: chunked\r\n"
           "X-Test-Nonce: %s\r\n"
           "\r\n"
           "0\r\n\r\n" % (host, n2))
    s.sendall(bad.encode())
    st2, h2, b2, closed2 = read_response(s, 30)
    print(json.dumps({"nonce": n2, "status": st2, "closed": closed2,
                      "headers": gw_headers(h2),
                      "body": b2.decode("utf8", "replace")[:200]}), flush=True)
    print(json.dumps({"summary": "kept_bad", "first": st1, "second": st2}), flush=True)
    return 0


def mode_pipelined(args):
    host = "%s:%d" % (args.host, args.port)
    s = socket.create_connection((args.host, args.port), timeout=30)
    n1 = args.nonce_prefix + "-first"
    n2 = args.nonce_prefix + "-next"
    s.sendall(request(host, n1, args.model, hold=True, extra="X-Test-Reset: 1\r\n"))
    time.sleep(args.after_s)
    # The head of the next request, cut before its end: the gateway has read
    # its X-Request-Id line and cannot dispatch it.
    part = ("POST /v1/chat/completions HTTP/1.1\r\n"
            "Host: %s\r\n"
            "X-Request-Id: %s\r\n"
            "X-Test-Nonce: %s\r\n"
            "Content-Type: application/json\r\n" % (host, n2, n2))
    s.sendall(part.encode())
    print(json.dumps({"nonce": n2, "action": "partial-head-sent"}), flush=True)
    st, h, b, closed = read_response(s, args.timeout)
    print(json.dumps({"nonce": n1, "status": st, "closed": closed,
                      "headers": gw_headers(h),
                      "content_length": h.get("content-length", ""),
                      "body": b.decode("utf8", "replace")[:200]}), flush=True)
    print(json.dumps({"summary": "pipelined", "status": st}), flush=True)
    return 0


def partial_head(host, nonce):
    # The head of a request, cut before its end: the gateway has read its
    # X-Request-Id line and cannot dispatch it.
    return ("POST /v1/chat/completions HTTP/1.1\r\n"
            "Host: %s\r\n"
            "X-Request-Id: %s\r\n"
            "X-Test-Nonce: %s\r\n"
            "Content-Type: application/json\r\n" % (host, nonce, nonce)).encode()


def mode_pipelined_full(args):
    host = "%s:%d" % (args.host, args.port)
    s = socket.create_connection((args.host, args.port), timeout=30)
    n1 = args.nonce_prefix + "-first"
    n2 = args.nonce_prefix + "-next"
    s.sendall(request(host, n1, args.model, hold=True, extra="X-Test-Reset: 1\r\n"))
    time.sleep(args.after_s)
    s.sendall(request(host, n2, args.model))
    print(json.dumps({"nonce": n2, "action": "next-request-sent"}), flush=True)
    st, h, b, closed = read_response(s, args.timeout)
    print(json.dumps({"answer": 1, "status": st, "closed": closed,
                      "headers": gw_headers(h),
                      "body": b.decode("utf8", "replace")[:200]}), flush=True)
    print(json.dumps({"summary": "pipelined_full", "status": st}), flush=True)
    return 0


def mode_kept_partial(args):
    host = "%s:%d" % (args.host, args.port)
    s = socket.create_connection((args.host, args.port), timeout=30)
    n1 = args.nonce_prefix + "-first"
    n2 = args.nonce_prefix + "-next"
    s.sendall(request(host, n1, args.model,
                      extra="X-Test-Close-After-Ms: %d\r\n" % args.close_after_ms))
    st1, h1, b1, closed1 = read_response(s, 30)
    print(json.dumps({"nonce": n1, "status": st1, "closed": closed1}), flush=True)
    if closed1 or st1 != "200":
        print(json.dumps({"summary": "kept_partial", "first": st1, "second": "NOT_SENT"}), flush=True)
        return 1
    s.sendall(partial_head(host, n2))
    print(json.dumps({"nonce": n2, "action": "partial-head-sent"}), flush=True)
    try:
        st2, h2, b2, closed2 = read_response(s, args.timeout)
    except socket.timeout:
        st2, h2, b2, closed2 = ("TIMEOUT", {}, b"", False)
    print(json.dumps({"nonce": n2, "status": st2, "closed": closed2,
                      "headers": gw_headers(h2),
                      "body": b2.decode("utf8", "replace")[:200]}), flush=True)
    print(json.dumps({"summary": "kept_partial", "first": st1, "second": st2}), flush=True)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["disconnect", "kept", "shed_keepalive", "kept_bad", "pipelined",
                                     "pipelined_full", "kept_partial"])
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--n", type=int, default=4)
    ap.add_argument("--after-s", type=float, default=2.0)
    ap.add_argument("--signal", default="/tmp/h1_client.signal")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--nonce-prefix", default="h1c")
    ap.add_argument("--model", default="cap-model")
    ap.add_argument("--second-no-rid", action="store_true")
    ap.add_argument("--close-after-ms", type=int, default=2000)
    args = ap.parse_args()
    if args.mode == "disconnect":
        return mode_disconnect(args)
    if args.mode == "shed_keepalive":
        return mode_shed_keepalive(args)
    if args.mode == "kept_bad":
        return mode_kept_bad(args)
    if args.mode == "pipelined":
        return mode_pipelined(args)
    if args.mode == "pipelined_full":
        return mode_pipelined_full(args)
    if args.mode == "kept_partial":
        return mode_kept_partial(args)
    return mode_kept(args)


if __name__ == "__main__":
    sys.exit(main())
