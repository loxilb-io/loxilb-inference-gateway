#!/usr/bin/env python3
"""Recording HTTP/1.1 backend: the forwarding oracle for oversized requests.

A refusal the gateway is supposed to make BEFORE dispatch cannot be proven
from the client side: a 401 looks the same whether the gateway refused the
request or forwarded it and then answered on its own. This backend records
what actually reached it — every accepted connection, the first byte on it,
and every request with the nonce found in its bytes — so "was the request
forwarded" becomes "does the record carry the request's nonce", which no
client-visible outcome can fake.

Unlike a raw sink it is a working keep-alive HTTP/1.1 server: it reads each
request to completion (Content-Length, chunked, or until close), answers 200
with a JSON body naming the nonce, connection and request number, and keeps
the connection open. That is what lets a scenario prove the positive twins
(the admitted request arrives whole, and a kept backend leg carries a second
request) against the same record.

Record format: one JSON object per line, appended to <outfile>.
  {"event":"accept","conn":N}
  {"event":"first_byte","conn":N}
  {"event":"request","conn":N,"req":M,"path":...,"content_length":CL,
   "chunked":bool,"body_bytes":n,"complete":bool,"nonce":"nonce-..."|null,
   "saw_key":bool}

Usage: bigsink.py <port> <outfile>
"""

import json
import re
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/ai-apikey-bigsink.out"

NONCE_RE = re.compile(rb"nonce-[0-9a-f]{16}")
READ_TIMEOUT_S = 10

_lock = threading.Lock()
_conn_seq = 0


def record(obj):
    line = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
    with _lock:
        with open(OUT, "ab", 0) as f:
            f.write(line)


def read_until(conn, buf, marker):
    """Grow buf until marker is present; return (buf, found)."""
    while marker not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return buf, False
        buf += chunk
    return buf, True


def read_exact(conn, buf, n):
    """Grow buf until it holds n bytes; return (buf, complete)."""
    while len(buf) < n:
        chunk = conn.recv(min(65536, n - len(buf)))
        if not chunk:
            return buf, False
        buf += chunk
    return buf, True


def read_chunked(conn, buf):
    """Decode a chunked body from buf (+ socket). Return (body, rest, complete)."""
    body = b""
    while True:
        buf, ok = read_until(conn, buf, b"\r\n")
        if not ok:
            return body, buf, False
        line, buf = buf.split(b"\r\n", 1)
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            return body, buf, False
        if size == 0:
            # Last chunk: the trailer section ends at the next CRLF (this
            # client sends no trailers, so that CRLF is the terminator).
            buf, ok = read_until(conn, buf, b"\r\n")
            if not ok:
                return body, buf, False
            buf = buf.split(b"\r\n", 1)[1]
            return body, buf, True
        buf, ok = read_exact(conn, buf, size + 2)
        if not ok:
            body += buf[:size]
            return body, b"", False
        body += buf[:size]
        buf = buf[size + 2:]


def serve(conn, conn_id):
    conn.settimeout(READ_TIMEOUT_S)
    buf = b""
    req_no = 0
    first_byte_seen = False
    try:
        while True:
            try:
                buf, ok = read_until(conn, buf, b"\r\n\r\n")
            except (socket.timeout, OSError):
                ok = False
            if buf and not first_byte_seen:
                first_byte_seen = True
                record({"event": "first_byte", "conn": conn_id})
            if not ok:
                if buf:
                    record({"event": "request", "conn": conn_id, "req": req_no + 1,
                            "path": None, "content_length": None, "chunked": False,
                            "body_bytes": 0, "complete": False,
                            "nonce": None, "saw_key": False, "partial_headers": len(buf)})
                return
            req_no += 1
            head, buf = buf.split(b"\r\n\r\n", 1)
            lines = head.split(b"\r\n")
            request_line = lines[0].decode("latin-1", "replace")
            parts = request_line.split(" ")
            path = parts[1] if len(parts) > 1 else ""
            headers = {}
            for ln in lines[1:]:
                if b":" in ln:
                    k, v = ln.split(b":", 1)
                    headers[k.strip().lower()] = v.strip()
            cl = headers.get(b"content-length")
            chunked = b"chunked" in headers.get(b"transfer-encoding", b"").lower()
            close_after = headers.get(b"connection", b"").lower() == b"close"
            body = b""
            complete = True
            try:
                if chunked:
                    body, buf, complete = read_chunked(conn, buf)
                elif cl is not None:
                    n = int(cl)
                    buf, complete = read_exact(conn, buf, n)
                    body, buf = buf[:n], buf[n:]
                else:
                    body, buf = b"", buf
            except (socket.timeout, OSError):
                complete = False
                body, buf = buf, b""
            m = NONCE_RE.search(head + body)
            nonce = m.group(0).decode() if m else None
            record({"event": "request", "conn": conn_id, "req": req_no,
                    "path": path,
                    "content_length": int(cl) if cl is not None else None,
                    "chunked": chunked, "body_bytes": len(body),
                    "complete": complete, "nonce": nonce,
                    "saw_key": b"x-api-key" in headers})
            if not complete:
                return
            payload = json.dumps({"ok": True, "nonce": nonce, "conn": conn_id,
                                  "req": req_no, "body_bytes": len(body)}).encode()
            resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    b"Content-Length: %d\r\n" % len(payload))
            resp += (b"Connection: close\r\n\r\n" if close_after else b"\r\n") + payload
            conn.sendall(resp)
            if close_after:
                return
    except (socket.timeout, OSError):
        return
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    global _conn_seq
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(64)
    print(f"bigsink listening on :{PORT} -> {OUT}", flush=True)
    while True:
        conn, _addr = server.accept()
        with _lock:
            _conn_seq += 1
            conn_id = _conn_seq
        record({"event": "accept", "conn": conn_id})
        threading.Thread(target=serve, args=(conn, conn_id), daemon=True).start()


if __name__ == "__main__":
    main()
