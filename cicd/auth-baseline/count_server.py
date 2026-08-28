#!/usr/bin/env python3
# Counting HTTP backend for the authentication-plane baselines.
#
# It logs every arriving request to /tmp/backend_reqs.log, one line each, so the
# request count moves only for requests that genuinely reached the backend. That
# is what decides whether a denied request is still dispatched upstream: the
# gateway's own counters cannot answer it, because the question is precisely
# whether the gateway forwarded something it told the client it had rejected.
import socket
import sys
import time
import threading

LOG = "/tmp/backend_reqs.log"
name = sys.argv[1] if len(sys.argv) > 1 else "server1"
port = 8080

open(LOG, "w").close()  # truncate at start

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port))
srv.listen(128)


def handle(conn, addr):
    try:
        conn.settimeout(5)
        data = b""
        # Read until the end of the headers; the request line and headers are
        # all that is needed to characterise what arrived.
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        text = data.decode("latin1", "replace")
        line0 = text.split("\r\n", 1)[0] if text else "<empty>"
        has_key = "x-api-key" in text.lower()
        authz = "authorization" in text.lower()
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        with open(LOG, "a") as f:
            f.write("%s peer=%s reqline=%r x_api_key=%s authz=%s bytes=%d\n"
                    % (ts, addr[0], line0, has_key, authz, len(data)))
        body = name.encode()
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: %d\r\nConnection: close\r\n\r\n%s"
                % (len(body), body))
        conn.sendall(resp)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


print("count_server %s listening on :%d, logging to %s" % (name, port, LOG), flush=True)
while True:
    conn, addr = srv.accept()
    threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
