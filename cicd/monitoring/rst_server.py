#!/usr/bin/env python3
"""Abortive-close TCP server for the F7/F13 regression guard.

Accepts a connection, reads one request, then closes with SO_LINGER=0 so the
kernel sends RST instead of FIN. Each client connection therefore produces a
server-side abortive close on an *established* connection — exactly the event
loxilb_l4_error_events_total{proto="tcp"} must count (and the only kind the
management-plane fix must still count).
"""
import socket
import struct
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port))
srv.listen(16)
print(f"rst_server listening on :{port}", flush=True)

while True:
    conn, _ = srv.accept()
    try:
        conn.settimeout(5)
        conn.recv(4096)          # let the connection fully establish + carry data
    except OSError:
        pass
    # SO_LINGER with zero timeout => close() sends RST, not FIN
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack("ii", 1, 0))
    conn.close()
