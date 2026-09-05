#!/usr/bin/env python3
"""Hold N TCP connections open against a VIP for T seconds.

Ground-truth driver for the conntrack-gauge assertion (internal monitoring CI
plan, assertion catalog): while the connections are held,
loxilb_active_conntrack_entries must
reflect them. Prints READY once all connections are established so the caller
knows when to sample Prometheus.
"""
import socket
import sys
import time

host, port, count, hold = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])

conns = []
for _ in range(count):
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(b"GET / HTTP/1.1\r\nHost: hold\r\n\r\n")
    conns.append(s)

print(f"READY {len(conns)}", flush=True)
time.sleep(hold)
for s in conns:
    # Drain the pending response before closing: closing a socket with unread
    # received data makes the kernel send RST instead of FIN, which would leak
    # client-abort events into the L4 error counters the caller asserts on.
    try:
        s.settimeout(0.5)
        while s.recv(4096):
            pass
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass
print("DONE", flush=True)
