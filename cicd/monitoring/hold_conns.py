#!/usr/bin/env python3
"""Hold N TCP connections open against a VIP for T seconds.

Ground-truth driver for the conntrack-gauge assertion (docs/MONITORING-CICD.md
§7): while the connections are held, loxilb_active_conntrack_entries must
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
    try:
        s.close()
    except OSError:
        pass
print("DONE", flush=True)
