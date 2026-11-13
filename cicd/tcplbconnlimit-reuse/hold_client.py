#!/usr/bin/env python3
"""Opens N connections to host:port one after another, proves each one with a
one-byte echo, prints one JSON line per attempt and holds the successful ones
open for HOLD seconds.

  hold_client.py HOST PORT COUNT CONNECT_TIMEOUT HOLD [SOURCE_PORT]

With SOURCE_PORT the (single) connection is bound to that local port, so two
clients on different addresses can be made to use the same one. A dropped SYN
shows up as "timeout", a reset as "refused" (during connect) or "reset" (while
held), anything else as the errno name. While holding, the client reports how
each held connection ended if the peer ends it first."""
import errno
import json
import select
import socket
import sys
import time


def attempt(host, port, timeout, sport):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if sport:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', sport))
        s.connect((host, port))
        s.sendall(b'x')
        if s.recv(1) != b'x':
            s.close()
            return None, 'no-echo'
        s.settimeout(None)
        return s, 'connected'
    except socket.timeout:
        s.close()
        return None, 'timeout'
    except ConnectionRefusedError:
        s.close()
        return None, 'refused'
    except OSError as e:
        s.close()
        return None, errno.errorcode.get(e.errno, str(e))


def main():
    host, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    timeout, hold = float(sys.argv[4]), float(sys.argv[5])
    sport = int(sys.argv[6]) if len(sys.argv) > 6 else 0
    held = {}
    for i in range(count):
        s, result = attempt(host, port, timeout, sport)
        print(json.dumps({'i': i, 'result': result}), flush=True)
        if s is not None:
            held[s] = i
    print(json.dumps({'connected': len(held), 'attempted': count}), flush=True)
    start = time.time()
    deadline = start + hold
    while held and time.time() < deadline:
        ready, _, _ = select.select(list(held), [], [], max(0.0, deadline - time.time()))
        for s in ready:
            try:
                end = 'eof' if s.recv(1) == b'' else 'data'
            except ConnectionResetError:
                end = 'reset'
            except OSError as e:
                end = errno.errorcode.get(e.errno, str(e))
            if end != 'data':
                print(json.dumps({'i': held.pop(s), 'ended': end,
                                  'after': round(time.time() - start, 1)}), flush=True)
                s.close()
    for s in held:
        s.close()
    print(json.dumps({'closed': len(held)}), flush=True)


if __name__ == '__main__':
    main()
