#!/usr/bin/env python3
"""Opens N connections to host:port one after another, proves each one with a
one-byte echo, prints one JSON line per attempt, holds the successful ones
open for HOLD seconds and then closes them.

  hold_client.py HOST PORT COUNT CONNECT_TIMEOUT HOLD

A dropped SYN shows up as "timeout" (no reset ever arrives); a reset shows up
as "refused"; anything else is the errno name. The scenario tells a refused
connection from a dropped one by that word."""
import errno
import json
import socket
import sys
import time


def attempt(host, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
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
    host, port, count, timeout, hold = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5])
    held = []
    for i in range(count):
        s, result = attempt(host, port, timeout)
        print(json.dumps({'i': i, 'result': result}), flush=True)
        if s is not None:
            held.append(s)
    print(json.dumps({'connected': len(held), 'attempted': count}), flush=True)
    if hold > 0:
        time.sleep(hold)
    for s in held:
        s.close()
    print(json.dumps({'closed': len(held)}), flush=True)


if __name__ == '__main__':
    main()
