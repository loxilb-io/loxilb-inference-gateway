#!/usr/bin/env python3
"""A TCP backend that answers one byte and then holds every connection open
until the client closes it, so the connections a scenario opens stay counted
by the load balancer for as long as the scenario wants."""
import socket
import sys
import threading


def serve(conn):
    try:
        data = conn.recv(1)
        if data:
            conn.sendall(data)
        while conn.recv(1):
            pass
    except OSError:
        pass
    finally:
        conn.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    srv.listen(64)
    print('listening on %d' % port, flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == '__main__':
    main()
