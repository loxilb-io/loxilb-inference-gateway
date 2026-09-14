#!/usr/bin/env python3
"""Open and tear down many HTTP/2 connections against one service.

The leak under test is per-CONNECTION, not per-request: the client's
HTTP/2 session (its nghttp2 state and any stream still attached) was
never freed when the connection closed. So this churns connections —
one stream each — rather than multiplexing many streams onto one.

Half the connections are closed abruptly with the stream still in
flight (the response headers have arrived but the stream has not
ended), because that path also leaves stream structs attached to the
session. The other half complete normally, which frees the streams and
leaves the session as the only thing outstanding.

No credential is sent: a 401 still builds the session, which is the
allocation being measured, and it keeps the run independent of token
lifetime.

Usage: h2_churn.py <host> <port> <count> [progress-every]
Prints one line per progress step and a final summary to stdout.
"""

import json
import socket
import sys

import h2.config
import h2.connection
import h2.events

BODY = json.dumps({"model": "llama", "messages": [{"role": "user",
                                                   "content": "soak"}]}).encode()


def one_connection(host, port, abrupt):
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(10)
    try:
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True,
                                             header_encoding=None))
        conn.initiate_connection()
        conn.send_headers(1, [
            (b":method", b"POST"),
            (b":path", b"/v1/chat/completions"),
            (b":scheme", b"http"),
            (b":authority", f"{host}:{port}".encode()),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(BODY)).encode()),
        ])
        conn.send_data(1, BODY, end_stream=True)
        sock.sendall(conn.data_to_send())

        saw_headers = False
        while True:
            data = sock.recv(65535)
            if not data:
                return "eof"
            for event in conn.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    saw_headers = True
                    if abrupt:
                        # Walk away with the stream still open.
                        return "abrupt"
                if isinstance(event, (h2.events.StreamEnded,
                                      h2.events.StreamReset,
                                      h2.events.ConnectionTerminated)):
                    return "complete" if saw_headers else "reset"
            out = conn.data_to_send()
            if out:
                sock.sendall(out)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main():
    if len(sys.argv) < 4:
        sys.stderr.write("usage: h2_churn.py <host> <port> <count> "
                         "[progress-every]\n")
        return 2
    host, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    step = int(sys.argv[4]) if len(sys.argv) > 4 else 200

    tally = {}
    failures = 0
    for i in range(count):
        try:
            outcome = one_connection(host, port, abrupt=(i % 2 == 1))
        except Exception as exc:              # noqa: BLE001 - churn tool
            outcome = f"error:{type(exc).__name__}"
            failures += 1
        tally[outcome] = tally.get(outcome, 0) + 1
        if step and (i + 1) % step == 0:
            print(f"  churned {i + 1}/{count}", flush=True)

    print(f"outcomes: {json.dumps(tally, sort_keys=True)}")
    # A run where most connections errored proves nothing about memory.
    if failures > count // 10:
        sys.stderr.write(f"too many connection errors: {failures}/{count}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
