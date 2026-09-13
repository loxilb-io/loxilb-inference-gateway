#!/usr/bin/env python3
"""h2c (HTTP/2 prior-knowledge, no TLS) echo backend for the H2 gate legs.

The hdr_echo.py pools speak HTTP/1.1, which makes them useless as ADMISSION
oracles for HTTP/2: the gateway forwards h2 frames upstream, an H/1.1 server
cannot parse them, and the client-side reset looks identical to a refusal.
This backend completes the h2 exchange, so "admitted" and "refused" finally
produce different client-visible outcomes over HTTP/2.

Behaviour mirrors hdr_echo.py where it matters to the legs:
  POST *            -> 200 JSON carrying the label, header-presence markers
                       (authorization / x-api-key / x-auth-tenant / x-auth-user)
                       and a usage object (feeds the H2 settle path);
                       an x-test-nonce header is counted as a receipt.
  GET /__receipts/N -> the count for nonce N, as a decimal body.

Usage: h2c_echo.py <label> <port>
"""

import json
import socket
import sys
import threading

import h2.config
import h2.connection
import h2.events

LABEL = sys.argv[1] if len(sys.argv) > 1 else "server-h2"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8090

receipts = {}
receipts_lock = threading.Lock()


def respond(conn, stream_id, status, body):
    conn.send_headers(stream_id, [
        (":status", str(status)),
        ("content-type", "application/json"),
        ("content-length", str(len(body))),
    ])
    conn.send_data(stream_id, body, end_stream=True)


def handle_request(conn, stream_id, headers, body):
    hdr = {}
    for name, value in headers:
        if isinstance(name, bytes):
            name = name.decode("utf8", "replace")
        if isinstance(value, bytes):
            value = value.decode("utf8", "replace")
        hdr[name.lower()] = value

    method = hdr.get(":method", "")
    path = hdr.get(":path", "/")

    if method == "GET" and path.startswith("/__receipts/"):
        nonce = path[len("/__receipts/"):]
        with receipts_lock:
            count = receipts.get(nonce, 0)
        respond(conn, stream_id, 200, str(count).encode())
        return

    nonce = hdr.get("x-test-nonce", "")
    if nonce:
        with receipts_lock:
            receipts[nonce] = receipts.get(nonce, 0) + 1

    reply = {
        "label": LABEL,
        "object": "chat.completion",
        "authorization": "yes" if "authorization" in hdr else "no",
        "apikey": "yes" if "x-api-key" in hdr else "no",
        "x_auth_tenant": hdr.get("x-auth-tenant", ""),
        "x_auth_user": hdr.get("x-auth-user", ""),
        "body_len": len(body),
        "usage": {"prompt_tokens": 5, "completion_tokens": 7,
                  "total_tokens": 12},
    }
    respond(conn, stream_id, 200, json.dumps(reply).encode())


def handle_conn(sock):
    config = h2.config.H2Configuration(client_side=False,
                                       header_encoding=None)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    streams = {}  # stream_id -> {"headers": [...], "body": bytearray}
    sock.settimeout(20)
    try:
        while True:
            data = sock.recv(65535)
            if not data:
                break
            events = conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    streams[event.stream_id] = {
                        "headers": event.headers, "body": bytearray()}
                    if event.stream_ended:
                        st = streams.pop(event.stream_id)
                        handle_request(conn, event.stream_id,
                                       st["headers"], bytes(st["body"]))
                elif isinstance(event, h2.events.DataReceived):
                    st = streams.get(event.stream_id)
                    if st is not None:
                        st["body"] += event.data
                    conn.acknowledge_received_data(
                        len(event.data), event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    st = streams.pop(event.stream_id, None)
                    if st is not None:
                        handle_request(conn, event.stream_id,
                                       st["headers"], bytes(st["body"]))
                elif isinstance(event, h2.events.ConnectionTerminated):
                    return
            out = conn.data_to_send()
            if out:
                sock.sendall(out)
    except (socket.timeout, OSError):
        pass
    finally:
        sock.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(16)
    print(f"h2c_echo '{LABEL}' listening on :{PORT}", flush=True)
    while True:
        sock, _ = server.accept()
        threading.Thread(target=handle_conn, args=(sock,),
                         daemon=True).start()


if __name__ == "__main__":
    main()
