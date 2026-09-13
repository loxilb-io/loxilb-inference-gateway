#!/usr/bin/env python3
"""One HTTP/2 connection, several interleaved streams — the multiplexing
oracle for the multi-model legs.

curl cannot produce this shape: even with --parallel it settles one
request before the next leaves, so the connection never holds two
in-flight streams whose models differ. Here every stream's HEADERS+DATA
are sent before ANY response is read, which is exactly the interleaving a
real H2 client produces and the case a per-connection backend cache gets
wrong.

Usage:
    h2_mux_client.py <host> <port> <model>|<token-file>|<nonce> ...

Each positional spec opens one stream: POST /v1/chat/completions with the
model and nonce in the JSON body, the nonce again in x-test-nonce (the
backend receipt header), and Authorization: Bearer <token> unless the
token-file field is '-'. Output is one JSON line per stream:
    {"stream": <id>, "model": "...", "nonce": "...", "status": "...",
     "body": "..."}
so the caller can bind every verdict to the stream that produced it.
Exits non-zero if any stream never completed.
"""

import json
import socket
import sys

import h2.config
import h2.connection
import h2.events


def main():
    if len(sys.argv) < 4:
        sys.stderr.write("usage: h2_mux_client.py <host> <port> "
                         "<model>|<tokenfile>|<nonce> ...\n")
        return 2
    host, port = sys.argv[1], int(sys.argv[2])

    specs = []
    for raw in sys.argv[3:]:
        model, tokenfile, nonce = raw.split("|", 2)
        token = ""
        if tokenfile != "-":
            with open(tokenfile) as f:
                token = f.read().strip()
        specs.append({"model": model, "token": token, "nonce": nonce})

    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(10)
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True,
                                         header_encoding=None))
    conn.initiate_connection()

    # Phase 1: every stream's request goes out before any response is
    # read. This is the interleaving under test — do not reorder.
    streams = {}
    for spec in specs:
        sid = conn.get_next_available_stream_id()
        body = json.dumps({
            "model": spec["model"],
            "messages": [{"role": "user", "content": spec["nonce"]}],
        }).encode()
        headers = [
            (":method", "POST"),
            (":path", "/v1/chat/completions"),
            (":scheme", "http"),
            (":authority", "%s:%d" % (host, port)),
            ("content-type", "application/json"),
            ("content-length", str(len(body))),
            ("x-test-nonce", spec["nonce"]),
        ]
        if spec["token"]:
            headers.append(("authorization", "Bearer " + spec["token"]))
        conn.send_headers(sid, headers)
        conn.send_data(sid, body, end_stream=True)
        streams[sid] = {"spec": spec, "status": "", "body": bytearray(),
                        "done": False}
    sock.sendall(conn.data_to_send())

    # Phase 2: collect every response.
    try:
        while not all(st["done"] for st in streams.values()):
            data = sock.recv(65535)
            if not data:
                break
            for event in conn.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    st = streams.get(event.stream_id)
                    if st is not None:
                        for name, value in event.headers:
                            if isinstance(name, bytes):
                                name = name.decode("utf8", "replace")
                            if isinstance(value, bytes):
                                value = value.decode("utf8", "replace")
                            if name == ":status":
                                st["status"] = value
                elif isinstance(event, h2.events.DataReceived):
                    st = streams.get(event.stream_id)
                    if st is not None:
                        st["body"] += event.data
                    conn.acknowledge_received_data(
                        len(event.data), event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    st = streams.get(event.stream_id)
                    if st is not None:
                        st["done"] = True
                elif isinstance(event, h2.events.StreamReset):
                    st = streams.get(event.stream_id)
                    if st is not None:
                        st["status"] = st["status"] or "RST"
                        st["done"] = True
                elif isinstance(event, h2.events.ConnectionTerminated):
                    raise ConnectionError("GOAWAY")
            out = conn.data_to_send()
            if out:
                sock.sendall(out)
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        sock.close()

    incomplete = 0
    for sid in sorted(streams):
        st = streams[sid]
        if not st["done"]:
            incomplete += 1
        print(json.dumps({
            "stream": sid,
            "model": st["spec"]["model"],
            "nonce": st["spec"]["nonce"],
            "status": st["status"] or "NONE",
            "body": bytes(st["body"]).decode("utf8", "replace"),
        }), flush=True)
    return 1 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
