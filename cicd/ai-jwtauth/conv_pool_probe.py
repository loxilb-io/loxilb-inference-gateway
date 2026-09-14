#!/usr/bin/env python3
"""Conversation stickiness must not be shared between model pools.

conv_map hangs off proxy_map_ent_t (one table per VIP:port) and is keyed by
conv_id ALONE, while the ep_idx it stores indexes ONE pool's eps[]. Port 2050
puts two model pools on one VIP, so a single x-conversation-id reaches both.

Two streams on ONE h2 connection, different models, different identities, the
SAME conversation id. Each pool must record its OWN binding.

Usage: conv_pool_probe.py <host> <port> <conv-id> <model|tokenfile> ...
Prints one JSON line per stream.
"""
import json
import socket
import sys

import h2.config
import h2.connection
import h2.events


def main():
    host, port, conv_id = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    specs = []
    for raw in sys.argv[4:]:
        model, tokenfile = raw.split("|", 1)
        with open(tokenfile) as f:
            specs.append({"model": model, "token": f.read().strip()})

    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(15)
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True,
                                         header_encoding=None))
    conn.initiate_connection()

    streams = {}
    for spec in specs:
        sid = conn.get_next_available_stream_id()
        body = json.dumps({
            "model": spec["model"],
            "messages": [{"role": "user", "content": conv_id}],
        }).encode()
        headers = [
            (":method", "POST"),
            (":path", "/v1/chat/completions"),
            (":scheme", "http"),
            (":authority", "%s:%d" % (host, port)),
            ("content-type", "application/json"),
            ("content-length", str(len(body))),
            # the whole point: ONE conversation id across BOTH model pools
            ("x-conversation-id", conv_id),
            ("authorization", "Bearer " + spec["token"]),
        ]
        conn.send_headers(sid, headers)
        conn.send_data(sid, body, end_stream=True)
        streams[sid] = {"spec": spec, "status": "", "body": bytearray(),
                        "done": False}
    sock.sendall(conn.data_to_send())

    try:
        while not all(st["done"] for st in streams.values()):
            data = sock.recv(65535)
            if not data:
                break
            for event in conn.receive_data(data):
                st = streams.get(getattr(event, "stream_id", None))
                if isinstance(event, h2.events.ResponseReceived) and st:
                    for name, value in event.headers:
                        name = name.decode() if isinstance(name, bytes) else name
                        value = value.decode() if isinstance(value, bytes) else value
                        if name == ":status":
                            st["status"] = value
                elif isinstance(event, h2.events.DataReceived) and st:
                    st["body"] += event.data
                    conn.acknowledge_received_data(len(event.data), event.stream_id)
                elif isinstance(event, h2.events.StreamEnded) and st:
                    st["done"] = True
                elif isinstance(event, h2.events.StreamReset) and st:
                    st["status"] = st["status"] or "RST"
                    st["done"] = True
                elif isinstance(event, h2.events.ConnectionTerminated):
                    raise ConnectionError("GOAWAY")
            out = conn.data_to_send()
            if out:
                sock.sendall(out)
    except (socket.timeout, ConnectionError, OSError) as exc:
        sys.stderr.write("probe transport: %s\n" % exc)

    rc = 0
    for sid, st in streams.items():
        if not st["done"]:
            rc = 1
        print(json.dumps({
            "stream": sid, "model": st["spec"]["model"],
            "conv_id": conv_id, "status": st["status"],
            "body": bytes(st["body"]).decode("utf8", "replace")[:400],
        }))
    sock.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
