#!/usr/bin/env python3
"""h2_admit.py — HTTP/2 driver for the capacity gate.

One connection, k streams opened back to back, each held at the backend for
--delay-ms. What the gate does with them is reported per stream: the
:status and the x-loxilb-admission-* headers of a refusal, or the status of
an admitted stream once its response arrives. With --rst N, the first N
streams still in flight after --rst-after-s seconds are cancelled with
RST_STREAM(CANCEL) while the connection stays up, which is the only shape
that isolates the per-stream release from the connection teardown.

Every stream prints one JSON line; a final "summary" line carries the
counts. The drive shape is reported rather than assumed, so a caller can
refuse a run in which the cancels landed on streams that had already
answered.

Usage: h2_admit.py <host> <port> --streams K --delay-ms D
                   [--rst N --rst-after-s S] [--nonce-prefix P] [--model M]
                   [--header name=value ...]
"""
import argparse
import json
import socket
import sys
import time

import h2.config
import h2.connection
import h2.errors
import h2.events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--streams", type=int, default=1)
    ap.add_argument("--delay-ms", type=int, default=0)
    ap.add_argument("--rst", type=int, default=0)
    ap.add_argument("--rst-after-s", type=float, default=0)
    ap.add_argument("--nonce-prefix", default="h2adm")
    ap.add_argument("--model", default="cap-model")
    ap.add_argument("--path", default="/v1/chat/completions")
    ap.add_argument("--header", action="append", default=[],
                    help="name=value, added to every stream's request (repeatable)")
    args = ap.parse_args()

    timeout = args.delay_ms / 1000.0 + 20.0
    sock = socket.create_connection((args.host, args.port), timeout=timeout)
    sock.settimeout(timeout)
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, header_encoding=None))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    streams = {}
    for i in range(args.streams):
        nonce = "%s-%d" % (args.nonce_prefix, i)
        sid = conn.get_next_available_stream_id()
        body = json.dumps({"model": args.model,
                           "messages": [{"role": "user", "content": nonce}]}).encode()
        headers = [
            (":method", "POST"), (":path", args.path), (":scheme", "http"),
            (":authority", "%s:%d" % (args.host, args.port)),
            ("content-type", "application/json"),
            ("content-length", str(len(body))),
            ("x-test-nonce", nonce),
            ("x-request-id", nonce),
        ]
        if args.delay_ms:
            headers.append(("x-test-delay-ms", str(args.delay_ms)))
        for h in args.header:
            name, _, value = h.partition("=")
            headers.append((name.lower(), value))
        conn.send_headers(sid, headers)
        conn.send_data(sid, body, end_stream=True)
        streams[sid] = {"nonce": nonce, "status": "", "headers": {},
                        "body": bytearray(), "done": False, "rst": False}
    sock.sendall(conn.data_to_send())

    start = time.monotonic()
    deadline = start + timeout
    rst_at = start + args.rst_after_s if args.rst else None
    rst_done = 0

    while time.monotonic() < deadline:
        if all(st["done"] for st in streams.values()):
            break
        if rst_at is not None and time.monotonic() >= rst_at and rst_done < args.rst:
            for sid in sorted(streams):
                st = streams[sid]
                if rst_done >= args.rst:
                    break
                if st["done"] or st["status"]:
                    continue        # answered already: not a cancel of a live stream
                conn.reset_stream(sid, error_code=h2.errors.ErrorCodes.CANCEL)
                st["rst"] = True
                st["done"] = True
                st["status"] = "RST_SENT"
                rst_done += 1
            sock.sendall(conn.data_to_send())
            rst_at = None
        try:
            wait = 0.2
            if rst_at is not None:
                wait = max(0.05, min(wait, rst_at - time.monotonic()))
            sock.settimeout(wait)
            data = sock.recv(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        if not data:
            break
        for event in conn.receive_data(data):
            st = streams.get(getattr(event, "stream_id", None))
            if isinstance(event, h2.events.ResponseReceived) and st is not None:
                for name, value in event.headers:
                    name = name.decode() if isinstance(name, bytes) else name
                    value = value.decode() if isinstance(value, bytes) else value
                    if name == ":status":
                        st["status"] = value
                    elif (name.startswith("x-loxilb-admission-") or
                          name.startswith("x-loxilb-refusal-") or
                          name in ("retry-after", "x-request-id")):
                        st["headers"][name] = value
            elif isinstance(event, h2.events.DataReceived) and st is not None:
                st["body"] += event.data
                try:
                    conn.acknowledge_received_data(len(event.data), event.stream_id)
                except Exception:  # noqa: BLE001
                    pass
            elif isinstance(event, h2.events.StreamEnded) and st is not None:
                st["done"] = True
            elif isinstance(event, h2.events.StreamReset) and st is not None:
                st["status"] = st["status"] or "RST"
                st["done"] = True
            elif isinstance(event, h2.events.ConnectionTerminated):
                deadline = 0
        out = conn.data_to_send()
        if out:
            sock.sendall(out)

    try:
        conn.close_connection()
        sock.sendall(conn.data_to_send())
        sock.close()
    except OSError:
        pass

    admitted = refused = rst = none = 0
    for sid in sorted(streams):
        st = streams[sid]
        print(json.dumps({"stream": sid, "nonce": st["nonce"],
                          "status": st["status"] or "NONE",
                          "headers": st["headers"],
                          "body": bytes(st["body"]).decode("utf8", "replace")[:200]}),
              flush=True)
        if st["rst"]:
            rst += 1
        elif st["status"] == "200":
            admitted += 1
        elif st["status"] == "429":
            refused += 1
        else:
            none += 1
    print(json.dumps({"summary": "hold", "streams": len(streams), "admitted": admitted,
                      "refused": refused, "rst": rst, "other": none}), flush=True)
    return 0 if none == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
