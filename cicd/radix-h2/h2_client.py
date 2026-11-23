#!/usr/bin/env python3
"""h2_client.py - HTTP/2 (h2c, prior knowledge) request driver for radix-h2.

Bodies come from radix-h1's client.py (build(), mounted at /opt/rxh1), so
both scenarios send the same synthetic text. Prints one JSON line per
request: request id, connection label, stream id, status, serving endpoint,
latency in ms. It never prints request bodies.

Usage:
  h2_client.py <host> <port> run <plan.json>   steps in order; a step without
                                               "conn" uses a fresh connection,
                                               steps with the same "conn" share
                                               one, one stream at a time
  h2_client.py <host> <port> mux <plan.json>   every step on ONE connection:
                                               all requests sent before any
                                               answer is read; a step with
                                               "rst": true is reset by the
                                               client right after it is sent
  h2_client.py <host> <port> bench <n> <body-file> <tag> <latfile>
                                               n identical requests with that body,
                                               one stream at a time on one
                                               connection; prints a summary, writes
                                               one latency (ms) per line
Step: {"rid": "...", "body": {...}, "conn": "k1", "path": "/v1/...",
       "ctype": "application/json", "conv_id": "...", "x_model": "...",
       "rst": false}
"""
import json
import socket
import sys
import time

sys.path.insert(0, "/opt/rxh1")
from client import build  # noqa: E402  (radix-h1's body builder)

import h2.config      # noqa: E402
import h2.connection  # noqa: E402
import h2.events      # noqa: E402


class H2:
    def __init__(self, host, port):
        self.host = host
        self.sock = socket.create_connection((host, port), timeout=30)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.c = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
        self.c.initiate_connection()
        self.flush()
        self.res = {}

    def flush(self):
        data = self.c.data_to_send()
        if data:
            self.sock.sendall(data)

    def pump(self):
        data = self.sock.recv(65536)
        if not data:
            raise ConnectionError("closed")
        for ev in self.c.receive_data(data):
            r = self.res.get(getattr(ev, "stream_id", None))
            if isinstance(ev, h2.events.ResponseReceived) and r is not None:
                r["status"] = int(dict(ev.headers).get(":status", "0"))
            elif isinstance(ev, h2.events.DataReceived):
                self.c.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                if r is not None:
                    r["body"] += ev.data
            elif isinstance(ev, h2.events.StreamEnded) and r is not None:
                r["done"] = True
            elif isinstance(ev, h2.events.StreamReset) and r is not None:
                r["done"] = True
                r["reset"] = True
        self.flush()

    def send(self, step):
        body = build(step["body"]) if step.get("body") else b""
        extra = []
        if step.get("conv_id"):
            extra.append(("x-conversation-id", step["conv_id"]))
        if step.get("x_model"):
            extra.append(("x-model", step["x_model"]))
        if step.get("body", {}).get("stream"):
            extra.append(("x-test-stream", "1"))
        return self.send_bytes(step["rid"], body, step.get("path", "/v1/chat/completions"),
                               step.get("ctype", "application/json"), extra)

    def send_bytes(self, rid, body, path="/v1/chat/completions", ctype="application/json", extra=()):
        hdrs = [(":method", "POST"), (":path", path), (":scheme", "http"),
                (":authority", self.host), ("content-type", ctype), ("x-request-id", rid)]
        hdrs += list(extra)
        sid = self.c.get_next_available_stream_id()
        self.res[sid] = {"status": 0, "body": b"", "done": False, "t0": time.time()}
        self.c.send_headers(sid, hdrs, end_stream=not body)
        off = 0
        while off < len(body):
            w = min(self.c.local_flow_control_window(sid), self.c.max_outbound_frame_size,
                    len(body) - off)
            if w <= 0:
                self.flush()
                self.pump()
                continue
            self.c.send_data(sid, body[off:off + w], end_stream=off + w == len(body))
            off += w
        self.flush()
        return sid

    def wait(self, sids):
        while not all(self.res[s]["done"] for s in sids):
            self.pump()

    def result(self, step, label, sid):
        r = self.res[sid]
        ep = "?"
        txt = r["body"].decode("utf-8", "replace")
        for part in (txt, txt.split("data: ", 1)[-1].split("\n", 1)[0]):
            try:
                ep = json.loads(part).get("ep", "?")
                break
            except ValueError:
                pass
        return {"rid": step["rid"], "conn": label, "stream": sid, "status": r["status"],
                "ep": ep, "reset": bool(r.get("reset")), "sse": txt.startswith("data: "),
                "ms": round((time.time() - r["t0"]) * 1000, 3)}

    def close(self):
        try:
            self.c.close_connection()
            self.flush()
        except Exception:
            pass
        self.sock.close()


def bench(host, port, n, bodyfile, tag, latfile):
    with open(bodyfile, "rb") as f:
        data = f.read()
    t_start = time.monotonic()
    c = H2(host, port)
    lat, ok = [], 0
    for i in range(n):
        t0 = time.monotonic()
        try:
            sid = c.send_bytes("%s-%d" % (tag, i), data)
            c.wait([sid])
            ok += c.res.pop(sid)["status"] == 200
        except Exception:  # noqa: BLE001 - counted as not ok, reconnect
            c.close()
            c = H2(host, port)
        lat.append((time.monotonic() - t0) * 1000)
    c.close()
    with open(latfile, "w") as f:
        f.write("\n".join("%.3f" % v for v in lat) + "\n")
    s = sorted(lat)
    print(json.dumps({"tag": tag, "n": n, "ok": ok, "bytes": len(data),
                      "wall_s": round(time.monotonic() - t_start, 3),
                      "p50": round(s[len(s) // 2], 3), "p99": round(s[len(s) * 99 // 100], 3),
                      "mean": round(sum(s) / len(s), 3)}))


def main():
    host, port, cmd = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    if cmd == "bench":
        bench(host, port, int(sys.argv[4]), sys.argv[5], sys.argv[6], sys.argv[7])
        return
    plan = json.load(open(sys.argv[4]))
    if cmd == "run":
        conns = {}
        for step in plan:
            label = step.get("conn")
            c = conns.get(label) if label else None
            if c is None:
                c = H2(host, port)
                if label:
                    conns[label] = c
            try:
                sid = c.send(step)
                c.wait([sid])
                print(json.dumps(c.result(step, label or "-", sid)), flush=True)
            except Exception as e:
                print(json.dumps({"rid": step["rid"], "conn": label or "-", "status": 0,
                                  "ep": "?", "error": type(e).__name__}), flush=True)
            if not label:
                c.close()
        for c in conns.values():
            c.close()
    elif cmd == "mux":
        c = H2(host, port)
        sids = []
        for step in plan:
            sid = c.send(step)
            if step.get("rst"):
                c.c.reset_stream(sid)
                c.flush()
                c.res[sid]["done"] = True
                c.res[sid]["reset"] = True
            sids.append(sid)
        c.wait(sids)
        for step, sid in zip(plan, sids):
            print(json.dumps(c.result(step, "mux", sid)), flush=True)
        c.close()


if __name__ == "__main__":
    main()
