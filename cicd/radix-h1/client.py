#!/usr/bin/env python3
"""client.py - HTTP/1.1 request driver for the radix-h1 scenario.

Builds chat bodies itself (deterministic, synthetic text) and sends them to
the gateway VIP. Prints one JSON line per request: request id, connection
label, status, serving endpoint (from the mock's answer), latency in ms.
It never prints request bodies.

Usage:
  client.py <host> <port> run <plan.json>
  client.py <host> <port> latency <n> <tag>      n sequential conversation turns
  client.py <host> <port> pipe <plan.json> <gap-ms>
                                                 HTTP/1.1 pipelining on one connection: the
                                                 first request, a pause, then the next ones
                                                 before any answer is read; answers are read
                                                 in order (one result line each)
  client.py <host> <port> body <bytes> <plain|parts> <file>
                                                 write a request body of about <bytes>
  client.py <host> <port> bench <n> <body-file> <tag> <latfile>
                                                 n identical requests with that body on
                                                 one kept-alive connection; prints a
                                                 summary, writes one latency (ms) per line

Plan: a JSON list of steps:
  {"rid": "...", "body": {...}, "conn": "k1", "close": false,
   "headers": {"x-session-id": "s1"}, "chunked": false}
A step without "conn" uses a fresh connection, closed after the answer, so
the gateway selects an endpoint for it (on HTTP/1.1 a kept-alive connection
keeps the backend leg of its previous request).
Body kinds:
  {"kind": "conv", "conv": 3, "turns": 2}       turn n+1 extends turn n
  {"kind": "conv", ..., "variant": 1}           same system prompt, other turns
  {"kind": "short"}                             under one 256-byte block
  {"kind": "tokens", "n": 2000}                 2,000 messages: over 8,192 JSON tokens
  {"kind": "big", "bytes": 800000}              Content-Length above 768 KiB
  {"kind": "marker", "marker": "..."}           a marker string in the system prompt
  any body may add "stream": true
"""
import http.client
import json
import socket
import sys
import time

MODEL = "rx-model"


def filler(seed, n):
    words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
             "hotel", "india", "juliet", "kilo", "lima"]
    out, i, length = [], seed, 0
    while length < n:
        w = words[i % len(words)]
        out.append(w)
        length += len(w) + 1
        i = i * 7 + 3
    return " ".join(out)[:n]


def build(spec):
    k = spec["kind"]
    if k == "conv":
        c = spec["conv"]
        v = spec.get("variant", 0)       # 0 keeps the original text of every conversation
        tag = "" if v == 0 else " (variant %d)" % v
        msgs = [{"role": "system",
                 "content": "System prompt of conversation %d. %s" % (c, filler(c, 1500))}]
        for t in range(spec["turns"]):
            msgs.append({"role": "user", "content": "Question %d of %d%s. %s" % (t, c, tag, filler(c * 31 + t + 1000 * v, 600))})
            if t < spec["turns"] - 1:
                msgs.append({"role": "assistant", "content": "Answer %d of %d%s. %s" % (t, c, tag, filler(c * 17 + t + 1000 * v, 600))})
        body = {"model": MODEL, "messages": msgs}
    elif k == "short":
        body = {"model": MODEL, "messages": [{"role": "user", "content": "hi"}]}
    elif k == "tokens":
        body = {"model": MODEL, "messages": [
            {"role": "user" if i % 2 == 0 else "assistant", "content": "hi"} for i in range(spec["n"])]}
    elif k == "big":
        body = {"model": MODEL, "messages": [{"role": "user", "content": filler(5, spec["bytes"])}]}
    elif k == "marker":
        body = {"model": MODEL, "messages": [
            {"role": "system", "content": "%s %s" % (spec["marker"], filler(9, 1200))},
            {"role": "user", "content": "%s question" % spec["marker"]}]}
    else:
        raise SystemExit("unknown body kind " + k)
    if spec.get("stream"):
        body["stream"] = True
    return json.dumps(body).encode()


class Conn(http.client.HTTPConnection):
    def connect(self):
        super().connect()
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def quickack(self):
        # ACK the reply at once (no 40 ms delayed-ACK stall on a split reply)
        try:
            if self.sock:
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        except (AttributeError, OSError):
            pass


def sized(nbytes, form):
    """A chat body of about nbytes: a system prompt, then one user message
    whose content is a string (plain) or text parts of 512 bytes (parts)."""
    def make(n):
        text = filler(77, n)
        if form == "parts":
            content = [{"type": "text", "text": text[i:i + 512]} for i in range(0, len(text), 512)]
        else:
            content = text
        return json.dumps({"model": MODEL, "messages": [
            {"role": "system", "content": "Cost measurement. " + filler(3, 1500)},
            {"role": "user", "content": content}]}).encode()
    n = max(0, nbytes - 1700)
    for _ in range(6):
        b = make(n)
        if abs(len(b) - nbytes) <= 64:
            break
        n = max(0, n + (nbytes - len(b)) * (n + 1) // max(len(b), 1))
    return b


def bench(host, port, n, bodyfile, tag, latfile):
    with open(bodyfile, "rb") as f:
        data = f.read()
    t_start = time.monotonic()
    conn = Conn(host, port, timeout=60)
    lat, ok = [], 0
    hdrs = {"Content-Type": "application/json"}
    for i in range(n):
        hdrs["X-Request-Id"] = "%s-%d" % (tag, i)
        t0 = time.monotonic()
        try:
            conn.request("POST", "/v1/chat/completions", body=data, headers=hdrs)
            conn.quickack()
            r = conn.getresponse()
            r.read()
            ok += r.status == 200
        except Exception:  # noqa: BLE001 - counted as not ok, reconnect
            conn.close()
            conn = Conn(host, port, timeout=60)
        lat.append((time.monotonic() - t0) * 1000)
    conn.close()
    with open(latfile, "w") as f:
        f.write("\n".join("%.3f" % v for v in lat) + "\n")
    s = sorted(lat)
    print(json.dumps({"tag": tag, "n": n, "ok": ok, "bytes": len(data),
                      "wall_s": round(time.monotonic() - t_start, 3),
                      "p50": round(s[len(s) // 2], 3), "p99": round(s[len(s) * 99 // 100], 3),
                      "mean": round(sum(s) / len(s), 3)}))


def one(conns, host, port, step):
    label = step.get("conn")
    if label is None:
        label = "fresh:" + step["rid"]
        step = dict(step, close=True)
    conn = conns.get(label)
    if conn is None:
        conn = conns[label] = Conn(host, port, timeout=30)
    data = build(step["body"])
    hdrs = {"Content-Type": "application/json", "X-Request-Id": step["rid"]}
    hdrs.update(step.get("headers", {}))
    t0 = time.monotonic()
    rec = {"rid": step["rid"], "conn": label}
    try:
        if step.get("chunked"):
            conn.request("POST", "/v1/chat/completions",
                         body=iter([data[i:i + 4096] for i in range(0, len(data), 4096)]),
                         headers=hdrs, encode_chunked=True)
        else:
            conn.request("POST", "/v1/chat/completions", body=data, headers=hdrs)
        conn.quickack()
        r = conn.getresponse()
        payload = r.read()
        rec["status"] = r.status
        ep = None
        try:
            if payload.startswith(b"data:"):
                ep = json.loads(payload.split(b"\n")[0][5:]).get("ep")
            else:
                ep = json.loads(payload).get("ep")
                if ep is None:
                    ep = json.loads(payload).get("error", {}).get("ep")
        except Exception:
            pass
        rec["ep"] = ep
        rec["sse"] = payload.startswith(b"data:")
        if r.getheader("Connection", "").lower() == "close":
            conn.close()
            conns.pop(label, None)
    except Exception as e:  # noqa: BLE001 - recorded, the scenario judges it
        rec["status"] = 0
        rec["error"] = type(e).__name__
        conn.close()
        conns.pop(label, None)
    rec["ms"] = round((time.monotonic() - t0) * 1000, 3)
    if step.get("close") and label in conns:
        conns.pop(label).close()
    print(json.dumps(rec), flush=True)


def pipe(host, port, plan, gap_ms):
    """Pipelined requests on one raw connection: request 1, gap_ms, then the
    rest, then the answers in order (Content-Length or chunked bodies)."""
    s = socket.create_connection((host, port), timeout=30)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    raw = []
    for step in plan:
        data = build(step["body"])
        head = ("POST /v1/chat/completions HTTP/1.1\r\nHost: %s:%d\r\n"
                "Content-Type: application/json\r\nX-Request-Id: %s\r\n"
                "Content-Length: %d\r\n\r\n" % (host, port, step["rid"], len(data)))
        raw.append(head.encode() + data)
    s.sendall(raw[0])
    time.sleep(gap_ms / 1000.0)
    for r in raw[1:]:
        s.sendall(r)
    f = s.makefile("rb")
    for step in plan:
        rec = {"rid": step["rid"], "conn": "pipe"}
        try:
            line = f.readline()
            rec["status"] = int(line.split()[1])
            hdrs = {}
            while True:
                h = f.readline()
                if h in (b"\r\n", b"\n", b""):
                    break
                k, _, v = h.decode("latin-1").partition(":")
                hdrs[k.strip().lower()] = v.strip()
            if "content-length" in hdrs:
                payload = f.read(int(hdrs["content-length"]))
            else:
                payload = b""
                while True:
                    n = int(f.readline().split(b";")[0], 16)
                    chunk = f.read(n)
                    f.readline()
                    if n == 0:
                        break
                    payload += chunk
            try:
                obj = json.loads(payload)
                rec["ep"], rec["id"] = obj.get("ep"), obj.get("id")
            except Exception:
                rec["ep"] = rec["id"] = None
        except Exception as e:  # noqa: BLE001 - recorded, the scenario judges it
            rec["status"] = 0
            rec["error"] = type(e).__name__
        print(json.dumps(rec), flush=True)
    s.close()


def main():
    host, port, cmd = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    conns = {}
    if cmd == "run":
        for step in json.load(open(sys.argv[4])):
            one(conns, host, port, step)
    elif cmd == "pipe":
        pipe(host, port, json.load(open(sys.argv[4])), int(sys.argv[5]))
    elif cmd == "body":
        with open(sys.argv[6], "wb") as f:
            f.write(sized(int(sys.argv[4]), sys.argv[5]))
    elif cmd == "bench":
        bench(host, port, int(sys.argv[4]), sys.argv[5], sys.argv[6], sys.argv[7])
    elif cmd == "latency":
        n, tag = int(sys.argv[4]), sys.argv[5]
        for i in range(n):
            one(conns, host, port, {"rid": "%s-%d" % (tag, i), "conn": "lat",
                                    "body": {"kind": "conv", "conv": 900 + i % 20, "turns": 1 + (i // 20) % 6}})
    for c in conns.values():
        c.close()


if __name__ == "__main__":
    main()
