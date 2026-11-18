#!/usr/bin/env python3
"""Measurement tools for ai-ha-failover-bfd. Standard library only.

  probe     open-loop client: one new TCP connection per request at a fixed
            rate, every outcome classified (run inside the client namespace)
  node      per-node sampler: role, VIP on lo, listeners on the VIP
            (run inside a gateway's namespace)
  neigh     the client's neighbour entry for the VIP over time
  arp       an observer on the client segment: asks who has the VIP at a
            fixed rate and records every ARP frame that claims it
  timeline  turns one failover's recordings into intervals and a histogram
  retry     one identity retried until it answers 200; every attempt kept
  burst     N distinct credentials released at once by one barrier
  conv      one request per conversation id -> the backend that answered
  debtwatch one identity asked repeatedly; flags an admission that came
            earlier than the gateway's own last Retry-After allowed

All timestamps are epoch milliseconds from the one host clock, so intervals
across namespaces are comparable.
"""
import argparse
import errno
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time


def now_ms():
    return int(time.time() * 1000)


def ticker(period_s, stop_file, deadline_s=None):
    """Yields at a fixed rate, never drifting, until the stop file appears."""
    start = time.monotonic()
    i = 0
    while True:
        if os.path.exists(stop_file):
            return
        if deadline_s is not None and time.monotonic() - start > deadline_s:
            return
        yield i
        i += 1
        delay = start + i * period_s - time.monotonic()
        if delay > 0:
            time.sleep(delay)


# ---------------------------------------------------------------- probe
# Outcome classes. "refused" and "connect_timeout" must never share a
# bucket: a refusal while the VIP is already on the new master is a listener
# that is not there yet, a timeout is a VIP nobody answers for.
ERR_CODE = re.compile(rb'"(?:code|error)"\s*:\s*"([A-Za-z0-9_.\-]+)"')


def stream_fields(rec, data):
    """What a streaming client holds when the connection ends: the status
    line it saw, how many SSE events arrived, and whether the terminator did."""
    m = re.match(rb"HTTP/1\.[01] (\d{3})", data)
    if m:
        rec["status_seen"] = int(m.group(1))
    rec["events"] = data.count(b"data: ")
    rec["done_seen"] = b"data: [DONE]" in data


def one_request(args, seq, out=None, lock=None, headers=None):
    rec = {"seq": seq, "t_send": now_ms()}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(args.connect_timeout)
        try:
            s.connect((args.vip, args.port))
        except ConnectionRefusedError:
            rec["cls"] = "refused"
            return
        except socket.timeout:
            rec["cls"] = "connect_timeout"
            return
        except OSError as e:
            if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
                rec["cls"] = "unreachable"
            else:
                rec["cls"] = "connect_error"
                rec["detail"] = errno.errorcode.get(e.errno, str(e.errno))
            return
        rec["t_conn"] = now_ms()
        payload = {"model": args.model, "messages": [{"role": "user", "content": "hi"}]}
        if getattr(args, "stream", False):
            payload["stream"] = True
        body = json.dumps(payload).encode()
        head = ("POST /v1/chat/completions HTTP/1.1\r\nHost: %s:%d\r\n"
                "Content-Type: application/json\r\nContent-Length: %d\r\n"
                "X-Test-Nonce: %s-%d\r\nConnection: close\r\n"
                % (args.vip, args.port, len(body), args.tag, seq))
        for h in (headers if headers is not None else args.header):
            head += h + "\r\n"
        s.settimeout(args.timeout)
        data = b""
        try:
            s.sendall(head.encode() + b"\r\n" + body)
            while len(data) < (4 << 20):
                chunk = s.recv(8192)
                if not chunk:
                    break
                if not data:
                    rec["t_first_byte"] = now_ms()
                rec["t_last_byte"] = now_ms()
                data += chunk
        except (ConnectionResetError, BrokenPipeError):
            rec["cls"] = "reset_after_connect"
            rec["bytes"] = len(data)
            stream_fields(rec, data)
            return
        except socket.timeout:
            rec["cls"] = "read_timeout"
            rec["bytes"] = len(data)
            stream_fields(rec, data)
            return
        rec["bytes"] = len(data)
        stream_fields(rec, data)
        if not data:
            rec["cls"] = "closed_no_response"
            return
        m = re.match(rb"HTTP/1\.[01] (\d{3})", data)
        if not m:
            rec["cls"] = "http_error"
            rec["detail"] = data[:60].decode("latin1")
            return
        rec["status"] = int(m.group(1))
        if rec["status"] == 200 and getattr(args, "stream", False) and not rec["done_seen"]:
            # A 200 status line and then a body that ended without its terminator.
            rec["cls"] = "closed_without_done"
        elif rec["status"] == 200:
            # Store failover probes use the fixed-length echo. A clean TCP
            # EOF after a partial body still fails that customer's request.
            body = data.split(b"\r\n\r\n", 1)
            length = re.search(rb"\r\nContent-Length:[ \t]*([0-9]+)[ \t]*(?:\r\n|$)", body[0], re.I)
            if getattr(args, "require_content_length", False) and (
                len(body) != 2 or not length or len(body[1]) != int(length.group(1)) or not body[1]
            ):
                rec["cls"] = "incomplete_body"
                return
            rec["cls"] = "ok"
            if len(body) == 2:
                rec["label"] = body[1][:48].split(b"|")[0].decode("latin1")
        else:
            # A response the gateway (or a backend) wrote: keep its code.
            rec["cls"] = "refusal"
            e = ERR_CODE.search(data)
            rec["error"] = e.group(1).decode() if e else ""
            ra = re.search(rb"\r\nRetry-After:\s*([^\r\n]+)", data, re.I)
            if ra:
                rec["retry_after"] = ra.group(1).decode()
    finally:
        rec["t_done"] = now_ms()
        s.close()
        with lock:
            out.write(json.dumps(rec) + "\n")


def request(args, seq, headers=None):
    """One classified request; returns its record."""
    box = []

    class Sink:
        def write(self, line):
            box.append(json.loads(line))

    one_request(args, seq, Sink(), threading.Lock(), headers)
    return box[0]


def cmd_retry(args):
    """One identity, retried at a fixed interval until it answers 200 (or the
    bound passes). Prints every attempt: what a client that keeps trying sees."""
    t_start = now_ms()
    attempts = []
    i = 0
    while True:
        r = request(args, i)
        r["latency_ms"] = r["t_done"] - r["t_send"]
        attempts.append(r)
        i += 1
        if r["cls"] == "ok" or args.max <= 0 or now_ms() - t_start > args.max * 1000:
            break
        time.sleep(args.interval)
    ok = attempts[-1]["cls"] == "ok"
    seqs = []
    for a in attempts:
        lab = a["cls"] if a["cls"] != "refusal" else "refusal:%s:%s" % (a.get("status"), a.get("error", ""))
        if seqs and seqs[-1][0] == lab:
            seqs[-1][1] += 1
        else:
            seqs.append([lab, 1])
    json.dump({"ok": ok, "attempts": len(attempts), "t_start": t_start,
               "first_200_after_ms": (attempts[-1]["t_send"] - t_start) if ok else None,
               "first_200_latency_ms": attempts[-1]["latency_ms"] if ok else None,
               "first_attempt": attempts[0], "last_attempt": attempts[-1], "sequence": seqs,
               "last_nonce": "%s-%d" % (args.tag, attempts[-1]["seq"])}, sys.stdout)
    sys.stdout.write("\n")


def cmd_debtwatch(args):
    """One identity asked at a fixed interval for --max seconds (or until the
    stop file appears). The oracle is the gateway's own advice: a refusal at
    time t that carries Retry-After r says no request of this identity can be
    admitted before t + r. A 200 sent earlier than the latest such horizon
    (less --margin) is an admission the gateway itself said could not happen.
    --horizon carries the horizon in from refusals seen before this call."""
    t_start = now_ms()
    horizon = args.horizon
    rows, leaks, seqs = [], [], []
    i = 0
    stop = args.out + ".stop" if args.out else ""
    while now_ms() - t_start < args.max * 1000 and not (stop and os.path.exists(stop)):
        r = request(args, i)
        lab = r["cls"] if r["cls"] != "refusal" else "refusal:%s:%s" % (r.get("status"), r.get("error", ""))
        row = {"seq": i, "t_send": r["t_send"], "lab": lab, "horizon_before": horizon,
               "retry_after": r.get("retry_after", ""), "nonce": "%s-%d" % (args.tag, i)}
        if r["cls"] == "ok" and horizon and r["t_send"] < horizon - args.margin * 1000:
            row["leak_ms_early"] = horizon - r["t_send"]
            leaks.append(row)
        if r["cls"] == "refusal" and r.get("status") == 429:
            try:
                horizon = max(horizon, r["t_send"] + int(float(r.get("retry_after", "0"))) * 1000)
            except ValueError:
                pass
        rows.append(row)
        if seqs and seqs[-1][0] == lab:
            seqs[-1][1] += 1
        else:
            seqs.append([lab, 1])
        i += 1
        time.sleep(args.interval)
    if args.out:
        with open(args.out, "w") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")
    after = [x for x in rows if x["t_send"] >= args.mark]
    json.dump({"attempts": len(rows), "sequence": seqs, "leaks": len(leaks),
               "first_leak": leaks[0] if leaks else None, "horizon": horizon,
               "refused_429_after_mark": sum(1 for x in after if x["lab"].startswith("refusal:429")),
               "ok_after_mark": sum(1 for x in after if x["lab"] == "ok"),
               "ok_nonces": [x["nonce"] for x in rows if x["lab"] == "ok"],
               "not_ok_nonces": [x["nonce"] for x in rows if x["lab"] != "ok"],
               "retry_after_seen": sorted(set(x["retry_after"] for x in rows if x["retry_after"]))},
              sys.stdout)
    sys.stdout.write("\n")


def cmd_burst(args):
    """N distinct credentials, each on its own new connection, released by one
    barrier. Prints the count per status and per error code and the spread of
    the send times."""
    hdrs = [ln.strip() for ln in open(args.headers_file) if ln.strip()]
    barrier = threading.Barrier(len(hdrs))
    out = [None] * len(hdrs)

    def run(i):
        try:
            barrier.wait(10)
        except threading.BrokenBarrierError:
            return
        out[i] = request(args, i, [hdrs[i]])

    ths = [threading.Thread(target=run, args=(i,)) for i in range(len(hdrs))]
    for t in ths:
        t.start()
    for t in ths:
        t.join(args.timeout + args.connect_timeout + 15)
    recs = [r for r in out if r]
    counts = {}
    for r in recs:
        lab = r["cls"] if r["cls"] != "refusal" else "refusal:%s:%s" % (r.get("status"), r.get("error", ""))
        counts[lab] = counts.get(lab, 0) + 1
    sends = sorted(r["t_send"] for r in recs)
    lat = sorted(r["t_done"] - r["t_send"] for r in recs if r["cls"] == "ok")
    res = {"n": len(hdrs), "answered": len(recs), "counts": counts,
           "send_spread_ms": (sends[-1] - sends[0]) if sends else None,
           "t_first_send": sends[0] if sends else None,
           "ok_latency_ms": {"median": lat[len(lat) // 2], "max": lat[-1]} if lat else None,
           "retry_after": sorted(set(r.get("retry_after", "") for r in recs if r.get("retry_after")))}
    if args.out:
        with open(args.out, "w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")
    json.dump(res, sys.stdout)
    sys.stdout.write("\n")


def cmd_conv(args):
    """One request per conversation id; prints {id: backend label or outcome}."""
    if args.ids_file:
        with open(args.ids_file, encoding="ascii") as source:
            ids = source.read().splitlines()
    else:
        ids = ["%s-%d" % (args.prefix, i) for i in range(args.n)]
    res = {}
    lock = threading.Lock()
    sem = threading.Semaphore(args.parallel)

    def run(i, cid):
        with sem:
            r = request(args, i, [args.conv_header + ": " + cid] + args.header)
        with lock:
            res[cid] = r.get("label") if r["cls"] == "ok" else (
                "!" + (r["cls"] if r["cls"] != "refusal" else "%s:%s" % (r.get("status"), r.get("error", ""))))

    ths = [threading.Thread(target=run, args=(i, c)) for i, c in enumerate(ids)]
    for t in ths:
        t.start()
    for t in ths:
        t.join(args.timeout + args.connect_timeout + 30)
    json.dump(res, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


def cmd_probe(args):
    lock = threading.Lock()
    threads = []
    with open(args.out, "a", buffering=1) as out:
        for i in ticker(1.0 / args.rate, args.out + ".stop", args.duration):
            t = threading.Thread(target=one_request, args=(args, i, out, lock), daemon=True)
            t.start()
            threads.append(t)
            if len(threads) > 2000:
                threads = [x for x in threads if x.is_alive()]
        for t in threads:
            t.join(args.timeout + args.connect_timeout + 1)


# ---------------------------------------------------------------- node
def vip_hex(vip):
    return "%08X" % struct.unpack("<I", socket.inet_aton(vip))[0]


def node_sample(vip, vhex):
    rec = {"t": now_ms()}
    # Role, from the node's own REST API.
    try:
        c = socket.create_connection(("127.0.0.1", 11111), timeout=0.2)
        c.settimeout(0.2)
        c.sendall(b"GET /netlox/v1/config/cistate/all HTTP/1.0\r\n\r\n")
        buf = b""
        while True:
            d = c.recv(4096)
            if not d:
                break
            buf += d
        c.close()
        m = re.search(rb'"state"\s*:\s*"([A-Z_]+)"', buf)
        rec["role"] = m.group(1).decode() if m else "UNPARSED"
    except OSError:
        rec["role"] = "UNREACHABLE"
    # The VIP as a local address of this namespace.
    vip_local = 0
    try:
        with open("/proc/net/fib_trie") as f:
            lines = f.read().split("\n")
        for i, ln in enumerate(lines[:-1]):
            if ln.strip().endswith("-- " + vip) and "host LOCAL" in lines[i + 1]:
                vip_local = 1
                break
    except OSError:
        vip_local = -1
    rec["vip"] = vip_local
    # Listening sockets bound to the VIP.
    ports = []
    try:
        with open("/proc/net/tcp") as f:
            next(f)
            for ln in f:
                p = ln.split()
                if p[3] == "0A" and p[1].startswith(vhex + ":"):
                    ports.append(int(p[1].split(":")[1], 16))
    except OSError:
        ports = [-1]
    rec["listen"] = sorted(ports)
    # Is a gateway process alive in this namespace's view of the host?
    return rec


def cmd_node(args):
    vhex = vip_hex(args.vip)
    with open(args.out, "a", buffering=1) as out:
        for _ in ticker(args.interval, args.out + ".stop"):
            rec = node_sample(args.vip, vhex)
            if args.pidfile and os.path.exists(args.pidfile):
                try:
                    pid = open(args.pidfile).read().strip()
                    rec["proc"] = 1 if pid and os.path.exists("/proc/%s" % pid) else 0
                except OSError:
                    pass
            out.write(json.dumps(rec) + "\n")


# ---------------------------------------------------------------- neigh
def cmd_neigh(args):
    with open(args.out, "a", buffering=1) as out:
        for _ in ticker(args.interval, args.out + ".stop"):
            t = now_ms()
            try:
                o = subprocess.run(["ip", "neigh", "show", args.vip], capture_output=True,
                                   text=True, timeout=1).stdout.split()
            except (OSError, subprocess.TimeoutExpired):
                o = []
            mac = o[o.index("lladdr") + 1] if "lladdr" in o else ""
            out.write(json.dumps({"t": t, "mac": mac, "state": o[-1] if o else "NONE"}) + "\n")


# ---------------------------------------------------------------- arp
def cmd_arp(args):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    s.bind((args.iface, 0x0806))
    s.settimeout(0.05)
    mymac = s.getsockname()[4]
    vip = socket.inet_aton(args.vip)
    src = socket.inet_aton(args.src)
    req = (b"\xff" * 6 + mymac + b"\x08\x06" +
           struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mymac + src + b"\x00" * 6 + vip)
    stop = args.out + ".stop"
    done = threading.Event()

    def rx(out):
        while not done.is_set():
            try:
                f = s.recv(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(f) < 42 or f[12:14] != b"\x08\x06":
                continue
            op = struct.unpack("!H", f[20:22])[0]
            sha, spa, tpa = f[22:28], f[28:32], f[38:42]
            if spa != vip or sha == mymac:
                continue
            out.write(json.dumps({
                "t": now_ms(), "op": "reply" if op == 2 else "request",
                "mac": ":".join("%02x" % b for b in sha),
                "eth_dst": ":".join("%02x" % b for b in f[0:6]),
                "gratuitous": 1 if tpa == vip else 0}) + "\n")

    with open(args.out, "a", buffering=1) as out:
        t = threading.Thread(target=rx, args=(out,), daemon=True)
        t.start()
        for _ in ticker(args.interval, stop):
            try:
                s.send(req)
            except OSError:
                pass
        done.set()
        t.join(1)


# ---------------------------------------------------------------- timeline
def load(path):
    rows = []
    try:
        with open(path) as f:
            for ln in f:
                try:
                    rows.append(json.loads(ln))
                except ValueError:
                    pass
    except OSError:
        pass
    return rows


def first(rows, t0, pred, key="t"):
    for r in rows:
        if r[key] >= t0 and pred(r):
            return r[key]
    return None


def cmd_timeline(args):
    d = args.dir
    t0 = args.t0
    surv = load(os.path.join(d, "node-%s.jsonl" % args.survivor))
    dead = load(os.path.join(d, "node-%s.jsonl" % args.dead))
    probe = sorted(load(os.path.join(d, "probe.jsonl")), key=lambda r: r["t_send"])
    neigh = load(os.path.join(d, "neigh.jsonl"))
    arp = load(os.path.join(d, "arp.jsonl"))
    port = args.port
    tl = {"t0": t0, "mode": args.mode, "dead": args.dead, "survivor": args.survivor}

    def rel(t):
        return None if t is None else t - t0

    t_master = first(surv, t0, lambda r: r["role"] == "MASTER")
    t_vip = first(surv, t0, lambda r: r["vip"] == 1)
    t_listen = first(surv, t0, lambda r: port in r["listen"])
    t_listen_all = first(surv, t0, lambda r: len(r["listen"]) >= args.nports)
    tl["survivor_role_before"] = next((r["role"] for r in reversed(surv) if r["t"] < t0), None)
    tl["survivor_master_ms"] = rel(t_master)
    tl["survivor_vip_ms"] = rel(t_vip)
    tl["survivor_listen_ms"] = rel(t_listen)
    tl["survivor_listen_all_ms"] = rel(t_listen_all)
    # What the dead node's namespace still showed (a process crash keeps it).
    tl["dead_vip_last_ms"] = rel(next((r["t"] for r in reversed(dead) if r["vip"] == 1), None))
    tl["dead_listen_last_ms"] = rel(next((r["t"] for r in reversed(dead) if port in r["listen"]), None))
    tl["dead_role_unreachable_ms"] = rel(first(dead, t0, lambda r: r["role"] == "UNREACHABLE"))
    tl["dead_proc_gone_ms"] = rel(first(dead, t0, lambda r: r.get("proc") == 0))
    # Did two nodes report MASTER in overlapping samples?
    dual = 0
    j = 0
    for r in surv:
        if r["role"] != "MASTER":
            continue
        while j + 1 < len(dead) and dead[j + 1]["t"] <= r["t"]:
            j += 1
        if dead and abs(dead[j]["t"] - r["t"]) < 100 and dead[j]["role"] == "MASTER":
            dual += 1
    tl["dual_master_samples"] = dual

    # The client's view.
    after = [r for r in probe if r["t_send"] >= t0]
    before = [r for r in probe if t0 - 3000 <= r["t_send"] < t0]
    tl["probe_before_3s"] = {"n": len(before), "ok": sum(1 for r in before if r["cls"] == "ok")}
    t_first_fail = next((r["t_send"] for r in after if r["cls"] != "ok"), None)
    t_last_fail = next((r["t_send"] for r in reversed(after) if r["cls"] != "ok"), None)
    t_first_ok = None
    if t_first_fail is not None:
        t_first_ok = next((r["t_send"] for r in after if r["t_send"] > t_first_fail and r["cls"] == "ok"), None)
    t_stable_ok = None
    if t_last_fail is not None:
        t_stable_ok = next((r["t_send"] for r in after if r["t_send"] > t_last_fail and r["cls"] == "ok"), None)
    tl["first_non200_ms"] = rel(t_first_fail)
    tl["first_200_after_fault_ms"] = rel(t_first_ok)
    tl["last_non200_ms"] = rel(t_last_fail)
    tl["stable_200_from_ms"] = rel(t_stable_ok)
    tl["probe_after"] = {"n": len(after), "ok": sum(1 for r in after if r["cls"] == "ok")}

    def label(r):
        if r["cls"] == "refusal":
            return "refusal:%s:%s" % (r.get("status"), r.get("error", ""))
        return r["cls"]

    def hist(lo, hi):
        h = {}
        for r in after:
            if (lo is None or r["t_send"] >= lo) and (hi is None or r["t_send"] < hi):
                h[label(r)] = h.get(label(r), 0) + 1
        return h

    end = t_stable_ok if t_stable_ok is not None else (after[-1]["t_send"] + 1 if after else t0)
    tl["histogram_fault_to_stable"] = hist(t0, end)
    marks = [("fault", t0), ("master", t_master), ("vip", t_vip), ("listen", t_listen), ("stable", end)]
    marks = [(n, t) for n, t in marks if t is not None]
    marks.sort(key=lambda x: x[1])
    tl["histogram_by_phase"] = {}
    for (n1, a), (n2, b) in zip(marks, marks[1:]):
        if b > a:
            tl["histogram_by_phase"]["%s..%s" % (n1, n2)] = hist(a, b)
    # H1: the VIP is on the new master and nothing listens on it.
    if t_vip is not None and t_listen is not None:
        w = hist(t_vip, t_listen) if t_listen > t_vip else {}
        tl["vip_without_listener_ms"] = t_listen - t_vip
        tl["vip_without_listener_probe"] = w
    else:
        tl["vip_without_listener_ms"] = None
    # Neighbour entry and ARP claims.
    if args.survivor_mac:
        tl["client_neigh_to_survivor_ms"] = rel(first(neigh, t0, lambda r: r["mac"] == args.survivor_mac))
        tl["first_garp_from_survivor_ms"] = rel(first(
            arp, t0, lambda r: r["mac"] == args.survivor_mac and r["gratuitous"] == 1))
        tl["first_arp_reply_from_survivor_ms"] = rel(first(
            arp, t0, lambda r: r["mac"] == args.survivor_mac and r["op"] == "reply" and r["gratuitous"] == 0))
    if args.dead_mac:
        tl["last_arp_claim_from_dead_ms"] = rel(next(
            (r["t"] for r in reversed(arp) if r["mac"] == args.dead_mac and r["t"] >= t0), None))
        both = {}
        for r in arp:
            if r["t"] >= t0 and r["op"] == "reply":
                both.setdefault(r["t"] // 1000, set()).add(r["mac"])
        tl["seconds_with_two_arp_answerers"] = sum(1 for v in both.values() if len(v) > 1)
    # BFD on the wire (text capture, one line per packet: epoch src > dst ...).
    bfd = []
    try:
        with open(os.path.join(d, "bfd.txt")) as f:
            for ln in f:
                m = re.match(r"(\d+\.\d+) IP (\d+\.\d+\.\d+\.\d+)\.\d+ > (\d+\.\d+\.\d+\.\d+)\.3784", ln)
                if m:
                    bfd.append((int(float(m.group(1)) * 1000), m.group(2), ln))
    except OSError:
        pass
    for who, ip in (("dead", args.dead_ip), ("survivor", args.survivor_ip)):
        ts = [t for t, src, _ in bfd if src == ip and t < t0]
        gaps = sorted(b - a for a, b in zip(ts, ts[1:]))
        if gaps:
            tl["bfd_tx_spacing_ms_%s" % who] = {
                "n": len(gaps), "median": gaps[len(gaps) // 2],
                "p05": gaps[len(gaps) // 20], "p95": gaps[(len(gaps) * 19) // 20]}
    # The last BFD packet the faulted node sent before the survivor took the
    # role (a node restarted in place sends again later; that is not this).
    lim = t_master if t_master is not None else t0 + 60000
    last_dead = [t for t, src, _ in bfd if src == args.dead_ip and t <= lim]
    if last_dead:
        tl["last_bfd_from_dead_ms"] = rel(last_dead[-1])
        if t_master is not None:
            tl["bfd_detection_ms"] = t_master - last_dead[-1]
    # What the faulted node said on the wire after t0 (a clean stop may send
    # AdminDown or Down before it goes quiet).
    states = []
    for t, src, ln in bfd:
        if src == args.dead_ip and t0 <= t <= t0 + 15000:
            m = re.search(r"State ([A-Za-z]+)", ln)
            st = m.group(1) if m else "?"
            if not states or states[-1][0] != st:
                states.append([st, t - t0, 1])
            else:
                states[-1][2] += 1
    tl["bfd_states_from_dead_after_t0"] = states
    json.dump(tl, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--vip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--header", action="append", default=[])
    p.add_argument("--rate", type=float, default=20.0)
    p.add_argument("--connect-timeout", type=float, default=0.3)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--duration", type=float, default=None)
    p.add_argument("--tag", default="probe")
    p.add_argument("--out", required=True)
    p.add_argument("--require-content-length", action="store_true")
    p.set_defaults(fn=cmd_probe)
    for name, fn in (("retry", cmd_retry), ("burst", cmd_burst), ("debtwatch", cmd_debtwatch)):
        p = sub.add_parser(name)
        p.add_argument("--vip", required=True)
        p.add_argument("--port", type=int, required=True)
        p.add_argument("--model", required=True)
        p.add_argument("--header", action="append", default=[])
        p.add_argument("--headers-file", default="")
        p.add_argument("--connect-timeout", type=float, default=0.3)
        p.add_argument("--timeout", type=float, default=5.0)
        p.add_argument("--interval", type=float, default=0.2)
        p.add_argument("--max", type=float, default=60.0)
        p.add_argument("--tag", default=name)
        p.add_argument("--out", default="")
        p.add_argument("--stream", action="store_true")
        p.add_argument("--horizon", type=int, default=0)
        p.add_argument("--mark", type=int, default=0)
        p.add_argument("--margin", type=float, default=2.0)
        p.set_defaults(fn=fn)
    p = sub.add_parser("conv")
    p.add_argument("--vip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--header", action="append", default=[])
    p.add_argument("--conv-header", default="X-Conversation-Id")
    ids = p.add_mutually_exclusive_group(required=True)
    ids.add_argument("--prefix")
    ids.add_argument("--ids-file")
    p.add_argument("--require-content-length", action="store_true")
    p.add_argument("--n", type=int, default=100)
    p.add_argument("--parallel", type=int, default=8)
    p.add_argument("--connect-timeout", type=float, default=0.5)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--tag", default="conv")
    p.set_defaults(fn=cmd_conv)
    p = sub.add_parser("node")
    p.add_argument("--vip", required=True)
    p.add_argument("--interval", type=float, default=0.025)
    p.add_argument("--pidfile", default="")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_node)
    p = sub.add_parser("neigh")
    p.add_argument("--vip", required=True)
    p.add_argument("--interval", type=float, default=0.05)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_neigh)
    p = sub.add_parser("arp")
    p.add_argument("--vip", required=True)
    p.add_argument("--src", required=True)
    p.add_argument("--iface", required=True)
    p.add_argument("--interval", type=float, default=0.1)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_arp)
    p = sub.add_parser("timeline")
    p.add_argument("--dir", required=True)
    p.add_argument("--t0", type=int, required=True)
    p.add_argument("--mode", default="")
    p.add_argument("--dead", required=True)
    p.add_argument("--survivor", required=True)
    p.add_argument("--dead-ip", default="")
    p.add_argument("--survivor-ip", default="")
    p.add_argument("--dead-mac", default="")
    p.add_argument("--survivor-mac", default="")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--nports", type=int, default=4)
    p.set_defaults(fn=cmd_timeline)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
