#!/usr/bin/env python3
"""h2_mock.py - an h2c (HTTP/2, prior knowledge) chat backend for radix-h2.

One process per endpoint container. Every POST stream is answered with
{"ep": <name>, "id": <x-request-id>} as JSON, or as SSE when the request
carries x-test-stream: 1. Each answer runs in its own thread, so several
held streams can be in flight on one connection. Request bodies are read
and discarded; nothing is recorded or printed.

Usage: h2_mock.py <endpoint-name> <h2c-port> <admin-port>

Control over HTTP/1.1 on <admin-port> (GET):
  /health                      200
  /admin/status/<code>/<n>     the next <n> answers carry <code>
  /admin/delay/<ms>/<n>        the next <n> answers wait <ms> first
  /admin/reset                 clear both
"""
import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import h2.config
import h2.connection
import h2.events
import h2.exceptions

NAME, PORT, ADMIN = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
lock = threading.Lock()
arms = {"status": [], "delay": []}


def take():
    with lock:
        st = arms["status"].pop(0) if arms["status"] else 200
        d = arms["delay"].pop(0) if arms["delay"] else 0
    return st, d


class Conn:
    def __init__(self, sock):
        self.sock = sock
        self.c = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
        self.wl = threading.Lock()
        self.heads = {}

    def flush(self):
        data = self.c.data_to_send()
        if data:
            self.sock.sendall(data)

    def answer(self, sid, hdrs):
        st, d = take()
        if d:
            time.sleep(d / 1000.0)
        doc = json.dumps({"ep": NAME, "id": hdrs.get("x-request-id", "-")})
        if hdrs.get("x-test-stream") == "1":
            body, ctype = ("data: %s\n\ndata: [DONE]\n\n" % doc).encode(), "text/event-stream"
        else:
            body, ctype = doc.encode(), "application/json"
        with self.wl:
            try:
                self.c.send_headers(sid, [(":status", str(st)), ("content-type", ctype),
                                          ("content-length", str(len(body)))])
                self.c.send_data(sid, body, end_stream=True)
                self.flush()
            except (h2.exceptions.StreamClosedError, h2.exceptions.ProtocolError, OSError):
                pass

    def run(self):
        with self.wl:
            self.c.initiate_connection()
            self.flush()
        while True:
            try:
                data = self.sock.recv(65536)
            except OSError:
                break
            if not data:
                break
            with self.wl:
                try:
                    events = self.c.receive_data(data)
                except h2.exceptions.ProtocolError:
                    break
                for ev in events:
                    if isinstance(ev, h2.events.RequestReceived):
                        self.heads[ev.stream_id] = dict(ev.headers)
                    elif isinstance(ev, h2.events.DataReceived):
                        self.c.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                    elif isinstance(ev, h2.events.StreamEnded):
                        hdrs = self.heads.pop(ev.stream_id, {})
                        threading.Thread(target=self.answer, args=(ev.stream_id, hdrs),
                                         daemon=True).start()
                    elif isinstance(ev, h2.events.StreamReset):
                        self.heads.pop(ev.stream_id, None)
                self.flush()
        self.sock.close()


def serve():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(64)
    while True:
        c, _ = s.accept()
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=Conn(c).run, daemon=True).start()


class Admin(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        p = self.path.strip("/").split("/")
        if p == ["health"]:
            pass
        elif len(p) == 4 and p[:2] == ["admin", "status"]:
            with lock:
                arms["status"] += [int(p[2])] * int(p[3])
        elif len(p) == 4 and p[:2] == ["admin", "delay"]:
            with lock:
                arms["delay"] += [int(p[2])] * int(p[3])
        elif p == ["admin", "reset"]:
            with lock:
                arms.update(status=[], delay=[])
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")


threading.Thread(target=serve, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", ADMIN), Admin).serve_forever()
