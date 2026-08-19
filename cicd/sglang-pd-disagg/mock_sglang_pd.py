#!/usr/bin/env python3
"""
Mock SGLang P/D server for the sglang-pd-disagg CICD scenario.

Simulates SGLang prefill/decode disaggregation semantics faithfully enough to
pin the gateway's CONCURRENT dual-dispatch contract:

- The gateway injects a bootstrap triple (bootstrap_host / bootstrap_port /
  bootstrap_room) into the SAME request body and sends it to the prefill AND
  decode servers SIMULTANEOUSLY.
- The prefill server runs a real bootstrap listener on --bootstrap-port. Its
  /v1/chat/completions handler BLOCKS until a decode /join with the same room
  arrives at that listener, then responds. A proxy that waits for the prefill
  response before contacting decode therefore times out here — the scenario
  fails a sequential implementation BY CONSTRUCTION.
- The decode server joins the room at bootstrap_host:bootstrap_port (its copy
  of the triple — the prefill side verifies equality), then polls the
  bootstrap listener until the prefill handler marks the "KV transfer" done,
  and only then streams/answers. So decode produces ZERO client-visible bytes
  when prefill fails first — exactly the window the gateway's failure
  coupling and pair retry are specified against.

Fault knobs (admin server, loopback :9100, one-shot each):
  POST /admin/fail-next   -> next chat request answers HTTP 500 immediately
  POST /admin/die-next    -> next chat request closes the TCP connection
                             without any response (transport death)
  POST /admin/reject-next -> next chat request answers HTTP 400 immediately
                             (origin-computed CLIENT error, e.g. a prompt
                             over the context window — the gateway must
                             relay this body verbatim, not mask it as 502)
  GET  /admin/status      -> armed flags + request count

Log grammar (validation.sh greps these; keep stable):
  BOOTSTRAP reqid=<id> room=<room> host=<h> port=<p>
  RENDEZVOUS-OK room=<room>
  RENDEZVOUS-TIMEOUT room=<room>
  PREFILL-CONN-CLOSED room=<room> elapsed=<s>
  DECODE-CONN-CLOSED room=<room> elapsed=<s>
  DECODE-SERVED room=<room> mode=<sse|json>
  INJECT-500 reqid=<id> room=<room>
  INJECT-DIE reqid=<id> room=<room>
  INJECT-400 reqid=<id> room=<room>
  errors: TRIPLE-MISSING / PORT-MISMATCH / HOST-MISMATCH / ROOM-RANGE-ERROR /
          TRIPLE-MISMATCH / JOIN-FAILED

Usage:
    python3 mock_sglang_pd.py --role prefill --port 8100 --bootstrap-port 9998 \
        --expect-host 31.31.31.1 --ep-idx 1
    python3 mock_sglang_pd.py --role decode --port 8100 --ep-idx 3
"""

import argparse
import json
import select
import socket
import threading
import time
import urllib.request
import urllib.parse
from http.server import ThreadingHTTPServer, HTTPServer, BaseHTTPRequestHandler

MODEL_NAME = "Qwen/Qwen3-0.6B"
ROOM_MAX = (1 << 63) - 1

_args = None
_request_count = 0
_fail_next = False
_die_next = False
_reject_next = False
_knob_lock = threading.Lock()

# Prefill-side rendezvous state: room -> {"join": <decode triple dict>|None,
# "done": bool}. Guarded by _rooms_cond; joins may arrive BEFORE the prefill
# request (concurrent dispatch has no ordering guarantee), so joins are
# buffered here regardless of arrival order.
_rooms = {}
_rooms_cond = threading.Condition()


def _log(msg):
    print(f"[{_args.role}] {msg}", flush=True)


class MockSGLangHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *largs):
        print(f"[{_args.role}] {fmt % largs}", flush=True)

    # ---- plumbing -------------------------------------------------------

    def _send_json(self, status, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        req_id = self.headers.get("X-Request-Id", "")
        if req_id:
            self.send_header("X-Request-Id", req_id)
        if _args.role == "prefill":
            self.send_header("X-SG-Prefill-Ep", str(_args.ep_idx))
        else:
            self.send_header("X-SG-Decode-Ep", str(_args.ep_idx))
        self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def _conn_closed(self):
        """Peer-EOF probe while a handler is parked in a rendezvous wait.
        The request body is fully consumed before any wait starts, so a
        readable socket means EOF (or an error) — the gateway tore this leg
        down (pair abort / drain close). Detecting it here is what lets the
        mock assert 'my connection was closed within N seconds'."""
        try:
            r, _, _ = select.select([self.connection], [], [], 0)
            if not r:
                return False
            return self.connection.recv(1, socket.MSG_PEEK) == b""
        except (BlockingIOError, InterruptedError):
            return False
        except OSError:
            return True

    # ---- HTTP entry points ---------------------------------------------

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "role": _args.role})
        elif self.path == "/v1/models":
            self._send_json(200, {"object": "list", "data": [{
                "id": MODEL_NAME, "object": "model",
                "created": int(time.time()), "owned_by": "mock-sglang"}]})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        global _request_count
        content_len = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_len).decode("utf-8") if content_len else "{}"
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON"})
            return
        with _knob_lock:
            _request_count += 1
        if self.path in ("/v1/chat/completions", "/v1/completions"):
            self._handle_chat(req)
        else:
            self._send_json(404, {"error": "Not found"})

    # ---- the P/D contract ----------------------------------------------

    def _extract_triple(self, req, req_id):
        """Validate + log the injected bootstrap triple. Returns the triple
        dict, or None after answering 500 (config-side defect)."""
        host = req.get("bootstrap_host")
        port = req.get("bootstrap_port")
        room = req.get("bootstrap_room")
        if host is None or port is None or room is None:
            _log(f"TRIPLE-MISSING reqid={req_id} body_keys={sorted(req.keys())}")
            self._send_json(500, {"error": "bootstrap triple missing"})
            return None
        if not isinstance(room, int) or room < 0 or room > ROOM_MAX:
            _log(f"ROOM-RANGE-ERROR reqid={req_id} room={room!r}")
            self._send_json(500, {"error": "bootstrap_room out of range"})
            return None
        _log(f"BOOTSTRAP reqid={req_id} room={room} host={host} port={port}")
        if _args.role == "prefill":
            if port != _args.bootstrap_port:
                _log(f"PORT-MISMATCH reqid={req_id} got={port} want={_args.bootstrap_port}")
                self._send_json(500, {"error": "bootstrap_port mismatch"})
                return None
            if _args.expect_host and host != _args.expect_host:
                _log(f"HOST-MISMATCH reqid={req_id} got={host} want={_args.expect_host}")
                self._send_json(500, {"error": "bootstrap_host mismatch"})
                return None
        return {"bootstrap_host": host, "bootstrap_port": port,
                "bootstrap_room": room}

    def _consume_knobs(self, req_id, room):
        """One-shot fault injection. Returns 'fail'|'die'|'reject'|None."""
        global _fail_next, _die_next, _reject_next
        with _knob_lock:
            if _fail_next:
                _fail_next = False
                _log(f"INJECT-500 reqid={req_id} room={room}")
                return "fail"
            if _die_next:
                _die_next = False
                _log(f"INJECT-DIE reqid={req_id} room={room}")
                return "die"
            if _reject_next:
                _reject_next = False
                _log(f"INJECT-400 reqid={req_id} room={room}")
                return "reject"
        return None

    def _handle_chat(self, req):
        req_id = self.headers.get("X-Request-Id", "-")
        triple = self._extract_triple(req, req_id)
        if triple is None:
            return
        room = triple["bootstrap_room"]

        knob = self._consume_knobs(req_id, room)
        if knob == "fail":
            self._send_json(500, {"error": "injected_fault"})
            return
        if knob == "reject":
            # Shaped like a real engine validation error (over-context-window
            # 400) — the distinctive marker is what validation greps for on
            # the CLIENT side to prove verbatim relay.
            self._send_json(400, {"object": "error",
                                  "message": "mock_client_reject: prompt over context window",
                                  "type": "BadRequestError"})
            return
        if knob == "die":
            # Transport death: no response bytes at all.
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.close_connection = True
            return

        if _args.role == "prefill":
            self._prefill_rendezvous(req_id, triple)
        else:
            self._decode_rendezvous(req_id, req, triple)

    def _prefill_rendezvous(self, req_id, triple):
        """Block until decode joins the room (this is the load-bearing wait:
        a sequential proxy never gets here past the timeout), verify the
        decode-side triple copy, mark the 'KV transfer' done, respond."""
        room = triple["bootstrap_room"]
        deadline = time.monotonic() + _args.rendezvous_timeout
        start = time.monotonic()
        join = None
        with _rooms_cond:
            _rooms.setdefault(room, {"join": None, "done": False})
            while True:
                join = _rooms[room]["join"]
                if join is not None:
                    break
                if time.monotonic() >= deadline:
                    break
                _rooms_cond.wait(timeout=0.2)
                # EOF probe must run unlocked-agnostic; it only touches our
                # own connection.
                if self._conn_closed():
                    _log(f"PREFILL-CONN-CLOSED room={room} "
                         f"elapsed={time.monotonic() - start:.1f}")
                    self.close_connection = True
                    return
        if join is None:
            _log(f"RENDEZVOUS-TIMEOUT room={room}")
            self._send_json(500, {"error": "rendezvous timeout",
                                  "detail": "decode never joined the room"})
            return
        if join != triple:
            _log(f"TRIPLE-MISMATCH room={room} prefill={triple} decode={join}")
            self._send_json(500, {"error": "triple mismatch"})
            return
        with _rooms_cond:
            _rooms[room]["done"] = True
            _rooms_cond.notify_all()
        _log(f"RENDEZVOUS-OK room={room}")
        self._send_json(200, {
            "id": f"chatcmpl-prefill-{room}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": MODEL_NAME,
            "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": ""},
                         "finish_reason": "length"}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 1,
                      "total_tokens": 13},
        })

    def _decode_rendezvous(self, req_id, req, triple):
        """Join the room at the prefill's bootstrap server with OUR copy of
        the triple, then poll for transfer-done before producing any client
        byte (SGLang decode semantics: nothing streams until KV arrived)."""
        room = triple["bootstrap_room"]
        base = f"http://{triple['bootstrap_host']}:{triple['bootstrap_port']}"
        joined = False
        for _ in range(3):
            try:
                body = json.dumps(triple).encode()
                r = urllib.request.urlopen(
                    urllib.request.Request(f"{base}/join", data=body,
                                           headers={"Content-Type": "application/json"}),
                    timeout=3)
                r.read()
                joined = True
                break
            except Exception as exc:
                _log(f"join attempt failed room={room}: {exc}")
                time.sleep(0.3)
        if not joined:
            _log(f"JOIN-FAILED room={room} target={base}")
            self._send_json(500, {"error": "bootstrap join failed"})
            return

        deadline = time.monotonic() + _args.rendezvous_timeout
        start = time.monotonic()
        done = False
        while time.monotonic() < deadline:
            if self._conn_closed():
                _log(f"DECODE-CONN-CLOSED room={room} "
                     f"elapsed={time.monotonic() - start:.1f}")
                self.close_connection = True
                return
            try:
                r = urllib.request.urlopen(f"{base}/status?room={room}", timeout=3)
                st = json.loads(r.read().decode())
                if st.get("state") == "done":
                    done = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not done:
            _log(f"RENDEZVOUS-TIMEOUT room={room}")
            self._send_json(500, {"error": "kv transfer never completed"})
            return

        if req.get("stream", False):
            _log(f"DECODE-SERVED room={room} mode=sse")
            self._send_sse(room)
        else:
            _log(f"DECODE-SERVED room={room} mode=json")
            self._send_json(200, {
                "id": f"chatcmpl-decode-{room}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": MODEL_NAME,
                "choices": [{"index": 0,
                             "message": {"role": "assistant",
                                         "content": "Hello from mock SGLang decode."},
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 6,
                          "total_tokens": 18},
            })

    def _send_sse(self, room):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-SG-Decode-Ep", str(_args.ep_idx))
        self.close_connection = True
        self.end_headers()
        tokens = ["Hello", " from", " mock", " SGLang", " decode", "."]
        for i, tok in enumerate(tokens):
            chunk = {
                "id": f"chatcmpl-decode-{room}",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": MODEL_NAME,
                "choices": [{"index": 0,
                             "delta": ({"role": "assistant", "content": tok}
                                       if i == 0 else {"content": tok}),
                             "finish_reason": None}],
            }
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.05)
        final = {
            "id": f"chatcmpl-decode-{room}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": MODEL_NAME,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }
        self.wfile.write(f"data: {json.dumps(final)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


class BootstrapHandler(BaseHTTPRequestHandler):
    """The prefill-side disaggregation bootstrap server (the thing SGLang
    runs on --disaggregation-bootstrap-port). Records decode joins and
    exposes the transfer state decode polls before producing output."""

    def log_message(self, fmt, *largs):
        pass

    def do_POST(self):
        if self.path != "/join":
            self.send_response(404)
            self.end_headers()
            return
        content_len = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_len).decode("utf-8") if content_len else "{}"
        try:
            join = json.loads(raw)
            room = int(join["bootstrap_room"])
        except Exception:
            self.send_response(400)
            self.end_headers()
            return
        with _rooms_cond:
            _rooms.setdefault(room, {"join": None, "done": False})
            _rooms[room]["join"] = join
            _rooms_cond.notify_all()
        _log(f"bootstrap: decode joined room={room}")
        data = json.dumps({"status": "joined"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        if q.path != "/status":
            self.send_response(404)
            self.end_headers()
            return
        try:
            room = int(urllib.parse.parse_qs(q.query)["room"][0])
        except Exception:
            self.send_response(400)
            self.end_headers()
            return
        with _rooms_cond:
            ent = _rooms.get(room)
            state = "done" if (ent and ent["done"]) else "waiting"
        data = json.dumps({"state": state}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class AdminHandler(BaseHTTPRequestHandler):
    """Loopback-only fault-injection knobs (mock_vllm.py admin idiom)."""

    def log_message(self, fmt, *largs):
        pass

    def _reply(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        global _fail_next, _die_next, _reject_next
        if self.path == "/admin/fail-next":
            with _knob_lock:
                _fail_next = True
            _log("admin: fail-next ARMED")
            self._reply({"fail_next": True})
        elif self.path == "/admin/die-next":
            with _knob_lock:
                _die_next = True
            _log("admin: die-next ARMED")
            self._reply({"die_next": True})
        elif self.path == "/admin/reject-next":
            with _knob_lock:
                _reject_next = True
            _log("admin: reject-next ARMED")
            self._reply({"reject_next": True})
        elif self.path == "/admin/reset":
            with _knob_lock:
                _fail_next = False
                _die_next = False
                _reject_next = False
            _log("admin: knobs RESET")
            self._reply({"fail_next": False, "die_next": False,
                         "reject_next": False})
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/admin/status":
            with _knob_lock:
                self._reply({"role": _args.role, "request_count": _request_count,
                             "fail_next": _fail_next, "die_next": _die_next})
        else:
            self.send_response(404)
            self.end_headers()


def main():
    global _args
    parser = argparse.ArgumentParser(description="Mock SGLang P/D server")
    parser.add_argument("--role", choices=["prefill", "decode"], required=True)
    parser.add_argument("--port", type=int, default=8100)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--bootstrap-port", type=int, default=8998,
                        help="prefill only: disaggregation bootstrap listener port")
    parser.add_argument("--expect-host", default="",
                        help="prefill only: assert the injected bootstrap_host "
                             "equals this address (this EP's own IP)")
    parser.add_argument("--ep-idx", type=int, default=0)
    parser.add_argument("--rendezvous-timeout", type=float, default=20.0)
    parser.add_argument("--admin-port", type=int, default=9100)
    _args = parser.parse_args()

    threading.Thread(
        target=lambda: HTTPServer(("127.0.0.1", _args.admin_port), AdminHandler).serve_forever(),
        daemon=True).start()

    if _args.role == "prefill":
        threading.Thread(
            target=lambda: ThreadingHTTPServer(
                ("0.0.0.0", _args.bootstrap_port), BootstrapHandler).serve_forever(),
            daemon=True).start()
        print(f"[prefill] bootstrap server on 0.0.0.0:{_args.bootstrap_port}",
              flush=True)

    # ThreadingHTTPServer is REQUIRED for the main server: a prefill chat
    # handler parks for up to --rendezvous-timeout, and the gateway's health
    # probes keep hitting /health meanwhile — a single-threaded server would
    # queue the probes and get the EP marked down mid-request.
    server = ThreadingHTTPServer((_args.host, _args.port), MockSGLangHandler)
    print(f"Mock SGLang server: role={_args.role} addr={_args.host}:{_args.port} "
          f"ep_idx={_args.ep_idx} admin=127.0.0.1:{_args.admin_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
