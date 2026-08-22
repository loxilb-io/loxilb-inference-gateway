#!/usr/bin/env python3
"""
Mock llama.cpp server (llama-server) for plain-LB CICD testing.

Simulates the OpenAI-compatible surface of a CONVERGED single-model
llama-server with the quirks that matter to the gateway (no GPU required),
each pinned live against b10524 on a 5-EP fleet:

- Unknown JSON request fields are SILENTLY IGNORED (the schema pulls known
  fields only) — the vLLM-tolerant posture, opposite of TRT-LLM's
  extra="forbid". A leaked kv_transfer_params or bootstrap triple must
  serve 200 here.
- MALFORMED request JSON answers HTTP 500 (with the OAI error object), not
  400 — the live-pinned taxonomy quirk that matters to origin-5xx
  dashboards.
- SSE: chat.completion.chunk frames; bare ":" comment frames as keep-alive
  pings whenever generation stalls longer than --sse-ping-interval; final
  usage chunk only under stream_options.include_usage; "data: [DONE]"
  terminator.
- usage.prompt_tokens_details.cached_tokens computed from a PER-PROCESS
  prefix store (longest common prefix vs previously served prompts) —
  models the engine's per-slot/host-RAM contiguous-prefix cache: repeats
  land warm only on the EP that served the family before. The receipts
  oracle for the CHWBL affinity legs.
- /props (total_slots/model_path/build_info/is_sleeping), /slots
  (?fail_on_no_slot=1 -> 503 when exhausted), /metrics (real Prometheus
  text, llamacpp: prefix incl. prompt_tokens_cached_total), /health with a
  503 "Loading model" window, /tokenize, /v1/models.
- The response "model" field always echoes the server ALIAS — in
  single-model mode the request model selects nothing.

Admin (loopback :9700 by default, mock_vllm.py idiom):
  POST /admin/fail-next        one-shot HTTP 500 on the next inference
  POST /admin/fail-count       {"count": N} fail the next N inferences
  POST /admin/loading-on|off   /health + inference answer the 503
                               "Loading model" shape while on
  POST /admin/sleeping-on|off  /props.is_sleeping flag (probe-warn leg)
  POST /admin/slots-full-on|off  /slots?fail_on_no_slot=1 -> 503; the
                               requests_deferred gauge reports 1
  POST /admin/stall            {"secs": N} one-shot mid-stream stall on the
                               next streaming inference (emits ":" pings)
  POST /admin/reset            clear every knob
  GET  /admin/status

Usage:
    python3 mock_llamacpp.py --port 8085 --ep-idx 1
"""

import argparse
import json
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

ALIAS = "mock-llamacpp"
MODEL_PATH = "/models/qwen2.5-7b-instruct-q8_0.gguf"
BUILD_INFO = "b10524-mock"
TOTAL_SLOTS = 4
EP_IDX = 0
CTX_SIZE = 32768
PING_INTERVAL = 2.0

_lock = threading.Lock()
_loading = False
_sleeping = False
_slots_full = False
_fail_next = False
_fail_count = 0
_stall_secs = 0.0            # one-shot
_served = 0
_prompt_tokens_total = 0     # excl. cached (engine counter semantics)
_prompt_tokens_cached_total = 0
_tokens_predicted_total = 0
_prefix_store = []           # previously served prompt texts (per-process =
                             # per-EP, like the engine's slot/host-RAM cache)
_PREFIX_STORE_CAP = 64


def _tok(text):
    """~4 chars/token mock tokenizer — deterministic, monotone in length."""
    return max(1, len(text) // 4)


def _prompt_text(req):
    msgs = req.get("messages")
    if isinstance(msgs, list):
        return "\x1e".join(f'{m.get("role","")}\x1f{m.get("content","")}'
                           for m in msgs if isinstance(m, dict))
    return str(req.get("prompt") or "")


def _cached_tokens(text):
    """Longest common prefix vs the store, in mock tokens; then remember the
    text. A first-seen prompt is fully cold; an exact repeat is warm up to
    prompt_tokens-1 (the engine always evaluates at least one token)."""
    global _prefix_store
    best = 0
    with _lock:
        for prev in _prefix_store:
            n = 0
            for a, b in zip(prev, text):
                if a != b:
                    break
                n += 1
            best = max(best, n)
        _prefix_store.append(text)
        if len(_prefix_store) > _PREFIX_STORE_CAP:
            _prefix_store.pop(0)
    return min(best // 4, _tok(text) - 1)


def _err(code, message, etype):
    return {"error": {"code": code, "message": message, "type": etype}}


class MockLlamacppHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"[ep{EP_IDX}] {fmt % args}", flush=True)

    def _send_json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    # ── GET surface ──────────────────────────────────────────────────────
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/health":
            if _loading:
                self._send_json(503, _err(503, "Loading model",
                                          "unavailable_error"))
            else:
                self._send_json(200, {"status": "ok"})
        elif path == "/props":
            self._send_json(200, {
                "total_slots": TOTAL_SLOTS,
                "model_path": MODEL_PATH,
                "build_info": BUILD_INFO,
                "is_sleeping": _sleeping,
                "chat_template": "",
                "modalities": {"vision": False, "audio": False},
            })
        elif path == "/slots":
            if _slots_full and "fail_on_no_slot=1" in self.path:
                self._send_json(503, _err(503, "no slot available",
                                          "unavailable_error"))
                return
            self._send_json(200, [
                {"id": i, "is_processing": False, "id_task": -1,
                 "n_ctx": CTX_SIZE // TOTAL_SLOTS}
                for i in range(TOTAL_SLOTS)])
        elif path == "/metrics":
            with _lock:
                body = (
                    "# TYPE llamacpp:prompt_tokens_total counter\n"
                    f"llamacpp:prompt_tokens_total {_prompt_tokens_total}\n"
                    "# TYPE llamacpp:prompt_tokens_cached_total counter\n"
                    f"llamacpp:prompt_tokens_cached_total {_prompt_tokens_cached_total}\n"
                    "# TYPE llamacpp:tokens_predicted_total counter\n"
                    f"llamacpp:tokens_predicted_total {_tokens_predicted_total}\n"
                    "# TYPE llamacpp:requests_processing gauge\n"
                    "llamacpp:requests_processing 0\n"
                    "# TYPE llamacpp:requests_deferred gauge\n"
                    f"llamacpp:requests_deferred {1 if _slots_full else 0}\n")
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
            self.wfile.write(data)
        elif path == "/v1/models":
            self._send_json(200, {"object": "list", "data": [{
                "id": ALIAS, "object": "model",
                "created": int(time.time()), "owned_by": "mock-llamacpp"}]})
        else:
            self._send_json(404, _err(404, "File Not Found", "not_found_error"))

    # ── POST surface ─────────────────────────────────────────────────────
    def do_POST(self):
        global _fail_next, _fail_count, _stall_secs
        global _served, _prompt_tokens_total, _prompt_tokens_cached_total
        global _tokens_predicted_total
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode() if n > 0 else "{}"

        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            # live-pinned quirk: malformed JSON answers HTTP 500 (+ error
            # obj), NOT the 400 the README suggests
            self._send_json(500, _err(500, "Failed to parse request JSON",
                                      "server_error"))
            return

        if self.path == "/tokenize":
            text = str(req.get("content") or "")
            self._send_json(200, {"tokens":
                                  [(i * 7 + len(text)) % 32000
                                   for i in range(_tok(text))]})
            return

        if self.path not in ("/v1/chat/completions", "/v1/completions"):
            self._send_json(404, _err(404, "File Not Found", "not_found_error"))
            return

        # NOTE: no unknown-field validation anywhere — silent-ignore posture.
        if _loading:
            self._send_json(503, _err(503, "Loading model",
                                      "unavailable_error"))
            return
        with _lock:
            fail = _fail_next
            _fail_next = False
            if not fail and _fail_count > 0:
                _fail_count -= 1
                fail = True
            stall = _stall_secs
            _stall_secs = 0.0
        if fail:
            print(f"[ep{EP_IDX}] FAIL knob consumed", flush=True)
            self._send_json(500, _err(500, "injected_fault", "server_error"))
            return

        text = _prompt_text(req)
        pt = _tok(text)
        if pt > CTX_SIZE:
            self._send_json(400, _err(
                400, f"the request exceeds the available context size "
                     f"({pt} > {CTX_SIZE})", "exceed_context_size"))
            return
        ct = _cached_tokens(text)
        completion = "The mock llama.cpp answer flows steadily onward."
        words = completion.split(" ")
        with _lock:
            _served += 1
            _prompt_tokens_total += pt - ct
            _prompt_tokens_cached_total += ct
            _tokens_predicted_total += len(words)

        usage = {"prompt_tokens": pt, "completion_tokens": len(words),
                 "total_tokens": pt + len(words),
                 "prompt_tokens_details": {"cached_tokens": ct}}
        cmpl_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        chat = self.path == "/v1/chat/completions"

        if req.get("stream") is True:
            self._serve_stream(cmpl_id, chat, words, usage,
                               bool((req.get("stream_options") or {})
                                    .get("include_usage")), stall)
        else:
            if chat:
                self._send_json(200, {
                    "id": cmpl_id, "object": "chat.completion",
                    "created": int(time.time()), "model": ALIAS,
                    "choices": [{"index": 0,
                                 "message": {"role": "assistant",
                                             "content": completion},
                                 "finish_reason": "stop"}],
                    "usage": usage})
            else:
                self._send_json(200, {
                    "id": cmpl_id, "object": "text_completion",
                    "created": int(time.time()), "model": ALIAS,
                    "choices": [{"index": 0, "text": completion,
                                 "finish_reason": "stop"}],
                    "usage": usage})

    def _serve_stream(self, cmpl_id, chat, words, usage, want_usage, stall):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()

        def frame(delta, finish):
            if chat:
                return {"id": cmpl_id, "object": "chat.completion.chunk",
                        "created": int(time.time()), "model": ALIAS,
                        "choices": [{"index": 0, "delta": delta,
                                     "finish_reason": finish}]}
            return {"id": cmpl_id, "object": "text_completion",
                    "created": int(time.time()), "model": ALIAS,
                    "choices": [{"index": 0,
                                 "text": delta.get("content", ""),
                                 "finish_reason": finish}]}

        half = max(1, len(words) // 2)
        for i, w in enumerate(words):
            if i == half and stall > 0:
                # scripted stall: the engine emits bare ":" comment frames
                # after --sse-ping-interval of no tokens — the
                # ping-through-VIP pin (relay + idle clocks)
                deadline = time.monotonic() + stall
                while time.monotonic() < deadline:
                    time.sleep(PING_INTERVAL)
                    self.wfile.write(b":\n\n")
                    self.wfile.flush()
            body = {"content": (" " + w if i else w)}
            if chat and i == 0:
                body["role"] = "assistant"
            self.wfile.write(f"data: {json.dumps(frame(body, None))}\n\n"
                             .encode())
            self.wfile.flush()
            time.sleep(0.02)
        self.wfile.write(f"data: {json.dumps(frame({}, 'stop'))}\n\n".encode())
        if want_usage:
            final = {"id": cmpl_id,
                     "object": "chat.completion.chunk" if chat
                     else "text_completion",
                     "created": int(time.time()), "model": ALIAS,
                     "choices": [], "usage": usage}
            self.wfile.write(f"data: {json.dumps(final)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class AdminHandler(BaseHTTPRequestHandler):
    def _reply(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        global _loading, _sleeping, _slots_full, _fail_next, _fail_count
        global _stall_secs, _prefix_store
        n = int(self.headers.get("Content-Length", 0))
        body = {}
        if n:
            try:
                body = json.loads(self.rfile.read(n).decode())
            except json.JSONDecodeError:
                body = {}
        if self.path == "/admin/fail-next":
            with _lock:
                _fail_next = True
            self._reply({"fail_next": True})
        elif self.path == "/admin/fail-count":
            with _lock:
                _fail_count = int(body.get("count", 3))
            self._reply({"fail_count": _fail_count})
        elif self.path == "/admin/loading-on":
            _loading = True
            self._reply({"loading": True})
        elif self.path == "/admin/loading-off":
            _loading = False
            self._reply({"loading": False})
        elif self.path == "/admin/sleeping-on":
            _sleeping = True
            self._reply({"sleeping": True})
        elif self.path == "/admin/sleeping-off":
            _sleeping = False
            self._reply({"sleeping": False})
        elif self.path == "/admin/slots-full-on":
            _slots_full = True
            self._reply({"slots_full": True})
        elif self.path == "/admin/slots-full-off":
            _slots_full = False
            self._reply({"slots_full": False})
        elif self.path == "/admin/stall":
            with _lock:
                _stall_secs = float(body.get("secs", 6))
            self._reply({"stall_secs": _stall_secs})
        elif self.path == "/admin/reset":
            with _lock:
                _fail_next = False
                _fail_count = 0
                _stall_secs = 0.0
                _prefix_store = []
            _loading = False
            _sleeping = False
            _slots_full = False
            self._reply({"reset": True})
        else:
            self._reply({"error": "not found"}, 404)

    def do_GET(self):
        if self.path == "/admin/status":
            with _lock:
                self._reply({
                    "ep_idx": EP_IDX, "served": _served,
                    "loading": _loading, "sleeping": _sleeping,
                    "slots_full": _slots_full,
                    "fail_next": _fail_next, "fail_count": _fail_count,
                    "stall_secs": _stall_secs,
                    "prompt_tokens_total": _prompt_tokens_total,
                    "prompt_tokens_cached_total": _prompt_tokens_cached_total,
                    "prefix_store": len(_prefix_store),
                })
        else:
            self._reply({"error": "not found"}, 404)

    def log_message(self, fmt, *args):
        pass


def main():
    global ALIAS, BUILD_INFO, TOTAL_SLOTS, EP_IDX, PING_INTERVAL
    p = argparse.ArgumentParser(description="Mock llama.cpp server")
    p.add_argument("--port", type=int, default=8085)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--admin-port", type=int, default=9700)
    p.add_argument("--ep-idx", type=int, default=0)
    p.add_argument("--alias", default="mock-llamacpp")
    p.add_argument("--build", default="b10524-mock")
    p.add_argument("--slots", type=int, default=4)
    p.add_argument("--sse-ping-interval", type=float, default=2.0)
    args = p.parse_args()

    ALIAS = args.alias
    BUILD_INFO = args.build
    TOTAL_SLOTS = args.slots
    EP_IDX = args.ep_idx
    PING_INTERVAL = args.sse_ping_interval

    admin = HTTPServer(("127.0.0.1", args.admin_port), AdminHandler)
    threading.Thread(target=admin.serve_forever, daemon=True).start()

    srv = ThreadingHTTPServer((args.host, args.port), MockLlamacppHandler)
    print(f"Mock llama.cpp: addr={args.host}:{args.port} alias={ALIAS} "
          f"build={BUILD_INFO} slots={TOTAL_SLOTS} "
          f"admin=127.0.0.1:{args.admin_port} ep_idx={EP_IDX}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    srv.server_close()


if __name__ == "__main__":
    main()
