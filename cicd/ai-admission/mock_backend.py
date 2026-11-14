#!/usr/bin/env python3
"""
mock_backend.py — an OpenAI-compatible backend the capacity gate can be
measured against.

One process serves every port it is given, so the counters below are shared
across the pool's endpoints: "how many requests were executing at the
backend at the same instant" is a question about the pool, and two
processes cannot answer it.

Endpoints:
  POST /v1/chat/completions   the inference request (JSON, or SSE when the
                              body carries "stream": true)
  GET  /v1/models             a non-inference request on the same service
  GET  /health                readiness
  GET  /__receipts/<nonce>    requests that arrived carrying that X-Test-Nonce
  GET  /__headers/<nonce>     the llm-d request headers and an x-vllm-priority of the last
                              request carrying that nonce, as the backend received them
                              ({"name": ["value", ...]})
  GET  /__body/<nonce>        what the backend's JSON parser read from the last body
                              carrying that nonce: its top-level "model", "service_tier",
                              "priority" and "_gw_prio" ("absent" when the key is not there), so
                              a scenario can tell a nulled tier from one that was never
                              sent, in whichever spelling the client wrote the key
  GET  /__peak/<nonce>        the most requests with that nonce executing at
                              once, across every port, plus the per-port peaks
  GET  /__inflight            requests executing right now
  GET  /__order/<nonce>       the X-Request-Id of every request carrying that
                              nonce, in the order they arrived
  GET  /__release/<nonce>     let every held request with that nonce answer
  GET  /__release_all         let every held request answer
  GET  /metrics               the engine's own metrics, as the gateway's
                              scraper reads them: vllm:num_requests_waiting
  GET  /__waiting/<n>         report <n> requests waiting from now on (every port)
  GET  /__metrics/off|on      stop answering /metrics (503) or answer again,
                              so the gateway's view of the engine goes stale
  GET  /admin/answer-429-object
                              the NEXT inference request (any port) is answered
                              429 the way an OpenAI-compatible engine refuses:
                              an {"error": {...}} object body and a Retry-After
                              of its own (7). One request, then back to normal
  GET  /admin/echo-spoof-headers
                              the NEXT inference answer (any port) carries
                              X-Loxilb-Refusal-Stage: capacity and
                              X-Loxilb-Admission-Inflight: 999 of the backend's
                              own: the gateway's families, which a backend may
                              not hand a client. One answer, then back to normal
  GET  /admin/split-head/<n>/<delay_ms>
                              the NEXT inference answer (any port), plain or
                              SSE, leaves the backend with its head (status
                              line through the blank line) cut into <n> writes
                              of equal size, <delay_ms> apart; <n> 0 means one
                              byte a write. The body follows the last piece as
                              usual. One answer, then back to normal; the arm
                              can be combined with the two above
  GET  /__split/<nonce>       how the head of the last answer to that nonce
                              left: {"pieces": <writes>, "head_bytes": <n>},
                              0 pieces when it was not split

Request headers that shape the answer:
  X-Test-Nonce: <n>       counted as a receipt and tracked for its peak
  X-Test-Hold: 1          the request is read in full, counted, then held
                          until released (or 90 s), so a caller can look at
                          the gateway while the request is executing
  X-Test-Delay-Ms: <ms>   time to first byte (for a stream: to its first
                          event, the time to first token)
  X-Test-Fail: <status>   answer with that status and an error body
  X-Test-Reset: 1         drop the connection with a TCP RST, no answer
  X-Test-Close-After-Ms: <ms>
                          answer as usual, keep the connection, and close it
                          (FIN) that long after the answer was written: a
                          backend whose idle timeout ends a kept connection
  X-Test-Forever: 1       with "stream": true, keep sending SSE chunks until
                          the connection dies
  X-Test-Spoof-Admission: 1
                          the answer carries X-Loxilb-Admission-Inflight: 999
                          of its own, which the gateway must replace
  X-Test-Spoof-Objective: 1
                          the answer carries
                          X-Loxilb-Admission-Objective-Requested: forged of its
                          own, which the gateway must not relay
  X-Test-Head-Pad: <bytes>
                          the answer's head carries that many extra bytes, as
                          X-Test-Pad-<i> lines of 1000 "p" each (the last one
                          shorter): a head larger than a proxy assembles
  X-Test-Engine: vllm|sglang|trtllm
                          answer as that engine would a top-level body key
                          it does not know: vllm allows it, sglang ignores
                          it, trtllm refuses the request 400 naming it

The receipt count is the honest oracle for a refused request: from the
client side a refusal and a forwarded request whose answer was discarded
look identical, and the count is read from inside the backend's own
namespace, never through the gateway.

Usage: mock_backend.py <port> [<port> ...]
"""

import json
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

HOLD_MAX_S = 90.0

LOCK = threading.Lock()
RECEIPTS = {}        # nonce -> arrivals
INFLIGHT = 0         # executing right now, every port
INFLIGHT_PORT = {}   # port -> executing right now
PEAK = {}            # nonce -> most executing at once, every port
PEAK_PORT = {}       # nonce -> {port: most executing at once on that port}
ORDER = {}           # nonce -> request ids in arrival order
SEEN_HDRS = {}       # nonce -> the llm-d headers of its last request
SEEN_BODY = {}          # nonce -> what the parser read from the last body

# The OpenAI chat request surface an engine with extra="forbid" accepts
# (TensorRT-LLM's ChatCompletionRequest; it has no priority field). A
# top-level key outside it is refused when X-Test-Engine names trtllm.
ENGINE_CHAT_FIELDS = {
    "model", "messages", "prompt", "max_tokens", "max_completion_tokens",
    "min_tokens", "temperature", "top_p", "top_k", "n", "stream",
    "stream_options", "stop", "seed", "frequency_penalty", "presence_penalty",
    "logit_bias", "logprobs", "top_logprobs", "user", "tools", "tool_choice",
    "response_format", "service_tier",
}

RELEASED = set()     # nonces whose holds were released
RELEASE_ALL = 0      # generation: bumped by /__release_all
COND = threading.Condition(LOCK)
WAITING = 0          # vllm:num_requests_waiting reported by /metrics
METRICS_ON = True    # /metrics answers; off: 503, the scrape fails
ARM_429_OBJECT = False   # /admin/answer-429-object: the next inference request
ARM_SPOOF_HEADERS = False  # /admin/echo-spoof-headers: the next inference answer
ARM_SPLIT_HEAD = None    # /admin/split-head/<n>/<delay_ms>: (n, delay_ms) for the next inference answer
SPLIT_SEEN = {}          # nonce -> how the head of its last answer left the backend
SPLIT_PIECES_MAX = 64    # <n> above this is refused: the arm is for a few cuts or for every byte
SPLIT_DELAY_MAX_MS = 2000

# What an OpenAI-compatible engine answers when it refuses on its own.
BACKEND_429_BODY = {"error": {"message": "the engine is overloaded",
                              "type": "rate_limit_error",
                              "code": "rate_limit_exceeded"}}
BACKEND_429_RETRY_AFTER = "7"


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    # ── helpers ────────────────────────────────────────────────────────────
    @property
    def port(self):
        return self.server.server_address[1]

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n > 0 else b""
        try:
            return json.loads(raw or b"{}")
        except (ValueError, UnicodeDecodeError):
            return {}

    def _send_json(self, obj, status=200, extra=()):
        payload = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in extra:
            self.send_header(k, v)
        self._spoof_header()
        self._pad_header()
        self.end_headers()
        self.wfile.write(payload)

    def _pad_header(self):
        left, i = getattr(self, "head_pad", 0), 0
        while left > 0:
            self.send_header("X-Test-Pad-%d" % i, "p" * min(left, 1000))
            left -= 1000
            i += 1

    def flush_headers(self):
        # The one place a head leaves this server: an armed split cuts it
        # here. An interim head (100 Continue) is never the armed answer.
        split = getattr(self, "split_head", None)
        buf = getattr(self, "_headers_buffer", None)
        if not split or not buf or buf[0].startswith(b"HTTP/1.1 1"):
            super().flush_headers()
            return
        self.split_head = None
        head = b"".join(buf)
        self._headers_buffer = []
        n, delay_ms = split
        size = 1 if n == 0 else max(1, -(-len(head) // n))
        pieces = [head[i:i + size] for i in range(0, len(head), size)]
        # Each piece is a segment of its own: no coalescing on this side.
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for i, piece in enumerate(pieces):
            if i:
                time.sleep(delay_ms / 1000.0)
            self.wfile.write(piece)
            self.wfile.flush()
        nonce = self.headers.get("X-Test-Nonce", "") if self.headers else ""
        if nonce:
            with LOCK:
                SPLIT_SEEN[nonce] = {"pieces": len(pieces), "head_bytes": len(head)}

    def _spoof_header(self):
        if getattr(self, "spoof", False):
            self.send_header("X-Loxilb-Admission-Inflight", "999")
        if getattr(self, "spoof_stage", False):
            self.send_header("X-Loxilb-Refusal-Stage", "capacity")
        if getattr(self, "spoof_objective", False):
            self.send_header("X-Loxilb-Admission-Objective-Requested", "forged")

    def _enter(self, nonce, body=None):
        global INFLIGHT
        with LOCK:
            if nonce:
                RECEIPTS[nonce] = RECEIPTS.get(nonce, 0) + 1
                if body is not None:
                    SEEN_BODY[nonce] = {"model": body.get("model", "absent"),
                                        "service_tier": body.get("service_tier", "absent"),
                                        "priority": body.get("priority", "absent"),
                                        "_gw_prio": body.get("_gw_prio", "absent"),
                                        "tools": body.get("tools", "absent")}
                ORDER.setdefault(nonce, []).append(
                    self.headers.get("X-Request-Id", ""))
                SEEN_HDRS[nonce] = {}
                for k in self.headers.keys():
                    if k.lower().startswith(("x-llm-d-", "x-gateway-inference-",
                                             "x-vllm-priority")):
                        SEEN_HDRS[nonce].setdefault(k.lower(), []).extend(
                            self.headers.get_all(k))
            INFLIGHT += 1
            INFLIGHT_PORT[self.port] = INFLIGHT_PORT.get(self.port, 0) + 1
            if nonce:
                if INFLIGHT > PEAK.get(nonce, 0):
                    PEAK[nonce] = INFLIGHT
                pp = PEAK_PORT.setdefault(nonce, {})
                if INFLIGHT_PORT[self.port] > pp.get(self.port, 0):
                    pp[self.port] = INFLIGHT_PORT[self.port]

    def _leave(self):
        global INFLIGHT
        with LOCK:
            INFLIGHT -= 1
            INFLIGHT_PORT[self.port] = INFLIGHT_PORT.get(self.port, 1) - 1

    def _hold(self, nonce):
        deadline = time.monotonic() + HOLD_MAX_S
        with COND:
            gen = RELEASE_ALL
            while nonce not in RELEASED and RELEASE_ALL == gen:
                left = deadline - time.monotonic()
                if left <= 0:
                    return "timeout"
                COND.wait(left)
        return "released"

    def _reset(self):
        try:
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       struct.pack("ii", 1, 0))
        except OSError:
            pass
        self.close_connection = True
        try:
            self.connection.close()
        except OSError:
            pass

    # ── routes ─────────────────────────────────────────────────────────────
    def do_GET(self):
        self.spoof = False
        self.spoof_stage = False
        self.split_head = None
        self.head_pad = 0
        global WAITING, METRICS_ON, ARM_429_OBJECT, ARM_SPOOF_HEADERS, ARM_SPLIT_HEAD
        path = urlparse(self.path).path
        nonce = self.headers.get("X-Test-Nonce", "")
        if path == "/health":
            self._send_json({"status": "ok"})
            return
        if path == "/metrics":
            with LOCK:
                on, waiting = METRICS_ON, WAITING
            if not on:
                self.send_error(503)
                return
            payload = ("# TYPE vllm:num_requests_waiting gauge\n"
                       "vllm:num_requests_waiting{model_name=\"cap-model\"} %d\n"
                       % waiting).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path.startswith("/__waiting/"):
            with LOCK:
                WAITING = int(path[len("/__waiting/"):] or 0)
            self._send_json({"waiting": WAITING})
            return
        if path in ("/__metrics/off", "/__metrics/on"):
            with LOCK:
                METRICS_ON = path.endswith("/on")
            self._send_json({"metrics": METRICS_ON})
            return
        if path == "/admin/answer-429-object":
            with LOCK:
                ARM_429_OBJECT = True
            self._send_json({"armed": "answer-429-object"})
            return
        if path == "/admin/echo-spoof-headers":
            with LOCK:
                ARM_SPOOF_HEADERS = True
            self._send_json({"armed": "echo-spoof-headers"})
            return
        if path.startswith("/admin/split-head/"):
            try:
                n, delay_ms = (int(x) for x in path[len("/admin/split-head/"):].split("/"))
            except ValueError:
                n = delay_ms = -1
            if not (0 <= n <= SPLIT_PIECES_MAX and n != 1 and 0 <= delay_ms <= SPLIT_DELAY_MAX_MS):
                self._send_json({"error": "split-head/<n>/<delay_ms>: n 0 (byte-wise) or 2..%d, "
                                          "delay_ms 0..%d" % (SPLIT_PIECES_MAX, SPLIT_DELAY_MAX_MS)}, 400)
                return
            with LOCK:
                ARM_SPLIT_HEAD = (n, delay_ms)
            self._send_json({"armed": "split-head", "pieces": n, "delay_ms": delay_ms})
            return
        if path.startswith("/__split/"):
            n = path[len("/__split/"):]
            with LOCK:
                self._send_json({"nonce": n, **SPLIT_SEEN.get(n, {"pieces": 0, "head_bytes": 0})})
            return
        if path == "/v1/models":
            # A non-inference request: counted like any other arrival so a
            # scenario can prove it reached the backend while the gate was
            # full, then answered as a model listing.
            self._enter(nonce)
            try:
                self._send_json({"object": "list", "data": [
                    {"id": "cap-model", "object": "model", "owned_by": "cicd"}]})
            finally:
                self._leave()
            return
        if path.startswith("/__receipts/"):
            n = path[len("/__receipts/"):]
            with LOCK:
                self._send_json({"nonce": n, "count": RECEIPTS.get(n, 0)})
            return
        if path.startswith("/__headers/"):
            n = path[len("/__headers/"):]
            with LOCK:
                self._send_json({"nonce": n, "headers": SEEN_HDRS.get(n, {})})
            return
        if path.startswith("/__body/"):
            n = path[len("/__body/"):]
            with LOCK:
                self._send_json({"nonce": n, "body": SEEN_BODY.get(n, {})})
            return
        if path.startswith("/__peak/"):
            n = path[len("/__peak/"):]
            with LOCK:
                self._send_json({"nonce": n, "peak": PEAK.get(n, 0),
                                 "ports": {str(k): v for k, v in
                                           PEAK_PORT.get(n, {}).items()}})
            return
        if path.startswith("/__order/"):
            n = path[len("/__order/"):]
            with LOCK:
                self._send_json({"nonce": n, "order": list(ORDER.get(n, []))})
            return
        if path == "/__inflight":
            with LOCK:
                self._send_json({"inflight": INFLIGHT,
                                 "ports": {str(k): v for k, v in INFLIGHT_PORT.items()}})
            return
        if path.startswith("/__release/"):
            n = path[len("/__release/"):]
            with COND:
                RELEASED.add(n)
                COND.notify_all()
            self._send_json({"released": n})
            return
        if path == "/__release_all":
            global RELEASE_ALL
            with COND:
                RELEASE_ALL += 1
                COND.notify_all()
            self._send_json({"released": "all"})
            return
        self.send_error(404)

    def do_POST(self):
        if urlparse(self.path).path != "/v1/chat/completions":
            self.send_error(404)
            return
        nonce = self.headers.get("X-Test-Nonce", "")
        hold = self.headers.get("X-Test-Hold", "") == "1"
        delay_ms = int(self.headers.get("X-Test-Delay-Ms") or 0)
        fail = int(self.headers.get("X-Test-Fail") or 0)
        reset = self.headers.get("X-Test-Reset", "") == "1"
        close_after_ms = int(self.headers.get("X-Test-Close-After-Ms") or 0)
        forever = self.headers.get("X-Test-Forever", "") == "1"
        self.spoof = self.headers.get("X-Test-Spoof-Admission", "") == "1"
        self.spoof_objective = self.headers.get("X-Test-Spoof-Objective", "") == "1"
        engine = self.headers.get("X-Test-Engine", "")
        self.head_pad = min(int(self.headers.get("X-Test-Head-Pad") or 0), 64000)
        # The admin arms are taken by the next inference request, whichever
        # port it arrives on, and by that one only.
        global ARM_429_OBJECT, ARM_SPOOF_HEADERS, ARM_SPLIT_HEAD
        with LOCK:
            answer_429, ARM_429_OBJECT = ARM_429_OBJECT, False
            spoof_next, ARM_SPOOF_HEADERS = ARM_SPOOF_HEADERS, False
            self.split_head, ARM_SPLIT_HEAD = ARM_SPLIT_HEAD, None
            if nonce:
                SPLIT_SEEN.pop(nonce, None)
        self.spoof_stage = spoof_next
        if spoof_next:
            self.spoof = True

        body = self._body()          # read before anything else: a held
        self._enter(nonce, body)     # request has fully arrived
        try:
            # Answer as the engine named would, on a top-level key it does
            # not know (from the engines' request classes): vLLM's
            # OpenAIBaseModel has extra="allow" (vllm/entrypoints/openai/
            # engine/protocol.py), SGLang's ChatCompletionRequest is a plain
            # pydantic BaseModel, extra="ignore" (sglang/srt/entrypoints/
            # openai/protocol.py), TensorRT-LLM's OpenAIBaseModel has
            # extra="forbid" (tensorrt_llm/serve/openai_protocol.py). With
            # no engine named the mock is its own: everything is accepted.
            if engine == "trtllm":
                unknown = sorted(set(body.keys()) - ENGINE_CHAT_FIELDS)
                if unknown:
                    self._send_json({"error": {
                        "message": "Extra inputs are not permitted: %s" % unknown,
                        "type": "extra_forbidden"}}, 400)
                    return
            if hold:
                self._hold(nonce)
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
            if reset:
                self._reset()
                return
            if answer_429:
                self._send_json(BACKEND_429_BODY, 429,
                                extra=(("Retry-After", BACKEND_429_RETRY_AFTER),))
                return
            if fail:
                self._send_json({"error": {"message": "injected", "type": "test"}}, fail)
                return
            model = body.get("model") or "cap-model"
            if body.get("stream"):
                self._stream(model, forever)
            else:
                self._complete(model)
            if close_after_ms > 0:
                self._close_later(close_after_ms)
        finally:
            self._leave()

    def _close_later(self, ms):
        conn = self.connection

        def shut():
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        t = threading.Timer(ms / 1000.0, shut)
        t.daemon = True
        t.start()

    def _complete(self, model):
        self._send_json({
            "id": "cmpl-cap", "object": "chat.completion",
            "created": int(time.time()), "model": model,
            "backend_port": self.port,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        })

    def _stream(self, model, forever):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self._spoof_header()
        self._pad_header()
        self.end_headers()

        def chunk(payload):
            self.wfile.write(b"%x\r\n" % len(payload) + payload + b"\r\n")
            self.wfile.flush()

        def sse(obj):
            chunk(b"data: " + json.dumps(obj).encode() + b"\n\n")

        base = {"id": "cmpl-cap", "object": "chat.completion.chunk", "model": model}
        i = 0
        try:
            while True:
                sse(dict(base, choices=[{"index": 0, "delta": {"content": "t%d " % i}}]))
                i += 1
                if not forever and i >= 3:
                    break
                time.sleep(0.2)
        except OSError:
            # The connection died under a forever stream: that is how a
            # forever stream ends, not an error of the fixture.
            self.close_connection = True
            return
        sse(dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}]))
        sse(dict(base, choices=[],
                 usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}))
        chunk(b"data: [DONE]\n\n")
        chunk(b"")


def main():
    ports = [int(p) for p in sys.argv[1:]] or [8080]
    servers = [Server(("0.0.0.0", p), Handler) for p in ports]
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print("mock_backend listening on %s" % ",".join(str(p) for p in ports), flush=True)
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
