#!/usr/bin/env python3
"""
Mock TensorRT-LLM server for P/D disaggregation CICD testing.

Simulates trtllm-serve's OpenAI-compatible API surface with the
disaggregation dialect (no GPU required):

- extra="forbid" EVERYWHERE: any unknown top-level request field draws a
  400 naming it — pinning the dialect split forever (a vLLM
  kv_transfer_params or an SGLang bootstrap triple leaking into a TRT-LLM
  request must fail loudly, exactly like the real engine).
- context role: a request whose disaggregated_params.request_type is
  "context_only" answers non-streamed with ONE generated token,
  choices[0].disaggregated_params carrying request_type/ctx_request_id/
  first_gen_tokens/encoded_opaque_state (base64, echoes the
  disagg_request_id so the generation side can verify relay integrity)
  and a knob-able finish_reason ("length" default; "stop" scripts the
  early-exit leg deterministically).
- generation role: "generation_only" requests must carry an
  encoded_opaque_state whose magic prefix + base64 payload round-trip
  intact (stateless — context/generation mocks are separate processes; any
  byte surgery inside the extracted span breaks the decode, pinning that
  the gateway relays the EXTRACTED span verbatim, not a reconstruction);
  plain requests (no disaggregated_params) serve normally — the
  converged-degradation path the gateway uses when extraction fails.
- /server_info: kv_cache_hash_algo/tokens_per_block for the phase-0b
  admission guard (knob-able to script refusal legs).
- /kv_cache_events: DESTRUCTIVE drain (POST) of a queue of KVEventBatch-
  shaped entries; emits a `created` event on start, `stored` events with
  per-block token lists as context requests arrive (Option A shape), and
  supports scripted event_id gaps (/admin/event-gap) for the resync leg.

Admin (loopback :9600 by default, mock_vllm.py idiom):
  POST /admin/fail-next       one-shot HTTP 500 on the next inference
  POST /admin/health-fail|ok  toggle /health
  POST /admin/finish-reason   {"value": "stop"|"length"} for the NEXT
                              context response (one-shot; default length)
  POST /admin/event-gap       {"skip": N} advance event_id by N (gap)
  POST /admin/reset           clear all one-shot knobs
  GET  /admin/status

Usage:
    python3 mock_trtllm.py --role context    --port 8355
    python3 mock_trtllm.py --role generation --port 8355
    python3 mock_trtllm.py --role converged  --port 8355
"""

import argparse
import base64
import json
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler

MODEL_NAME = "Qwen/Qwen2.5-7B-Instruct"
SERVER_ROLE = "converged"
EP_IDX = 0
TOKENS_PER_BLOCK = 32
HASH_ALGO = "v1_block_key"
OPAQUE_MAGIC = "MOCKTRT1:"   # relay-integrity secret prefix (see module doc)

_lock = threading.Lock()
_health_ok = True
_fail_next = False
_fail_count = 0                # fail the next N inference requests (500) —
                               # the deterministic origin-streak trigger
_finish_reason_next = None     # one-shot override for the next context serve
_ctx_served = 0
_gen_served = 0
_early_exits_scripted = 0
_event_id = 0
_event_queue = []              # KVEventBatch-shaped dicts awaiting drain
_block_hash_seq = 1000

# The OpenAI + TRT-LLM request surface (CompletionRequest /
# ChatCompletionRequest fields the dialect may legitimately carry). Unknown
# keys 400 — the extra="forbid" pin.
ALLOWED_FIELDS = {
    "model", "prompt", "messages", "max_tokens", "max_completion_tokens",
    "min_tokens", "temperature", "top_p", "top_k", "n", "stream",
    "stream_options", "stop", "seed", "frequency_penalty",
    "presence_penalty", "logit_bias", "logprobs", "echo", "user",
    "best_of", "suffix", "disaggregated_params", "cache_salt",
}

DISAGG_ALLOWED = {
    "request_type", "first_gen_tokens", "ctx_request_id",
    "encoded_opaque_state", "opaque_state", "draft_tokens",
    "disagg_request_id", "multimodal_embedding_handles",
}


def _next_event_id(skip=0):
    global _event_id
    with _lock:
        _event_id += 1 + skip
        return _event_id


def _push_created():
    _event_queue.append({
        "event_id": _next_event_id(),
        "data": {"type": "created",
                 "num_blocks_per_cache_level": [1000, 0]},
    })


def _push_stored_for_tokens(n_tokens):
    """Emit one `stored` event covering the full blocks of an n_tokens
    prompt (Option A: per-block token lists present)."""
    global _block_hash_seq
    n_blocks = n_tokens // TOKENS_PER_BLOCK
    if n_blocks <= 0:
        return
    blocks = []
    with _lock:
        parent = None
        for b in range(n_blocks):
            _block_hash_seq += 1
            blocks.append({
                "block_hash": _block_hash_seq,
                "tokens": [{"token_id": (b * TOKENS_PER_BLOCK + i) % 32000,
                            "token_extra_id": 0}
                           for i in range(TOKENS_PER_BLOCK)],
            })
    _event_queue.append({
        "event_id": _next_event_id(),
        "data": {"type": "stored", "parent_hash": parent, "blocks": blocks},
    })


class MockTRTLLMHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"[{SERVER_ROLE}] {fmt % args}", flush=True)

    def _send_json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        if SERVER_ROLE == "context":
            self.send_header("X-Prefill-Ep", str(EP_IDX))
        elif SERVER_ROLE == "generation":
            self.send_header("X-Decode-Ep", str(EP_IDX))
        self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def _send_sse(self, chunks):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        for chunk in chunks:
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.03)
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    # ── GET surface ──────────────────────────────────────────────────────
    def do_GET(self):
        if self.path == "/health":
            if _health_ok:
                self._send_json(200, {"status": "ok", "role": SERVER_ROLE})
            else:
                self._send_json(503, {"status": "fail", "role": SERVER_ROLE})
        elif self.path == "/server_info":
            self._send_json(200, {
                "kv_cache_hash_algo": HASH_ALGO,
                "tokens_per_block": TOKENS_PER_BLOCK,
                "disaggregated_params": {"server_role": SERVER_ROLE.upper()
                                         if SERVER_ROLE != "converged" else None},
                "max_batch_size": 64,
            })
        elif self.path == "/v1/models":
            self._send_json(200, {"object": "list", "data": [{
                "id": MODEL_NAME, "object": "model",
                "created": int(time.time()), "owned_by": "mock-trtllm"}]})
        else:
            self._send_json(404, {"error": "Not found"})

    # ── POST surface ─────────────────────────────────────────────────────
    def do_POST(self):
        global _fail_next
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode() if n > 0 else "{}"

        if self.path == "/kv_cache_events":
            # destructive drain: return-and-clear
            with _lock:
                batch = list(_event_queue)
                _event_queue.clear()
            self._send_json(200, batch)
            return

        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        if self.path not in ("/v1/completions", "/v1/chat/completions"):
            self._send_json(404, {"error": "Not found"})
            return

        # extra="forbid" — the dialect pin. Reject BEFORE any knob so a
        # mis-dialected request can never be masked by fault injection.
        unknown = sorted(set(req.keys()) - ALLOWED_FIELDS)
        if unknown:
            self._send_json(400, {"error": {
                "message": f"Extra inputs are not permitted: {unknown}",
                "type": "extra_forbidden"}})
            return
        dp = req.get("disaggregated_params")
        if isinstance(dp, dict):
            dp_unknown = sorted(set(dp.keys()) - DISAGG_ALLOWED)
            if dp_unknown:
                self._send_json(400, {"error": {
                    "message": f"disaggregated_params: extra inputs are not "
                               f"permitted: {dp_unknown}",
                    "type": "extra_forbidden"}})
                return

        global _fail_count
        with _lock:
            fail = _fail_next
            _fail_next = False
            if not fail and _fail_count > 0:
                _fail_count -= 1
                fail = True
        if fail:
            print(f"[{SERVER_ROLE}] FAIL knob consumed", flush=True)
            self._send_json(500, {"error": "injected_fault"})
            return

        rtype = dp.get("request_type") if isinstance(dp, dict) else None
        if rtype == "context_only":
            if SERVER_ROLE == "generation":
                self._send_json(400, {"error":
                    "generation server received a context_only request"})
                return
            self._serve_context(req, dp)
        elif rtype == "generation_only":
            if SERVER_ROLE == "context":
                self._send_json(400, {"error":
                    "context server received a generation_only request"})
                return
            self._serve_generation(req, dp)
        elif dp is not None:
            self._send_json(400, {"error":
                f"unknown disaggregated_params.request_type: {rtype}"})
        else:
            # plain request — role'd servers still serve it standalone
            # (the gateway's extraction-failure degradation path)
            self._serve_generation(req, None)

    # ── dialect serves ───────────────────────────────────────────────────
    def _prompt_token_count(self, req):
        text = req.get("prompt") or json.dumps(req.get("messages", ""))
        # ~4 chars/token mock tokenizer — deterministic, monotone in length
        return max(1, len(text) // 4)

    def _serve_context(self, req, dp):
        global _ctx_served, _finish_reason_next, _early_exits_scripted
        if req.get("stream") is True:
            self._send_json(400, {"error":
                "context_only request must not stream"})
            return
        with _lock:
            _ctx_served += 1
            fr = _finish_reason_next or "length"
            if _finish_reason_next is not None:
                _early_exits_scripted += 1
            _finish_reason_next = None
        pt = self._prompt_token_count(req)
        opaque = OPAQUE_MAGIC + base64.b64encode(
            json.dumps({"disagg_request_id": dp.get("disagg_request_id"),
                        "ctx": uuid.uuid4().hex[:8]}).encode()).decode()
        _push_stored_for_tokens(pt)
        self._send_json(200, {
            "id": f"cmpl-{uuid.uuid4().hex[:12]}",
            "object": "text_completion",
            "created": int(time.time()),
            "model": req.get("model", MODEL_NAME),
            "choices": [{
                "index": 0,
                "text": " mock-first-token" if fr != "stop" else " DONE.",
                "finish_reason": fr,
                "disaggregated_params": {
                    "request_type": "context_only",
                    "first_gen_tokens": [12345],
                    "ctx_request_id": _ctx_served,
                    "encoded_opaque_state": opaque,
                    "draft_tokens": None,
                },
            }],
            "usage": {"prompt_tokens": pt, "completion_tokens": 1,
                      "total_tokens": pt + 1},
        })

    def _serve_generation(self, req, dp):
        global _gen_served
        with _lock:
            _gen_served += 1
        if dp is not None:
            # Relay-integrity pin, STATELESS by design (context and
            # generation mocks are separate processes on separate hosts): the
            # opaque state must carry the mock magic prefix AND its base64
            # payload must round-trip to the JSON a context serve emits — any
            # byte surgery inside the extracted span breaks the decode.
            opaque = dp.get("encoded_opaque_state") or dp.get("opaque_state")
            intact = False
            if isinstance(opaque, str) and opaque.startswith(OPAQUE_MAGIC):
                try:
                    inner = json.loads(
                        base64.b64decode(opaque[len(OPAQUE_MAGIC):],
                                         validate=True))
                    intact = isinstance(inner, dict) and "ctx" in inner
                except Exception:
                    intact = False
            if not intact:
                self._send_json(400, {"error":
                    "generation_only request carries an opaque_state this "
                    "fleet never issued (magic/base64 integrity check)"})
                return
        pt = self._prompt_token_count(req)
        cmpl_id = f"cmpl-{uuid.uuid4().hex[:12]}"
        model = req.get("model", MODEL_NAME)
        text = " The mock TRT-LLM generation answer is 42." \
            if dp is not None else " Standalone mock TRT-LLM answer."
        if req.get("stream") is True:
            words = text.split(" ")
            chunks = [{
                "id": cmpl_id, "object": "text_completion",
                "created": int(time.time()), "model": model,
                "choices": [{"index": 0, "text": (" " + w if i else w),
                             "finish_reason": None}],
            } for i, w in enumerate(words)]
            chunks.append({
                "id": cmpl_id, "object": "text_completion",
                "created": int(time.time()), "model": model,
                "choices": [{"index": 0, "text": "",
                             "finish_reason": "stop"}],
            })
            self._send_sse(chunks)
        else:
            self._send_json(200, {
                "id": cmpl_id, "object": "text_completion",
                "created": int(time.time()), "model": model,
                "choices": [{"index": 0, "text": text,
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": pt,
                          "completion_tokens": len(text.split(" ")),
                          "total_tokens": pt + len(text.split(" "))},
            })


class AdminHandler(BaseHTTPRequestHandler):
    def _reply(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        global _health_ok, _fail_next, _fail_count, _finish_reason_next
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
        elif self.path == "/admin/health-fail":
            _health_ok = False
            self._reply({"health_ok": False})
        elif self.path == "/admin/health-ok":
            _health_ok = True
            self._reply({"health_ok": True})
        elif self.path == "/admin/finish-reason":
            with _lock:
                _finish_reason_next = body.get("value", "stop")
            self._reply({"finish_reason_next": _finish_reason_next})
        elif self.path == "/admin/event-gap":
            skip = int(body.get("skip", 10))
            _next_event_id(skip)   # burn ids — the next event opens a gap
            self._reply({"event_id_advanced_by": skip + 1})
        elif self.path == "/admin/event-push":
            _push_stored_for_tokens(int(body.get("tokens", TOKENS_PER_BLOCK)))
            self._reply({"pushed": True})
        elif self.path == "/admin/reset":
            with _lock:
                _fail_next = False
                _fail_count = 0
                _finish_reason_next = None
            _health_ok = True
            self._reply({"reset": True})
        else:
            self._reply({"error": "not found"}, 404)

    def do_GET(self):
        if self.path == "/admin/status":
            with _lock:
                self._reply({
                    "role": SERVER_ROLE, "health_ok": _health_ok,
                    "fail_next": _fail_next,
                    "finish_reason_next": _finish_reason_next,
                    "ctx_served": _ctx_served, "gen_served": _gen_served,
                    "early_exits_scripted": _early_exits_scripted,
                    "event_id": _event_id,
                    "events_queued": len(_event_queue),
                })
        else:
            self._reply({"error": "not found"}, 404)

    def log_message(self, fmt, *args):
        pass


def main():
    global SERVER_ROLE, EP_IDX, TOKENS_PER_BLOCK, HASH_ALGO
    p = argparse.ArgumentParser(description="Mock TRT-LLM P/D server")
    p.add_argument("--role", choices=["context", "generation", "converged"],
                   default="converged")
    p.add_argument("--port", type=int, default=8355)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--admin-port", type=int, default=9600)
    p.add_argument("--ep-idx", type=int, default=0)
    p.add_argument("--tokens-per-block", type=int, default=32)
    p.add_argument("--hash-algo", default="v1_block_key")
    args = p.parse_args()

    SERVER_ROLE = args.role
    EP_IDX = args.ep_idx
    TOKENS_PER_BLOCK = args.tokens_per_block
    HASH_ALGO = args.hash_algo

    _push_created()   # restart signature: drain starts with `created`

    admin = HTTPServer(("127.0.0.1", args.admin_port), AdminHandler)
    threading.Thread(target=admin.serve_forever, daemon=True).start()

    srv = HTTPServer((args.host, args.port), MockTRTLLMHandler)
    print(f"Mock TRT-LLM: role={SERVER_ROLE} addr={args.host}:{args.port} "
          f"tpb={TOKENS_PER_BLOCK} algo={HASH_ALGO} "
          f"admin=127.0.0.1:{args.admin_port} ep_idx={EP_IDX}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    srv.server_close()


if __name__ == "__main__":
    main()
