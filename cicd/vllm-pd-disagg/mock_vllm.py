#!/usr/bin/env python3
"""
Mock vLLM server for P/D disaggregation CICD testing.

Simulates OpenAI-compatible API with prefill/decode behavior:
- Prefill mode: Returns non-streaming response with kv_transfer_params
- Decode mode: Returns streaming SSE response, accepts kv_transfer_params

Usage:
    python3 mock_vllm.py --role prefill --port 8000
    python3 mock_vllm.py --role decode --port 8000
"""

import argparse
import json
import os
import socket
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler

MODEL_NAME = "Qwen/Qwen3-0.6B"
SERVER_ROLE = "normal"  # Set by command-line args
NIXL_PORT = 0           # Set by main(); used by _make_kv_params to avoid hardcoded 9001 (R2 fix)
EP_IDX = 0              # Set by main() from --ep-idx CLI flag; echoed back via X-Prefill-Ep / X-Decode-Ep
                        # response headers so the HA failover test can correlate which (prefill_ep, decode_ep) pair
                        # served each request (required for restore_rate).
_health_ok = True       # Toggled by admin server; GIL-safe (CPython, simple bool assignment)
_request_count = 0      # Incremented per POST request; used by --fail-every.
                        # WR-07: protected by _request_count_lock — under the
                        # single-threaded HTTPServer the GIL covers a bare
                        # `+= 1`, but if anyone swaps for ThreadingHTTPServer
                        # the read-modulo-write of --fail-every becomes
                        # non-deterministic. Lock is cheap; harden now.
_request_count_lock = threading.Lock()
_fail_next = False      # One-shot: next inference request answers HTTP 500
                        # (origin-computed error — the connection stays up).
                        # Armed via POST /admin/fail-next, cleared on consume
                        # or /admin/reset; mirrors the mock_sglang_pd.py knob.
_args = None            # Set by main(); allows handlers to access parsed args
# Identity of this server instance, echoed as the X-Served-By response header so
# a test can attribute a proxied response to the endpoint that produced it. In
# Kubernetes POD_NAME (downward API) names the pod; hostname covers docker/netns.
SERVED_BY = os.environ.get("POD_NAME") or socket.gethostname()


class MockVLLMHandler(BaseHTTPRequestHandler):
    """Handles OpenAI-compatible API requests."""

    def log_message(self, format, *args):
        """Log to stdout for debugging."""
        print(f"[{SERVER_ROLE}] {format % args}")

    def _send_json(self, status, body):
        """Send a JSON response."""
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        # Echo back X-Request-Id if present
        req_id = self.headers.get("X-Request-Id", "")
        if req_id:
            self.send_header("X-Request-Id", req_id)
        # Emit X-Prefill-Ep / X-Decode-Ep based on SERVER_ROLE so the HA
        # validation.sh can correlate which (prefill_ep, decode_ep) served each
        # turn before/after failover and compute restore_rate.
        # Verify with: curl -sI -X POST http://<ep>:8000/v1/chat/completions -d '{}' | grep -i X-Prefill-Ep
        if SERVER_ROLE == "prefill":
            self.send_header("X-Prefill-Ep", str(EP_IDX))
        elif SERVER_ROLE == "decode":
            self.send_header("X-Decode-Ep", str(EP_IDX))
        self.send_header("X-Served-By", SERVED_BY)
        self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def _send_sse(self, chunks):
        """Send SSE streaming response."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        req_id = self.headers.get("X-Request-Id", "")
        if req_id:
            self.send_header("X-Request-Id", req_id)
        # Mirror the X-Prefill-Ep / X-Decode-Ep echo from _send_json
        # so SSE streaming responses also carry the EP-identity header.
        if SERVER_ROLE == "prefill":
            self.send_header("X-Prefill-Ep", str(EP_IDX))
        elif SERVER_ROLE == "decode":
            self.send_header("X-Decode-Ep", str(EP_IDX))
        self.send_header("X-Served-By", SERVED_BY)
        self.close_connection = True
        self.end_headers()

        for chunk in chunks:
            line = f"data: {json.dumps(chunk)}\n\n"
            self.wfile.write(line.encode("utf-8"))
            self.wfile.flush()
            time.sleep(0.05)  # Small delay between chunks

        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def do_GET(self):
        if self.path == "/v1/models":
            self._handle_models()
        elif self.path == "/health":
            if _health_ok:
                self._send_json(200, {"status": "ok", "role": SERVER_ROLE})
            else:
                self._send_json(503, {"status": "fail", "role": SERVER_ROLE})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"

        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        # One-shot fail-next fault injection (origin-computed HTTP 500 with the
        # TCP connection healthy — the exact shape the breaker's origin-error
        # streak demotes on; connect-level failure_count never sees it).
        global _fail_next
        if _fail_next and self.path in ("/v1/chat/completions", "/v1/completions"):
            _fail_next = False
            print(f"[{SERVER_ROLE}] FAIL-NEXT consumed reqid={self.headers.get('X-Request-Id', '-')}",
                  flush=True)
            self._send_json(500, {"error": "injected_fault_oneshot"})
            return

        # --fail-every fault injection (HTTP 500; an isolated 5xx does not trip
        # the breaker — the origin-error streak needs consecutive 5xx, and the
        # interleaved successes here keep resetting it)
        global _request_count
        if _args is not None and _args.fail_every > 0:
            # WR-07: atomic increment + modulo under a lock so the
            # injection cadence is deterministic regardless of HTTPServer
            # threading model. Capture the post-increment value inside
            # the lock then drop the lock before doing I/O.
            with _request_count_lock:
                _request_count += 1
                snapshot = _request_count
                should_fail = (snapshot % _args.fail_every == 0)
            if should_fail:
                self._send_json(500, {"error": "injected_fault", "request_count": snapshot})
                return

        # Log incoming request metadata for CICD verification (T4c max_tokens, T5 ID correlation)
        req_id = self.headers.get("X-Request-Id", "")
        if req_id:
            print(f"[{SERVER_ROLE}] X-Request-Id: {req_id}", flush=True)
        max_tokens = req.get("max_tokens")
        if max_tokens is not None:
            print(f"[{SERVER_ROLE}] max_tokens: {max_tokens}", flush=True)
        user_id = req.get("user")
        if user_id:
            print(f"[{SERVER_ROLE}] user_id: {user_id}", flush=True)

        if self.path == "/v1/chat/completions":
            self._handle_chat_completions(req)
        elif self.path == "/v1/completions":
            self._handle_completions(req)
        else:
            self._send_json(404, {"error": "Not found"})

    def _handle_models(self):
        self._send_json(200, {
            "object": "list",
            "data": [{
                "id": MODEL_NAME,
                "object": "model",
                "created": int(time.time()),
                "owned_by": "mock-vllm",
            }]
        })

    def _handle_chat_completions(self, req):
        """Handle /v1/chat/completions based on server role."""
        cmpl_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        model = req.get("model", MODEL_NAME)
        stream = req.get("stream", False)

        # Log received kv_transfer_params for decode verification
        kv_params = req.get("kv_transfer_params")
        if kv_params:
            print(f"[{SERVER_ROLE}] [decode] kv_transfer_params: {json.dumps(kv_params)[:200]}", flush=True)

        if SERVER_ROLE == "prefill":
            # Prefill always returns non-streaming with kv_transfer_params
            self._send_prefill_response(cmpl_id, model)
        elif SERVER_ROLE == "decode":
            if stream:
                self._send_decode_stream(cmpl_id, model)
            else:
                self._send_decode_response(cmpl_id, model)
        else:
            # Normal mode — just respond normally
            if stream:
                self._send_decode_stream(cmpl_id, model)
            else:
                self._send_decode_response(cmpl_id, model)

    def _handle_completions(self, req):
        """Handle /v1/completions (legacy endpoint)."""
        cmpl_id = f"cmpl-{uuid.uuid4().hex[:12]}"
        model = req.get("model", MODEL_NAME)

        if SERVER_ROLE == "prefill":
            self._send_json(200, {
                "id": cmpl_id,
                "object": "text_completion",
                "created": int(time.time()),
                "model": model,
                "choices": [{
                    "index": 0,
                    "text": "",
                    "finish_reason": "length"
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11},
                "kv_transfer_params": self._make_kv_params()
            })
        else:
            self._send_json(200, {
                "id": cmpl_id,
                "object": "text_completion",
                "created": int(time.time()),
                "model": model,
                "choices": [{
                    "index": 0,
                    "text": "The answer is 42.",
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
            })

    def _send_prefill_response(self, cmpl_id, model):
        """Prefill: non-streaming response with kv_transfer_params."""
        self._send_json(200, {
            "id": cmpl_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": ""},
                "finish_reason": "length"
            }],
            "usage": {"prompt_tokens": 12, "completion_tokens": 1, "total_tokens": 13},
            "kv_transfer_params": self._make_kv_params()
        })

    def _send_decode_response(self, cmpl_id, model):
        """Decode: non-streaming response."""
        self._send_json(200, {
            "id": cmpl_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hello! I am a mock vLLM decode response."},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
        })

    def _send_decode_stream(self, cmpl_id, model):
        """Decode: SSE streaming response."""
        tokens = ["Hello", "!", " I", " am", " a", " mock", " vLLM", " decode", " response", "."]
        chunks = []
        for i, token in enumerate(tokens):
            chunks.append({
                "id": cmpl_id,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [{
                    "index": 0,
                    "delta": {"content": token} if i > 0 else {"role": "assistant", "content": token},
                    "finish_reason": None
                }]
            })
        # Final chunk with finish_reason
        chunks.append({
            "id": cmpl_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop"
            }]
        })
        self._send_sse(chunks)

    @staticmethod
    def _make_kv_params(tp_size=1, blocks_per_rank=4):
        """Generate mock kv_transfer_params matching real vLLM nixl_connector.py format.

        remote_block_ids is a nested array: one list of block IDs per TP rank.
        """
        remote_block_ids = [
            list(range(i * 100, i * 100 + blocks_per_rank))
            for i in range(tp_size)
        ]
        return {
            "do_remote_prefill": True,
            "do_remote_decode": False,
            "remote_block_ids": remote_block_ids,
            "remote_host": "127.0.0.1",
            "remote_port": NIXL_PORT,
            "remote_engine_id": f"prefill-engine-{uuid.uuid4().hex[:8]}",
            "remote_request_id": str(uuid.uuid4()),
            "tp_size": tp_size
        }


class AdminHandler(BaseHTTPRequestHandler):
    """Admin HTTP server — health toggle and status.

    Binds to 127.0.0.1:9000 only (loopback). Never exposed externally.
    Access via: docker exec <ep> curl -s -X POST http://localhost:9000/admin/health-fail

    SECURITY: loopback binding limits reachability to 'docker exec'.
    Additionally, if the env var MOCK_VLLM_ADMIN_TOKEN is set, every
    admin request MUST carry a matching 'X-Admin-Token' header. This
    upgrades the boundary from 'authentication-by-network-location'
    to 'authentication-by-shared-secret', so the mock is safe to reuse
    outside CICD (e.g. as a chaos-engineering tool in a shared cluster).
    When the env var is unset the loopback-only behaviour is preserved
    for backwards compatibility with the existing CICD harness (WR-11).
    """

    def _auth_ok(self) -> bool:
        """WR-11: shared-secret check. Returns True if no token is
        configured (CICD mode) or if the request carries the right one."""
        expected = os.environ.get("MOCK_VLLM_ADMIN_TOKEN", "")
        if not expected:
            return True
        return self.headers.get("X-Admin-Token", "") == expected

    def _reply_json(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        global _health_ok, _fail_next
        if not self._auth_ok():
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/admin/fail-next":
            _fail_next = True
            self._reply_json({"fail_next": True})
            print(f"[{SERVER_ROLE}] [admin] fail-next ARMED", flush=True)
        elif self.path == "/admin/reset":
            _fail_next = False
            self._reply_json({"fail_next": False})
            print(f"[{SERVER_ROLE}] [admin] knobs RESET", flush=True)
        elif self.path == "/admin/health-fail":
            _health_ok = False
            data = json.dumps({"health_ok": False}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            print(f"[{SERVER_ROLE}] [admin] health set to FAIL", flush=True)
        elif self.path == "/admin/health-ok":
            _health_ok = True
            data = json.dumps({"health_ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            print(f"[{SERVER_ROLE}] [admin] health set to OK", flush=True)
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if not self._auth_ok():
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/admin/status":
            data = json.dumps({
                "health_ok": _health_ok,
                "fail_next": _fail_next,
                "role": SERVER_ROLE,
                "request_count": _request_count,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress admin server access logs


def _start_admin_server():
    """Start admin HTTP server on 127.0.0.1:9000 (loopback only).

    Daemon thread — exits when main thread exits.
    SECURITY: 127.0.0.1 binding ensures admin API is not reachable from the
    host network — only via 'docker exec' inside the container.
    """
    admin = HTTPServer(("127.0.0.1", 9000), AdminHandler)
    admin.serve_forever()


def _start_nixl_listener(port, role):
    """Start a mock NIXL side-channel TCP listener (simulates VLLM_NIXL_SIDE_CHANNEL_PORT).

    Real vLLM listens on this port for ZMQ/UCX KV block transfer coordination.
    The mock simply accepts TCP connections and logs them so CICD T9 can verify
    the port is reachable and loxilb is embedding the correct address in X-Request-Id.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(16)
        print(f"[{role}] NIXL side-channel listening on port {port} (VLLM_NIXL_SIDE_CHANNEL_PORT)", flush=True)
        while True:
            try:
                conn, addr = sock.accept()
                print(f"[{role}] NIXL side-channel connection from {addr[0]}:{addr[1]}", flush=True)
                conn.close()
            except OSError:
                break
        sock.close()
    except Exception as exc:
        print(f"[{role}] NIXL side-channel listener failed on port {port}: {exc}", flush=True)


def main():
    global SERVER_ROLE, NIXL_PORT, EP_IDX, _args

    parser = argparse.ArgumentParser(description="Mock vLLM server for P/D testing")
    parser.add_argument("--role", choices=["prefill", "decode", "normal"],
                        default="normal", help="Server role (prefill/decode/normal)")
    parser.add_argument("--port", type=int, default=8000, help="Listen port")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--nixl-port", type=int, default=0,
                        help="NIXL side-channel TCP port (VLLM_NIXL_SIDE_CHANNEL_PORT); 0=disabled")
    parser.add_argument("--fail-every", type=int, default=0,
                        help="Return HTTP 500 on every Nth request (0=disabled). "
                             "NOTE: does NOT trigger circuit breaker (CB requires TCP failure).")
    parser.add_argument("--ep-idx", type=int, default=0,
                        help="EP index (1..N); echoed as X-Prefill-Ep / X-Decode-Ep response "
                             "header so Phase L CICD harness can correlate the (prefill, decode) "
                             "pair across failover for restore_rate measurement.")
    args = parser.parse_args()

    SERVER_ROLE = args.role
    NIXL_PORT = args.nixl_port
    EP_IDX = args.ep_idx
    _args = args

    # Start admin HTTP server on loopback (127.0.0.1:9000) as daemon thread.
    # Provides /admin/health-fail, /admin/health-ok, /admin/fail-next,
    # /admin/reset, /admin/status endpoints.
    admin_thread = threading.Thread(target=_start_admin_server, daemon=True)
    admin_thread.start()

    # Start NIXL side-channel listener if configured (simulates vLLM --kv-connector-port).
    # This allows T9 in validation.sh to verify loxilb embeds the NIXL port, not HTTP port,
    # in the X-Request-Id ___prefill_addr_IP:NIXL_PORT___ / ___decode_addr_IP:NIXL_PORT___ format.
    if args.nixl_port:
        nixl_thread = threading.Thread(
            target=_start_nixl_listener,
            args=(args.nixl_port, SERVER_ROLE),
            daemon=True,
        )
        nixl_thread.start()
    server = HTTPServer((args.host, args.port), MockVLLMHandler)
    print(f"Mock vLLM server starting: role={SERVER_ROLE} addr={args.host}:{args.port} nixl_port={args.nixl_port or 'disabled'} admin=127.0.0.1:9000 fail_every={args.fail_every or 'disabled'} ep_idx={EP_IDX}")
    print(f"Model: {MODEL_NAME}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
