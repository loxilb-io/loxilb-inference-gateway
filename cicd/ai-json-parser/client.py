#!/usr/bin/env python3
"""Drive the OpenAI JSON boundary matrix from a Linux Docker host."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
from pathlib import Path
import socket
import select
import subprocess
import threading
import time
import urllib.error
import urllib.request

MODEL = "Qwen/Qwen3-32B-FP8"
BODY_BYTES = 106206
CASE_COUNT = 133
RESULT_LOCK = threading.Lock()
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


def token_count(value):
    if isinstance(value, dict):
        return 1 + len(value) + sum(token_count(item) for item in value.values())
    if isinstance(value, list):
        return 1 + sum(token_count(item) for item in value)
    return 1


def payload(size, model_last=False, body_bytes=BODY_BYTES):
    messages = [
        {"role": "user" if index % 2 == 0 else "assistant",
         "content": "Synthetic compaction message."}
        for index in range(16)
    ]
    tools = [
        {"type": "function", "function": {
            "name": f"mock_{index}", "description": "Synthetic tool.",
            "parameters": {"type": "object",
                           "properties": {"value": {"type": "string", "enum": []}},
                           "required": ["value"]}}}
        for index in range(67)
    ]
    value = {"model": MODEL, "messages": messages, "tools": tools, "stream": True}
    if model_last:
        value["model"] = value.pop("model")
    needed = size - token_count(value)
    if needed < 0:
        raise ValueError("token target is smaller than the fixture skeleton")
    for index in range(needed):
        tools[index % len(tools)]["function"]["parameters"]["properties"]["value"]["enum"].append(
            f"v{index}"
        )
    padding = body_bytes - len(encode(value))
    if padding < 0:
        raise ValueError("fixture exceeds its fixed byte budget")
    messages[0]["content"] += "x" * padding
    raw = encode(value)
    assert token_count(value) == size and len(raw) == body_bytes
    return raw


def get_json(url):
    with HTTP.open(url, timeout=3) as response:
        return json.load(response)


def configure(gateway, backend, evidence):
    for attempt in range(40):
        try:
            version = get_json(f"http://{gateway}:11111/netlox/v1/version")
            if get_json(f"http://{backend}:8000/receipts") == {}:
                break
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    else:
        raise RuntimeError("gateway or mock readiness timed out")
    (evidence / "version.json").write_text(json.dumps(version, indent=2) + "\n")

    for port, protocol, auth in [(8081, "http1", "disabled"),
                                 (8082, "http1", "required"),
                                 (8083, "http2", "disabled"), (8084, "http2", "required"),
                                 (8085, "http1", "disabled")]:
        rule = {
            "serviceArguments": {
                "externalIP": gateway, "port": port, "protocol": "tcp",
                "mode": 4, "sel": 0, "host": gateway, "model_name": "m" if port == 8085 else MODEL,
                "sse_mode": True, "inactiveTimeOut": 30,
                "backend_protocol": protocol, "api_key_auth": auth,
            },
            "endpoints": [{"endpointIP": backend, "targetPort": 8000, "weight": 1}],
        }
        for attempt in range(40):
            request = urllib.request.Request(
                f"http://{gateway}:11111/netlox/v1/config/loadbalancer",
                data=encode(rule), headers={"Content-Type": "application/json"},
            )
            try:
                with HTTP.open(request, timeout=5) as response:
                    status, reply = response.status, response.read()
            except urllib.error.HTTPError as error:
                status, reply = error.code, error.read()
            if (b"boot config replay settles" in reply
                    or b"frozen while a snapshot restore is in progress" in reply):
                time.sleep(1)
                continue
            if status != 200 or b"success" not in reply.lower():
                raise RuntimeError(f"rule {port} failed: HTTP {status} {reply!r}")
            break
        else:
            raise RuntimeError("boot configuration never settled")

    rules = get_json(f"http://{gateway}:11111/netlox/v1/config/loadbalancer/all")
    (evidence / "rules.json").write_text(json.dumps(rules, indent=2) + "\n")
    actual = {
        item["serviceArguments"]["port"]: item["serviceArguments"]
        for item in rules["lbAttr"]
    }
    for port in (8081, 8082, 8083, 8084):
        assert actual[port]["model_name"] == MODEL
    assert actual[8083]["backend_protocol"] == "http2"
    assert actual[8085]["model_name"] == "m"
    keys = {}
    descriptions = {}
    for name, models in [("allowed", [MODEL]), ("denied", ["other-model"])]:
        request = urllib.request.Request(
            f"http://{gateway}:11111/netlox/v1/config/ai/apikey",
            data=encode({"tenant_id": "json-parser-fixture", "name": name,
                         "allowed_models": models, "rate_limit_rps": 10000,
                         "burst_size": 10000, "tokens_per_min": 1000000000}),
            headers={"Content-Type": "application/json"},
        )
        for attempt in range(40):
            try:
                with HTTP.open(request, timeout=10) as response:
                    created = json.load(response)
                break
            except urllib.error.HTTPError as error:
                if error.code != 503:
                    raise
                time.sleep(1)
        else:
            raise RuntimeError("isolated key store never became ready")
        keys[name] = created["raw_key"]
        descriptions[name] = {"key_id": created.get("key_id"), "allowed_models": models}
    (evidence / "auth-fixtures.json").write_text(json.dumps(descriptions, indent=2) + "\n")
    return keys



class Matrix:
    def __init__(self, gateway, backend, evidence, keys=None):
        self.gateway = gateway
        self.backend = backend
        self.evidence = evidence
        self.results = {}
        self.keys = keys or {}

    def receipts(self):
        return get_json(f"http://{self.backend}:8000/receipts")

    def record(self, request_id, raw, status, reply, receipt_count,
               expected_status, expected_error=None, **detail):
        done = b"[DONE]" in reply and b"mock-backend-receipt" in reply
        error = None
        error_message = None
        if status != 200:
            try:
                parsed_error = json.loads(reply)
                error = parsed_error.get("error")
                error_message = parsed_error.get("message")
            except (ValueError, AttributeError):
                error = "invalid_error_body"
        passed = status == expected_status
        if expected_status == 200:
            passed &= receipt_count == 1 and done
        else:
            passed &= receipt_count == 0 and not done and error == expected_error
        if expected_error == "invalid_model_field":
            passed &= isinstance(error_message, str) and "model" in error_message and "127" in error_message
        if detail.get("early_expected") is not None:
            passed &= detail["early_backend_head"] == int(detail["early_expected"])
        result = {
            "status": status, "error": error, "message": error_message, "done": done,
            "backend_receipts": receipt_count, "expected": bool(passed),
            "body_bytes": len(raw), "body_sha256": hashlib.sha256(raw).hexdigest(),
            **detail,
        }
        with RESULT_LOCK:
            if request_id in self.results:
                raise RuntimeError(f"duplicate matrix ID {request_id}")
            self.results[request_id] = result
            temporary = self.evidence / "expected.json.tmp"
            temporary.write_text(json.dumps(self.results, indent=2) + "\n")
            temporary.replace(self.evidence / "expected.json")
            print(json.dumps({"id": request_id, **result}), flush=True)

    def query(self, raw, request_id, *, media="application/json", offset=None,
              pieces=None, connection=None, xmodel=False, extra="", early=None,
              port=8081, expected_status=200, expected_error=None, api_key=None,
              chunked=False, headers_only=False, trailers=False, final_chunk_at=None, pause_after=None):
        before = self.receipts().get(request_id, 0)
        owned = connection is None
        if owned:
            connection = socket.create_connection((self.gateway, port), timeout=15)
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        head = f"POST /v1/chat/completions HTTP/1.1\r\nHost: {self.gateway}\r\n".encode()
        if offset is not None:
            pad, marker = b"X-Probe-Pad: ", b"\r\nContent-Type: "
            head += pad + b"a" * (offset - len(head) - len(pad) - len(marker))
            head += marker + media.encode() + b"\r\n"
            assert head.index(media.encode()) == offset
        elif media is not None:
            head += f"cOnTeNt-TyPe: {media}\r\n".encode()
        if xmodel:
            head += f"X-Model: {MODEL}\r\n".encode()
        head += extra.encode()
        if api_key:
            head += f"X-Api-Key: {api_key}\r\n".encode()
        if chunked:
            head += b"Transfer-Encoding: chunked\r\n"
        else:
            head += f"Content-Length: {len(raw)}\r\n".encode()
        head += f"X-Request-Id: {request_id}\r\n".encode()
        head += b"Connection: close\r\n\r\n" if owned else b"Connection: keep-alive\r\n\r\n"
        early_seen = None
        stream_probe = None
        pause_probe = None
        started = time.perf_counter()
        try:
            start = 0
            for end in sorted(pieces(head) if pieces else []):
                connection.sendall(head[start:end])
                start = end
                time.sleep(0.06)
            connection.sendall(head[start:])
            if early is not None:
                deadline = time.monotonic() + 1
                early_seen = 0
                while time.monotonic() < deadline:
                    early_seen = get_json(
                        f"http://{self.backend}:8000/heads"
                    ).get(request_id, 0)
                    if early_seen:
                        break
                    time.sleep(0.025)
            if not headers_only:
                stride = 16384 if chunked or len(raw) > 768 * 1024 else len(raw)
                body_start = 0
                if pause_after is not None:
                    assert not chunked and 0 < pause_after < len(raw)
                    connection.sendall(raw[:pause_after])
                    pause_started = time.monotonic()
                    time.sleep(1)
                    pause_probe = {"seconds": time.monotonic() - pause_started,
                                   "heads": get_json(f"http://{self.backend}:8000/heads").get(request_id, 0),
                                   "receipts": self.receipts().get(request_id, 0)}
                    assert pause_probe["seconds"] >= 1 and pause_probe["heads"] == 1 and pause_probe["receipts"] == 0, pause_probe
                    body_start = pause_after
                tail_at = None if final_chunk_at is None else final_chunk_at - body_start
                for offset_at, part in body_parts(raw[body_start:], stride, tail_at):
                    offset_at += body_start
                    wire = (f"{len(part):x}\r\n".encode() + part + b"\r\n") if chunked else part
                    try:
                        connection.sendall(wire)
                    except (BrokenPipeError, ConnectionResetError):
                        break
                    if select.select([connection], [], [], 0)[0]:
                        break
                    if (stream_probe is None and len(raw) > 768 * 1024
                            and offset_at + len(part) >= 64 * 1024
                            and expected_status in (200, 400)):
                        deadline = time.monotonic() + 2
                        while time.monotonic() < deadline:
                            heads = get_json(f"http://{self.backend}:8000/heads").get(request_id, 0)
                            if heads:
                                break
                            time.sleep(0.01)
                        stream_probe = {"heads": heads, "receipts": self.receipts().get(request_id, 0)}
                        assert stream_probe == {"heads": 1, "receipts": 0}, stream_probe
                    if stride < len(raw):
                        time.sleep(0.001)
                if chunked and not select.select([connection], [], [], 0)[0]:
                    ending = b"0\r\nContent-Type: text/plain\r\n\r\n" if trailers else b"0\r\n\r\n"
                    try:
                        connection.sendall(ending[:2])
                        time.sleep(0.02)
                        connection.sendall(ending[2:])
                    except (BrokenPipeError, ConnectionResetError):
                        pass
            response = http.client.HTTPResponse(connection)
            response.begin()
            status, reply = response.status, response.read()
            elapsed_ms = (time.perf_counter() - started) * 1000
            response.close()
        finally:
            if owned:
                connection.close()
        self.record(
            request_id, raw, status, reply,
            self.receipts().get(request_id, 0) - before,
            expected_status, expected_error, protocol="http1",
            content_type_offset=offset, early_backend_head=early_seen, early_expected=early,
            latency_ms=elapsed_ms, chunked=chunked, streaming_probe=stream_probe,
            pause_after=pause_after, pause_probe=pause_probe,
        )

    def query_h2(self, raw, request_id, expected_status=200, expected_error=None,
                 api_key=None, extra_type=None, media="application/json", xmodel=False):
        body_path = self.evidence / "h2-request.json"
        body_path.write_bytes(raw)
        command = [
            "curl", "--silent", "--show-error", "--noproxy", "*",
            "--http2-prior-knowledge", "--max-time", "15",
            "-H", f"Content-Type: {media}", "-H", f"X-Request-Id: {request_id}",
            "--data-binary", f"@{body_path}", "-w", "\n%{http_code}",
            f"http://{self.gateway}:{8084 if api_key else 8083}/v1/chat/completions",
        ]
        if api_key:
            command.extend(["-H", f"X-Api-Key: {api_key}"])
        if xmodel:
            command.extend(["-H", f"X-Model: {MODEL}"])
        if extra_type:
            command.extend(["-H", f"Content-Type: {extra_type}"])
        started = time.perf_counter()
        response = subprocess.run(command, capture_output=True, check=True, timeout=20)
        reply, status = response.stdout.rsplit(b"\n", 1)
        error = expected_error
        self.record(request_id, raw, int(status), reply,
                    self.receipts().get(request_id, 0), expected_status,
                    error, protocol="h2", latency_ms=(time.perf_counter() - started) * 1000)

    def run(self):
        assert self.receipts() == {}
        trees = [
            (2047, False), (2048, False), (2049, False), (3586, False),
            (3586, True), (2048, True), (8192, False), (8193, False),
            (8192, True), (8193, True),
        ]
        for size, last in trees:
            for trial in range(1, 4):
                position = "last" if last else "first"
                self.query(
                    payload(size, last), f"boundary-tree-{size}-{position}-{trial}",
                    expected_status=200,
                )

        self.query(b'["generic",{"model":"nested"}]', "boundary-json-array", xmodel=True)
        raw = payload(2048)
        for offset in (2032, 2033):
            for trial in range(1, 4):
                self.query(raw, f"boundary-ct-{offset}-{trial}", offset=offset)
        self.query(raw, "boundary-split-name-value-length", offset=2033, pieces=split_media)
        self.query(raw, "boundary-mixed-case-parameters",
                   media="ApPlIcAtIoN/JsOn \t; charset=utf-8", offset=2033)

        plain = b"x" * BODY_BYTES
        form = b"message=" + b"a" * (BODY_BYTES - len(b"message="))
        self.query(plain, "boundary-header-name-decoy", media="text/plain", xmodel=True,
                   extra="X-Content-Type: application/json\r\n", early=True)
        self.query(plain, "boundary-media-suffix-decoy", media="application/json-extra",
                   xmodel=True, early=True)
        self.query(form, "boundary-real-form-buffered",
                   media="application/x-www-form-urlencoded", xmodel=True, early=False)

        with socket.create_connection((self.gateway, 8081), timeout=15) as connection:
            self.query(raw, "boundary-keepalive-json-1",
                       connection=connection, offset=2033, early=False)
            self.query(plain, "boundary-keepalive-no-content-type",
                       connection=connection, media=None, xmodel=True, early=True)
            self.query(form, "boundary-keepalive-form", connection=connection,
                       media="application/x-www-form-urlencoded", xmodel=True, early=False)
            self.query(raw, "boundary-keepalive-json-2", connection=connection, pieces=split_media)
            self.query(payload(8193), "boundary-keepalive-limit", connection=connection,
                       expected_status=200)

        for size in (3586, 8193):
            self.query(payload(size), f"boundary-auth-missing-{size}", port=8082,
                       expected_status=401, expected_error="invalid_api_key")
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(
                lambda index: self.query(payload(3586), f"boundary-parallel-{index}"),
                range(16),
            ))
        for size in (3586, 8192, 8193):
            for last in (False, True):
                position = "last" if last else "first"
                self.query_h2(payload(size, last), f"boundary-h2-{size}-{position}",
                              200)

        for byte_size in (800 * 1024, 2 * 1024 * 1024):
            large = payload(8193, body_bytes=byte_size)
            self.query(large, f"boundary-large-h1-{byte_size}")
            self.query_h2(large, f"boundary-large-h2-{byte_size}")
        for location, escaped, byte_size in [
            ("front", False, BODY_BYTES), ("tail", False, 800 * 1024),
            ("tail", True, 800 * 1024),
        ]:
            duplicate = duplicate_payload(location, escaped, byte_size)
            suffix = f"{location}-{escaped}"
            self.query(duplicate, f"boundary-duplicate-h1-{suffix}",
                       expected_status=400, expected_error="duplicate_model_field")
            self.query_h2(duplicate, f"boundary-duplicate-h2-{suffix}", 400,
                          "duplicate_model_field")
        self.query(payload(8193, body_bytes=2 * 1024 * 1024), "boundary-chunked-normal",
                   chunked=True)
        self.query(payload(8193, body_bytes=800 * 1024), "boundary-chunked-trailers",
                   chunked=True, trailers=True)
        for location, escaped, byte_size in [
            ("front", False, BODY_BYTES), ("tail", False, 800 * 1024),
            ("tail", True, 800 * 1024),
        ]:
            self.query(duplicate_payload(location, escaped, byte_size),
                       f"boundary-chunked-duplicate-{location}-{escaped}", chunked=True,
                       expected_status=400, expected_error="duplicate_model_field")
        pause_prefix = b'{"model":"m"}'
        self.query(pause_prefix + b" " * (800 * 1024), "boundary-stream-guard-pause",
                   port=8085, pause_after=len(pause_prefix))
        user_duplicate, final_chunk_at = chunked_user_duplicate()
        self.query(user_duplicate, "boundary-chunked-user-duplicate-tail", chunked=True,
                   final_chunk_at=final_chunk_at, expected_status=400,
                   expected_error="duplicate_user_field")
        deep = (b'{"model":"' + MODEL.encode() + b'","user":"deep-session","nested":'
                + b"[" * 12000 + b"0" + b"]" * 12000 + b"}")
        self.query(deep, "boundary-deep-h1")
        self.query_h2(deep, "boundary-deep-h2")
        for media in ("application/json", "text/plain"):
            suffix = media.split("/")[-1]
            self.query(raw, f"boundary-duplicate-type-h1-{suffix}",
                       extra=f"Content-Type: {media}\r\n", headers_only=True,
                       expected_status=400, expected_error="duplicate_content_type")
            self.query_h2(raw, f"boundary-duplicate-type-h2-{suffix}", 400,
                          "duplicate_content_type", extra_type=media)
        for byte_size in (BODY_BYTES, 800 * 1024):
            authenticated = payload(8193, body_bytes=byte_size)
            for name in ("allowed", "denied"):
                status = 200 if name == "allowed" else 403
                error = None if name == "allowed" else "model_not_allowed"
                self.query(authenticated, f"boundary-auth-h1-{name}-{byte_size}",
                           port=8082, api_key=self.keys[name],
                           expected_status=status, expected_error=error)
                self.query_h2(authenticated, f"boundary-auth-h2-{name}-{byte_size}",
                              status, error, api_key=self.keys[name])
        for duplicate_first in (False, True):
            raw_model = b'{"model":null'
            if duplicate_first:
                raw_model += b',"model":"other-model"'
            raw_model += b'}'
            code = "duplicate_model_field" if duplicate_first else "invalid_model_field"
            self.query(raw_model, f"boundary-invalid-model-h1-{duplicate_first}", port=8082,
                       api_key=self.keys["allowed"], expected_status=400, expected_error=code)
            self.query_h2(raw_model, f"boundary-invalid-model-h2-{duplicate_first}", 400,
                          code, api_key=self.keys["allowed"])
        for kind, malformed in [
            ("hidden-model", b'{"model":"ok","a":1"model":"evil"}'),
            ("trailing-comma", b'{"model":"a",}'),
            ("literal", b'{"a":tru,"model":"a"}'),
        ]:
            self.query(malformed, f"boundary-malformed-h1-{kind}",
                       expected_status=400, expected_error="invalid_json_body")
            self.query_h2(malformed, f"boundary-malformed-h2-{kind}", 400, "invalid_json_body")
        for escaped in (False, True):
            user_key = b'us\\u0065r' if escaped else b'user'
            user_dup = b'{"model":"' + MODEL.encode() + b'","user":"first","' + user_key + b'":"last"}'
            self.query(user_dup, f"boundary-user-duplicate-h1-{escaped}",
                       expected_status=400, expected_error="duplicate_user_field")
            self.query_h2(user_dup, f"boundary-user-duplicate-h2-{escaped}", 400, "duplicate_user_field")
        for size in (127, 128):
            long_model = b'{"model":"' + b'm' * size + b'"}'
            status = 400 if size == 128 else 403
            error = "invalid_model_field" if size == 128 else "model_not_allowed"
            for authenticated in (False, True) if size == 128 else (True,):
                key = self.keys["allowed"] if authenticated else None
                self.query(long_model, f"boundary-model-length-h1-{size}-{authenticated}",
                           port=8082 if authenticated else 8081, api_key=key,
                           expected_status=status, expected_error=error)
                self.query_h2(long_model, f"boundary-model-length-h2-{size}-{authenticated}",
                              status, error, api_key=key)
        self.query(b'{"model":null}', "boundary-model-null-keyless-h1",
                   expected_status=400, expected_error="invalid_model_field")
        self.query_h2(b'{"model":null}', "boundary-model-null-keyless-h2", 400, "invalid_model_field")
        self.query_h2(b'{not JSON', "boundary-h2-text-plain-object-prefix", media="text/plain", xmodel=True)
        self.query_h2(b'{not JSON', "boundary-h2-json-suffix", media="application/json-extra", xmodel=True)
        self.query_h2(b'{"model":null}', "boundary-h2-json-parameters", 400, "invalid_model_field",
                      media="ApPlIcAtIoN/JsOn \t; charset=utf-8")
        self.query_h2(b'{not JSON', "boundary-h2-text-plain-authenticated", media="text/plain",
                      xmodel=True, api_key=self.keys["allowed"])
        self.query_h2(b'{"model":"other-model"}', "boundary-h2-text-plain-model-policy", 403,
                      "model_not_allowed", media="text/plain", xmodel=True, api_key=self.keys["allowed"])
        normal_primitives = b'{"model":"' + MODEL.encode() + b'","a":true,"b":false,"c":null,"d":-1.5e3}'
        self.query(normal_primitives, "boundary-primitives-h1")
        self.query_h2(normal_primitives, "boundary-primitives-h2")
        duplicate = duplicate_payload("tail", True, 800 * 1024)
        self.query(duplicate, "boundary-auth-duplicate-h1", port=8082,
                   api_key=self.keys["allowed"], expected_status=400,
                   expected_error="duplicate_model_field")
        self.query_h2(duplicate, "boundary-auth-duplicate-h2", 400,
                      "duplicate_model_field", api_key=self.keys["allowed"])

        receipts = self.receipts()
        (self.evidence / "receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
        assert len(self.results) == CASE_COUNT, "matrix case count changed"
        assert all(result["expected"] for result in self.results.values()), "response checks failed"
        assert receipts == {
            request_id: 1 for request_id, result in self.results.items() if result["status"] == 200
        }, "backend receipt inventory differs from successful requests"
        print("BOUNDARY_RUNTIME_PASS", flush=True)


def body_parts(raw, stride, final_chunk_at=None):
    """Keep a selected tail in its own final data chunk."""
    end = len(raw) if final_chunk_at is None else final_chunk_at
    if not 0 < end <= len(raw):
        raise ValueError("final chunk boundary must be inside the body")
    for offset in range(0, end, stride):
        yield offset, raw[offset:min(offset + stride, end)]
    if end < len(raw):
        yield end, raw[end:]


def chunked_user_duplicate():
    first = b',"user":"first"'
    tail = b',"user":"last"}'
    # The final data chunk starts only after 800KiB of valid object prefix.
    raw = payload(8193, body_bytes=800 * 1024 + 1 - len(first))
    marker = b'"model":"' + MODEL.encode() + b'"'
    prefix = raw.replace(marker, marker + first, 1)[:-1]
    assert len(prefix) == 800 * 1024
    return prefix + tail, len(prefix)


def duplicate_payload(location, escaped, byte_size):
    key = b"mod\\u0065l" if escaped else b"model"
    duplicate = b',"' + key + b'":"other-model"'
    raw = payload(8193, body_bytes=byte_size - len(duplicate))
    if location == "tail":
        return raw[:-1] + duplicate + b"}"
    marker = b'"model":"' + MODEL.encode() + b'"'
    return raw.replace(marker, marker + duplicate, 1)


def split_media(head):
    name = head.lower().index(b"content-type")
    value = head.lower().index(b"application/json")
    length = head.index(b"Content-Length: ") + len(b"Content-Length: ")
    return [name + 3, name + 9, value + 4, value + 12, length + 2, length + 4]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gateway")
    parser.add_argument("backend")
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    version = subprocess.run(["curl", "--version"], capture_output=True, text=True, check=True)
    if "HTTP2" not in version.stdout:
        raise RuntimeError("curl must support HTTP/2")
    keys = configure(args.gateway, args.backend, args.evidence)
    matrix = Matrix(args.gateway, args.backend, args.evidence, keys)
    try:
        matrix.run()
    finally:
        (args.evidence / "receipts.json").write_text(json.dumps(matrix.receipts(), indent=2) + "\n")


if __name__ == "__main__":
    main()
