#!/usr/bin/env python3
"""Drive the OpenAI JSON boundary matrix from a Linux Docker host."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
from pathlib import Path
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request

MODEL = "Qwen/Qwen3-32B-FP8"
BODY_BYTES = 106206
CASE_COUNT = 70
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


def payload(size, model_last=False):
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
    padding = BODY_BYTES - len(encode(value))
    if padding < 0:
        raise ValueError("fixture exceeds its fixed byte budget")
    messages[0]["content"] += "x" * padding
    raw = encode(value)
    assert token_count(value) == size and len(raw) == BODY_BYTES
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
                                 (8083, "http2", "disabled")]:
        rule = {
            "serviceArguments": {
                "externalIP": gateway, "port": port, "protocol": "tcp",
                "mode": 4, "sel": 0, "host": gateway, "model_name": MODEL,
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
    for port in (8081, 8082, 8083):
        assert actual[port]["model_name"] == MODEL
    assert actual[8083]["backend_protocol"] == "http2"


class Matrix:
    def __init__(self, gateway, backend, evidence):
        self.gateway = gateway
        self.backend = backend
        self.evidence = evidence
        self.results = {}

    def receipts(self):
        return get_json(f"http://{self.backend}:8000/receipts")

    def record(self, request_id, raw, status, reply, receipt_count,
               expected_status, expected_error=None, **detail):
        done = b"[DONE]" in reply and b"mock-backend-receipt" in reply
        error = None
        if status != 200:
            try:
                error = json.loads(reply).get("error")
            except (ValueError, AttributeError):
                error = "invalid_error_body"
        passed = status == expected_status
        if expected_status == 200:
            passed &= receipt_count == 1 and done
        else:
            passed &= receipt_count == 0 and not done and error == expected_error
        if detail.get("early_expected") is not None:
            passed &= detail["early_backend_head"] == int(detail["early_expected"])
        result = {
            "status": status, "error": error, "done": done,
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
              port=8081, expected_status=200, expected_error=None):
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
        head += f"Content-Length: {len(raw)}\r\nX-Request-Id: {request_id}\r\n".encode()
        head += b"Connection: close\r\n\r\n" if owned else b"Connection: keep-alive\r\n\r\n"
        early_seen = None
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
            connection.sendall(raw)
            response = http.client.HTTPResponse(connection)
            response.begin()
            status, reply = response.status, response.read()
            response.close()
        finally:
            if owned:
                connection.close()
        self.record(
            request_id, raw, status, reply,
            self.receipts().get(request_id, 0) - before,
            expected_status, expected_error, protocol="http1",
            content_type_offset=offset, early_backend_head=early_seen, early_expected=early,
        )

    def query_h2(self, raw, request_id, expected_status):
        body_path = self.evidence / "h2-request.json"
        body_path.write_bytes(raw)
        command = [
            "curl", "--silent", "--show-error", "--noproxy", "*",
            "--http2-prior-knowledge", "--max-time", "15",
            "-H", "Content-Type: application/json", "-H", f"X-Request-Id: {request_id}",
            "--data-binary", f"@{body_path}", "-w", "\n%{http_code}",
            f"http://{self.gateway}:8083/v1/chat/completions",
        ]
        response = subprocess.run(command, capture_output=True, check=True, timeout=20)
        reply, status = response.stdout.rsplit(b"\n", 1)
        error = "json_structure_limit_exceeded" if expected_status == 413 else None
        self.record(request_id, raw, int(status), reply,
                    self.receipts().get(request_id, 0), expected_status,
                    error, protocol="h2")

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
                    expected_status=200 if size <= 8192 else 413,
                    expected_error="json_structure_limit_exceeded" if size > 8192 else None,
                )

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
                       expected_status=413, expected_error="json_structure_limit_exceeded")

        for size in (3586, 8193):
            self.query(payload(size), f"boundary-auth-store-unavailable-{size}", port=8082,
                       expected_status=503, expected_error="policy_store_unavailable")
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(
                lambda index: self.query(payload(3586), f"boundary-parallel-{index}"),
                range(16),
            ))
        for size in (3586, 8192, 8193):
            for last in (False, True):
                position = "last" if last else "first"
                self.query_h2(payload(size, last), f"boundary-h2-{size}-{position}",
                              200 if size <= 8192 else 413)

        receipts = self.receipts()
        (self.evidence / "receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
        assert len(self.results) == CASE_COUNT, "matrix case count changed"
        assert all(result["expected"] for result in self.results.values()), "response checks failed"
        assert receipts == {
            request_id: 1 for request_id, result in self.results.items() if result["status"] == 200
        }, "backend receipt inventory differs from successful requests"
        print("BOUNDARY_RUNTIME_PASS", flush=True)


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
    configure(args.gateway, args.backend, args.evidence)
    Matrix(args.gateway, args.backend, args.evidence).run()


if __name__ == "__main__":
    main()
