#!/usr/bin/env python3
"""Unit tests for gen-traffic.py: SSE completion accounting and seed derivation.
Run: python3 -m unittest tools/kv-agent-traffic/test_gen_traffic.py (standard library only)."""
import importlib.util
import io
import json
import os
import random
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("TARGETS", "kv=http://127.0.0.1:9/v1/chat/completions")
os.environ["METRICS_PORT"] = "0"
os.environ["RECORD_CSV"] = ""
os.environ["MODE"] = "agent"
_spec = importlib.util.spec_from_file_location("gen_traffic", os.path.join(HERE, "gen-traffic.py"))
gt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gt)


def chunk(delta, usage=None):
    j = {"choices": [{"index": 0, "delta": delta}]}
    if usage:
        j["usage"] = usage
    return b"data: " + json.dumps(j).encode() + b"\n"


class FakeResponse:
    def __init__(self, status, lines):
        self.status = status
        self._lines = lines

    def __iter__(self):
        return iter(self._lines)

    def getheader(self, name):
        return None

    def read(self):
        return b""


class FakeSock:
    def getsockname(self):
        return ("127.0.0.1", 40000)


class FakeConnection:
    """http.client.HTTPConnection stand-in: the next response is taken from SCRIPT."""
    SCRIPT = []

    def __init__(self, host, port, timeout=None):
        self.sock = FakeSock()

    def connect(self):
        pass

    def request(self, method, path, body=None, headers=None):
        pass

    def getresponse(self):
        return FakeConnection.SCRIPT.pop(0)

    def close(self):
        pass


class SSECompletionTest(unittest.TestCase):
    def setUp(self):
        self._prev = gt.http.client.HTTPConnection
        gt.http.client.HTTPConnection = FakeConnection
        gt.AGENT_METRICS = gt.AgentMetrics()
        self._stdout, sys.stdout = sys.stdout, io.StringIO()

    def tearDown(self):
        gt.http.client.HTTPConnection = self._prev
        sys.stdout = self._stdout

    def send(self, lines, status=200):
        FakeConnection.SCRIPT = [FakeResponse(status, lines)]
        body = {"model": "m", "messages": [{"role": "user", "content": "hi"}], "stream": True}
        return gt.agent_request("kv", "http://127.0.0.1:9/v1/chat/completions", body, "a0", "0-0", 0)

    def recorded(self):
        return {st: n for (_r, _a, _s, st), n in gt.AGENT_METRICS.requests.items()}

    def test_complete_stream_is_an_answer(self):
        st, msg, calls, _ep, ttft, _secs, usage = self.send([
            chunk({"role": "assistant"}), chunk({"content": "pong"}),
            chunk({}, usage={"prompt_tokens": 3, "completion_tokens": 1}), b"data: [DONE]\n"])
        self.assertEqual(st, 200)
        self.assertEqual(msg["content"], "pong")
        self.assertIsNotNone(ttft)
        self.assertEqual(usage["completion_tokens"], 1)
        self.assertEqual(self.recorded(), {"200": 1})

    def test_error_chunk_then_eof_is_sse_error(self):
        # The reviewer's case: headers say 200, the stream carries an error
        # object and ends without [DONE]. Must not count as an answer.
        st, msg, calls, *_ = self.send([
            chunk({"role": "assistant"}),
            b'data: {"error": {"message": "engine fault mid-stream", "type": "InternalServerError", "code": 500}}\n'])
        self.assertEqual(st, "sse_error")
        self.assertIsNone(msg)
        self.assertEqual(calls, [])
        self.assertEqual(self.recorded(), {"sse_error": 1})
        self.assertIn("stream error", sys.stdout.getvalue())

    def test_eof_without_done_is_sse_truncated(self):
        st, msg, *_ = self.send([chunk({"role": "assistant"}), chunk({"content": "po"})])
        self.assertEqual(st, "sse_truncated")
        self.assertIsNone(msg)
        self.assertEqual(self.recorded(), {"sse_truncated": 1})

    def test_tool_call_stream_with_done(self):
        st, msg, calls, *_ = self.send([
            chunk({"tool_calls": [{"index": 0, "id": "c1", "type": "function", "function": {"name": "f", "arguments": "{\"a\":"}}]}),
            chunk({"tool_calls": [{"index": 0, "function": {"arguments": " 1}"}}]}),
            b"data: [DONE]\n"])
        self.assertEqual(st, 200)
        self.assertEqual(calls[0]["function"]["arguments"], '{"a": 1}')
        self.assertEqual(calls[0]["id"], "c1")

    def test_non_200_is_its_status(self):
        st, msg, *_ = self.send([], status=503)
        self.assertEqual(st, 503)
        self.assertEqual(self.recorded(), {"503": 1})


class SeedTest(unittest.TestCase):
    def test_seed_int_is_an_int_random_accepts(self):
        s = gt.seed_int("tools", 67)
        self.assertIsInstance(s, int)
        self.assertLess(s, 1 << 64)
        random.Random(s)  # a tuple seed raises TypeError on Python >= 3.11

    def test_seed_int_is_deterministic_and_distinct(self):
        self.assertEqual(gt.seed_int("tools", 67), gt.seed_int("tools", 67))
        self.assertNotEqual(gt.seed_int("tools", 67), gt.seed_int("tools", 10))
        self.assertNotEqual(gt.seed_int("kv", "a0", 0, 0), gt.seed_int("kv", "a0", 0, 1))

    def test_agent_tools_reproducible(self):
        a = gt.agent_tools(0, 5)
        b = gt.agent_tools(0, 5)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 5)
        self.assertTrue(all(t["function"]["name"].endswith("_a0") for t in a))

    def test_run_info_fields(self):
        info = gt.run_info()
        self.assertEqual(len(info["gen_traffic_sha256"]), 64)
        self.assertEqual(info["python"], sys.version.split()[0])
        self.assertIn(info["system_prompt"], ("per-agent", "shared"))


class SharedSystemPromptTest(unittest.TestCase):
    def test_shared_prompt_is_identical_across_agents(self):
        prev = gt.SYSTEM_PROMPT
        try:
            gt.SYSTEM_PROMPT = "shared"
            self.assertEqual(gt.agent_system_prompt(0, "s"), gt.agent_system_prompt(7, "s"))
            gt.SYSTEM_PROMPT = "per-agent"
            self.assertNotEqual(gt.agent_system_prompt(0, "s"), gt.agent_system_prompt(7, "s"))
        finally:
            gt.SYSTEM_PROMPT = prev


if __name__ == "__main__":
    unittest.main()
