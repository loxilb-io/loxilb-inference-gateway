#!/usr/bin/env python3
"""Keep the test oracle strict when a response or audit regression returns."""
import copy
import gzip
import hashlib
from pathlib import Path
import tempfile
import json
import unittest

from check_results import evaluate, read_audit
from client import CASE_COUNT, MODEL, body_parts, chunked_user_duplicate, duplicate_payload, payload, token_count


class OracleTests(unittest.TestCase):
    def test_chunked_user_duplicate_is_in_final_chunk(self):
        raw, boundary = chunked_user_duplicate()
        parts = list(body_parts(raw, 16384, boundary))
        self.assertEqual(boundary, 800 * 1024)
        self.assertEqual(b"".join(part for _, part in parts), raw)
        self.assertEqual(parts[-1], (boundary, b',"user":"last"}'))
        pairs = json.loads(raw, object_pairs_hook=list)
        self.assertEqual([value for key, value in pairs if key == "user"], ["first", "last"])

    def test_declared_matrix_count_is_enforced(self):
        _, summary = evaluate({}, [], {})
        self.assertEqual(summary["declared"], CASE_COUNT)
        self.assertFalse(summary["passed"])
        self.assertIn(f"executed 0 cases, expected {CASE_COUNT}", summary["errors"])

    def test_pause_requires_guard_log_and_incomplete_receipt(self):
        request_id = "boundary-stream-guard-pause"
        expected = {request_id: {"status": 200, "error": None, "done": True,
                                "backend_receipts": 1, "expected": True,
                                "pause_after": 13,
                                "pause_probe": {"seconds": 1.01, "heads": 1, "receipts": 0}}}
        events = [{"request_id": request_id, "event_type": "data.ai.complete",
                   "outcome": {"status": 200}}]
        def check(log):
            return evaluate(expected, events, {request_id: 1}, required_count=1,
                            dataplane_log=log)[1]["passed"]
        engaged = "[JSON_GUARD_STREAM] fd=1 request_id=" + request_id + " json_guard_streaming=1 hold=1"
        self.assertTrue(check(engaged))
        self.assertFalse(check(""))
        self.assertFalse(check(engaged + "\n[JSON_GUARD_SKIP]"))
        expected[request_id]["pause_probe"]["receipts"] = 1
        self.assertFalse(check(engaged))

    def setUp(self):
        self.request_id = "boundary-test"
        self.expected = {
            self.request_id: {
                "status": 200, "error": None, "done": True,
                "backend_receipts": 1, "expected": True,
            }
        }
        self.events = [{"request_id": self.request_id, "event_type": "data.ai.complete",
                        "outcome": {"status": 200}}]
        self.receipts = {self.request_id: 1}

    def passed(self):
        return evaluate(self.expected, self.events, self.receipts, required_count=1)[1]["passed"]

    def denial(self):
        self.expected[self.request_id].update(
            status=400, error="duplicate_model_field", done=False, backend_receipts=0
        )
        self.events = [{
            "request_id": self.request_id, "event_type": "sec.ai.deny",
            "outcome": {"status": 400},
            "detail": {"stage": "framing", "decision": "duplicate_model_field"},
        }]
        self.receipts = {}

    def test_success(self):
        self.assertTrue(self.passed())

    def test_duplicate_model_denial(self):
        self.denial()
        self.assertTrue(self.passed())

    def test_new_metadata_codes_require_framing(self):
        for code in ("duplicate_user_field", "invalid_model_field"):
            self.denial()
            self.expected[self.request_id]["error"] = code
            self.events[0]["detail"]["decision"] = code
            self.assertTrue(self.passed())
            self.events[0]["detail"]["stage"] = "auth"
            self.assertFalse(self.passed())

    def test_duplicate_denial_fails(self):
        self.denial()
        self.events.append(copy.deepcopy(self.events[0]))
        self.assertFalse(self.passed())

    def test_completion_mixed_with_denial_fails(self):
        self.denial()
        self.events.append({"request_id": self.request_id, "event_type": "data.ai.complete",
                            "outcome": {"status": 200}})
        self.assertFalse(self.passed())

    def test_unexpected_backend_receipt_fails(self):
        self.receipts["absent"] = 1
        self.assertFalse(self.passed())

    def test_missing_terminal_event_fails(self):
        self.events.clear()
        self.assertFalse(self.passed())

    def test_wrong_status_or_error_fails(self):
        self.denial()
        self.events[0]["outcome"]["status"] = 503
        self.assertFalse(self.passed())
        self.events[0]["outcome"]["status"] = 400
        self.events[0]["detail"]["decision"] = "no_route"
        self.assertFalse(self.passed())

    def test_response_failure_is_not_hidden_by_valid_audit(self):
        self.expected[self.request_id]["expected"] = False
        self.assertFalse(self.passed())

    def test_missing_matrix_case_fails(self):
        summary = evaluate(self.expected, self.events, self.receipts)[1]
        self.assertFalse(summary["passed"])

    def test_denied_request_reaching_backend_fails(self):
        self.denial()
        self.receipts[self.request_id] = 1
        self.assertFalse(self.passed())

    def test_wrong_metadata_stage_fails(self):
        self.denial()
        self.events[0]["detail"]["stage"] = "auth"
        self.assertFalse(self.passed())

    def test_duplicate_fixtures_decode_to_two_top_level_models(self):
        for location, escaped, size in [("front", False, 106206),
                                         ("tail", False, 800 * 1024),
                                         ("tail", True, 800 * 1024)]:
            raw = duplicate_payload(location, escaped, size)
            self.assertEqual(len(raw), size)
            pairs = json.loads(raw, object_pairs_hook=lambda value: value)
            self.assertEqual([v for k, v in pairs if k == "model"], [MODEL, "other-model"])
            if escaped:
                self.assertIn(b'mod\\u0065l', raw)

    def test_rotated_and_compressed_audit_segments(self):
        with tempfile.TemporaryDirectory() as folder:
            evidence = Path(folder)
            audit = evidence / "audit"
            audit.mkdir()
            (audit / "audit-20261105.jsonl").write_text(json.dumps(self.events[0]) + "\n")
            with gzip.open(audit / "audit-20261106.jsonl.gz", "wt") as stream:
                stream.write(json.dumps(self.events[0]) + "\n")
            self.assertEqual(read_audit(evidence), self.events * 2)
            self.assertTrue((evidence / "audit.jsonl").is_file())

    def test_empty_audit_directory_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            evidence = Path(folder)
            (evidence / "audit").mkdir()
            with self.assertRaises(RuntimeError):
                read_audit(evidence)

    def test_fixture_hashes_and_structural_boundaries(self):
        hashes = [
            "c1c75d4a1e1e2b6644944845b3ed72d1a8e311d274b63f445a2a56b23a028ccb",
            "b4651e45bf667ff3e7c8f2a9eb4ad1f87631c6fdf9652304ae2c2c394325041f",
        ]
        for last, expected_hash in zip((False, True), hashes):
            self.assertEqual(hashlib.sha256(payload(3586, last)).hexdigest(), expected_hash)
        for size in (2047, 2048, 2049, 8192, 8193):
            self.assertEqual(token_count(json.loads(payload(size))), size)


if __name__ == "__main__":
    unittest.main()
