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
from client import MODEL, duplicate_payload, payload, token_count


class OracleTests(unittest.TestCase):
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
