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
from client import payload, token_count


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
            status=413, error="json_structure_limit_exceeded", done=False, backend_receipts=0
        )
        self.events = [{
            "request_id": self.request_id, "event_type": "sec.ai.deny",
            "outcome": {"status": 413},
            "detail": {"stage": "framing", "decision": "json_structure_limit_exceeded"},
        }]
        self.receipts = {}

    def test_success(self):
        self.assertTrue(self.passed())

    def test_structure_denial(self):
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
        self.events[0]["outcome"]["status"] = 413
        self.events[0]["detail"]["decision"] = "no_route"
        self.assertFalse(self.passed())

    def test_response_failure_is_not_hidden_by_valid_audit(self):
        self.expected[self.request_id]["expected"] = False
        self.assertFalse(self.passed())

    def test_missing_matrix_case_fails(self):
        summary = evaluate(self.expected, self.events, self.receipts)[1]
        self.assertFalse(summary["passed"])

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
