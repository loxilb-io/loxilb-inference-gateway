#!/usr/bin/env python3
"""Negative controls for the image CLI identity gate."""
from pathlib import Path
import tempfile
import unittest

from verify_bundled_cli import expected_identity, verify_identity


class IdentityTests(unittest.TestCase):
    revision = "a" * 40
    version = "v0.9.9.2"

    def payload(self):
        return dict(apiVersion="loxilb.io/appliance/v1", kind="CommandResult",
                    command="version", success=True, code="OK",
                    data=dict(sourceRevision=self.revision, version=self.version))

    def test_correct_identity(self):
        verify_identity(self.payload(), self.revision, self.version)

    def test_wrong_or_missing_identity(self):
        for field, bad in (("sourceRevision", "b" * 40), ("sourceRevision", ""),
                           ("version", "v0.9.9.1"), ("version", "dev"),
                           ("version", None)):
            with self.subTest(field=field, bad=bad):
                payload = self.payload()
                payload["data"][field] = bad
                with self.assertRaises(ValueError):
                    verify_identity(payload, self.revision, self.version)

    def test_failed_or_unsupported_envelope(self):
        bad = [None, "legacy version output", {}, self.payload(), self.payload(), self.payload()]
        bad[3]["success"] = False
        bad[4]["command"] = "get lb"
        bad[5]["data"] = None
        for payload in bad:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                verify_identity(payload, self.revision, self.version)

    def test_defaults_must_be_explicit_unique_and_pinned(self):
        valid = f"ARG LOXICMD_TAG={self.revision}\nARG LOXICMD_VERSION={self.version}\n"
        cases = (valid.replace(self.revision, "main"), valid.replace(self.version, "dev"),
                 valid + valid, valid.splitlines()[0] + "\n")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Dockerfile"
            path.write_text(valid)
            self.assertEqual(expected_identity(path), (self.revision, self.version))
            for text in cases:
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(ValueError):
                    expected_identity(path)


if __name__ == "__main__":
    unittest.main()
