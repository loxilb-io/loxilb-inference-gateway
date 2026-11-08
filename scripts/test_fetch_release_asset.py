#!/usr/bin/env python3
"""Exercise real curl/checksum/atomic-file behavior against a local HTTP server."""
import hashlib
import http.server
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

SCRIPT = Path(__file__).with_name("fetch-release-asset.sh")
PAYLOAD = b"verified release fixture\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class FetchReleaseAssetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name) / "asset with spaces.tar.gz"
        self.requests = []
        self.responses = {"/api": (200, PAYLOAD), "/browser": (200, PAYLOAD)}
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append(self.path)
                code, body = outer.responses[self.path]
                self.send_response(code)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def fetch(self):
        base = "http://127.0.0.1:" + str(self.server.server_port)
        return subprocess.run(
            ["bash", "-c", 'source "$1"; fetch_verified "$2" "$3" "$4" "$5"',
             "fetch-test", str(SCRIPT), base + "/api", base + "/browser",
             DIGEST, str(self.output)], capture_output=True, text=True, timeout=30)

    def test_verified_primary_is_published_and_cached(self):
        self.assertEqual(self.fetch().returncode, 0)
        self.assertEqual(self.output.read_bytes(), PAYLOAD)
        self.assertEqual(self.requests, ["/api"])
        self.assertEqual(self.fetch().returncode, 0)
        self.assertEqual(self.requests, ["/api"])
        self.assertEqual(list(Path(self.tmp.name).glob("*.part.*")), [])

    def test_http_failure_uses_fallback(self):
        self.responses["/api"] = (504, b"gateway timeout")
        self.assertEqual(self.fetch().returncode, 0)
        self.assertEqual(self.output.read_bytes(), PAYLOAD)
        self.assertEqual(self.requests, ["/api", "/browser"])

    def test_corrupt_primary_is_never_published(self):
        self.responses["/api"] = (200, b"corrupt archive")
        self.assertEqual(self.fetch().returncode, 0)
        self.assertEqual(self.output.read_bytes(), PAYLOAD)
        self.assertEqual(self.requests, ["/api", "/browser"])

    def test_failures_are_bounded_and_preserve_existing_file(self):
        self.output.write_bytes(b"old file")
        self.responses = {"/api": (504, b"timeout"), "/browser": (200, b"bad checksum")}
        result = self.fetch()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.requests, ["/api", "/browser"] * 3)
        self.assertEqual(self.output.read_bytes(), b"old file")
        self.assertEqual(list(Path(self.tmp.name).glob("*.part.*")), [])

    def test_unknown_asset_fails_before_network(self):
        result = subprocess.run(["bash", str(SCRIPT), "tokenizers-linux-unknown",
                                 str(self.output)], capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
