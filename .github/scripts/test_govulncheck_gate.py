import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("govulncheck-gate.py")


class GateTests(unittest.TestCase):
    def gate(self, messages, binary=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            path.write_text("\n".join(json.dumps(m) for m in messages))
            return subprocess.run([sys.executable, str(SCRIPT), str(path), *(["--binary"] if binary else [])], capture_output=True, text=True)

    def finding(self, module, function=True, fixed=True):
        return {"finding": {"osv": "GO-2026-0001", "fixed_version": "v1.2.3" if fixed else "", "trace": [{"module": module, **({"function": "Parse"} if function else {})}]}}

    def config(self, mode):
        return {"config": {"scan_mode": mode, "scan_level": "symbol"}}

    def test_source_gate_keeps_root_call_requirement(self):
        for module, expected in [("example.org/dependency", 0), ("github.com/loxilb-io/loxilb/pkg/a", 1)]:
            with self.subTest(module=module):
                self.assertEqual(self.gate([self.config("source"), self.finding(module)]).returncode, expected)

    def test_binary_gate_covers_non_gateway_binaries(self):
        self.assertEqual(self.gate([self.config("binary"), self.finding("github.com/osrg/gobgp/v3")], True).returncode, 1)

    def test_no_fix_and_module_only_remain_visible_nonblocking(self):
        self.assertEqual(self.gate([self.config("binary"), self.finding("example.org/d", fixed=False)], True).returncode, 0)
        self.assertEqual(self.gate([self.config("binary"), self.finding("example.org/d", function=False)], True).returncode, 0)

    def test_empty_wrong_mode_and_incomplete_reports_fail_closed(self):
        for rows in [[], [{"unexpected": True}], [self.config("source")], [{"config": {"scan_mode": "binary", "scan_level": "module"}}], [self.config("binary"), {"finding": {"osv": "GO-X", "trace": ["bad"]}}]]:
            with self.subTest(rows=rows):
                self.assertEqual(self.gate(rows, True).returncode, 2)


if __name__ == "__main__":
    unittest.main()
