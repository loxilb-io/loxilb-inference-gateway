import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("scan", Path(__file__).with_name("scan-go-image-binaries.py"))
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class ImageScanChecks(unittest.TestCase):
    def test_all_actual_binaries_are_inventoried_including_new_ones(self):
        paths = sorted(scan.REQUIRED | {"opt/bin/another-controller"})
        report = {"Results": [{"Target": p, "Type": "gobinary"} for p in paths]}
        self.assertEqual(scan.inventory(report), paths)

    def test_missing_empty_and_duplicate_inventory_fail(self):
        for report in [{}, {"Results": []}, {"Results": [{"Type": "gobinary", "Target": "usr/sbin/gobgp"}]}]:
            with self.subTest(report=report), self.assertRaises(ValueError):
                scan.inventory(report)
        rows = [{"Type": "gobinary", "Target": p} for p in scan.REQUIRED]
        with self.assertRaises(ValueError):
            scan.inventory({"Results": rows + rows[:1]})

    def test_each_fixture_profile_requires_its_own_payload(self):
        for profile, paths in scan.PROFILES.items():
            if profile == "gateway":
                continue
            rows = [{"Target": p, "Type": "gobinary"} for p in paths]
            with self.subTest(profile=profile):
                self.assertEqual(scan.inventory({"Results": rows}, profile), sorted(paths))
                with self.assertRaises(ValueError):
                    scan.inventory({"Results": rows[1:]}, profile)

    def test_unsafe_extraction_paths_fail(self):
        for path in ["../key", "/usr/sbin/go", "a//b", "a/./b", "a\\b", "a:b", "x\0y"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                scan.target_path(path)

    def test_actual_build_metadata_must_match_pins(self):
        pins = {"go": "1.26.10", "x_net": "v0.62.0", "grpc": "v1.83.2"}
        info = {"GoVersion": "go1.26.10", "Deps": [{"Path": "golang.org/x/net", "Version": "v0.62.0"}]}
        scan.check_build_info(info, "usr/sbin/gobgp", pins)
        for changed in [{"GoVersion": "go1.25.0"}, {"Deps": []}, {"Deps": [{"Path": "golang.org/x/net", "Version": "v0.55.0"}]}, {"Deps": [{"Path": "golang.org/x/net", "Version": "v0.62.0", "Replace": {"Path": "local"}}]}]:
            bad = copy.deepcopy(info)
            bad.update(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                scan.check_build_info(bad, "usr/sbin/gobgp", pins)

    def test_critical_fixable_policy_is_preserved(self):
        report = {"Results": [{"Target": "image", "Vulnerabilities": [
            {"VulnerabilityID": "a", "Severity": "HIGH", "FixedVersion": "1"},
            {"VulnerabilityID": "b", "Severity": "CRITICAL"},
            {"VulnerabilityID": "c", "Severity": "CRITICAL", "FixedVersion": "1"},
        ]}]}
        self.assertEqual([v["VulnerabilityID"] for v in scan.trivy_gate(report)], ["c"])


if __name__ == "__main__":
    unittest.main()
