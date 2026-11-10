import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("pins", Path(__file__).with_name("update-go-pins.py"))
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)
PROJECT = Path(__file__).resolve().parents[1]


class PinChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = json.loads((PROJECT / pins.MANIFEST).read_text())
        paths = pins.RECIPES + pins.MODULES + ["cicd/common/reflect-echo/vendor/modules.txt"]
        for name in paths:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(PROJECT / name, target)
            if name in pins.RECIPES:
                target.write_text(pins.render_recipe(name, target.read_text(), self.config))
        target = self.root / pins.MANIFEST
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.config))

    def test_current_inputs_agree(self):
        self.assertEqual(pins.check(self.root, self.config), [])

    def test_stale_recipe_is_rejected(self):
        path = self.root / "Dockerfile.u24"
        path.write_text(path.read_text().replace("golang.org/x/net@" + self.config["x_net"], "golang.org/x/net@v0.60.0"))
        self.assertIn("stale generated pins: Dockerfile.u24", pins.check(self.root, self.config))

    def test_nested_module_and_vendor_drift_are_rejected(self):
        for name in ["cicd/common/reflect-echo/go.mod", "cicd/common/reflect-echo/vendor/modules.txt"]:
            path = self.root / name
            path.write_text(path.read_text().replace(self.config["x_net"], "v0.55.0"))
        errors = pins.check(self.root, self.config)
        self.assertTrue(any("stale x/net" in e for e in errors))
        self.assertIn("stale reflect-echo vendor metadata", errors)

    def test_new_unmanaged_recipe_or_module_is_rejected(self):
        (self.root / "Dockerfile.new").write_text("RUN go get golang.org/x/net@v0.62.0\n")
        path = self.root / "new/go.mod"
        path.parent.mkdir()
        path.write_text("module new\nrequire golang.org/x/net v0.62.0\n")
        errors = pins.check(self.root, self.config)
        self.assertIn("unmanaged Go dependency recipe: Dockerfile.new", errors)
        self.assertIn("unmanaged x/net module: new/go.mod", errors)

    def test_shared_vendor_consumers_reject_old_compilers(self):
        for name in pins.SHARED_VENDOR_BUILDS:
            with self.subTest(recipe=name):
                path = self.root / name
                good = path.read_text()
                path.write_text(good.replace(self.config["go"] + "-alpine", "1.25-alpine"))
                self.assertIn("stale generated pins: " + name, pins.check(self.root, self.config))
                path.write_text(good)

    def test_copy_and_add_consumers_cannot_bypass_managed_inventory(self):
        examples = [
            'COPY unrelated.txt cicd/common/reflect-echo/go.sum ./',
            'COPY ["cicd/common/reflect-echo/vendor/", "./vendor/"]',
            'copy --chown=1000:1000 ./cicd/common/reflect-echo/ /src/',
            'ADD cicd/common/reflect-echo/vendor/modules.txt /src/',
            'COPY unrelated.txt \\\n    cicd/common/reflect-echo/go.sum ./',
        ]
        path = self.root / "Dockerfile.consumer"
        for source in examples:
            with self.subTest(source=source):
                path.write_text('FROM golang:1.25-alpine\n' + source + '\n')
                self.assertIn("unmanaged shared-vendor recipe: Dockerfile.consumer", pins.check(self.root, self.config))

    def test_stage_copies_and_comments_are_not_repository_inputs(self):
        self.assertFalse(pins.copies_shared_vendor('COPY --from=build /cicd/common/reflect-echo/vendor /src/'))
        self.assertFalse(pins.copies_shared_vendor('# COPY cicd/common/reflect-echo/go.mod /src/'))
        self.assertFalse(pins.copies_shared_vendor('COPY unrelated.go /src/cicd/common/reflect-echo/go.mod'))

    def test_ci_inventory_fails_instead_of_omitting_unmanaged_consumer(self):
        command = [sys.executable, str(PROJECT / "scripts/update-go-pins.py"),
                   "--root", str(self.root), "--list-shared-vendor-builds"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [profile + "\t" + recipe
                         for recipe, profile in pins.SHARED_VENDOR_BUILDS.items()])
        (self.root / "Dockerfile.new-consumer").write_text('COPY cicd/common/reflect-echo/vendor/ ./vendor/\n')
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unmanaged shared-vendor recipe", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_untracked_consumer_is_detected_in_a_git_checkout(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / "Dockerfile.untracked").write_text('COPY cicd/common/reflect-echo/go.mod ./\n')
        self.assertIn("unmanaged shared-vendor recipe: Dockerfile.untracked", pins.check(self.root, self.config))

    def test_invalid_manifest_fails_before_running_go(self):
        for key, value in [("go", "1.26"), ("x_net", "v0.62.0; echo bad"), ("schema_version", 2)]:
            config = copy.deepcopy(self.config)
            config[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                pins.validate(config)

    def test_compiler_and_module_floor_are_checked(self):
        config = copy.deepcopy(self.config)
        config["go"] = "1.25.9"
        self.assertTrue(any("compiler is below" in e for e in pins.check(self.root, config)))
        path = self.root / "go.mod"
        path.write_text(path.read_text().replace("go 1.26.0", "go 1.25.0"))
        self.assertTrue(any("below vendored x/net" in e for e in pins.check(self.root, self.config)))

    def test_failed_go_update_does_not_publish_new_recipe_pins(self):
        path = self.root / "Dockerfile"
        before = path.read_bytes()
        with patch.object(pins.subprocess, "run", side_effect=pins.subprocess.CalledProcessError(1, ["go", "get"])):
            with self.assertRaises(pins.subprocess.CalledProcessError):
                pins.update(self.root, self.config)
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
