#!/usr/bin/env python3
"""Scan immutable candidate image contents with Trivy and binary govulncheck.

The container is never started. Reports are retained on gate failure; extracted
binaries are temporary. Symbol presence in a binary is not a source call stack.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {"root/loxilb-io/loxilb/loxilb", "usr/sbin/gobgp", "usr/sbin/gobgpd",
            "usr/local/sbin/loxicmd", "usr/local/go/bin/go", "usr/local/go/bin/gofmt"}
NET_REQUIRED = {"root/loxilb-io/loxilb/loxilb", "usr/sbin/gobgp", "usr/sbin/gobgpd"}
PROFILES = {"gateway": REQUIRED, "reflect-echo": {"reflect-echo"},
            "gobgp-legacy": {"usr/sbin/gobgp", "usr/sbin/gobgpd"},
            "json-parser-mock": {"json-parser-mock"},
            "edge-cloud-backend": {"uc7-backend"},
            **{name: {"root/" + name} for name in ["grpc-client", "grpc-server", "http-client", "http-server"]}}


def target_path(value):
    if not isinstance(value, str) or not value or any(x in value for x in ["\\", ":", "\0"]):
        raise ValueError("invalid binary path in Trivy report")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("binary paths must be normalized image-relative paths")
    return value


def inventory(report, profile="gateway"):
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list) or any(not isinstance(r, dict) for r in report["Results"]):
        raise ValueError("Trivy report has no result inventory")
    targets = [target_path(r["Target"]) for r in report["Results"] if r.get("Type") == "gobinary"]
    if len(targets) != len(set(targets)) or not PROFILES[profile].issubset(targets):
        raise ValueError("missing or duplicate required Go binaries in candidate image")
    return sorted(targets)


def check_build_info(info, path, pins, profile="gateway"):
    if info.get("GoVersion") != "go" + pins["go"]:
        raise ValueError(f"{path}: compiler differs from the central pin")
    modules = [info.get("Main", {}), *info.get("Deps", [])]
    found = {m.get("Path"): m for m in modules}
    expected = {"golang.org/x/net": pins["x_net"], "google.golang.org/grpc": pins["grpc"]}
    needs_net = path in (NET_REQUIRED if profile == "gateway" else PROFILES[profile])
    if needs_net and "golang.org/x/net" not in found:
        raise ValueError(f"{path}: missing expected x/net build dependency")
    for module, version in expected.items():
        if module in found and (found[module].get("Version") != version or found[module].get("Replace")):
            raise ValueError(f"{path}: {module} differs from the central pin")


def trivy_gate(report):
    return [dict(target=result.get("Target"), **v) for result in report.get("Results", [])
            for v in result.get("Vulnerabilities", [])
            if v.get("Severity") == "CRITICAL" and v.get("FixedVersion")]


def command(args, log=None, stdout=None, timeout=600):
    if log:
        with log.open("w") as err:
            result = subprocess.run(args, stdout=stdout if stdout is not None else err,
                                    stderr=err, timeout=timeout)
    else:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return result


def scan(args):
    if args.image.startswith("-"):
        raise ValueError("invalid image reference")
    spec = importlib.util.spec_from_file_location("go_pins", ROOT / "scripts/update-go-pins.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pins = module.validate(json.loads(args.manifest.read_text()))
    args.output.mkdir(parents=True, exist_ok=False)
    inspected = command(["docker", "image", "inspect", args.image])
    if inspected.returncode:
        raise ValueError("cannot inspect local candidate image: " + inspected.stderr)
    image = json.loads(inspected.stdout)[0]
    image_id = image["Id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("invalid Docker image ID")
    report_path = args.output / "trivy.json"
    result = command([args.trivy, "image", "--image-src", "docker", "--cache-dir", str(args.trivy_cache),
                      "--scanners", "vuln", "--list-all-pkgs", "--format", "json", "--output", str(report_path),
                      "--timeout", "10m", image_id], args.output / "trivy.log")
    if result.returncode:
        raise ValueError("Trivy failed to scan the candidate image")
    report = json.loads(report_path.read_text())
    if report.get("Metadata", {}).get("ImageID") != image_id:
        raise ValueError("Trivy inspected a different image")
    targets = inventory(report, args.profile)
    summary = {"image_id": image_id, "image_reference": args.image, "profile": args.profile, "binaries": [],
               "fixable_critical": trivy_gate(report), "binary_symbol_scan_is_not_a_call_stack": True}
    label = uuid.uuid4().hex
    created = command(["docker", "create", "--network", "none", "--label", "io.loxilb.go-scan=" + label,
                       "--entrypoint", "/bin/true", image_id])
    if created.returncode:
        raise ValueError("cannot create inspection-only container: " + created.stderr)
    cid = created.stdout.strip()
    try:
        with tempfile.TemporaryDirectory(prefix="go-image-binaries-") as directory:
            for index, path in enumerate(targets):
                binary = Path(directory) / str(index)
                copied = command(["docker", "cp", cid + ":/" + path, str(binary)])
                if copied.returncode or not binary.exists() or not stat.S_ISREG(binary.lstat().st_mode):
                    raise ValueError("binary extraction failed or produced a non-regular file: " + path)
                version = command([args.go, "version", "-m", "-json", str(binary)])
                if version.returncode:
                    raise ValueError("unreadable Go build metadata: " + path)
                info = json.loads(version.stdout)
                check_build_info(info, path, pins, args.profile)
                (args.output / f"{index}-build-info.json").write_text(json.dumps(info, indent=2) + "\n")
                scan_path = args.output / f"{index}-govulncheck.json"
                with scan_path.open("w") as output:
                    result = command([args.govulncheck, "-mode=binary", "-format=json", str(binary)],
                                     args.output / f"{index}-govulncheck.log", output)
                if result.returncode not in [0, 3]:
                    raise ValueError("binary govulncheck failed to execute: " + path)
                gated = command([sys.executable, str(ROOT / ".github/scripts/govulncheck-gate.py"),
                                 str(scan_path), "--binary"], args.output / f"{index}-gate.log")
                if gated.returncode not in [0, 1]:
                    raise ValueError("invalid binary govulncheck report: " + path)
                summary["binaries"].append({"path": path, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                                            "go_version": info["GoVersion"], "symbol_gate_exit": gated.returncode})
                (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    finally:
        inspect = command(["docker", "inspect", cid])
        owned = json.loads(inspect.stdout)[0]
        if owned["Id"] != cid or owned["Image"] != image_id or owned["Config"]["Labels"].get("io.loxilb.go-scan") != label:
            raise ValueError("inspection container identity changed; refusing cleanup")
        removed = command(["docker", "rm", cid])
        if removed.returncode:
            raise ValueError("failed to remove the exact inspection container")
    current = command(["docker", "image", "inspect", args.image])
    if current.returncode or json.loads(current.stdout)[0]["Id"] != image_id:
        raise ValueError("candidate tag changed while being scanned")
    failed = bool(summary["fixable_critical"]) or any(b["symbol_gate_exit"] for b in summary["binaries"])
    summary["result"] = "FAIL" if failed else "PASS"
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"{summary['result']}: {len(targets)} actual image Go binaries; reports: {args.output}")
    return int(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="gateway")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=ROOT / "build/go-dependencies.json")
    parser.add_argument("--go", default="go")
    parser.add_argument("--govulncheck", default="govulncheck")
    parser.add_argument("--trivy", default="trivy")
    parser.add_argument("--trivy-cache", type=Path, default=Path.home() / ".cache/trivy")
    args = parser.parse_args()
    try:
        return scan(args)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
