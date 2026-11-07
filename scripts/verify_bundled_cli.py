#!/usr/bin/env python3
"""Verify an image's CLI source and version before recording release identity."""
import argparse
import json
from pathlib import Path
import re
import sys


def expected_identity(dockerfile):
    text = Path(dockerfile).read_text()
    values = []
    for key, pattern in (("LOXICMD_TAG", r"[0-9a-f]{40}"),
                         ("LOXICMD_VERSION", r"v\d+\.\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?")):
        matches = re.findall(r"^ARG " + key + r"=(.*)$", text, re.MULTILINE)
        if len(matches) != 1 or not re.fullmatch(pattern, matches[0]):
            raise ValueError(f"{dockerfile}: requires one valid {key} default")
        values.append(matches[0])
    return tuple(values)


def verify_identity(payload, revision, version):
    if (not isinstance(payload, dict)
            or payload.get("apiVersion") != "loxilb.io/appliance/v1"
            or payload.get("kind") != "CommandResult"
            or payload.get("command") != "version"
            or payload.get("success") is not True
            or payload.get("code") != "OK"
            or not isinstance(payload.get("data"), dict)):
        raise ValueError("embedded CLI did not return a successful version envelope")
    data = payload["data"]
    for field, expected in (("sourceRevision", revision), ("version", version)):
        if data.get(field) != expected:
            raise ValueError(f"embedded CLI {field}: expected {expected!r}, got {data.get(field)!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dockerfile", required=True)
    parser.add_argument("--input", required=True, help="captured version -o json response")
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--variant", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        revision, version = expected_identity(args.dockerfile)
        verify_identity(json.loads(Path(args.input).read_text()), revision, version)
        if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
            raise ValueError("invalid embedded binary SHA-256")
        # Preserve the release metadata schema; verified now includes both fields.
        result = dict(variant=args.variant, arch=args.arch, cliRevision=revision,
                      embeddedSha256=args.sha256, identitySelfReport="verified")
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
        print(f"Verified embedded CLI {version} at {revision}")
    except (OSError, ValueError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
