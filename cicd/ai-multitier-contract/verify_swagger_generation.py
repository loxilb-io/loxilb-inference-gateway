#!/usr/bin/env python3
"""Independent semantic RED/repair oracle; uses only Python's standard library."""
import hashlib
import json
import re
import sys
from pathlib import Path

ZERO_PATHS = (
    ("definitions", "LoadbalanceEntry", "properties", "serviceArguments", "properties", "pd_session_ttl_sec"),
    ("definitions", "LoadbalanceEntry", "properties", "serviceArguments", "properties", "kvWarmupSec"),
    ("definitions", "PIIConfigEntry", "properties", "score_threshold"),
    ("definitions", "WorkerMetricsEntry", "properties", "queued_requests"),
)


def extract(source, name):
    matches = list(re.finditer(r"(?m)^\s*" + re.escape(name) + r"\s*=\s*json\.RawMessage\(\[\]byte\(", source))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {name} assignment")
    start = position = matches[0].end()
    parts = []
    while True:
        while position < len(source) and source[position].isspace():
            position += 1
        if source[position:position + 1] == "`":
            end = source.find("`", position + 1)
            if end < 0:
                raise ValueError("unterminated raw literal")
            parts.append(source[position + 1:end])
            position = end + 1
        elif source[position:position + 1] == '"':
            value, length = json.JSONDecoder().raw_decode(source[position:])
            if not isinstance(value, str):
                raise ValueError("expected quoted string")
            parts.append(value)
            position += length
        else:
            raise ValueError("unsupported generated expression")
        while position < len(source) and source[position].isspace():
            position += 1
        if source[position:position + 1] != "+":
            break
        position += 1
    if source[position:position + 2] != "))":
        raise ValueError("invalid generated closing expression")
    doc = json.loads("".join(parts))
    if not isinstance(doc, dict) or not doc:
        raise ValueError("empty/non-object embedded document")
    return doc, source[start:position]


def at(doc, path):
    for key in path:
        if not isinstance(doc, dict) or key not in doc:
            raise ValueError("missing schema path: " + "/".join(path))
        doc = doc[key]
    if not isinstance(doc, dict):
        raise ValueError("expected schema object")
    return doc


def verify(before, after):
    old, _ = extract(before, "SwaggerJSON")
    new, _ = extract(after, "SwaggerJSON")
    old_flat, old_expression = extract(before, "FlatSwaggerJSON")
    new_flat, new_expression = extract(after, "FlatSwaggerJSON")
    if old_expression != new_expression or old_flat != new_flat:
        raise ValueError("flattened contract changed")
    for path in ZERO_PATHS:
        if "minimum" in at(old, path):
            raise ValueError("baseline does not reproduce missing minimum: " + "/".join(path))
        for name, doc in (("fixed", new), ("flat-before", old_flat), ("flat-after", new_flat)):
            value = at(doc, path).get("minimum")
            if isinstance(value, bool) or value != 0:
                raise ValueError(name + " lacks numeric zero minimum: " + "/".join(path))
    return hashlib.sha256(old_expression.encode()).hexdigest()


def main():
    if len(sys.argv) != 3:
        raise ValueError("usage: verify_swagger_generation.py BEFORE_GO AFTER_GO")
    digest = verify(Path(sys.argv[1]).read_text(), Path(sys.argv[2]).read_text())
    print(f"PASS: {len(ZERO_PATHS)} identified zero-minimum regressions reproduced and repaired")
    print(f"PASS: nonempty flattened expression unchanged; sha256={digest}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
