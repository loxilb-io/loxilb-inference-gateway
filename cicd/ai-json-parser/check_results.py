#!/usr/bin/env python3
"""Join HTTP results, backend receipts and terminal audit events by request ID."""
from collections import Counter, defaultdict
import gzip
import json
from pathlib import Path
import sys

from client import CASE_COUNT


def evaluate(expected, events, receipts, required_count=CASE_COUNT, dataplane_log=None):
    errors = []
    rows = []
    grouped = defaultdict(list)
    for event in events:
        request_id = event.get("request_id", "")
        if request_id.startswith("boundary-") and request_id not in expected:
            errors.append(f"unexpected audit request ID {request_id}")
        if request_id in expected:
            grouped[request_id].append(event)
    if len(expected) != required_count:
        errors.append(f"executed {len(expected)} cases, expected {required_count}")

    successful = {}
    for request_id, result in expected.items():
        recorded = grouped[request_id]
        counts = Counter(event.get("event_type") for event in recorded)
        success = result["status"] == 200
        terminal = [
            event for event in recorded
            if event.get("event_type") in ("data.ai.complete", "sec.ai.deny")
        ]
        passed = (
            result["expected"]
            and counts["data.ai.complete"] == int(success)
            and counts["sec.ai.deny"] == int(not success)
            and len(terminal) == 1
            and terminal[0].get("outcome", {}).get("status") == result["status"]
        )
        if success:
            successful[request_id] = 1
            passed &= result["done"] and result["backend_receipts"] == 1
        else:
            passed &= not result["done"] and result["backend_receipts"] == 0
            passed &= counts["data.ai.settle"] == 0
            if terminal:
                detail = terminal[0].get("detail", {})
                passed &= detail.get("decision") == result["error"]
                if result["status"] == 413 or result["error"] in ("duplicate_model_field", "duplicate_user_field", "duplicate_content_type", "invalid_model_field", "invalid_json_body"):
                    passed &= detail.get("stage") == "framing"
        row = {"id": request_id, **result, "events": dict(counts), "passed": bool(passed)}
        rows.append(row)
        if not passed:
            errors.append(f"{request_id}: response/receipt/audit mismatch")
    pause = expected.get("boundary-stream-guard-pause")
    if pause is not None:
        probe = pause.get("pause_probe") or {}
        if (probe.get("seconds", 0) < 1 or probe.get("heads") != 1
                or probe.get("receipts") != 0 or pause.get("pause_after") != 13):
            errors.append("stream guard pause did not preserve incomplete backend framing")
        guard_line = "request_id=boundary-stream-guard-pause json_guard_streaming=1"
        if dataplane_log is None or guard_line not in dataplane_log:
            errors.append("stream guard engagement log missing for pause request")
        if dataplane_log and "JSON_GUARD_SKIP" in dataplane_log:
            errors.append("fail-open JSON_GUARD_SKIP log found")
    if receipts != successful:
        errors.append("backend receipt inventory differs from successful request IDs")

    summary = {
        "declared": required_count, "executed": len(expected),
        "success": sum(result["status"] == 200 for result in expected.values()),
        "metadata_denied": sum(result["status"] == 400 for result in expected.values()),
        "policy_denied": sum(result["status"] in (401, 403, 429, 503) for result in expected.values()),
        "backend_receipts": sum(receipts.values()),
        "passed": not errors, "errors": errors,
    }
    return rows, summary


def read_audit(evidence):
    directory = evidence / "audit"
    if directory.is_dir():
        paths = sorted(directory.glob("*.jsonl")) + sorted(directory.glob("*.jsonl.gz"))
    else:
        paths = [evidence / "audit.jsonl"]
    if not paths:
        raise RuntimeError("no active or sealed audit segments were collected")
    events = []
    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt") as stream:
            events.extend(json.loads(line) for line in stream if line.strip())
    if directory.is_dir():
        (evidence / "audit.jsonl").write_text(
            "".join(json.dumps(event) + "\n" for event in events)
        )
    return events


def main():
    evidence = Path(sys.argv[1])
    expected = json.loads((evidence / "expected.json").read_text())
    receipts = json.loads((evidence / "receipts.json").read_text())
    events = read_audit(evidence)
    rows, summary = evaluate(expected, events, receipts,
                             dataplane_log=(evidence / "dataplane.log").read_text())
    (evidence / "request-results.json").write_text(json.dumps(rows, indent=2) + "\n")
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    for row in rows:
        print(json.dumps({"audit_id": row["id"], "events": row["events"],
                          "status": row["status"], "passed": row["passed"]}), flush=True)
    print(json.dumps(summary), flush=True)
    print("AUDIT_PASS" if summary["passed"] else "AUDIT_FAIL", flush=True)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
