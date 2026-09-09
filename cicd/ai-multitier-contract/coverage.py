#!/usr/bin/env python3
"""Track every inventoried field. A present ledger row is not test coverage."""
import argparse
import json
import pathlib
import sys

DIMENSIONS = ("admission", "defaults", "propagation", "behavior", "failure", "restore")
STATES = {"GAP", "PARTIAL", "VERIFIED", "NOT_APPLICABLE"}


def seed(inventory):
    return {"schemaVersion": 1, "fields": [
        {"id": field["id"], "dimensions": {dimension: {
            "status": "GAP", "evidence": [], "note": "Not yet assessed"}
            for dimension in DIMENSIONS}} for field in inventory["fields"]]}


def validate(inventory, ledger):
    expected = {field["id"] for field in inventory["fields"]}
    rows = ledger["fields"]
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)) or set(ids) != expected:
        raise ValueError("ledger must contain every inventoried field exactly once; missing/unknown/duplicate IDs")
    counts = {state: 0 for state in STATES}
    for row in rows:
        if set(row["dimensions"]) != set(DIMENSIONS):
            raise ValueError("missing/unknown coverage dimension: " + row["id"])
        for value in row["dimensions"].values():
            status = value["status"]
            if status not in STATES:
                raise ValueError("unknown coverage status: " + status)
            if status != "GAP" and (not value.get("note") or not value.get("evidence")):
                raise ValueError("non-GAP claims require a rationale and evidence references")
            counts[status] += 1
    return {"fields": len(rows), "dimensions": counts,
            "gate": "ledger integrity only; runtime evidence still requires review",
            "ledgerComplete": counts["GAP"] == 0 and counts["PARTIAL"] == 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("inventory", type=pathlib.Path)
    parser.add_argument("ledger", nargs="?", type=pathlib.Path)
    parser.add_argument("--seed", action="store_true", help="emit GAP-only initial ledger; never infer coverage")
    parser.add_argument("--release", action="store_true", help="fail while GAP/PARTIAL remains")
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text())
    if args.seed:
        print(json.dumps(seed(inventory), indent=2))
        return 0
    if args.ledger is None:
        parser.error("ledger is required without --seed")
    result = validate(inventory, json.loads(args.ledger.read_text()))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if args.release and not result["ledgerComplete"] else 0


if __name__ == "__main__":
    sys.exit(main())
