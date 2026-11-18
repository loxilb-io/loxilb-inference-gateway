#!/usr/bin/env python3
"""Judge isolated VIP ownership and record the campaign A HTTP interval."""
import json
from pathlib import Path
import sys


def load(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


directory, start, limit, port = Path(sys.argv[1]), *map(int, sys.argv[2:])
samples = [sample for sample in load(directory / "node.jsonl") if sample["t"] >= start]
owns = lambda sample: sample["role"] == "MASTER" and sample["vip"] == 1
first_master = next((sample["t"] for sample in samples if sample["role"] == "MASTER"), None)
first_owned = next((sample["t"] for sample in samples if owns(sample)), None)
first_listener = next((sample["t"] for sample in samples if port in sample["listen"]), None)
delay = first_owned - start if first_owned is not None and start else None
passed = delay is not None and delay <= limit and len(samples) >= 3 and all(map(owns, samples[-3:]))
print(f"{'PASS' if passed else 'FAIL'} process start to MASTER with VIP={delay} ms (limit={limit} ms)")
requests = sorted(load(directory / "probe.jsonl"), key=lambda row: row["t_send"])
after = [row for row in requests if first_master is not None and row["t_send"] >= first_master]
bad = max((row["t_send"] for row in after if row["cls"] != "ok"), default=0)
successes = [row["t_send"] for row in after if row["cls"] == "ok" and row["t_send"] > bad]
stable = successes[0] if successes and successes[-1] - successes[0] >= 3000 else None
def elapsed(instant):
    return instant - first_master if instant is not None and first_master is not None else "unobserved"
print(f"promotion to listener={elapsed(first_listener)} ms to sustained HTTP 200={elapsed(stable)} ms (campaign A)")
