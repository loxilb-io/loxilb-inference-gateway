#!/usr/bin/env python3
"""Measure the first stable role streak after a peer returns."""
from bisect import bisect_right
import json
from pathlib import Path
import sys

def read(path):
    return [json.loads(row) for row in path.read_text().splitlines()] if path.exists() else []

directory, begin = Path(sys.argv[1]), int(sys.argv[2])
owner = read(directory / "node.jsonl")
peer = read(directory / "peer" / "node.jsonl")
times = [row["t"] for row in owner]
streak = 0
for row in peer:
    i = bisect_right(times, row["t"]) - 1
    paired = i >= 0 and row["t"] - times[i] <= 1000 and owner[i]["role"] == "MASTER"
    streak = streak + 1 if paired and row["role"] == "BACKUP" else 0
    if streak == 6:
        print(row["t"] - begin)
        break
else:
    print("unobserved")
