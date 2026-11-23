#!/usr/bin/env python3
"""Fixtures and assertions for distinguishing header hashing from peer state."""
import json
import re
import sys
from collections import Counter
from pathlib import Path

HEADER = "custom_X-Conversation-Id_"
COUNT = 100


def cohort(prefix):
    """Generate equal populations for the two temporarily unavailable members."""
    populations = Counter()
    counter = 0
    while sum(populations.values()) < COUNT:
        conversation = f"{prefix}-{counter}"
        counter += 1
        value = 5381
        for byte in (HEADER + conversation).encode("ascii"):
            value = (value * 33 + byte) & 0xFFFFFFFF
        index = value % 4
        if index in (1, 3) and populations[index] < COUNT // 2:
            print(conversation)
            populations[index] += 1


def compare(ids_file, previous, current, *members):
    ids = set(Path(ids_file).read_text().splitlines())
    before = json.loads(Path(previous).read_text())
    after = json.loads(Path(current).read_text())
    if len(ids) != COUNT or before.keys() != ids or after.keys() != ids:
        raise ValueError("incomplete conversation cohort")
    allowed = set(members)
    observed = Counter(after.values())
    matching = sum(before[key] == after[key] and after[key] in allowed for key in ids)
    bad = COUNT - sum(observed[label] for label in allowed)
    print(matching, bad, json.dumps(observed, sort_keys=True))


def installed(ids_file):
    keys = {HEADER + key for key in Path(ids_file).read_text().splitlines()}
    recognized = set()
    for line in sys.stdin:
        match = re.search(r"\[XSYNC_APPLY\].* conv=(\S+) .*outcome=0\s*$", line)
        if match and match[1] in keys:
            recognized.add(match[1])
    print(len(recognized))


if __name__ == "__main__":
    {"cohort": cohort, "compare": compare, "installed": installed}[sys.argv[1]](*sys.argv[2:])
