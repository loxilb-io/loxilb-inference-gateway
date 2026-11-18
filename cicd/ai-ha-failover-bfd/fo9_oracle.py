#!/usr/bin/env python3
"""Check FO-9 from timestamped client and survivor observations."""
import json
import sys
from pathlib import Path


def rows(path):
    with path.open() as records:
        return [json.loads(line) for line in records]


def stable(path, fault, end):
    samples = sorted(
        (row for row in rows(path) if fault <= row["t_send"] < end),
        key=lambda row: row["t_send"],
    )
    last_failure = max((i for i, row in enumerate(samples) if row["cls"] != "ok"), default=-1)
    suffix = samples[last_failure + 1:]
    if len(suffix) < 20 or suffix[-1]["t_send"] - suffix[0]["t_send"] < 3000:
        raise ValueError(f"{path.stem}: no continuous three-second run of complete responses")
    return suffix[0]["t_done"] - fault, suffix[0]["seq"]


def recovered(path, ready):
    successes = [row for row in rows(path) if row["cls"] == "ok" and row["t_done"] >= ready]
    if not successes:
        raise ValueError(f"{path.stem}: no complete response after PostgreSQL readiness")
    first = min(successes, key=lambda row: row["t_done"])
    return first["t_done"] - ready, first["seq"]


def main():
    mode, directory, start, end, *ports = sys.argv[1:]
    path = Path(directory)
    start, end = int(start), int(end)
    if mode == "outage":
        key, key_seq = stable(path / "warm-key.jsonl", start, end)
        jwt, jwt_seq = stable(path / "warm-jwt.jsonl", start, end)
        samples = [row for row in rows(path / "survivor.jsonl") if row["t"] >= start]
        master = next((row["t"] for row in samples if row["role"] == "MASTER"), None)
        vip = next((row["t"] for row in samples if row["vip"] == 1), None)
        listener = next((row["t"] for row in samples if row["vip"] == 1 and
                         all(int(port) in row["listen"] for port in ports)), None)
        if master is None or vip is None or listener is None:
            raise ValueError("missing MASTER, VIP or listener observation")
        print(key_seq, jwt_seq, key, jwt, master - start, vip - start, listener - vip)
        return max(key, jwt) <= 2000 and listener - vip <= 200

    key, key_seq = recovered(path / "recovery-key.jsonl", start)
    jwt, jwt_seq = recovered(path / "recovery-jwt.jsonl", start)
    print(key_seq, jwt_seq, key, jwt)
    return max(key, jwt) <= 6000


if __name__ == "__main__":
    try:
        sys.exit(0 if main() else 1)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
