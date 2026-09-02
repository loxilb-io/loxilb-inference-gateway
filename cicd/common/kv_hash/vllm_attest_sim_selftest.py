#!/usr/bin/env python3
"""vllm_attest_sim_selftest.py — proves the attestation simulator honest
before any suite trusts it.

The mixed-version harness earns attestation rungs THROUGH the simulator, so
a broken simulator would turn every suite leg green for the wrong reason.
This self-test drives one simulator instance per mode and asserts, from an
independent recomputation (kv_hash_parity, the proven-parity source of
record):

  positive     /version + /v1/models + /healthz answer; /tokenize reproduces
               the COMMITTED probe-fixture token ids (the add_special_tokens
               convention the gateway's parity probe pins); /v1/completions
               publishes exactly one map-v2 BlockStored batch whose frames,
               seq, msgpack envelope, block hashes and token ids all match
               the reference computation.
  tokenize-drift   /tokenize diverges from the fixture (and only in the
                   last id) while completions hashes stay CORRECT — the
                   drift must be visible to rung 1, not rung 2.
  no-echo      completions answers 200 but NOTHING arrives on the SUB
               socket within the wait window.
  wrong-echo   a batch arrives, token ids are right, but every block hash
               differs from the reference chain.

Run:  python3 vllm_attest_sim_selftest.py   (deps: pyzmq msgpack cbor2
      tokenizers transformers — same set the simulator itself needs)
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import msgpack  # noqa: E402
import zmq  # noqa: E402

from kv_hash_parity import _compute_client_blocks, _load_tokenizer  # noqa: E402

TOKENIZER = os.path.join(
    _HERE, "fixtures", "tokenizers", "Qwen__Qwen3-0.6B", "tokenizer.json")
PROBE_DIR = os.path.join(
    _HERE, "fixtures", "probefixtures", "qwen3-06b-completions-v1")
MODEL = "Qwen/Qwen3-0.6B"
BLOCK_SIZE = 16
ALGO = "sha256_cbor"
SEED = "0"
# Long enough for >= 2 full blocks of 16 under the Qwen3 tokenizer.
CHALLENGE_PROMPT = (
    "The quick brown fox jumps over the lazy dog. "
    "Pack my box with five dozen liquor jugs. "
    "Sphinx of black quartz, judge my vow. "
    "How vexingly quick daft zebras jump!")

_fails = 0


def chk(name: str, ok: bool, detail: str = ""):
    global _fails
    tag = "[OK]" if ok else "[FAILED]"
    print(f"{tag} {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        _fails += 1


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def http_json(method: str, url: str, body=None, timeout=5):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read())


class Sim:
    """One simulator subprocess + a pre-connected SUB socket."""

    def __init__(self, fail=None):
        self.http_port = free_port()
        self.zmq_port = free_port()
        cmd = [sys.executable, os.path.join(_HERE, "vllm_attest_sim.py"),
               "--tokenizer", TOKENIZER, "--model", MODEL,
               "--bind", "127.0.0.1",
               "--http-port", str(self.http_port),
               "--zmq-port", str(self.zmq_port),
               "--block-size", str(BLOCK_SIZE), "--algo", ALGO,
               "--none-hash-seed", SEED]
        if fail:
            cmd += ["--fail", fail]
        self.proc = subprocess.Popen(cmd)
        self.sub = zmq.Context.instance().socket(zmq.SUB)
        self.sub.setsockopt(zmq.SUBSCRIBE, b"")
        self.sub.connect(f"tcp://127.0.0.1:{self.zmq_port}")
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                st, _ = http_json(
                    "GET", f"http://127.0.0.1:{self.http_port}/healthz")
                if st == 200:
                    break
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError("simulator never became healthy")
        time.sleep(0.5)  # SUB slow-joiner guard (this side's connect)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.http_port}{path}"

    def recv_batch(self, timeout_s: float):
        if self.sub.poll(int(timeout_s * 1000)):
            return self.sub.recv_multipart()
        return None

    def close(self):
        self.sub.close(0)
        self.proc.terminate()
        self.proc.wait(timeout=10)


def reference_blocks(prompt: str):
    tok = _load_tokenizer(TOKENIZER)
    ids = tok.encode(prompt)
    blocks = _compute_client_blocks(ids, BLOCK_SIZE, ALGO, SEED)
    return ids, [u64 for (_i, u64, _c, _t) in blocks]


def probe_fixtures():
    out = []
    for name in sorted(os.listdir(PROBE_DIR)):
        if not name.endswith(".request.json"):
            continue
        base = name[: -len(".request.json")]
        with open(os.path.join(PROBE_DIR, name)) as f:
            req = json.load(f)
        with open(os.path.join(PROBE_DIR, base + ".expect.json")) as f:
            exp = json.load(f)
        out.append((base, req, exp))
    return out


def run_positive():
    print("=== positive: identity + tokenize parity + map-v2 echo ===")
    sim = Sim()
    try:
        st, body = http_json("GET", sim.url("/version"))
        chk("GET /version answers the pinned engine version",
            st == 200 and body.get("version") == "0.28.0", str(body))
        st, body = http_json("GET", sim.url("/v1/models"))
        served = [m.get("id") for m in body.get("data", [])]
        chk("GET /v1/models serves the model", st == 200 and served == [MODEL],
            str(body))

        fixtures = probe_fixtures()
        chk("committed probe fixtures present (3 pairs)", len(fixtures) == 3,
            str([f[0] for f in fixtures]))
        for base, req, exp in fixtures:
            st, body = http_json("POST", sim.url("/tokenize"),
                                 {"model": req["model"],
                                  "prompt": req["prompt"]})
            chk(f"/tokenize[{base}] reproduces committed expectedTokenIds",
                st == 200 and body.get("tokens") == exp["expectedTokenIds"],
                f"got {body.get('tokens')} want {exp['expectedTokenIds']}")

        ref_ids, ref_hashes = reference_blocks(CHALLENGE_PROMPT)
        chk("challenge prompt spans >= 2 full blocks", len(ref_hashes) >= 2,
            f"only {len(ref_hashes)} full blocks of {len(ref_ids)} tokens")
        st, body = http_json("POST", sim.url("/v1/completions"),
                             {"model": MODEL, "prompt": CHALLENGE_PROMPT})
        chk("/v1/completions answers 200 with usage",
            st == 200 and body.get("usage", {}).get("prompt_tokens")
            == len(ref_ids), str(body.get("usage")))

        frames = sim.recv_batch(5)
        chk("exactly one BlockStored batch published", frames is not None)
        if frames:
            chk("map-v2 envelope is 3 frames [topic|seq|payload]",
                len(frames) == 3, f"{len(frames)} frames")
            chk("seq frame is u64 big-endian 0 (first publish)",
                frames[1] == (0).to_bytes(8, "big"), frames[1].hex())
            batch = msgpack.unpackb(frames[2], raw=False)
            chk("payload is msgpack [ts, [event], dp_rank=0] (live v0.28.0 shape)",
                isinstance(batch, list) and len(batch) == 3
                and isinstance(batch[0], float) and batch[2] == 0,
                str(type(batch)))
            events = batch[1]
            chk("batch carries exactly one event", len(events) == 1)
            ev = events[0]
            chk("extra_keys is per-block nulls (live wire shape)",
                ev.get("extra_keys") == [None] * len(ev["block_hashes"]),
                str(ev.get("extra_keys")))
            chk("lora_id is null on plain events", ev.get("lora_id") is None)
            chk("event type is BlockStored", ev.get("type") == "BlockStored")
            chk("block_hashes match the independent reference chain",
                ev.get("block_hashes") == ref_hashes,
                f"got {ev.get('block_hashes')} want {ref_hashes}")
            chk("token_ids match the reference tokenization",
                ev.get("token_ids") == ref_ids)
            chk("no second batch follows", sim.recv_batch(1) is None)
    finally:
        sim.close()


def run_tokenize_drift():
    print("=== red twin: --fail tokenize-drift ===")
    sim = Sim(fail="tokenize-drift")
    try:
        _base, req, exp = probe_fixtures()[0]
        st, body = http_json("POST", sim.url("/tokenize"),
                             {"model": req["model"], "prompt": req["prompt"]})
        got = body.get("tokens", [])
        want = exp["expectedTokenIds"]
        chk("drifted /tokenize diverges from the fixture",
            st == 200 and got != want)
        chk("drift is confined to the last id (prefix intact)",
            got[:-1] == want[:-1] and got[-1] == want[-1] ^ 1,
            f"got {got} want-prefix {want[:-1]}")
        # The echo path must stay CORRECT in this mode — drift is a rung-1
        # defect, and a corrupted rung 2 would mask which rung caught it.
        ref_ids, ref_hashes = reference_blocks(CHALLENGE_PROMPT)
        http_json("POST", sim.url("/v1/completions"),
                  {"model": MODEL, "prompt": CHALLENGE_PROMPT})
        frames = sim.recv_batch(5)
        ok = False
        if frames:
            ev = msgpack.unpackb(frames[2], raw=False)[1][0]
            ok = ev["block_hashes"] == ref_hashes and ev["token_ids"] == ref_ids
        chk("echo stays correct under tokenize-drift", ok)
    finally:
        sim.close()


def run_no_echo():
    print("=== red twin: --fail no-echo ===")
    sim = Sim(fail="no-echo")
    try:
        st, _ = http_json("POST", sim.url("/v1/completions"),
                          {"model": MODEL, "prompt": CHALLENGE_PROMPT})
        chk("completions still answers 200", st == 200)
        chk("nothing is published on the KV event socket",
            sim.recv_batch(3) is None)
    finally:
        sim.close()


def run_wrong_echo():
    print("=== red twin: --fail wrong-echo ===")
    sim = Sim(fail="wrong-echo")
    try:
        ref_ids, ref_hashes = reference_blocks(CHALLENGE_PROMPT)
        http_json("POST", sim.url("/v1/completions"),
                  {"model": MODEL, "prompt": CHALLENGE_PROMPT})
        frames = sim.recv_batch(5)
        chk("a batch IS published (corruption, not silence)",
            frames is not None)
        if frames:
            ev = msgpack.unpackb(frames[2], raw=False)[1][0]
            chk("every block hash differs from the reference chain",
                all(g != w for g, w in zip(ev["block_hashes"], ref_hashes))
                and len(ev["block_hashes"]) == len(ref_hashes))
            chk("token_ids stay correct (hash-only corruption)",
                ev["token_ids"] == ref_ids)
    finally:
        sim.close()


def main():
    run_positive()
    run_tokenize_drift()
    run_no_echo()
    run_wrong_echo()
    print(f"selftest: {'PASS' if _fails == 0 else 'FAIL'} ({_fails} failed)")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
