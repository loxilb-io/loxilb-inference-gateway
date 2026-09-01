#!/usr/bin/env python3
"""sglang_attest_sim_selftest.py — proves the SGLang attestation simulator
honest before any suite trusts it (SGLang twin of vllm_attest_sim_selftest.py).

The suite earns attestation rungs THROUGH the simulator, so a broken
simulator would turn every leg green for the wrong reason. This self-test
drives one simulator instance per mode and asserts against an INDEPENDENT
in-file recomputation of the SGLang page-hash contract (SHA256 over
raw parent-digest ‖ LE32 token ids, FIRST-8 signed truncation — ~10 lines
of hashlib, deliberately NOT imported from sglang_hash_core, so a drift in
the shared core cannot vouch for itself):

  positive       /get_server_info self-describes version/revision/
                 page_size/kv_events coherently; /get_model_info serves the
                 alias; /v1/tokenize reproduces the COMMITTED probe-fixture
                 token ids; /v1/completions publishes exactly one
                 tagged-ARRAY BlockStored batch on the serving rank's
                 socket whose frames, seq, dp_rank, field order, signed
                 hashes and token ids all match the reference computation.
  dp-coverage    --dp-ranks 2: consecutive completions land on rank 0 then
                 rank 1, each batch's dp_rank matching its socket, per-rank
                 seq independent.
  tokenize-drift /v1/tokenize diverges from the fixture (last id only)
                 while completions hashes stay CORRECT — the drift must be
                 visible to rung 1, not rung 2.
  no-echo        completions answers 200 but NOTHING arrives on any SUB.
  wrong-echo     a batch arrives, token ids right, every hash differs from
                 the reference chain.
  rank-lie       the batch on rank 0's socket claims dp_rank 1.
  rank-split     one challenge's blocks split across rank 0 and rank 1
                 sockets, each batch's claim matching its own socket.
  geometry-lie   page_size self-description inflated by 16 while the
                 publish still hashes with the REAL page size (the lie
                 lives only in self-description — the gateway must refuse
                 on geometry, never see a hash mismatch).
  revision-lie   revision self-description differs from the launch pin.

Run:  python3 sglang_attest_sim_selftest.py
      (deps: pyzmq msgpack tokenizers — same set the simulator needs)
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import msgpack  # noqa: E402
import zmq  # noqa: E402

from tokenizers import Tokenizer  # noqa: E402

TOKENIZER = os.path.join(
    _HERE, "fixtures", "tokenizers", "Qwen__Qwen3-0.6B", "tokenizer.json")
PROBE_DIR = os.path.join(
    _HERE, "fixtures", "probefixtures", "qwen3-06b-completions-v1")
MODEL = "qwen3-0.6b-sim"
BLOCK_SIZE = 16
REVISION = "c1899de289a04d12100db370d81485cdf75e47ca"
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


# ---- independent reference math (hashlib only — see module docstring) ----

def ref_chain(token_ids, block_size):
    """Signed-int64 published chain for the FULL blocks of token_ids."""
    out = []
    prior = None
    full = (len(token_ids) // block_size) * block_size
    for i in range(0, full, block_size):
        h = hashlib.sha256()
        if prior is not None:
            h.update(prior)
        for t in token_ids[i:i + block_size]:
            h.update(struct.pack("<I", t))
        prior = h.digest()
        v = int.from_bytes(prior[:8], "big")
        out.append(v - (1 << 64) if v >= (1 << 63) else v)
    return out, full


class Sim:
    """One simulator subprocess + pre-connected SUB sockets (one per rank)."""

    def __init__(self, fail=None, dp_ranks=1):
        self.http_port = free_port()
        self.zmq_port = free_port()
        self.dp_ranks = dp_ranks
        cmd = [sys.executable, os.path.join(_HERE, "sglang_attest_sim.py"),
               "--tokenizer", TOKENIZER, "--model", MODEL,
               "--bind", "127.0.0.1",
               "--http-port", str(self.http_port),
               "--zmq-port", str(self.zmq_port),
               "--dp-ranks", str(dp_ranks),
               "--block-size", str(BLOCK_SIZE),
               "--revision", REVISION]
        if fail:
            cmd += ["--fail", fail]
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.ctx = zmq.Context.instance()
        self.subs = []
        for r in range(dp_ranks):
            sub = self.ctx.socket(zmq.SUB)
            sub.connect(f"tcp://127.0.0.1:{self.zmq_port + r}")
            sub.setsockopt(zmq.SUBSCRIBE, b"")
            self.subs.append(sub)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                st, _ = http_json("GET", self.url("/get_server_info"))
                if st == 200:
                    break
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError("sim never came up")
        time.sleep(0.5)  # PUB/SUB slow-joiner guard

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.http_port}{path}"

    def recv_batch(self, rank: int, timeout_s: float):
        if self.subs[rank].poll(int(timeout_s * 1000)):
            return self.subs[rank].recv_multipart()
        return None

    def close(self):
        self.proc.kill()
        self.proc.wait()
        for s in self.subs:
            s.close(0)


def probe_fixtures():
    out = []
    for n in sorted(os.listdir(PROBE_DIR)):
        if not n.endswith(".expect.json"):
            continue
        base = n[:-len(".expect.json")]
        with open(os.path.join(PROBE_DIR, base + ".request.json"), "rb") as f:
            req = json.loads(f.read())
        with open(os.path.join(PROBE_DIR, n)) as f:
            exp = json.load(f)
        out.append((base, req, exp["expectedTokenIds"]))
    return out


def decode_frames(frames):
    """-> (seq, ts, events, dp_rank)"""
    assert len(frames) == 3, f"{len(frames)} frames"
    seq = int.from_bytes(frames[1], "big")
    batch = msgpack.unpackb(frames[2], raw=False)
    assert isinstance(batch, list) and len(batch) == 3, f"batch {batch!r}"
    return seq, batch[0], batch[1], batch[2]


def tok_ids(prompt):
    return Tokenizer.from_file(TOKENIZER).encode(
        prompt, add_special_tokens=True).ids


def run_positive():
    sim = Sim()
    try:
        st, si = http_json("GET", sim.url("/get_server_info"))
        chk("positive: server_info version", si.get("version") == "0.5.18")
        chk("positive: server_info revision", si.get("revision") == REVISION)
        chk("positive: server_info page_size", si.get("page_size") == BLOCK_SIZE)
        kv = si.get("kv_events") or {}
        chk("positive: kv_events advertisement",
            kv.get("publisher") == "zmq"
            and kv.get("endpoint_port_base") == sim.zmq_port
            and kv.get("dp_size") == 1, f"kv_events={kv}")
        st, mi = http_json("GET", sim.url("/get_model_info"))
        chk("positive: model_info alias", mi.get("served_model_name") == MODEL)

        for name, req, want in probe_fixtures():
            st, resp = http_json("POST", sim.url("/v1/tokenize"), req)
            chk(f"positive: /v1/tokenize fixture {name}",
                resp.get("tokens") == want
                and resp.get("count") == len(want)
                and isinstance(resp.get("max_model_len"), int),
                f"got {resp.get('tokens')}")

        ids = tok_ids(CHALLENGE_PROMPT)
        want_chain, full = ref_chain(ids, BLOCK_SIZE)
        assert len(want_chain) >= 2, "challenge prompt too short for 2 blocks"
        st, _ = http_json("POST", sim.url("/v1/completions"),
                          {"model": MODEL, "prompt": CHALLENGE_PROMPT,
                           "max_tokens": 1})
        chk("positive: completions 200", st == 200)
        frames = sim.recv_batch(0, 5)
        chk("positive: one batch on rank 0", frames is not None)
        if frames:
            seq, _ts, events, dp_rank = decode_frames(frames)
            chk("positive: seq starts at 0", seq == 0)
            chk("positive: dp_rank field 0", dp_rank == 0)
            chk("positive: one event", len(events) == 1)
            ev = events[0]
            chk("positive: tagged-ARRAY event",
                isinstance(ev, list) and len(ev) == 9, f"event {type(ev)}")
            if isinstance(ev, list) and len(ev) == 9:
                chk("positive: tag BlockStored", ev[0] == "BlockStored")
                chk("positive: signed hash chain matches independent "
                    "recomputation", ev[1] == want_chain,
                    f"got {ev[1]} want {want_chain}")
                chk("positive: token ids are the full blocks",
                    ev[3] == ids[:full])
                chk("positive: block_size field", ev[4] == BLOCK_SIZE)
                chk("positive: lora/extra_keys empty",
                    ev[5] is None and ev[8] is None)
                chk("positive: medium GPU", ev[6] == "GPU")
    finally:
        sim.close()


def run_dp_coverage():
    sim = Sim(dp_ranks=2)
    try:
        st, si = http_json("GET", sim.url("/get_server_info"))
        chk("dp: advertisement dp_size 2",
            (si.get("kv_events") or {}).get("dp_size") == 2)
        ids = tok_ids(CHALLENGE_PROMPT)
        want_chain, full = ref_chain(ids, BLOCK_SIZE)
        for want_rank in (0, 1):
            http_json("POST", sim.url("/v1/completions"),
                      {"model": MODEL, "prompt": CHALLENGE_PROMPT,
                       "max_tokens": 1})
            frames = sim.recv_batch(want_rank, 5)
            chk(f"dp: batch on rank {want_rank}", frames is not None)
            other = sim.recv_batch(1 - want_rank, 0.5)
            chk(f"dp: rank {1 - want_rank} silent for rank-{want_rank} serve",
                other is None)
            if frames:
                seq, _ts, events, dp_rank = decode_frames(frames)
                chk(f"dp: rank {want_rank} claims itself",
                    dp_rank == want_rank)
                chk(f"dp: rank {want_rank} per-rank seq 0", seq == 0)
                chk(f"dp: rank {want_rank} chain correct",
                    events[0][1] == want_chain)
    finally:
        sim.close()


def run_tokenize_drift():
    sim = Sim(fail="tokenize-drift")
    try:
        name, req, want = probe_fixtures()[0]
        st, resp = http_json("POST", sim.url("/v1/tokenize"), req)
        got = resp.get("tokens")
        chk("tokenize-drift: differs from fixture", got != want)
        chk("tokenize-drift: only the last id",
            got[:-1] == want[:-1] and got[-1] != want[-1])
        ids = tok_ids(CHALLENGE_PROMPT)
        want_chain, _ = ref_chain(ids, BLOCK_SIZE)
        http_json("POST", sim.url("/v1/completions"),
                  {"model": MODEL, "prompt": CHALLENGE_PROMPT, "max_tokens": 1})
        frames = sim.recv_batch(0, 5)
        chk("tokenize-drift: completions hashes stay CORRECT",
            frames is not None
            and decode_frames(frames)[2][0][1] == want_chain)
    finally:
        sim.close()


def run_no_echo():
    sim = Sim(fail="no-echo")
    try:
        st, _ = http_json("POST", sim.url("/v1/completions"),
                          {"model": MODEL, "prompt": CHALLENGE_PROMPT,
                           "max_tokens": 1})
        chk("no-echo: completions still 200", st == 200)
        chk("no-echo: nothing published", sim.recv_batch(0, 2) is None)
    finally:
        sim.close()


def run_wrong_echo():
    sim = Sim(fail="wrong-echo")
    try:
        ids = tok_ids(CHALLENGE_PROMPT)
        want_chain, full = ref_chain(ids, BLOCK_SIZE)
        http_json("POST", sim.url("/v1/completions"),
                  {"model": MODEL, "prompt": CHALLENGE_PROMPT, "max_tokens": 1})
        frames = sim.recv_batch(0, 5)
        chk("wrong-echo: a batch arrives", frames is not None)
        if frames:
            ev = decode_frames(frames)[2][0]
            chk("wrong-echo: token ids right", ev[3] == ids[:full])
            chk("wrong-echo: EVERY hash differs",
                all(g != w for g, w in zip(ev[1], want_chain)))
    finally:
        sim.close()


def run_rank_lie():
    sim = Sim(fail="rank-lie", dp_ranks=2)
    try:
        http_json("POST", sim.url("/v1/completions"),
                  {"model": MODEL, "prompt": CHALLENGE_PROMPT, "max_tokens": 1})
        frames = sim.recv_batch(0, 5)
        chk("rank-lie: batch on rank 0's socket", frames is not None)
        if frames:
            dp_rank = decode_frames(frames)[3]
            chk("rank-lie: claims dp_rank 1", dp_rank == 1)
    finally:
        sim.close()


def run_rank_split():
    sim = Sim(fail="rank-split", dp_ranks=2)
    try:
        ids = tok_ids(CHALLENGE_PROMPT)
        want_chain, full = ref_chain(ids, BLOCK_SIZE)
        http_json("POST", sim.url("/v1/completions"),
                  {"model": MODEL, "prompt": CHALLENGE_PROMPT, "max_tokens": 1})
        f0 = sim.recv_batch(0, 5)
        f1 = sim.recv_batch(1, 5)
        chk("rank-split: both rank sockets carry a batch",
            f0 is not None and f1 is not None)
        if f0 and f1:
            _s0, _t0, ev0, r0 = decode_frames(f0)
            _s1, _t1, ev1, r1 = decode_frames(f1)
            chk("rank-split: claims match sockets", r0 == 0 and r1 == 1)
            chk("rank-split: chain split across ranks",
                ev0[0][1] == want_chain[:1] and ev1[0][1] == want_chain[1:])
            chk("rank-split: split token lists align to blocks",
                ev0[0][3] == ids[:BLOCK_SIZE]
                and ev1[0][3] == ids[BLOCK_SIZE:full])
    finally:
        sim.close()


def run_geometry_lie():
    sim = Sim(fail="geometry-lie")
    try:
        st, si = http_json("GET", sim.url("/get_server_info"))
        chk("geometry-lie: page_size inflated",
            si.get("page_size") == BLOCK_SIZE + 16)
        ids = tok_ids(CHALLENGE_PROMPT)
        want_chain, _ = ref_chain(ids, BLOCK_SIZE)
        http_json("POST", sim.url("/v1/completions"),
                  {"model": MODEL, "prompt": CHALLENGE_PROMPT, "max_tokens": 1})
        frames = sim.recv_batch(0, 5)
        chk("geometry-lie: publish still hashes REAL page size",
            frames is not None
            and decode_frames(frames)[2][0][1] == want_chain)
    finally:
        sim.close()


def run_revision_lie():
    sim = Sim(fail="revision-lie")
    try:
        st, si = http_json("GET", sim.url("/get_server_info"))
        chk("revision-lie: revision differs from pin",
            si.get("revision") != REVISION)
        chk("revision-lie: version untouched", si.get("version") == "0.5.18")
    finally:
        sim.close()


def main():
    for f in (TOKENIZER, os.path.join(PROBE_DIR, "basic-ascii.expect.json")):
        if not os.path.isfile(f):
            print(f"FATAL: committed fixture missing: {f}")
            return 1
    run_positive()
    run_dp_coverage()
    run_tokenize_drift()
    run_no_echo()
    run_wrong_echo()
    run_rank_lie()
    run_rank_split()
    run_geometry_lie()
    run_revision_lie()
    print(f"\nself-test {'FAILED' if _fails else 'PASSED'} ({_fails} failures)")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
