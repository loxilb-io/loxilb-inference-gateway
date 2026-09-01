# kv-sglang-attest — SGLang adapter attestation harness (GPU-free)

Proves the SGLang attestation adapter (plan §16.5 SGLang row) end-to-end
through the REAL gateway paths — REST admission, the compiled engine
contract (`sglang-kv-rank-v1`), the per-rank ZMQ subscriber with the
tagged-array rank wire binding, the challenge hasher's `sha256_sglang`
arm, and the kvexactstatus ladder — against the contract-faithful SGLang
simulator (`cicd/common/kv_hash/sglang_attest_sim.py`, proven honest by
`sglang_attest_sim_selftest.py` before any leg runs). No GPU, no live
engine.

## Topology

```
l3h1 (client) --10.10.10/24-- llb1 --31.31.31/24-- l3ep1 [sim, P role]
                                   --32.32.32/24-- l3ep2 [sim, D role]
```

Single node (no keepalived — the cluster capability gate passes with zero
peers, so READY is reachable; the mixed-version suite owns the HA cases).
Each case restarts the simulators in its fault mode and creates a FRESH
strict rule, so no ladder state bleeds between cases.

## Cases

| # | Sim mode | Must hold |
|---|----------|-----------|
| T1 | positive, dp=1 | ladder climbs to **READY**, goFenced=false, rank attribution (`1 rank(s) echoed`) in the log |
| T2 | positive, dp=2 | READY with **both ranks echoed** (`ranks [0 1]`) — the bounded per-rank challenge loop covers a real 2-rank publisher pair |
| T3 | tokenize-drift | holds `PROFILE_VALIDATED`, reason `token_mismatch` (rung 1 sees the drift; the echo half stays honest) |
| T4 | no-echo | holds `TOKEN_PARITY_VERIFIED`, reason `challenge_timeout` |
| T5 | wrong-echo | `challenge_timeout` (a corrupt chain is indistinguishable from silence — nonce uniqueness working as designed) |
| T6 | rank-lie, dp=2 | subscriber rejects every batch (`rank identity mismatch` log, rank-identity gate), challenge starves into `challenge_timeout` |
| T7 | rank-split, dp=2 | adapter refuses the split echo: reason `challenge_failed`, log `echoed from 2 rank streams` |
| T8 | geometry-lie | reason `engine_geometry_mismatch` BEFORE any nonce is spent, holds `TOKEN_PARITY_VERIFIED` |
| T9 | revision-lie | reason `identity_mismatch` — the manifest's `modelRevision` pin is read back from `/get_server_info` |

Fixture engine-scoping is pinned by construction: the registry stage
carries probe fixtures ONLY under `probefixtures/<profile>/sglang/` — a
gateway that looked in the flat vLLM location would fail T1 with
`probe_fixtures_missing`.

## Run (clean state)

```
cd cicd/kv-sglang-attest
export LOXILB_DOCKER_IMAGE=<build-under-test>   # e.g. kv-p8-ci
./config.sh && ./validation.sh ; ./rmconfig.sh
```

Deps on the host: docker, sudo, jq, python3 with pyzmq + msgpack +
tokenizers (the same set every kv suite needs). `config.sh` self-cleans an
aborted prior run, gates on the simulator self-test, and stages the
root-owned registry BEFORE spawning llb1 (the registry loads once at
init — a stage change always means a respawn). Simulators run as host
python inside the endpoint netns.

Expected: `validation.sh` prints `[OK]` per assert and exits 0 with
`ALL CASES PASSED`.

## Traps (do not regress)

- external `kill`/`pkill` binaries are DISABLED stubs on the CI host —
  `lib.sh` signals simulator pids with the shell BUILTIN kill only;
- the challenge prompt tokenizes through `/etc/loxilb/tokenizers/<slug>/`
  — the tokenizer stage is not optional;
- `LOXILB_KV_ATTEST_PROBE_CADENCE_S=5` keeps ladder retries inside the
  case timeouts; the default cadence would make T4/T6 wait minutes;
- the simulator publishes SIGNED int64 hashes in tagged-ARRAY events
  (`sglang-kv-tagged-array-rank-v1`) — the live wire capture recon
  banked EMPTY, so the live converged leg must re-verify this shape
  against a real banked capture before the tuple promotes.
