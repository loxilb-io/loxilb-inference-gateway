# kv-mixed-version — two-node mixed-version strict-KV harness (GPU-free)

Runs the plan's seven mixed-version HA cases against a two-node loxilb
cluster in which the peer's build version, profile-registry stage, and
liveness are varied per case. Attestation rungs are earned through the
contract-faithful vLLM simulator (`cicd/common/kv_hash/vllm_attest_sim.py`,
proven honest by `vllm_attest_sim_selftest.py` before any leg runs) — no
GPU, no live engine.

## Topology

```
l3h1 (client) --10.10.10/24-- llb1 (NEW image, fixed)   --31.31.31/24-- l3ep1 [sim P]
              --20.20.20/24-- llb2 (image varies/case)  --61.61.61/24-- l3ep1
                                                        --32.32.32/24-- l3ep2 [sim D]
                                                        --62.62.62/24-- l3ep2
llb1 <=xsync/keepalived over docker bridge=> llb2
```

Each node carries its OWN strict rule (same profile/model/contract, its own
endpoint addresses — the composed binding keys profile+contract, not the
member set, so binding digests converge). Sims bind 0.0.0.0 and serve both
sides; each node's subscriber and prober reach the sims over that node's
own links.

## Cases (plan §10.3, all seven)

| # | Case | Peer state | Must hold |
|---|------|-----------|-----------|
| 1 | new-active / old-standby | llb2 = old image | llb1 strict rule earns rungs 1–2 then HOLDS at `ENGINE_HASH_ATTESTED`, never READY across cadences; Tier-2 traffic continuity |
| 2 | old-active / new-standby | llb2 = old image | strict POST to llb2 admits as LEGACY (unknown fields dropped), no strict claims anywhere for it |
| 3 | old peer answers Unimplemented | llb2 = old image | the RPC-level refusal is the mechanism: reasonCodes = `peer_capability_mismatch` + `peer_incapable` |
| 4 | profile-set mismatch → converge | llb2 = new, divergent then identical stage | mismatch: hold with `profile_set_digest_mismatch`; converged: **READY, goFenced=false — the eligible=1 GPU-free positive** |
| 5 | standby artifact corrupt | llb2 = new, corrupt tokenizer artifact | llb2 registry refuses publish ⇒ empty set digest ⇒ llb1 holds `profile_set_digest_mismatch`; llb2 refuses its own strict POST |
| 6 | attestation expiring before failover | both new+READY, sims SIGSTOPped, llb1 stopped | llb2 is NOT READY at takeover (nothing inherited), holds fail-closed `peer_incapable` while the peer is dark, re-earns READY with fresh receipts only after the peer answers again; continuity throughout |
| 7 | post-downgrade bypass | llb2 respawned old, same strict body replayed | admits legacy, routes Tier-2, zero strict claims (no status sub-resource on the old build) |

## Run

```
export LOXILB_DOCKER_IMAGE=kv-p6-ci   # NEW build image
export KV_OLD_IMAGE=v0.9.8.9-rc.1-u24 # OLD build image (pre-campaign release)
./config.sh && ./validation.sh ; ./rmconfig.sh
```

Traps baked in (do not regress):
- registry stages are host-side, root-owned, volume-mounted RO **before**
  spawn (loads once at init) — changing a node's stage means respawning it;
- never `docker restart` a node whose veths must survive (case 6
  deliberately sacrifices llb1's data plane, so it is last-but-one);
- llb2 is respawned per phase and MUST come back on the same docker-bridge
  IP (asserted loudly — llb1's `--cluster` peer address was computed at its
  own spawn);
- the simulator self-test gates config.sh: a broken sim would make
  hold-state legs green for the wrong reason.
