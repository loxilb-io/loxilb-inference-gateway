# SGLang + vLLM KV-Cache Routing Coexistence CICD Scenario

## Overview

Exit gate for **multi-framework KV-cache-aware (Tier-1.5) routing on one
gateway**: VIP-A carries a vLLM-style P/D pool, VIP-B carries an SGLang
single-role pool with per-rank KV events (`kvEngineType=sglang`,
`kvDpRankCount=3`), and the legs assert that inventories, hash algebra, and
tier-1.5 hits stay correct and ISOLATED in both directions. The KV event
feeds are driven by `kv_event_publisher` replaying golden vectors (vLLM CBOR
and SGLang), so every hash comparison is against a known-good oracle rather
than another copy of our own code.

## Topology

```
l3h1 ── llb1 (ONE gateway, VIP 10.10.10.254 — rules are keyed VIP:port:proto)
           ├── VIP-A :8080  vLLM P/D mock pool (kvExactMode=1; prefills at
           │                non-adjacent EP indices 0/2 — the bitmask shape)
           └── VIP-B :9090  SGLang single-role pool (kvExactMode=3,
                            kvEngineType=sglang, kvDpRankCount=3)
```

(EP addressing and publisher bindings are set by `config.sh` — treat it as
the source of truth.)

## Run

```bash
cd cicd/sglang-loxilb-kvcache
./config.sh          # topology + publishers + rules   (LOXILB_DOCKER_IMAGE=<tag> pins the image)
./validation.sh      # the legs; SKELETON_STRICT=1 by default (functional asserts are FATAL)
./rmconfig.sh        # teardown
```

Success sentinel: `SCENARIO-sglang-loxilb-kvcache [OK]` (36 checks, 0 FAIL).

## Legs

| Leg | What it proves |
|---|---|
| L0 | publisher fidelity — `kv_event_publisher --self-check` against BOTH the vLLM CBOR vectors and the SGLang golden vectors before any leg runs |
| L1 | inventory grows / multi-rank union — a 3-rank publish to a virgin EP converges the per-EP inventory to exactly the distinct-block total |
| L2 | tier-1.5 hit on BOTH VIPs — a prompt whose blocks are known-cached routes to the holder (hit counter + routing agree) |
| L3 | isolation both ways — vLLM-side publishes never influence SGLang-side routing and vice versa |
| L4 | same-model negative control — an identical model name on the other VIP does NOT alias inventories |
| L5 | engine-immutable — flipping `kvEngineType` on a live rule is rejected |
| L6 | EP-restart clears — an EP restart wipes its inventory (no ghost blocks steering traffic) |
| L7 | zero-hit watchdog — traffic that CANNOT hit (fresh salts) keeps the hit counters flat |
| L8 | cold-start seed — the bounded 1-in-N cold-start diversion sends exactly the Nth eligible hit to the cold EP (`LOXILB_KV_COLDSTART_SEED_N`, `[KV_COLDSEED]` marker) |
