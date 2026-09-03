# cfg-persist-roundtrip

The flagship configuration-persistence suite: a gateway carrying one of
every restartable configuration class must survive persist + in-place
restart **field-identically**, with the datapath still enforcing what the
config says.

## Topology

`llb1` (BGP-enabled, `pick_config` volume so `snapshot.json` is
host-inspectable) + client `l3h1` + three reflect-echo backends. The
KV-exact profile registry is staged host-side and mounted read-only
before the gateway starts, the way a production operator stages it.

Fixture classes: plain L4 LB (hash select, health-monitored, source
allowlist), API-key-gated L7 fullproxy rule, strict KV-exact P/D rule
(creates a binding), standalone endpoint, firewall, QoS policy, SPAN
mirror, session + ULCL, ipfilter, securityrate, BGP global config and a
neighbor with **non-default transport** (port 1790 + multihop).

## Oracles (see `../common/persist_lib.sh`)

1. **Canonical deep-diff, not probe re-runs**: every domain dumped via
   its GET API before and after the restart, jq-canonicalized (sorted,
   volatile fields stripped by explicit per-domain filters), diffed.
   Diff output is kept under `artifacts/`.
2. **Persist response contract**: 200 + `result:ok` + `sha256:` checksum
   that matches the on-disk `snapshot.json`.
3. **Idle-capture stability**: two captures of an unchanged gateway must
   be domain-payload identical (runtime counters must not churn the
   persisted document).
4. **Restore planning**: a dry-run of the gateway's own capture must
   plan every domain, including `kvexactbinding`.
5. **Datapath probes**: L4 VIP routes, keyless requests to the
   API-key-required VIP are refused (401 with a key store, 503 fail-closed
   without one — the refusal class must be identical before/after).
6. **Speaker-level BGP oracle**: `gobgp -p 50052 -j neighbor` must show
   the restored transport config on the wire side, not just the REST echo.

## Red twin

`PLIB_RED_MUTATE=1 ./validation.sh` deletes the firewall rule and
re-persists AFTER the canonical baseline capture, so the restart comes
back different from the baseline — the deep-diff oracle must fail (exit
1). Run it whenever the harness changes; a suite whose asserts cannot go
red proves nothing.

## Traps (do not regress)

- Poll the boot replay receipt (`boot snapshot: snapshot.json applied`
  in `/tmp/loxilb.out`) before asserting anything after a restart.
- Never `docker restart` the gateway — in-place restart via the
  SIGTERM→SIGKILL trio with datapath scrub (`persist_lib.sh`).
- Fullproxy (mode 4) rules bind only on a locally-assigned VIP — they
  use the gateway's own client-side address, while the L4 rule uses a
  routed VIP.
- The three L7/L4 rules use non-overlapping endpoints ON PURPOSE:
  endpoint-host options are shared per endpoint key and first-writer-wins,
  so a non-monitored rule applying first would strip a monitored rule's
  probe config (pre-existing behavior, tracked separately).
- `gobgpd` serves its API on port 50052 here; the plain `gobgp` CLI
  default (50051) times out.
- Captured snapshots can carry secret-bearing domains; artifacts of this
  suite are for CI evidence only — never promote a captured
  `snapshot.json` to a committed fixture.
