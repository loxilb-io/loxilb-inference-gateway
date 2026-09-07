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
neighbor with **non-default transport** (port 1790 + multihop), plus the
four snapshot-1.3 domains: an **L7 REJECT policy** (non-default 451) on a
plain fullproxy, a **CORS allowlist** (one origin), an **OTLP export
config** with an auth header (the secret-split subject), and a **managed
TLS certificate** (`/config/cert`) whose SAN hostname lands in the SNI
store; an HTTPS-terminating proxy serves it at handshake.

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
7. **Secret split**: the captured document must carry the OTLP header
   NAME and the cert `{cert_id, digest}` metadata but never the header
   value or any PEM; the value must sit in the node-local
   `otlp-headers.json` (0600) and survive the restart.
8. **Enforcement probes for the 1.3 domains**: `/blocked` answers the
   policy's own 451 and a non-matching path the Gateway-API no-match
   default 404 before AND after restart (a detached policy flips both to
   plain forwarding); an allowlisted Origin gets
   its grant (with credentials) while an unlisted one gets NO grant
   either side of the restart; `openssl s_client -servername` receives
   the managed cert at handshake before AND after reboot.
9. **Configured-empty CORS**: removing the last origin is DENY-ALL, is
   captured as `{"origins":[]}` (distinct from unconfigured/absent), and
   a second restart must not re-seed the factory-open default.
10. **Recovery-dependencies manifest (schema 1.4)**: the document
    declares exactly the wired external stores, (type,id)-sorted — the
    captured KV binding makes `engine-contracts` + `kv-model-profiles`
    REQUIRED, the captured cert makes `cert-store` REQUIRED, and no DB
    entry appears (none is wired here). Entries carry identity fields
    only (type/id/generation/digest/required — never store content),
    and the manifest is byte-identical across idle captures AND across
    the restart. The fail-closed side of the contract lives in the
    negative suite.

## Red twin

`PLIB_RED_MUTATE=1 ./validation.sh` mutates AFTER the canonical baseline
capture and re-persists, so the restart comes back different from the
baseline: the firewall delete trips the deep-diff oracle, the l7policy
delete trips the RT-07 enforcement leg, the cors-origin delete trips the
grant leg, and removing `otlp-headers.json` trips the node-local secret
leg (persist rewrites only `snapshot.json`, so the file stays gone).
Exit must be 1. The cert legs get their red from the negative suite's
digest-divergence/missing-material legs (mutating the managed dir here
would wedge the boot-replay receipt on purpose-built retries). Run the
red twin whenever the harness changes; a suite whose asserts cannot go
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
