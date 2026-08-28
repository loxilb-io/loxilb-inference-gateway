# `cicd/auth-baseline` — authentication-plane evidence harness

Supports the authentication plane separation work, which gives each plane its
own credential store, its own database role and its own cache.

It exists because `cicd/ai-apikey` never starts a backend process at all, so it
cannot answer the question these baselines are for: when the gateway denies a
request, does the request still reach the backend?

`up.sh` establishes the topology and asserts nothing. The probes decide verdicts.

```
l3h1 (10.10.10.1) ── llb1 (VIP 10.10.10.254:2020, mgmt :11111) ── l3ep1 (31.31.31.1:8080)
                       │
                  mysql-ai (MariaDB 10.11, docker bridge)
```

`l3ep1` runs `count_server.py`, which appends one line per arriving request to
`/tmp/backend_reqs.log`. That log is the instrument: it moves only for requests
that genuinely reached the backend.

## Running

Build the image on this host first — never bind-mount a host-built binary into a
CI image, since the host glibc is newer than the image's and the container
crash-loops silently:

```bash
docker build --network host -t ghcr.io/loxilb-io/loxilb-inference-gateway:authsep-ci .
```

Pre-implementation baselines (B-1 … B-5), against unmodified code:

```bash
AUTHSEP_IMAGE=authsep-ci ./up.sh
./probe_b1.sh        # B-1: does a denied request reach the backend?
./probe_mgmt.sh      # B-2..B-5
```

Management-auth smoke run, starting from an empty user table so
the probe drives the bootstrap itself:

```bash
AUTHSEP_IMAGE=authsep-i1 AUTHSEP_BOOTSTRAP=no ./up.sh
./probe_i1.sh
```

Tear down with `docker rm -f llb1 l3h1 l3ep1 mysql-ai`. Do this when finished:
eBPF maps are kernel-global, so a second gateway perturbs the live one's map
counts even with `--network none`.

## The `pkg/aikey` store (PR 2, step I-3)

The `pkg/aikey` gates need a real PostgreSQL: they are about what the server
does with the statements, and a mock would only replay what the test already
assumed. `pg-up.sh` brings one up and provisions it with
`scripts/aigw-db-bootstrap.sql` — the file the product ships, so the fixture
and the deployment path are the same thing.

```bash
cicd/auth-baseline/pg-up.sh
AIKEY_TEST_PG=required AIKEY_TEST_DSN="$(cicd/auth-baseline/pg-up.sh dsn)" \
  go test ./pkg/aikey/ -count=1
cicd/auth-baseline/pg-up.sh down
```

`AIKEY_TEST_PG=required` turns an absent store into a failure. Without it the
store legs skip, which is right on a laptop and wrong in an evidence run: a
suite that skips its own subject reports `ok`.

Until step I-4 repointed the datapath, the gateway read keys from MariaDB and
`pkg/aikey` was dormant. It is not any more: `--aikey-db-host` is where keys
live, and MariaDB carries only the management plane's users and tokens.

## The PR 2 repoint (step I-4)

`up_i4.sh` builds the same topology as `up.sh`, with two differences that are
the whole point: the gateway is pointed at PostgreSQL rather than MariaDB, and
`--userservice` is **off**. That combination — a key store that exists and a
management plane that is not enabled — could not be expressed before this step.

```bash
docker build --network host -t ghcr.io/loxilb-io/loxilb-inference-gateway:authsep-i4 .
AUTHSEP_IMAGE=authsep-i4 cicd/auth-baseline/up_i4.sh
cicd/auth-baseline/probe_i4.sh
```

`probe_i4.sh` restarts the gateway between its three phases, because each phase
*is* a different gateway configuration: store + no user service (POL-1, POL-3,
POL-7, and the datapath legs), no store at all (POL-1b), store + user service
(POL-1c). The restart clears the four pieces of datapath state that outlive the
process — the persistent `llb0` TAP above all — because a bare kill-and-start
always fails on `llb_xh_init: Assertion 0 failed`.

One leg deliberately asserts something that is about to change: with no store
configured, a keyless request through the VIP is **admitted**. That is the
retained `nil → allow` branch, which keeps PR 2 behaviour-preserving and which
PR 3 deletes. Its companion leg asserts that the gateway says so in the log.

## Reading the results

`probe_i1.sh` prints `[PASS]`/`[FAIL]` per leg and a summary. A red leg is a code
defect until proven otherwise — fix the code, never the assertion.

`probe_b1.sh` prints the backend delta rather than a verdict, because the
verdict it feeds is a judgement recorded separately. Its
positive control runs first: without proof that a keyed request moves the
counter, a zero delta would prove nothing.

## Traps

- `set -u` breaks `source ../common.sh`, which reads `$1` at the top.
- `docker exec -d` gives the gateway no captured stderr, so a Go panic trace is
  lost. Restart it with `> /tmp/loxilb.out 2> /tmp/loxilb.err` when a panic is
  the thing being observed.
- An unauthenticated call that presents an unknown token still costs the token
  lookup's full retry budget before its 401 — a known defect fixed in a later
  phase, not a fault in the leg.

## The I-0b baseline re-run (step I-6)

`up_i6.sh` is the I-0 topology with one deliberate difference: the gateway also
gets `--aikey-db-*`. The management plane is still MariaDB — it does not move to
PostgreSQL until I-8 — but data-plane keys moved to `pkg/aikey` at I-4, so
without the store flags `POST /config/ai/apikey` answers `503
ai_key_store_unconfigured` and the B-5 leg has no key to present.

```bash
./up_i6.sh                       # image defaults to authsep-i5b
./probe_i6.sh                    # I-6: expect the I-0b defects to be present
AUTHSEP_EXPECT=green ./probe_i6.sh   # I-9: expect them repaired
```

`probe_i6.sh` is a recording instrument, not a gate on the product. Each leg
carries a **named** expectation and the script exits non-zero only when an
observation deviates from it — so a leg that stops reproducing, or starts, is
something a human has to read. The I-9 gate is this same file under
`AUTHSEP_EXPECT=green`, which means it cannot be produced by softening this one:
the expectation is named, not edited. Run it both ways once and you have shown
the instrument can fail.

Two things it learned the hard way, both of which made a leg unable to fail:

- `docker exec llb1 curl -o /tmp/body` writes the body **inside the container**,
  so reading it back on the host yields nothing and every body-shaped assertion
  silently passes. `mgmt()` returns status and body through the same stdout.
- A readiness poll aimed at a route the build does not serve gets `404`, which
  is not `503`, so the loop exits on its first iteration and waits for nothing.
  `up_i6.sh` treats `404` from the readiness URL as a hard failure.

`up_i6.sh` also removes `llb1_config/snapshot.json` before spawning. loxilb
persists its configuration into the mounted config directory, so without that a
second bring-up replays the first one's load-balancer rules and the create comes
back `409` — "clean bring-up" has to mean the gateway too, not just the
containers. `up.sh` and `up_i4.sh` do not do this; their recorded runs are
unaffected (the replayed rule is identical), but re-running them back to back
will show the 409.
