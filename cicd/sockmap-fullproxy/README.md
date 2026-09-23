# sockmap acceleration testbed

Functional, integrity and CPU tests for `sockMapMode` (per-service sockmap
acceleration on FullProxy). The feature itself is documented in
[`docs/sockmap-acceleration.md`](../../docs/sockmap-acceleration.md) — read its
**kernel requirement** section before believing any result from this directory.

One suite here runs in CI: `validation_apikey_response.sh`, as the
`sockmap-refusal-sanity` job of `.github/workflows/ai-gateway-sanity.yml`. It
accelerates nothing on the service it judges, so the kernel requirement below
does not bear on its verdicts. **Every other suite is run by hand**: the
acceleration suites need a patched kernel the hosted runners do not have. Unlike
the other `cicd/` scenarios, this directory holds many `validation_*.sh` scripts
over one shared testbed rather than a single `validation.sh`.

## Before you run anything

**Kernel.** On a kernel without the `sk_psock_backlog` fix (upstream `3b4f14b7`)
the accelerated path duplicates bytes. Functional suites mostly pass anyway
because their volumes are small; `validation_integrity.sh` is the one that looks
for it on purpose. Check `/proc/version_signature` against the table in the
feature doc before reading a failure as a loxilb defect.

**Image.** The default is `ghcr.io/loxilb-io/loxilb-inference-gateway:latest`,
overridden with `LOXILB_IMAGE`. The daemon is started with `--sockmapsupport` by
`config.sh`, so the image must be a build that has the sockmap assets.

```bash
LOXILB_IMAGE=ghcr.io/loxilb-io/loxilb-inference-gateway:sockmap-xyz ./config.sh
```

**API-key store.** `validation_apikey_response.sh` creates a key and drives keyed
traffic, so it needs the PostgreSQL key store the testbed does not start by
default. `SOCKMAP_AI_KEY_STORE=1 ./config.sh` spawns one (`postgres:18.6`,
bootstrapped by `scripts/aigw-db-bootstrap.sql`, the fixture `cicd/ai-apikey`
uses) and starts `llb1` with the `--aikey-db-*` options; `rmconfig.sh` removes
it. The store is configured by its own options, not by `--userservice`, so the
REST API stays token-free for every other suite. Without the knob the suite
refuses to start and says so.

**CPU suites need a quiet build.** The default image is a
`HAVE_PROXY_EXTRA_DEBUG` build that logs on every `recv()`, which only the
userspace relay pays — it biases any on/off comparison. `validation-cpu.sh` and
`validation-sse-cpu.sh` want the `:sockmap-nodebug` image from
`./build-measure-image.sh` and `LOXILB_LOGLEVEL=info` (the `config.sh` default).

## Bring it up and tear it down

```bash
cd cicd/sockmap-fullproxy
./config.sh          # llb1 + l3h1 (client) + l3ep1, l3ep2 (backends)
./validation.sh      # ... any suite below
./rmconfig.sh        # tears the testbed down and clears artifacts/
```

`config.sh` leaves two rules behind that some suites depend on:

| rule | VIP | backend | mode |
|---|---|---|---|
| R1 | `10.10.10.254:2020` | `tcp/8080` | `both` |
| R2 | `10.10.10.254:2021` | `tcp/8080` | `off` (control) |

## The suites

| script | what it pins |
|---|---|
| `validation.sh` | assets attach, R1 registers and R2 does not, portset cleanup on delete, and the configuration-time refusals (cases R-1..R-16) |
| `validation_apikey_response.sh` | a declared `api_key_auth` is refused acceleration in every direction, when the rule is created and when it is replaced, naming the direction; its traffic is relayed (every request admitted on its own, `X-Api-Key` stripped on every request, no redirect either way) while a credential-free control rule on the same testbed is accelerated, so the subject's zero is a refusal and not a dead counter. Needs `SOCKMAP_AI_KEY_STORE=1 ./config.sh`. Runs in CI |
| `validation_directional.sh` | `request` / `response` modes, the unaccelerated direction skipping the verdict, portset cleanup, mode change on a reused listener, and one endpoint shared by an accelerated and an `off` rule |
| `validation_refcount.sh` | portset refcounts across in-place updates, mode changes and shared endpoints |
| `validation_concurrent.sh` | concurrent connections over one rule |
| `validation_request_path.sh` | h2c through every mode, split / streamed / pipelined requests, and rule changes under a live connection |
| `validation_equivalence.sh` | **invariant I3**: what the client and the backend observe on an accelerated rule is identical to `off`. Four rules over one endpoint, compared record by record (cases E-*) |
| `validation_control.sh` | **invariant I5**: stopping acceleration on live connections (cases C-*). The admin action does not exist yet, so this suite is mostly XFAIL and BLOCKED |
| `validation_observability.sh` | what an operator can see of accelerated traffic: the rule's endpoint counter against `off` (O-3), a connection closed by the reset action (O-5), a refused redirect counted as `REDIRECT_DROP` (O-2), and `debug/psock-drops.bt` attributing a drop (O-6) |
| `validation_integrity.sh` | byte-level integrity of a streamed response against a sequence oracle — the suite that can see the kernel's duplication defect |
| `validation_perf.sh` | throughput, on vs off, over two rules that share every port |
| `validation-cpu.sh` | loxilb CPU, on vs off, on that same pair |
| `validation-sse-cpu.sh` | CPU per token under SSE streaming, including the `request` and `response` arms |

Each suite creates and deletes its own rules, except where noted below.

## Run order, and the dependency that bites

Suites are **not** independent, and none of them may run concurrently with
another (they share one testbed, one set of counters and one port space).

- **`validation.sh` deletes R1** in its step 7, and R1 is created by `config.sh`.
  So `validation.sh` is not idempotent: a second run fails its own steps 2 and 4
  (`R1 vip 2020 in sockmap_vip_portset : FAILED`, `delta=0; sockmap not
  engaging`). `validation_refcount.sh` and `validation_concurrent.sh` read R1
  too and fail the same way after it. Re-create R1 before re-running any of them:

  ```bash
  source ../common.sh; source ./sockmap_common.sh
  sockmap_create_lb_via_api llb1 10.10.10.254 2020 8080 "31.31.31.1,32.32.32.1" both sockmap-on
  ```
- `validation_perf.sh`, `validation-cpu.sh` and `validation-sse-cpu.sh` create
  their own rules on their own ports and are otherwise self-contained.
- A suite that aborts halfway leaves its rules behind. The next suite's create is
  then a **replace** of a rule with different settings rather than a create, which
  is not what it thinks it is doing. After an aborted run, delete the leftovers
  or re-run `config.sh`.

A working order for a full pass:

```bash
./config.sh
./validation_refcount.sh
./validation_concurrent.sh
./validation_directional.sh
./validation_request_path.sh
./validation_equivalence.sh
./validation_control.sh
./validation_observability.sh
./validation.sh          # last: it deletes R1
```

## Port map

Ports are hand-partitioned. **Check this table before adding a suite** — nothing
enforces it, and a collision shows up as a rule replace, not as an error.

| range | owner |
|---|---|
| 2000, 2030 | `validation_perf.sh`, `validation-cpu.sh` |
| 2020, 2021 | `config.sh` (R1, R2) — also read by refcount and concurrent |
| 2040–2043 | `validation_directional.sh` (2040/2041), `validation-sse-cpu.sh`; `validation_apikey_response.sh` (2042/2043, self-contained: creates and deletes its own rules) |
| 2044, 2045 | `validation_directional.sh` shared-endpoint step |
| 2050–2055 | `validation_refcount.sh` |
| 2060, 2061 | `validation.sh` AI-gateway refusals, `validation_integrity.sh` |
| 2062 | `validation.sh` L7-policy refusals |
| 2070–2075 | `validation_request_path.sh` |
| 2080–2083 | `validation_equivalence.sh` |
| 2090–2092 | `validation_control.sh` (2099 is deliberately ruleless) |
| 2100–2105 | `validation_observability.sh` |

Backend ports: 8080 (`config.sh`), 8260/8261 (`validation.sh`, no listener
needed), 9080–9083 (perf and CPU), 9090/9091 (directional), 9092/9093 (request
path, equivalence, control, observability), 9100–9106 (refcount), 9160–9170 (integrity).

## Reading a result

`sockmap_common.sh` prints five verdicts. The last three exist because these
suites are written **before** the fixes they describe.

| verdict | meaning |
|---|---|
| `OK` | passed |
| `FAILED` | failed, and the suite fails |
| `XFAIL` | a known defect, registered with `sockmap_xfail_register`, failing as expected. Does not fail the suite |
| `XPASS` | a registered defect that now **passes** — the fix landed, so the suite fails until the registration is removed |
| `BLOCKED` | cannot be judged at all, because a precondition is missing. Reported with `sockmap_result_blocked` |

`XFAIL` and `BLOCKED` are different on purpose. A case that fails today is xfail;
a case that would pass **vacuously** is blocked. "The other rule's connections
survived" is automatically true while nothing is being dropped, so registering it
as xfail would report XPASS and claim a fix that never happened.

The `RESULT:` line reports both counts, so a green run with pending work never
looks like a clean one:

```
RESULT: SCENARIO-sockmap-fullproxy-control [OK] (6 known defect(s) xfailed) (7 case(s) blocked, not evaluated)
```

## Fixtures

| file | used by |
|---|---|
| `sockmap_common.sh` | every suite: map readers, counters, rule helpers, the verdict vocabulary above |
| `request_path_server.js` | HTTP/1.1 backend that echoes the request headers it received, with `?bytes=`, `?status=` and `?abort=` response shapes |
| `request_path_client.py` | raw HTTP/1.1 client, one request shape per mode (`split`, `stream`, `pipeline`, `chunked`, `sizes`, `special`, `abort`, `halfclose`, `halfpartial`, `idle`, `keepalive`, `echo`, `volume`) |
| `equivalence_diff.py` | compares two `echo` runs; normalizes only the Host port and `Date`, and exempts no header |
| `h2c_server.js` | prior-knowledge HTTP/2 backend |
| `sse_server.js`, `sse_client.js`, `sse_raw_probe.js` | SSE streaming load and the integrity oracle |
| `perf_server.js`, `perf_client.js` | throughput load |
| `build-measure-image.sh` | builds the `:sockmap-nodebug` image for the CPU suites |
| `cert/`, `minica*.pem`, `loxilb.io/` | TLS material, unused by the plaintext suites |

Artifacts from a run land in `artifacts/` and are cleared by `rmconfig.sh`.

## `debug/`

`psock-drops.bt` is an operator diagnostic rather than an investigation record:
it attributes data the kernel's sockmap code freed instead of delivering (after
the verdict, where `sockmap_stats` cannot see) to the function and source socket
that lost it. Run it on the host with `sudo bpftrace debug/psock-drops.bt`, then
Ctrl-C. `validation_observability.sh` O-6 exercises it.

The shell scripts are diagnostics from investigations that are now closed. They are kept because each
is a re-runnable probe for a class of problem that can come back, and because
their headers record how the answers were reached. None of them is part of a
normal run.

| script | the question it answered |
|---|---|
| `crash-repro.sh` | why the loxilb process disappeared under burst SSE load — restarts it under a wrapper that records the exit status |
| `crash-hunt.sh` | the same, driving the exact sequence under which it actually died |
| `crash-hunt-orig.sh` | whether the death depended on the testbed's `exec` start (pty teardown SIGHUP), which the wrapper does not reproduce |
| `crash-latest.sh` | whether the `rfd_ent[]` race is product-wide rather than sockmap-specific — runs the load on a main build with no sockmap at all |
| `crash-offonly.sh` | whether sockmap raises the probability of that race, using the same binary with a single `off` rule |
| `churn-repro.sh` | whether deleting and recreating a rule under live load is the trigger |
| `seq-diag.sh` | whether the corruption is loss, reordering or duplication — a monotonic sequence stamped into every token |
| `latest-sockmap-probe.sh` | whether the duplication also reproduces on `:latest`, which predates this work |

They run from the suite directory (each one `cd`s there), so invoke them as
`./debug/<script>.sh`. Several set `set -u` before sourcing `../common.sh`, which
reads `$1` and `LOXILB_DOCKER_IMAGE` unguarded — export what they need or pass
their argument. That is pre-existing, not a consequence of the move.

## `minrepro/`

A standalone reproducer for the kernel duplication defect. It contains no loxilb
code and can be submitted upstream as-is.
