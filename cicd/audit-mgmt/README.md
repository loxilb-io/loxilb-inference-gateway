# audit-mgmt

The management-plane audit trail, end to end, on a self-contained bed: one
gateway, one PostgreSQL holding both stores, no GPU, no external identity
provider. This is the scenario the coverage manifest points at when it says
an event type is covered.

## What it proves

| id | claim | how |
|---|---|---|
| T-GW-1 | `/audit/status` reports the writer and never the trail's content | field checks; the first record of a boot is `sys.writer.start` |
| T-GW-3 | the log-archive API refuses an audit segment by name | `GET /log-archives/audit.jsonl` is not 200 and leaks no record |
| T25 | the delegated originator is recorded on every record of a request, trusted only for an account marked `delegation_allowed`, never promoted to `actor.user`; a malformed value is dropped and counted | an admin account, a delegating account, a viewer's 403, a malformed header; `/metrics` and `/audit/status` counters |
| TM | the named routes each leave an intent+result pair of their own type with the detail the plan lists | persist, export, maintenance on/off, token upgrade, logout, user create/delete, API-key create, two listing reads |
| T22 | the side-effecting OAuth GETs are gated | healthy: start answers 307 with a fingerprinted state, unknown-state callback 400, refresh with both tokens in the query string recorded without the query; wedged: all three 503 before any exchange |
| T15 | canary secrets reach no segment (active, sealed, compressed) and no error body | nine canaries the harness sends (proved from its own request log) plus the raw API keys and the OAuth state the gateway minted |
| T11 | actor conformance | with `--userservice` every successful result names a principal with `auth=session`; without it every record says `auth=none` and names nobody |
| T20 | a crash between a durable intent and its result is reported at the next boot, never guessed | the store is paused, a user create blocks after its intent, the process is SIGKILLed; boot 2 writes exactly one `sys.intent.orphaned` naming that `event_id`, the counter reads 1, no result exists |
| T3 | the gate fails closed with the authoritative state unchanged | the audit directory sits on a 1 MiB tmpfs that is filled to the last byte; a generated route, a raw route and a named route answer 503 `audit_unavailable` and the rule table, the key and the account list are unchanged; freed, the same calls leave a pair sharing one `event_id`, intent before result by `seq` |
| T19 | the writer is not the only witness to its own failure | `loxilb_audit_write_failures_total` rises, `loxilb_audit_last_write_timestamp_seconds` stands still across a heartbeat interval, the operational log carries the fallback line; after recovery one `sys.writer.write_failed` names the interval and count, and every line of the segment still parses |

## Layout

| file | role |
|---|---|
| `config.sh` | PostgreSQL (both roles from `scripts/aigw-db-bootstrap.sql`), the topology, the gateway with `--userservice`, the OAuth routes on a placeholder provider, the API-key store and `--audit-dir … --audit-required`; the administrator; `.state` with the flag sets |
| `validation.sh` | the matrix above, across four boots of the gateway process |
| `rmconfig.sh` | teardown (unpauses the store first, in case T20 was interrupted) |
| `gen-coverage-manifest.py` | the event matrix: one entry per event type, stage-scoped requirements naming the assertions above; `--check` is the drift gate CI runs |
| `audit-coverage-manifest.json` | generated; its SHA-256 over the entries is the `matrix_digest` |

## The four boots

The gateway process is restarted inside its container (the `tiers.sh`
pattern) because the flag set and the audit directory have to change, and
because T20 needs a crash. Every boot's records stay readable: the previous
boot's segment is sealed at recovery and compressed, never removed.

1. `--userservice`, OAuth, audit at `/var/log/loxilb/audit` — T-GW-1, T-GW-3,
   T25, TM, T22 healthy arms, the canary sends, T11 arm 1. Ends with the
   T20 crash.
2. same flags — the orphan report, then an orderly stop.
3. audit at `/var/log/loxilb/audit-wedge`, a 1 MiB tmpfs — the key for the
   raw arm is created, the filesystem is filled, T3 / T22 wedged / T19,
   the filesystem is freed, the positive arms and the retroactive record.
4. no `--userservice` — T11 arm 2. The canary sweep runs last, over both
   directories, so it covers the compressed segments of boots 1 and 2.

## Design decisions worth knowing

- **The wedge is a full filesystem, not a fault build.** Mounting over the
  audit directory or changing its mode does nothing to a file the writer
  already holds open; only the filesystem itself can refuse an append. A
  tmpfs of one MiB filled with `dd` (page-sized, then byte-sized to close
  the last page) makes the next append fail with ENOSPC, and `rm` undoes
  it. That is also the "fill the filesystem" arm of T19. The
  permission-loss arm of T19 is not driven here: a `chmod` of the directory
  cannot reach an open descriptor either; the writer's reaction to EACCES
  is covered by the unit suite through the fault hook.
- **T20 needs no fault point.** `docker pause` freezes the store's
  processes but the kernel keeps acknowledging TCP, so a handler that
  already holds a pooled connection waits for an answer that never comes.
  A fresh login just before the pause makes sure such a connection exists
  (the pool recycles connections after five minutes). The intent is durable
  before the handler runs; SIGKILL then leaves it without a result.
  Whether the paused store commits the insert once it resumes is printed,
  not asserted: the trail does not guess either way and neither does the
  scenario.
- **T11 exempts two shapes, counted separately.** The loopback bootstrap of
  the first account (`actor.bootstrap`) and the unauthenticated OAuth start
  whose result inherits the provisional view (`actor.provisional`) have no
  principal by design; the scenario counts them so the exemption cannot
  swallow the rule.
- **T15 proves the canaries were sent before proving they are absent.**
  The harness keeps its own request log and greps it first; the raw API
  keys and the OAuth state are received rather than sent and join only the
  absence sweep. The operational log runs at debug on this bed, which the
  product does not ship; a canary there is printed as a note, not scored.
- **Restarts pass `-p --loglevel debug` explicitly.** `spawn_docker_host`
  adds them to the first boot; a restart that forgot them would lose
  `/metrics` (503 "Prometheus option is disabled") and read as a product
  failure.

## What this bed cannot do

- The OAuth callback that completes a login needs a real identity provider;
  only the unknown-state refusal and the wedged refusal run here.
- T17 (writer panic, supervised restart) needs the `audit_faults` build tag
  and `LOXILB_AUDIT_FAULT=writer.panic`; the CI image is built by `make`
  without tags. It runs in the unit suite in every build (the package's
  internal hook) and once more with the tag in the `unit-gates` job.
- The disk reserve (`sys.disk.reserve_breached`) is zero in the shipped
  configuration; its crossing is driven in the unit suite.
- A restore (`mgmt.snapshot.restore`) rolls the whole configuration back on
  failure and is exercised behind the real gate in the unit suite, not on
  the shared bed.

## Observed, not scored

- After `POST /auth/logout`, a `GET /auth/users` with the logged-out token
  still answers 200 on this bed. Whether an issued token dies with the
  logout is the authentication plane's contract, not the trail's; the
  scenario prints the answer as a note for that plane's owner and scores
  only the logout's own record.
- The operational log runs at debug here. A canary found there is printed,
  not scored; none was found in the reference run.

## Red twins

A test counts only once its red twin has been run: the named mutation that
makes the assertion fail for the right reason (plan §6.1). Twins are code
mutations followed by a rebuild, which CI cannot do to itself, so they are
run by hand on the bed and recorded here; `gen-coverage-manifest.py` marks
a requirement *covered and tested* only when its `red_twin_run_id` names a
row of this table, and nothing else may set one.

Each run: the mutation applied to a synced copy of this tree (the diff is
in the run log), the image rebuilt with the overlay recipe, the whole
scenario run against it, the file restored. The baseline run on the same
tree and bed was green (165 assertions, 0 failed).

| run id | twin (plan §6.1) | mutation | assertions that went red, and nothing else |
|---|---|---|---|
| `llbigw-2-twin-T3-r1` | middleware moved back to post-handler | in `AuditGateMiddleware`, the handler runs against a discarded recorder before the 503 is answered | T3-1d (rule created), T3-2c (key disabled), T3-3b (account created); T3-4a followed with 409 because the rule already existed |
| `llbigw-2-twin-T20-r1` | recovery scan skipped | `scanOrphans` returns at entry | T20-1a, T20-1b, T20-2a, T20-2b, T20-2c |
| `llbigw-2-twin-T19-r1` | fallback counters removed | `noteWriteFailure` no longer counts | T19-1a, T19-1b, T19-3b, T19-5 |
| `llbigw-2-twin-T15-r1` | a secret enters a recorded field | the login body reader returns the password with the claimed name | T15-s1e and T15-2.1, T15-2.2, T15-2.8, T15-2.9 (every login password canary found in a segment) |

T11, T22 and T25 have no twin in the plan's table; their assertions are
scored but the manifest does not claim them as tested.

## Running

```
cd cicd/audit-mgmt
LOXILB_DOCKER_IMAGE=<tag> ./config.sh && ./validation.sh; ./rmconfig.sh
python3 gen-coverage-manifest.py --check
```

`jq` must be on the host: the requests go through `docker exec`, the
extraction does not. One gateway at a time on a shared host; teardown
removes `pg-audit`, which runs with `--rm`. The whole run takes about six
minutes, most of it the four boots and the 35 s staleness window.
