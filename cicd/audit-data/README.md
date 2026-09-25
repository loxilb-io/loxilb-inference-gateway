# audit-data

The inference-path audit trail, end to end, on a self-contained bed: no GPU,
no cloud service, no inference engine. A gateway with the API-key store on
PostgreSQL, two enforcing AI services, and the trail written under
`--audit-dir` with `--audit-required`.

This is the data-plane twin of `cicd/audit-mgmt`, which covers the
management plane.

## What it proves

| | claim | how |
|---|---|---|
| T14 | one request leaves one key: an admitted request produces exactly one completion and exactly one settle joined by `request_id`; a refused one produces exactly one deny carrying a non-empty `request_id` and the tenant of the credential that was refused | three requests through the gate — a 403 on a model the key may not use, an admitted non-streaming request, an admitted SSE request — each with its own `X-Request-Id` |
| T4 | the tokens in the record are the tokens that were charged | a non-streaming body cut mid-usage-object across two TCP writes, and an SSE stream with `include_usage`, each asking the backend for counts no other arm uses; the record is compared with the Prometheus charge counter's delta |
| T2 | the drop counter is reachable | the writer is stalled, the data channel is saturated, and the counter is asserted to **rise** — an "no drops observed" check passes on an idle system and proves nothing |
| T18 | what was lost before the writer is named exactly | every `sys.producer.gap` names a producer, a stream and whether its range is exact; a range too large for the ring is conservative rather than a guess, and an exact one covers exactly the count it reports; more than one producer appears; `loxilb_audit_records_unattributed_total` is zero |
| T21 | a reorder is not a drop | concurrent traffic from several workers with the writer healthy produces no new gap record |

## The join key

The gateway adopts a client-supplied `X-Request-Id` before the admission
gate decides, so every record of a request — the refusal, the completion,
the settle — carries the value this scenario chose. No assertion has to
guess which record belongs to which request, and none of them joins on
time.

## Layout

| file | what it does |
|---|---|
| `config.sh` | PostgreSQL, the topology, the backend, three API keys, a tenant token quota, two AI services |
| `validation.sh` | the assertions; restarts the gateway itself for the fault arms |
| `mock_inference.py` | the backend |
| `rmconfig.sh` | teardown |

## The backend

`mock_inference.py` reports the token counts the request asks for
(`?pt=N&ct=N`), rather than fixed ones. That is deliberate: a record
hard-coded to the same constants as a fixed-count backend would pass a
token-accounting assertion while proving nothing. Every arm asks for counts
no other arm uses.

It also serves `GET /__receipts/<nonce>`, counting requests that carried
each `X-Test-Nonce`. That is the only honest oracle for a refused request:
from the client side a refusal and a forwarded request whose answer was
discarded look identical, and the count is read from inside the backend's
own namespace, never through the gateway.

`?split=1` writes the non-streaming body in two TCP writes, cutting inside
the usage object, so a reader that parses only the first segment sees no
counts at all.

## The fault arms need a fault-enabled image

T2, T18 and T21 stall the writer on purpose, which only a build carrying
the `audit_faults` tag can do:

```
make HAVE_AUDIT_FAULTS=1
```

The stall is armed with a budget (`writer.stall:<n>`) so that it releases
itself after n records. An unbounded stall could only be lifted by
restarting, and a restart takes the producers' drop rings with it — the
gap records are written from those rings, so the evidence of what was lost
would die with the process that lost it.

`validation.sh` reads the gateway's build tags from `loxilb --version` and
**fails** when they are absent, naming the rebuild. It does not skip them:
an arm that quietly did not run would report a green that proves nothing.
A release image never carries the tag, and `scripts/release-hygiene.sh`
asserts that.

## What this bed cannot do

- **T9** (the audit load gates) needs the sockproxy benchmark on the
  designated hardware, audit off versus on, across six traffic shapes. It
  is not a container scenario and is not run here.
- **T10** (the AI regression) is `cicd/vllm-pd-disagg` re-run with audit
  on, not a separate suite.
- The **exact-range** arm of T18 (`exact=true`) is arithmetic this bed
  cannot reach. Nothing is dropped until the 8192-deep queue is full, and
  a producer that has been refused at all has been refused far more times
  than its 256-entry drop ring can name, so every gap here is a
  conservative one. The exact range is driven in the unit suite, over a
  four-deep queue where the whole drop set fits the ring.

## Known red, and why

The suite is red on T4's split-body arm: a response whose body arrives in
more than one segment has its completion record written when the headers
land, which is before the usage object it should report, so the record
says nothing was spent while the settle beside it charges the real counts.
That is a defect it found, not an assertion waiting to be softened.

- **`data.ai.complete` and `data.ai.settle` carry no `request_id`.** The
  gate mints or adopts the id and the refusal record carries it, but the
  keep-alive reset in `pd_setup_and_forward` clears
  `pfe->vllm_request_id` on the *current* request's forward path, before
  the response records read it. Every assertion that joins a completion or
  a settle to its request fails on this, which is most of T14 and T4.
- **The authorization refusal does not name its tenant.** The 403
  `model_not_allowed` arm resolved a valid key before refusing, so the
  record must carry that key's tenant; `actor.tenant` is empty. The
  rate-limit refusal on the same bed does carry its tenant, so the record
  path is fine and the arm is not handing the identity over.

Both live in the eBPF half and are fixed there, not here.

## Design decisions worth knowing

- **The quota that is enforced is the tenant's.** `tokens_per_min` on an
  API key is stored metadata and charges nothing, so an assertion built on
  it would pass against a gateway that enforced no quota at all. The
  refused-charge arm sets `POST /config/ai/tenant/ratelimit` instead.
- **The deny arm that must name a tenant is the 403, not the 401.** An
  unrecognised credential resolves no identity and the record honestly
  names nobody; the 403 is the case where the key is valid, its tenant is
  known, and the refusal must carry it.
- **The refused-charge oracle has no timing in it.** The backend answers
  12 tokens and the tenant is limited to 10 per minute, so the first
  request is admitted against a clean bucket and its settle puts the bucket
  in debt; the second is refused at admission. A burst would be a race.
- **Saturation uses the shipped queue size.** The channels are 8192 deep
  and there is no flag to shrink them. Rather than add one for a test, the
  scenario drives enough traffic to fill them, so what is measured is the
  queue the product ships.
- **Gaps are drained at the heartbeat**, every 30 seconds. The arms that
  read them wait for one; none asserts a gap inside a short boot.

## Red twins

A test counts only once its red twin has been run: the named mutation that
makes the assertion fail for the right reason (plan §6.1). Twins are code
mutations followed by a rebuild, which CI cannot do to itself, so they are
run by hand on the bed and recorded here; `gen-coverage-manifest.py` marks
a requirement *covered and tested* only when its `red_twin_run_id` names a
row of this table, and nothing else may set one.

Four of these revert a defect this scenario found; the gap twin had no
defect to revert, so it mutates the claim the record exists to make. Each
run: the mutation applied to a synced copy of the tree (the diff is in the
run log), the image rebuilt with the fault-enabled overlay recipe, the
whole scenario run against it, the file restored. The baseline run on the
same trees and bed was green (71 assertions, 0 failed). Two of the
mutations are fork-side, which the management scenario's twin patcher
could not reach.

| run id | twin | mutation | assertions that went red, and nothing else |
|---|---|---|---|
| `llbigw-2-twin-1b-reqid-r1` | the request-id join removed | `proxy_request_id` returns the live field only, dropping the snapshot (fork `common/sockproxy.h`) | T14-3c, T14-3d, T14-3f, T14-3g, T14-4a, T14-4c, T14-4d, T14-4e, T14-5d, T14-5e, T14-5f, T14-5g, T14-5h, T4-1a, T4-1b, T4-1c, T4-1d, T4-1e, T4-2a, T4-2b, T4-2c — every record that has to be found by its key |
| `llbigw-2-twin-1b-complete-r1` | the completion written at header time | `proxy_ai_record_completion` called where the response status is parsed, before the body's usage object is read (fork `common/sockproxy_http.c`) | T4-1d, T4-1e (the completion says 0 tokens while the settle charges 41/9), T14-5e, T14-5h |
| `llbigw-2-twin-1b-deny-r1` | the refusal cannot name its tenant | the identity copy moved back inside `if decision == 0` (`pkg/loxinet/ai_gateway_dp.go`) | T14-2b |
| `llbigw-2-twin-1b-drops-r1` | the drop totals blind to producer drops | the producer fold removed from `Stats()` (`pkg/audit/writer.go`) | T2-1a |
| `llbigw-2-twin-1b-gap-r1` | a gap that does not name its producer | `ProducerID` emitted empty in `emitProducerGaps` (`pkg/audit/writer.go`) | T18-1b (180 gaps unnamed), T18-2c |

T2-1a asserts a Prometheus counter rather than a record field, so no
requirement row claims it and its twin sets no `red_twin_run_id`; the
mutation is recorded here because the drop totals are what the data
stream's loss accounting is read from.

### A twin that stayed green, and what it found

A sixth mutation was run and is kept because it failed to go red:
`exact := true` in `emitProducerGaps`, so every gap claims its range is
exact whether or not the ring behind it overflowed. The scenario stayed at
71/0. Two assertions were expected to catch it and neither can:

- **T18-1e** selects `.detail.exact==false` and then checks the range. With
  `exact` never false the filter matches nothing, and the assertion passes
  on an empty set.
- **T18-2b** selects `.detail.exact==true` and checks `counter_delta`
  against the range width — but `emitProducerGaps` computes
  `CounterDelta: run.to - run.from + 1`, so the two agree by construction
  whatever `exact` says.

So the bed does not currently test the exactness claim in either
direction, and the requirement is marked tested on `llbigw-2-twin-1b-gap-r1`
(the per-producer claim), not on these two. Detecting a lying `exact` needs
an assertion that compares the flag against the producer's own ring
overflow count, which the trail does not currently publish. Recorded rather
than fixed here; the unit suite (`TestProducerDropAccounting`) still drives
the exact-range arithmetic on a four-deep queue.

## Running

```
cd cicd/audit-data
./config.sh
./validation.sh
./rmconfig.sh
```

Needs `jq` on the host — the requests go through a namespace, the JSON
extraction does not. `config.sh` pulls `postgres:18.6`.
