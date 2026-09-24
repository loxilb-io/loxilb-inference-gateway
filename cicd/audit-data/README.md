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
| T18 | what was lost before the writer is named exactly | every `sys.producer.gap` names a producer, a stream and whether its range is exact; an exact range covers exactly the count it reports; more than one producer appears; `loxilb_audit_records_unattributed_total` is zero |
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
- The drop-ring **overflow** arm of T18 (`exact=false` with a counter
  delta) needs the ring to overflow between two heartbeats, which the
  queue sizes here do not reach; it is driven in the unit suite.

## Known red, and why

The suite is red on the `request_id` join and on one identity field. Both
are datapath defects it found, not assertions waiting to be softened.

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

## Running

```
cd cicd/audit-data
./config.sh
./validation.sh
./rmconfig.sh
```

Needs `jq` on the host — the requests go through a namespace, the JSON
extraction does not. `config.sh` pulls `postgres:18.6`.
