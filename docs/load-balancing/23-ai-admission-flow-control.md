# AI admission flow control: the capacity gate and its queue

The capacity admission gate bounds how many inference requests execute on a
model pool at once, and how many may wait for a turn. It runs on every
AI-gateway service (a rule with `sse_mode`, `pd_disagg_mode` or an API-key
policy) after the policy checks (credential, quota, rate limit) and before
any byte reaches a backend. A refused request never opens a backend
connection; a queued request holds no backend resource while it waits.

This page covers the gate's modes and ceilings, the bounded queue, the rule
fields that configure each of them over the process defaults, what the
client sees, the maintenance drain, and the metrics. The REST fields are also listed in the
[REST reference](05-rest-api-reference.md).

## Modes

A rule sets its mode with `fc_mode` (`off`, `observe`, `enforce`); a rule
that declares none, or declares `inherit`, runs on the process default
`LLB_FC_MODE`. A rule may switch the gate off under an enforcing
environment.

| Mode | Behaviour |
|---|---|
| unset / `off` | The dispatch path is unchanged. Every pool still exports its state with mode `0`, so a scrape can tell an ungated AI pool from a non-AI service. |
| `observe` | Every decision is computed and counted; everything is admitted. The `observe_would_shed` and `observe_would_queue` counters say what `enforce` would have done, at each ceiling that would have refused the request. |
| `enforce` | Over a ceiling, a request is queued when the pool has a queue depth and the request may wait, else refused. |

## Ceilings

A ceiling of `0` in force means unlimited at that level.

| Level | Field (`serviceArguments`) | Environment default | Counts |
|---|---|---|---|
| service (pool-wide) | `fc_max_outstanding` | `LLB_FC_MAX_OUTSTANDING` | one unit per executing inference request, however many backend legs it opens |
| endpoint, normal role | `fc_ep_max_inflight` | `LLB_FC_EP_MAX_INFLIGHT` | one unit per executing request on that endpoint |
| endpoint, prefill role | `fc_prefill_max_inflight` | `LLB_FC_PREFILL_MAX_INFLIGHT` (falls back to `LLB_PD_MAX_INFLIGHT_PER_EP`) | one unit per prefill leg |
| endpoint, decode role | `fc_decode_max_inflight` | `LLB_FC_DECODE_MAX_INFLIGHT` | one unit per decode leg |

Each field is at most 100000.

### Where a value comes from

Every setting on this page resolves the same way, per rule: the rule's own
value when it declares one, else the process environment, else the product
default. A rule field of `0` (or `fc_mode` `inherit`) declares nothing: it
inherits, so a rule cannot ask for "unlimited" under an environment that
sets a ceiling. GET on the rule returns what was declared, and
`fc_effective` returns what is in force on the pool together with
`fc_effective.source`, which names for each value whether it came from the
`rule`, the `env` or the `default`.

All the fields are runtime settings. A replace `POST` with the same key
applies the new values to the live pool without touching executing
requests: an omitted field keeps its stored value, an explicit `0` (or
`inherit`) returns it to the environment or default, and JSON `null` is
refused. When a change lets waiting requests through (a higher ceiling, or
a mode that no longer enforces), they are woken at once, in wake order, one
per free unit, or all of them when the pool no longer enforces, instead of
one per second. PATCH does not reach FullProxy rules; on an AI service the
runtime change is a replace `POST`.

A replace that changes only these fields (and the queue's two) is applied
in place. A replace that also changes anything else re-creates the
service's data-plane entry: requests waiting in its queue are then ended
with `503 admission_drained`, as on a rule delete, and the pool's counts
start again. Change the gate on its own when requests may be waiting.

These are rule configuration, like every other `serviceArguments` field:
nothing replicates them between gateway instances. Each instance holds the
rules its controller (or its snapshot) gave it, so two instances given the
same rule resolve the same values, and an instance given a rule without
them runs on its own environment.

A unit is taken once per request: an HTTP/1.1 request (each request on a
keep-alive connection is gated again), or an HTTP/2 stream. It is released
when the request completes, when the client goes away, or when the backend
leg fails, whichever comes first. Requests that are not inference calls
(`GET /v1/models`, health probes) bypass the ceilings and are counted under
`bypass_non_inference`.

## The bounded queue

When the pool is over a ceiling and has a queue depth, an HTTP/1.1 request
whose body has arrived is parked instead of refused: its connection stays
open with reads paused, and it holds no capacity unit and no backend
connection. Each release of an executing unit on the pool wakes exactly one
waiter, the one the wake order chooses (see [Which waiter a freed unit
wakes](#which-waiter-a-freed-unit-wakes); with every waiter in one band and
`fifo`, the oldest); a newcomer never jumps a waiter of its own band that
could take the unit. A woken
request that loses the race for the unit goes back to the head, even when
newcomers filled the queue to its depth meanwhile; one that fails an
endpoint ceiling goes back without waking anyone, since the next waiter
would meet the same ceiling. Going back does not restart the clock: the
request keeps the deadline it was first parked with, so
`fc_max_queue_wait_ms` bounds its whole wait however often it is woken, and
several woken requests that go back keep the order they arrived in. A turn
is never lost: when a woken client has
gone before it resumed, or its wake could not be delivered, the turn passes
to the next waiter, and a once-a-second pass wakes the head of any pool that
has a free unit and requests still waiting.

| Field (`serviceArguments`) | Process default | Meaning |
|---|---|---|
| `fc_max_queue_depth` | `LLB_FC_MAX_QUEUE_DEPTH` | requests that may wait on the pool; `0` means over a ceiling is refused at once. Ceiling 65536. |
| `fc_max_queue_wait_ms` | `LLB_FC_MAX_QUEUE_WAIT_MS` (5000 when a depth is set and the window is not; at most 3600000) | the longest a request may wait before it is ended with `504 admission_queue_timeout`. Required, greater than `0`, whenever a depth is set. Ceiling 3600000 (an hour). |

Rules of the two fields:

- A rule value wins over the environment; the environment is the process
  default for rules that declare nothing.
- Both are runtime settings: a replace `POST` with the same key that
  changes only the admission fields applies the new values to the live pool
  without touching the executing requests. Waiters already in the queue keep
  their place; a smaller depth applies to newcomers (see "Where a value
  comes from" for a replace that changes other fields too). `PATCH` does not reach FullProxy (mode 4) rules, which every
  AI-gateway service is, so the replace `POST` is the way to change them.
- Omitting a field on a replace keeps the stored value; an explicit `0`
  resets it to the process default; JSON `null` is rejected.
- The rule that a depth needs a wait window is judged on the rule a request
  leaves behind: a replace carrying only a new depth keeps the stored wait
  and is accepted; one carrying only `fc_max_queue_wait_ms: 0` on a rule with
  a stored depth is refused `400`, and the stored rule is unchanged.
- `GET` reads back the posted values and, for AI-gateway services, the
  `fc_effective` object with what the data plane holds: `mode`,
  `max_outstanding`, `ep_max_inflight`, `prefill_max_inflight`,
  `decode_max_inflight`, `queue_depth`, `queue_wait_ms`, the live
  `inflight` and `queued`, `queue_memory_bound_mib`, `telemetry_stale_ms`,
  and `source` (where each value came from: `rule`, `env` or `default`).

### What a queue costs

A waiting request keeps its client connection, and a parked connection
holds about 1 MiB of receive buffer with the request in it. A depth is
therefore a memory bound as much as a queue bound:

```
memory the full queue may park ≈ fc_max_queue_depth × 1 MiB
```

65536 is about 64 GiB. The gateway applies any depth up to the ceiling and
logs one WARNING at rule apply when the bound exceeds half of the node's
memory:

```
[AIGateway] 10.10.10.254:2026 (…) fc_max_queue_depth=65536 may park up to 65536 MiB of client receive buffers (about 1 MiB per waiting request), more than half of this node's 63976 MiB; bound the connections with connectionLimit or LLB_PD_MAX_TOTAL_INFLIGHT
```

The two guards it names bound the connections themselves rather than the
queue: the per-rule `connectionLimit` (SYN-time, DNAT rules) and the
process valve `LLB_PD_MAX_TOTAL_INFLIGHT` (accept-time, every proxied
connection). Size the depth from the memory you can spend, and read
`fc_effective.queue_memory_bound_mib` back to see the bound in force.

### Who waits

| Request | Over a ceiling |
|---|---|
| HTTP/1.1, body fully buffered | queued when the pool has a depth |
| HTTP/1.1, streamed body (large or chunked) | queued when the pool has a depth; the connection closes after the answer either way |
| HTTP/2 stream | refused on its own stream with `429`; streams never wait |
| the prefill or decode leg of a P/D request | refused; role legs never wait, the request is answered once |

## Priority floors and the reserve

Two knobs protect a priority band's share of the service ceiling, and they are
different mechanisms. Both are a percentage of the ceiling in force, so they
follow the adaptive ceiling, in whole units.

- **A floor** (`fc_band_min_share_pct`, `critical:standard:sheddable`) is a
  guarantee under contention, not a reservation. It binds only while that band
  has a waiter. With a 20 % sheddable floor and no sheddable demand, standard
  takes 100 % of the units.
- **The reserve** (`fc_critical_reserve_pct`) is the only true reservation:
  units no other band may take, even when critical is idle.

The rule the gate implements: when a unit frees, the highest-ranked band that
is below its floor and has a runnable waiter takes it; when no band is below
its floor, the wake policy chooses. On the admission side, a request of a band
at or above its own floor takes a unit only if the units left after it still
cover what every other band with a waiter is short of its floor, and what
critical is short of its reserve. A band below its floor does not wait behind
the other bands' waiters, only behind its own band's. Nothing already running is
cut when a ceiling tightens.

HTTP/2 streams and P/D role legs never wait. On a service that carries only
HTTP/2, a floor therefore never binds, and only the reserve protects a band. A
floor does bind against an HTTP/2 stream while HTTP/1.1 waiters of the floored
band exist.

A percentage becomes whole units rounded up, in the band's favour, but a share
under 100 never rounds to the whole ceiling (a ceiling of 1 gives no floor). The
claims never exceed the ceiling: where rounding would, they are clamped in rank
order, critical, standard, then sheddable. Critical holds the larger of its
floor and the reserve. `fc_effective.bands` reports each band's `floor_units`
and, beside the bands, `critical_reserve_pct` and `critical_reserve_units`, as
enforced.

Declaring them is refused with `400` when the three floors sum to more than
100 (`fc_band_min_share_pct`), when `fc_critical_reserve_pct` is above 100, or
when the reserve plus the standard and sheddable floors is above 100
(`fc_critical_reserve_pct`). A floor is independent of the wake policy and of the
weights.

## Which waiter a freed unit wakes

Two knobs decide the order of the queue, one across the priority bands and one
inside a band. Both act only with `fc_mode` enforce, and only on HTTP/1.1
requests: streams and P/D role legs never queue.

**Across the bands** (`fc_wake_policy`):

- `strict` (the default) wakes the highest band that has a waiter able to take
  the unit. While higher-band demand keeps the ceiling full, a lower band is
  admitted nothing, and its waiters are refused when their wait window ends. A
  newcomer waits only behind a waiter of its own band or a higher one.
- `weighted` is a deficit round robin with unit cost over the bands, with the
  weights of `fc_band_weights` (`critical:standard:sheddable`, each 1 to 62, at
  most 64 together). A round gives each band that has a waiter able to take the
  unit its weight in credits. The highest band with credit left is served
  first, and one wake costs one credit: within a round bands are served
  highest first, and the credit decides how many each band gets per round
  (not the order in which the waiters arrived). A band with no such waiter forfeits its
  turn in the round, and a band whose first waiter arrives in the middle of a
  round waits for the next one. Over whole rounds the wakes split exactly as
  the weights do: with `8:3:1`, every 12 wakes are 8 critical, 3 standard and 1
  sheddable, in that order inside a round, whenever all three bands keep a
  waiter. The share is of admissions, not of tokens, GPU time or latency, and no
  band is promoted because it has waited long. A newcomer waits behind any
  waiter that could run, in any band, so a steady stream of critical newcomers
  cannot get past the weights. Weighted needs every weight at least 1 (a weight
  of 0 would be strict under another name, so it is refused with `400`).

With every waiter standard, both policies are the plain first come, first
served queue. A floor comes first under either policy: a band below its floor
that has a waiter takes the freed unit before the round is consulted (see
[Priority floors and the reserve](#priority-floors-and-the-reserve)).

**Inside a band** (`fc_tenant_wake`):

- `fifo` (the default) wakes the oldest waiter that can run. Tenants are not
  told apart.
- `rr` rotates across the tenants that have a waiter able to take the unit,
  oldest first inside one tenant. Each band keeps its own place in the
  rotation, and a tenant with no waiter left is skipped. It needs no tenant
  share (`fc_tenant_max_share_pct`) and holds with one.

A wake that cannot be delivered (its connection is being closed) puts the
request back at the head of the queue and gives the credit and the rotation
turn back. Changing the policy, the weights or the tenant order while requests
wait starts a new round and loses nobody: waiters keep their place and their
band. `fc_effective` reports `wake_policy_effective`, `tenant_wake_effective`,
and, when the weighted wake is in force, each band's `weight` and `weight_pct`
(its share of the round).

## Wait windows and queue shares per band

Two knobs shape how long and how many a band may queue. Both are written as
`critical:standard:sheddable`, and a band that is not named keeps the rule's
own values.

- **A wait window** (`fc_band_wait_ms`, milliseconds, 0 to 3600000). A band's
  wait window is a cap inside the rule's window (`max_queue_wait_ms`), never
  above it; 0 = the rule's window. A value above `fc_max_queue_wait_ms` runs at
  `fc_max_queue_wait_ms`. A waiter whose window ends is answered
  `504 admission_queue_timeout` at the window's end: the deadline is met by a
  timer armed to the earliest pending deadline across the pools (25 ms
  granularity), not by a periodic pass, so a 100 ms window is a 100 ms
  window. `fc_effective.bands.<band>.wait_ms` reads back
  the configured value (0 is the rule's window); `queue_wait_ms` is the rule's.
- **A queue share** (`fc_band_queue_pct`, percent). A band's queue share bounds
  that band's own occupancy of `max_queue_depth`, a ceiling and not a
  reservation: what a band does not use stays open to every other band, and the
  queue as a whole never holds more than `max_queue_depth`; 0 = the shared
  depth. The share is rounded up to whole waiters, at least one. A band at its
  share is refused with `429 admission_capacity` (the `queue_full` reason) even
  while the queue has room, and nobody is evicted to make room for it. When
  all three are non-zero they sum to at most 100.

## The llm-d headers

`fc_llmd_headers` (`on`, `off`, `inherit`; default off, process default
`LLB_FC_LLMD_HEADERS`) lets the gateway speak the llm-d request headers. With it
off, none of the following happens: the TTL header is ignored and every header is
forwarded as sent. With it on:

- **Refusals name their reason.** Every refusal of the gate carries
  `x-llm-d-request-dropped-reason`:

  | Refusal | `x-llm-d-request-dropped-reason` |
  |---|---|
  | `admission_capacity`, `admission_shed`, `admission_tenant_share` | `rejected-saturated` |
  | `admission_queue_timeout`, `admission_ttl_expired` | `rejected-ttl-expired` |
  | `admission_no_capacity` | `rejected-no-endpoints` |
  | `gateway_draining`, `admission_drained` | `rejected-shutting-down` |

- **The client's TTL can shorten a wait.** `x-llm-d-inference-ttl` is a
  positive duration in Go syntax (`500ms`, `2s`, `1m30s`; held at one day). A
  TTL shorter than the window that applies to the request's band shortens that
  request's wait; a longer one never extends it. A wait the client's TTL ended is
  answered `429 admission_ttl_expired`; a wait a window of the rule ended stays
  `504 admission_queue_timeout`. A value that is not a duration is ignored. The
  deadline is met by the queue's timer, so a TTL is honoured within 25 ms. The
  TTL applies to HTTP/1.1 requests; HTTP/2 streams never wait.
- **The forwarded identity is the gateway's.** The request the backend receives
  carries `x-llm-d-inference-objective` set to the class the request was
  admitted as (`critical`, `standard` or `sheddable`) and
  `x-llm-d-inference-fairness-id` set to the authenticated tenant (none for a
  request without a tenant). A client's copy of either, and of the deprecated
  `x-gateway-inference-objective` and `x-gateway-inference-fairness-id`, is
  removed first. On a chunked HTTP/1.1 request the client's copies are removed
  and nothing is written. An HTTP/2 stream is forwarded with the same two
  values in place of the client's, and its refusals carry the dropped reason
  too.

## Scraped queue depth: how long it is trusted

The P/D scorers weigh each endpoint by its scraped queue depth. A depth that
has not been refreshed for longer than the pool's telemetry window is no
longer trusted: the scorer uses the candidates' average in its place, so a
dead endpoint whose last report was an empty queue is not favoured forever.
The window is `fc_telemetry_stale_ms` on the rule, else
`LLB_FC_TELEMETRY_STALE_MS`, else 30000 (three default scrape intervals);
at most 3600000. The scraper stamps whole seconds, so the window is
effectively rounded to them. The window in force is
`fc_effective.telemetry_stale_ms`.

The same window decides what the adaptive ceiling below may act on.

The scrape that delivers the queue depth also delivers the endpoint's
KV-cache usage (`vllm:kv_cache_usage_perc`, `vllm:gpu_cache_usage_perc` or
`sglang:token_usage`). The gateway stores it beside the queue depth under the
same freshness stamp, so the window above governs it too, and it keeps "not
reported" apart from "0 %": an endpoint whose `/metrics` carries no usage
family is unknown, never empty. Today only P/D decode selection reads it, when
`LLB_PD_DECODE_KV_WEIGHT` is set (doc 10 §3.6). It is the shared signal the
flow-control plan's E-11(c) will read; that work adds a reader, not a second
store or scrape.

## The adaptive service ceiling

With `fc_adaptive` `on` (or `LLB_FC_ADAPTIVE=on` and the rule declaring
nothing), the pool-wide ceiling in force follows what the pool's engines
report, between a quarter of the configured `fc_max_outstanding` (at least
one) and all of it. Once a second, per pool:

| The pool's endpoints, within the telemetry window | The ceiling in force |
|---|---|
| an endpoint reports requests waiting in its engine (`vllm:num_requests_waiting` above 0) | four fifths of what it was, never below the quarter (reason `queued`) |
| an endpoint's time to first token is above `fc_ttft_target_ms` | the same (reason `ttft`) |
| fresh reports, no backpressure | one unit more, up to the configured ceiling; the request waiting longest is woken for it (reason `clear`) |
| nothing fresh (the scrapes fail, or stopped) | unchanged: it is held, never widened (state `frozen`, reason `stale`) |

Only fresh evidence moves it, and only fresh evidence without backpressure
widens it: a gateway that has lost sight of its engines keeps the tighter
bound it last had reason for. The configured ceiling stays the hard bound;
the adaptive one is never above it, and a pool without a service ceiling
(`fc_max_outstanding` `0` in force) has nothing to adapt.

The waiting requests come from the engine's own `/metrics`, which the
gateway scrapes every 10 s for every rule that adapts (and for P/D rules,
whose scorers read the same values). A service with several model pools on
one VIP and port gets the depth on its first pool only; the others adapt on
the time to first token alone.

The time to first token is measured on streamed responses: from the moment
a request is admitted (a wait at the gate is not the engine's) to its first
data event, and credited to the endpoint that holds its unit (the decode
endpoint of a disaggregated request). Each endpoint keeps an average that
weights a new sample one eighth, so an endpoint that was twice over the
target needs about eight fast samples to come back under it. One endpoint
over the target is enough to tighten the pool, and the ceiling climbs again
only while no endpoint is. An average older than the telemetry window is
not used: with nothing fresh the ceiling freezes where it is, and the next
sample starts that endpoint's average over. A buffered response is not measured: its
headers come when the whole completion is done, so its first byte says how
long the answer was, not how soon the engine started. `fc_ttft_target_ms`
`0` in force leaves the time to first token out.

`fc_effective` reads back `adaptive`, `effective_max_outstanding` (the
ceiling in force now), `adapt_state` (`off`, `open` at the ceiling,
`tightened`, `frozen`) and `adapt_reason`. Turning `fc_adaptive` off by a
replace gives the configured ceiling back at once; a replace that lowers
the ceiling takes the adaptive one down with it, and one that raises it
lets a tightened pool climb on, one unit a second.

## Warm-up after a return to service

An endpoint that comes back (its circuit breaker closes, its health probe
or host state turns it active again, or a replace adds it) takes a full
share of a burst at once; a cold engine then answers slowly or fails. With
`fc_warmup_ms` on the rule (or `LLB_FC_WARMUP_MS`), its per-endpoint
ceilings ramp instead: a quarter of each (at least one) at the moment it
returns, rising in a straight line to all of it at the end of the window.
An unlimited role stays unlimited. The service ceiling is not ramped.
`fc_effective.warming_endpoints` counts the endpoints inside their window.

## Tenant fair share

Without a share the queue is strictly first come, first served, so one
tenant sending a burst fills the ceiling and the queue and everyone else
waits behind it. With `fc_tenant_max_share_pct` on the rule (or
`LLB_FC_TENANT_MAX_SHARE_PCT`), a tenant holds at most that percentage of
the service ceiling in force (the adaptive one while the pool adapts) and of
the queue depth, rounded up and at least one each:

| `fc_max_outstanding` | `fc_max_queue_depth` | share | a tenant may execute | and wait |
|---|---|---|---|---|
| 8 | 16 | 25 | 2 | 4 |
| 10 | 0 | 30 | 3 | refused at once |
| 3 | 1 | 10 | 1 | 1 |

A tenant is the tenant id the request's credential resolved to (API key or
JWT, on a service that enforces one); every request without a tenant id,
keyless traffic included, is one tenant. A tenant at its share of the
ceiling waits for one of its own units when the pool queues and it still has
room in its share of the queue; otherwise it is refused `429
admission_tenant_share` while every other tenant still admits. A waiting
tenant that cannot run holds nobody up: a newcomer waits behind the queue
only when someone in it could take the unit, and a released unit wakes the
oldest waiter whose tenant is under its share, the others keeping their
place. The share is a hard cap: it binds even when the service is otherwise
idle. It needs a service ceiling (`fc_max_outstanding`); a share of `100`
is no share.

A pool tracks up to `LLB_FC_TENANT_SLOTS` tenants at a time: 256 by default,
64 at least and 4096 at most (a value outside that range is held to it).
The value is read from the gateway's environment when a pool is created and
is the same for every pool; it is not a rule setting, and changing it takes a
gateway restart. Tenants past the table share one last slot and are held
together to one share; each request placed there counts
`loxilb_ai_admission_anomalies_total{kind="tenant_table_full"}`. A tenant's
slot is freed as soon as it holds nothing, so the table bounds the tenants
active at once, not the tenants known: with a service ceiling in `enforce`
mode that is never more than `fc_max_outstanding` plus `fc_max_queue_depth`.
`fc_effective.tenants_active` counts them and `fc_effective.tenant_slots`
is the size in force; Prometheus has both per service as
`loxilb_ai_fc_tenant_slots` (`kind="used"`, `kind="max"`).

When a rule with a tenant share is applied on a node whose key store knows
more tenants (API-key owners and tenant rate-limit rows) than a pool tracks,
the rule is applied and the reply reads `Success; warning: …`, with the same
text at WARN level in the gateway log. It is advice and can be early: it
compares the tenants known, not the tenants active at once.

The table costs 24 bytes per slot and 4 for its lookup index, per model pool
that has a tenant share: about 7 KiB at 256 slots and about 112 KiB at 4096.
A pool without a tenant share allocates none.

## What the client sees

Every refusal carries `Retry-After` in seconds (`1` for a ceiling refusal;
the mean queue wait, between `1` and `30`, when the queue was full or a wait
timed out; `5` for a drain, on HTTP/1.1 and HTTP/2 alike) and the three admission headers `X-Loxilb-Admission-Inflight`,
`X-Loxilb-Admission-Queued` and `X-Loxilb-Admission-Limit`, the live counts
and the ceiling that refused. The body is JSON.

| Status | `error` | When | Connection |
|---|---|---|---|
| `429` | `admission_capacity` | over a ceiling with no queue, or the queue at its depth (`X-Loxilb-Admission-Queued` then equals the depth); body carries `retry_after` and `jitter_hint_ms` | kept open when the request body was fully buffered, else closed |
| `429` | `admission_tenant_share` | the request's tenant holds its share of the ceiling (and may not wait) or of the queue; the admission headers carry the pool's counts, not the tenant's | as `admission_capacity` |
| `429` | `admission_shed` | a sheddable request at a ceiling that may not wait (`fc_shed_queue` off), or a sheddable waiter evicted for a request of a higher band at a full queue; an evicted waiter's body carries `queued_ms` | as `admission_capacity`; an evicted waiter keeps its connection, unless the 1 Hz pass writes its answer (`Connection: close`) |
| `503` | `admission_no_capacity` | no healthy endpoint of the pool has capacity | closed |
| `503` | `gateway_draining` | the gateway is in maintenance (see below) | closed |
| `504` | `admission_queue_timeout` | the request waited the whole `fc_max_queue_wait_ms`, or its band's wait window when that is shorter; body carries `queued_ms`, the wait it spent | closed |
| `429` | `admission_ttl_expired` | with `fc_llmd_headers` on, the request's own `x-llm-d-inference-ttl` ended its wait; body carries `queued_ms` | closed |
| `503` | `admission_drained` | the request was waiting when its pool was deleted or the gateway entered maintenance | closed |

A client that keeps a `429` connection open may send its next request on the
same socket; it is gated again. Clients should honour `Retry-After` and add
the jitter the body hints, so a burst of refusals does not return as one
burst of retries. Every non-admit decision is also a `sec.ai.deny` record on
the audit trail with the service, the model and the decision.

These are the capacity-stage rows of the gateway's whole refusal table. The
other stages (credentials, rate limits and quotas, routing, framing), what
is safe to retry, and the HTTP/1.1 and HTTP/2 differences are in the
[client refusal contract](27-ai-gateway-client-refusal-contract.md).

### The same headers on admitted responses

With `fc_expose_headers` `on` (or `LLB_FC_EXPOSE_HEADERS=on` and the rule
declaring nothing), every admitted HTTP/1.1 and HTTP/2 response whose head
is ≤ 16 KiB carries the three admission headers too, so a client can slow
down before it is refused:
`X-Loxilb-Admission-Inflight` and `X-Loxilb-Admission-Queued` are the pool's
executing and waiting requests as the response head goes out (the request
itself counted), and `X-Loxilb-Admission-Limit` the service ceiling in force
(the adaptive one while the pool adapts; `0` when the pool has none). They
go on the response head on HTTP/1.1 and HTTP/2, streamed (`text/event-stream`,
chunked) responses included; the body is never touched. Fields of those
names sent by the backend are replaced. A pool in `observe` mode reports
them too, since it counts its requests; requests the gate does not count
(non-inference paths, a pool in `off` mode) carry none.

An HTTP/1.1 response head that reaches the gateway in several pieces is put
together first, up to 16 KiB, and then gets the headers like a head that
arrived whole; nothing a client could act on is held back, since part of a
head is of no use to it. A head that arrives in pieces and grows past 16 KiB
is relayed as the backend sent it, without the headers and with the backend's
own fields of those names, and is counted in
`loxilb_ai_admission_anomalies_total{kind="expose_head_overflow"}` (one log
line per connection).

A rule refuses `fc_expose_headers` `on` with a `sockMapMode` of `both` or
`response` (`400`): those responses go from the backend to the client in the
kernel and the gateway never sees them. Set process-wide with
`LLB_FC_EXPOSE_HEADERS=on`, the headers appear only on the responses the
gateway relays.

## Maintenance drain

`PUT /netlox/v1/maintenance {"enabled": true}` now reaches the data path:
new inference requests on every gated pool are answered `503
gateway_draining`, every request waiting in a queue is ended with `503
admission_drained`, and executing requests finish on their own. `GET
/netlox/v1/maintenance` reports `refusing_new_inference: true` while this is
in effect and `in_flight_requests`, the executing count summed over the
gated pools; `enabled: false` restores admission. On a management plane
with no data path attached `refusing_new_inference` stays `false`, so the
read-back never claims a drain that is not happening.

## Metrics

All families are per service and pool (`service="VIP:port"`, `pool` = the
pool key) and are emitted for every AI-gateway pool in every mode.

| Family | Type | Meaning |
|---|---|---|
| `loxilb_ai_admission_mode` | gauge | `0` off, `1` observe, `2` enforce |
| `loxilb_ai_admission_inflight{role}` | gauge | units held: `service` pool-wide, `normal`/`prefill`/`decode` summed over the endpoints |
| `loxilb_ai_admission_limit{role}` | gauge | the ceiling in force per role; `role="queue"` is the depth |
| `loxilb_ai_admission_queued` | gauge | requests waiting right now |
| `loxilb_ai_admission_queue_wait_seconds` | histogram | how long requests waited in the queue (buckets 10 ms to 5 s): one sample per park, when it ends (admitted, expired, shed by eviction, cancelled), measured from the first park; a woken request that goes back to its place is one wait |
| `loxilb_ai_admission_decisions_total{reason}` | counter | `admitted`, `capacity_shed`, `no_healthy_capacity`, `observe_would_shed`, `bypass_non_inference`, `queued` (once per park), `queue_full`, `queue_timeout`, `cancelled`, `drained`, `observe_would_queue`, `draining`, `tenant_share`, `shed` |
| `loxilb_ai_admission_effective_limit` | gauge | the service ceiling in force now: the adaptive one while the pool adapts, else the configured one |
| `loxilb_ai_admission_adapt_state{state}` | gauge | state set, `1` for the current one: `off`, `open`, `tightened`, `frozen` |
| `loxilb_ai_admission_adapt_reason{reason}` | gauge | state set: `none`, `queued`, `ttft`, `clear`, `stale` |
| `loxilb_ai_admission_adapt_moves_total{direction}` | counter | steps of the adaptive ceiling, `down` and `up` |
| `loxilb_ai_admission_warming_endpoints` | gauge | endpoints inside their warm-up window |
| `loxilb_ai_admission_tenants_active` | gauge | tenants holding a unit or waiting, while the pool has a tenant share |
| `loxilb_ai_fc_tenant_slots{service, kind}` | gauge | the tenant table, per service: `kind="max"` is the table size (`LLB_FC_TENANT_SLOTS`), `kind="used"` the tenants on the service's fullest pool right now. `used` above `max` means tenants past the table share one budget; alert before that, for example on `used / max > 0.8` |
| `loxilb_ai_admission_anomalies_total{kind}` | counter | process-wide: `underflow` and `unknown_permit` are bookkeeping faults and `h2_deny_headers` an HTTP/2 refusal whose headers did not fit its frame (the stream is reset instead): any increase of these three is a defect, not load; `tenant_table_full` counts requests whose tenant shared the overflow slot; `expose_head_overflow` counts HTTP/1.1 response heads that arrived in pieces and grew past 16 KiB, relayed without the admission headers |
| `loxilb_ai_fc_band_total{service, band, outcome}` | counter | per service (its pools summed), by priority band (`critical`, `standard`, `sheddable`: the request's class) and outcome; fifteen series per service, zero included. The per-band split of five decisions above, counted where they are counted |

A request's band is its class ([AI gateway controls](19-ai-gateway-controls.md)). `priority_class` is a cap, not a default: to run a tenant's un-hinted requests above `standard`, set its `default_objective` to an objective with a positive priority; `priority_class` only bounds what its requests may be raised to.

The five outcomes of `loxilb_ai_fc_band_total`:

- `admitted`: the request took a capacity unit (terminal).
- `shed`: `429 admission_shed`, a sheddable request refused at a ceiling or evicted from the queue for a higher band (terminal). With `fc_shed_queue` on, a sheddable request may wait, and when the queue is full an arriving request of any higher band, `standard` as well as `critical`, takes the place of the youngest sheddable waiter; the evicted waiter is answered `429 admission_shed` on its own connection, with `queued_ms` in the body. That is what sheddable means. The connection stays open for the client's next request, as after a queue-full `429`: a `429` asks the client to retry, and closing on it would make every shed client reconnect while the gateway is shedding. The answer normally goes out at the eviction; it is never later than the second pass of the 1 Hz health check. Only an answer that pass writes (the waiter's wake was lost) ends the connection, and it says so with `Connection: close`. HTTP/2 streams never wait in the queue, so an eviction never touches an HTTP/2 connection. At most 16 evicted waiters per pool may be awaiting their answer at once: while 16 are, an arriving request evicts nobody and is refused as a full queue.
- `expired`: `504 admission_queue_timeout`, its wait window ended while it waited, or, with `fc_llmd_headers` on, `429 admission_ttl_expired`, the client's own TTL ended it (terminal; both are `decisions_total{reason="queue_timeout"}`).
- `cancelled`: its client left while it waited; nothing is written to it (terminal). Its request record in `loxilb_ai_requests_total` is `outcome="aborted"`, `cause="client"`, status none; a `shed` or `expired` request is one `outcome="denied"` record. The band counter is the split of the gate's decisions beside that record, not a second count of the request.
- `queued`: it parked to wait; counted once per park, not an end (a woken request that goes back to its place is the same park).

Each request lands in exactly one terminal outcome, so per band
`admitted + shed + expired + cancelled` is the requests of that band, and
`queued` equals the parked requests that ended admitted, expired, evicted or
cancelled, unless a parked request was ended another way (a drain of its
pool). A request refused for any other reason (a full queue, its tenant's
share, no healthy capacity, a drain) is counted in
`loxilb_ai_admission_decisions_total` only. The queue-wait histogram takes
its sample when the same parks end, so over a window in which every park
ended and none was drained, `queued` summed over the three bands equals the
growth of `loxilb_ai_admission_queue_wait_seconds_count` for the service: the
two are written at different points (the park and its end) and must agree.

How the `standard` row is counted: a request with no class is `standard`, and
counting it would add an atomic write on the busiest path (keyless and MCP
traffic). The gateway therefore counts only `critical` and `sheddable` in
their own rows, and reads `standard` for each outcome as
`decisions_total{reason=R} − critical − sheddable`, where R is `admitted`,
`queued`, `shed`, `queue_timeout` (outcome `expired`) or `cancelled`. Every
increment of those five reasons is made together with its band's row, at the
same point, so the difference is exact. A read that falls between the two
writes of one request can come out one low; the next read is exact again,
and the published value never goes down, so the series is a true counter.

The process accept valve (`LLB_PD_MAX_TOTAL_INFLIGHT`) bounds connection
contexts, not requests, before any pool sees them:

| Family | Type | Meaning |
|---|---|---|
| `loxilb_proxy_context_inflight` | gauge | connection contexts held, client and backend legs alike; counted only while the valve is on, so `0` when unbounded |
| `loxilb_proxy_accept_bound` | gauge | the bound; `0` when unbounded |
| `loxilb_proxy_accept_blocked_total` | counter | times the valve paused accepting at the bound: connections wait in the listen backlog until a context is released, which re-arms the listener; one per pause, not per connection, so a steady rate is the node reaching its bound again and again |

At the bound the valve pauses the listeners: poll stops reporting them, so
connections waiting in the backlog cost no CPU. The release of a connection
context re-arms them, and the once-a-second health pass re-arms any that a
release missed. Measured on a test bed with ten streams held at a bound of
12: 8.5 % of one core, against 8.2 % with no bound.
Size the bound so that it is reached only in overload, and treat contexts
held at the bound as a capacity alarm.

The AI dashboard's "AI admission gate" row plots in flight against the
ceiling, queued against the depth, the queue wait p50/p95 and the decisions
by reason.

## Runbook

| What you see | What it means | What to do |
|---|---|---|
| `decisions_total{reason="capacity_shed"}` rising while `effective_limit` equals `limit{role="service"}` | the pool is at its configured ceiling | raise `fc_max_outstanding` if the engines have headroom (their own `num_requests_waiting` stays at 0), else add endpoints |
| the same while `effective_limit` is below the configured one, `adapt_reason` `queued` or `ttft` | the engines report backpressure and the gateway is shedding in front of them, as intended | add capacity; a target (`fc_ttft_target_ms`) far below what the model can do keeps the ceiling at its floor |
| `adapt_state{state="frozen"}` | the scrapes stopped (engine `/metrics` down or blocked) while the ceiling was tightened: it holds | check the engines' `/metrics` and `loxilb_ai_worker_scrape_total`; turn `fc_adaptive` off by a replace to return to the configured ceiling at once |
| `decisions_total{reason="queue_timeout"}` rising | requests wait a whole `fc_max_queue_wait_ms` | the queue only delays refusals at this load: shorten the wait or add capacity |
| `queued` near `limit{role="queue"}` for minutes | the queue absorbs a sustained, not a burst, overload | add capacity; a deeper queue parks more client memory (depth × 1 MiB) |
| `warming_endpoints` above 0 after every health flap | an endpoint flaps between down and up | fix the endpoint; its ramp restarts on every return |
| `proxy_context_inflight` at `proxy_accept_bound`, or `proxy_accept_blocked_total` rising | the node is at its connection-context bound; new connections wait in the listen backlog | raise `LLB_PD_MAX_TOTAL_INFLIGHT` if memory allows, else add gateway instances |
| `anomalies_total{kind=~"underflow\|unknown_permit\|h2_deny_headers"}` above 0 | a bookkeeping defect | report it with the gateway log |
| `anomalies_total{kind="expose_head_overflow"}` rising | a backend sends HTTP/1.1 response heads larger than 16 KiB, in pieces; those responses go out without the admission headers | shrink the backend's response head (large cookies or debug headers), or accept that these responses carry no admission headers |
| `decisions_total{reason="tenant_share"}` rising while `inflight` is below the limit | one tenant is at its share; the rest of the ceiling is left for others, as intended | raise `fc_tenant_max_share_pct` if one tenant should be allowed more of an idle pool |
| `anomalies_total{kind="tenant_table_full"}` rising | more tenants active on one pool at once than `fc_effective.tenant_slots`; the ones past the table share one budget | raise `LLB_FC_TENANT_SLOTS` (up to 4096) and restart the gateway, or split the pool |

The shipped alert rules (`deploy/monitoring/prometheus/rules/loxilb-alerts.yml`,
group `loxilb-ai-admission`) fire on sustained shedding, queue timeouts, a
queue held near its depth, a frozen adaptive ceiling, the accept valve
holding connections back, and any anomaly.

## Limits

- The queue is per gateway process; nothing is shared across instances.
- HTTP/2 streams and P/D role legs never wait (they are refused at the
  ceiling); only HTTP/1.1 requests queue.
- A `429` keeps the connection only when the request body was fully
  buffered before the decision; a streamed body closes it.
- The queue is first come, first served within the tenant share; without a
  share it is FIFO inside a band unless `fc_tenant_wake` is `rr`. There are no
  priorities between tenants beyond the share.
