# vllm-pd-admission-cpu — P/D bounded-admission gate (GPU-free)

Drives the per-EP **bounded admission** layer of P/D disaggregation end-to-end against a
live gateway, with no GPU and no inference engine: six `reflect-echo` backends behind one
P/D service, and the prefill endpoints put behind hanging stubs so requests genuinely
overlap.

It exists because three counter families have no committed coverage anywhere else, and
cannot get it inside another scenario — see **Why a separate scenario** below.

| Family | Branch it counts |
|---|---|
| `loxilb_pd_admission_shed_total` | every healthy prefill EP at the in-flight cap, queueing OFF → retriable 429 |
| `loxilb_pd_admission_queued_total` | same condition, queueing ON → request PARKED on a per-EP FIFO (hold-don't-drop) |
| `loxilb_pd_admission_overflow_shed_total` | pool capped AND every eligible FIFO full → 429 from the overflow valve |

## Why a separate scenario

Both knobs are process environment read **getenv-once at start**
(`pd_max_inflight_per_ep`, `pd_queue_depth_per_ep` in `sockproxy_pd.c`), so unlike a
per-rule field they cannot be toggled on a live gateway. That alone would only argue for
setting them somewhere. The reason they get their own scenario is stronger:

**The three families are mutually exclusive inside one gateway process.** The all-capped
branch reads:

```c
if (healthy_elig > 0 && under_cap == 0) {
    depth = pd_queue_depth_per_ep();
    if (depth == 0) { pd_admission_shed_total++;   return NO_CAPACITY; }  // site A
    ... park ...    { pd_admission_queued_total++;  return PARKED; }       // site B
                      pd_admission_overflow_shed_total++;                  // site C
```

Site A is reachable only at depth 0; sites B and C only at depth > 0. No single
configuration drives all three, so `validation.sh` runs **two gateway lifecycles** and
re-invokes `config.sh` between them.

Arming these knobs inside `vllm-kvcache-routing-cpu` was considered and rejected on
evidence, not taste: that scenario's HOL stage drives **12 concurrent shared-prefix
requests**, cache affinity lands them on one prefill EP owner, and any cap low enough to be
drivable here sheds most of them as 429. Because that stage scores **p99 latency** and a
429 returns fast, it would have kept passing while measuring nothing — a vacuous oracle
rather than a red gate.

## What it proves

| Leg | Claim | Control / twin |
|---|---|---|
| A-control | `HOLD_N` overlapping requests **exactly fill** a 3-EP pool at cap=1 and shed nothing — `under_cap` is non-zero at the moment of every selection | one request away from the drive; rules out a cap that sheds merely because requests overlap |
| A-drive | one request past the pool sheds: Δcounter == Δplain-shed log lines == 6 client 429s carrying `pd_overloaded` / `all prefill endpoints at in-flight capacity` | receipt leaves via the response path, counter via the metrics pipeline — two independent oracles |
| A-attribution | at depth 0 the park and overflow sites are **structurally unreachable** and asserted flat | a movement there means the fixture is not what it claims |
| re-fixture | `llb1` is a genuinely **new process** (PID changed) at depth 2 | a silent no-op would leave phase B reading phase A's binary |
| B-control | filling the pool parks nothing | same shape as A-control |
| B-drive | the FIFO holds **exactly** 3 EPs × depth 2 = 6; every park probe is **held, not answered** (curl exit 28) | depth 2 not 1, so an off-by-one drive cannot land in the right branch by accident |
| B-overflow | the 7th and 8th requests hit the overflow valve: Δ2, matching log lines, client 429 `pd_overloaded` | the exact split Δqueued==6 ∧ Δoverflow==2 attributes all eight requests |
| B-attribution | at depth 2 the plain-shed site is unreachable — counter **and** log line flat | at the client the two shed families are byte-identical; this is the only thing that separates them |

Every family has exactly one writer site in the C tree, so a per-family delta is honest
here — unlike the multi-writer families in `vllm-kvcache-routing-cpu`. The cross-phase flat
asserts are what turn "the counter moved" into "**this branch** ran".

## Two traps encoded in the stage

1. **The three log lines collide under a literal grep.** The overflow line contains the
   `shed:` substring the plain line is identified by, so `grep -cF "shed:"` counts both and
   a plain-shed assert would be satisfied by overflow sheds. The discriminators used are the
   counter-name suffixes, which do not nest (`(shed_total=`, `(queued_total=`,
   `overflow_shed_total=`), and the loose count is asserted to equal plain + overflow — so a
   discriminator that stops discriminating **fails** the stage instead of passing it.

2. **A hanging backend gets demoted, and then the prediction is for the wrong pool.**
   Control-plane health demotes an unresponsive backend after roughly 19s, and a demoted EP
   leaves `healthy_elig` — which makes the all-capped guard false and the **entire admission
   block unreachable**. Every counter then reads flat and the client hangs, which presents
   exactly like a dead feature. This was measured here, not assumed: a first cut held the
   fault across the settle window, and requests issued after ~19s scored Δ0 with an empty
   `%{http_code}` while requests issued before it shed correctly with `healthy_elig==3`.

   Two consequences, both load-bearing. Every arm now **releases the fault before it
   settles** — the settle only waits for the polled metrics pipeline, never for the product
   to decide anything, so the verdict is already banked. And every shed/overflow line is
   asserted to report `healthy_elig==3`, reading the drive shape out of the product's own
   log rather than assuming it.

   A related ordering constraint: a parked entry leaves the FIFO when its client
   **disconnects**, not when it is answered. Parking six probes, letting them time out, and
   only then driving the overflow empties every FIFO first — the "overflow" request simply
   parks and hangs, scoring Δ0 as if the valve were dead. The overflow probes are therefore
   fired while the park probes are still connected.

## Topology

```
llb1   — loxilb (control plane + eBPF dataplane), REST on localhost:11111 (auth-off, CICD mode)
l3h1   — client host
l3ep1  — reflect-echo  31.31.31.1  serverP0  PREFILL  (abs idx 0)  ep_role=1
l3ep2  — reflect-echo  32.32.32.1  serverD0  DECODE   (abs idx 1)  ep_role=2
l3ep3  — reflect-echo  33.33.33.1  serverP1  PREFILL  (abs idx 2)  ep_role=1
l3ep4  — reflect-echo  34.34.34.1  serverD1  DECODE   (abs idx 3)  ep_role=2
l3ep5  — reflect-echo  35.35.35.1  serverP2  PREFILL  (abs idx 4)  ep_role=1
l3ep6  — reflect-echo  36.36.36.1  serverD2  DECODE   (abs idx 5)  ep_role=2
```

Plain `pd_disagg_mode` — no KV-exact, no ZMQ publisher, no tokenizer staging. The admission
gate sits in `pd_select_prefill` above every tier, so it fires regardless of which tier
would have chosen the EP; leaving KV-exact off removes an unrelated failure surface from a
scenario whose subject is admission.

The prefill EPs are held in flight by `../vllm-kvcache-routing-cpu/pd-fault-swap.sh`, which
REDIRECTs `:80` to a hanging stub inside the EP netns. Cross-scenario asset reuse is the
established idiom here (`sglang-loxilb-kvcache/config.sh` sources this repo's
`kv_event_publisher.py` the same way) and keeps one copy of the fault machinery.

## Running it

```
sudo ./config.sh && sudo ./validation.sh ; ./rmconfig.sh
```

`validation.sh` tears the bed down and rebuilds it at depth 2 partway through, and cleans up
after itself — a completed run leaves **zero containers**, which is normal and not breakage.

Knobs: `ADM_CAP` (default 1), `ADM_QUEUE_DEPTH` (default 0, phase A), `ADM_SETTLE` (default
14s — must stay above one 10s collector period), `SKELETON_STRICT=0` for a non-enforcing
dev dry-run.

On macOS only `bash -n` and `shellcheck -S error` are meaningful; Docker and `ip netns` are
not available there.
