# ai-qos-ha-sync

The AI-QoS rate-limiter HA sync path, on a two-node container cluster.
GPU-free: the backend is the usage-bearing echo from `cicd/ai-jwtauth`, so
every answered request charges exactly 12 tokens and the quota arithmetic
in `validation.sh` is exact rather than approximate.

```
l3h1 10.10.10.1 ── llb1 10.10.10.254:2020 ─┐
     20.20.20.1 ── llb2 20.20.20.254:2020 ─┴─ l3ep1 (echo, :8080)
                                              pg-qos-ha (shared API-key store)
```

## Running it

```bash
cd cicd/ai-qos-ha-sync
LOXILB_DOCKER_IMAGE=<your gateway image> sudo -E ./config.sh
sudo ./validation.sh
sudo ./rmconfig.sh
```

Or through the product-harness runner, which handles cleanup, timeouts and
leftover-state detection for you:

```bash
cd cicd && ./run_product_harness.sh ai-qos-ha-sync
```

## What it asserts

| case | claim |
|---|---|
| SYNC-1 | RateLimiterSync RPCs actually complete from the elected master |
| SYNC-2 | a node holding no MASTER cluster instance sends none |
| QOS-HA-002 | per-tenant token quota debt refuses at the other node |
| QOS-HA-003 | per-tenant-per-model quota debt refuses at the other node |
| QOS-HA-004 | per-key (`kq:`) quota debt refuses at the other node |
| QOS-HA-006 | the per-VIP keyless bucket is per node ident, not per cluster |
| QOS-METRIC-1 | the tenant quota series carries tenants, and only tenants |
| QOS-HA-SNAP-1 | a peer snapshot does not refill the receiver's own rate limits |

## Three things that make a verdict here mean something

**A per-case control.** Every cross-node refusal is paired with an identity
bounded identically that has never spent, driven at the same node. Without
it, "refused at the standby" is equally well explained by a standby that
refuses everything. Each case gets its OWN control: a control that has
itself been spent has stopped controlling for anything.

**The backend receipt counter.** Each request carries a nonce; the count
for that nonce is read from inside the backend's own namespace, never
through the gateway, so a denial is proved to have delivered nothing rather
than merely to have returned 429. `new_nonce` is called by the CALLER, not
inside `req` — every call site captures the status with `$( )`, which runs
in a subshell, so a nonce minted there would be discarded and every receipt
lookup would silently ask about a nonce the backend has never seen.

**A sync-liveness precondition.** SYNC-1 runs first and fails the rest
interpretively if it cannot read a completed RateLimiterSync push. Every
"still refused at the other node" result below it is equally consistent
with a sync channel that never carried anything, and `peer_up` cannot
settle that — six sites write that gauge, most on the session-sync path.
The discriminating series is the push-latency histogram's per-RPC count,
which only `sendRateLimiterBatch` observes with `rpc="RateLimiterSync"`.

## Why the standby is driven directly instead of via a VIP failover

What the quota cases claim is that a caller cannot buy fresh quota by
arriving at the other node. Moving a keepalived VIP proves that only if the
move happens, which makes the case a timing test wearing a quota test's
name. Driving the same identity at the other node's own VIP asserts the
same property with no election in the loop.

## Note on QOS-HA-SNAP-1's oracle

It counts admissions over a window instead of checking one request after a
wait. A single late request cannot distinguish a snapshot refill from the
bucket's own legitimate refill: at `rps=1` a token returns every second, so
any wait long enough to cover several 200ms push intervals is also long
enough to make an admission correct. The count prices the defect directly —
a refill on every snapshot makes admissions scale with the push rate rather
than with the configured rate.
