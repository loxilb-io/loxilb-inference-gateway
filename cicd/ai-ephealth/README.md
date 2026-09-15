# ai-ephealth

Guards the lightweight endpoint-health path: a probe transition is keyed on
the endpoint **address** (`proxy_update_ep_health_by_addr`), so one signal
must reach the endpoint's row in **every** pool of its service.

## Topology

```
l3h1 (10.10.10.1) ── llb1 (VIP 10.10.10.254) ── l3ep1 (31.31.31.1, server-a)
                                              ── l3ep2 (32.32.32.1, server-b)
```

Three FullProxy rules:

| rule | pools | monitor | role |
|---|---|---|---|
| `:2050` | one (wildcard) | on | control: a transition applies to exactly 1 row |
| `:2060` model-alpha | shares both backends | on | the only probe on :2060 |
| `:2060` model-beta | shares both backends | **off** | its row can flip ONLY via the cross-pool fan-out of alpha's signal |

## Oracles

Load-bearing: the datapath's own log lines in `/var/log/loxilbdp.log` —
`applied to 1/2 endpoint row(s)` per transition, the per-pool
`pool='...|model-beta'` receipts (impossible without cross-pool fan-out,
because the beta rule never probes), and **zero** `not found in service`
lines (an address-key miss is the byte-order/keying regression this suite
exists to catch). Traffic checks ride along as product-level confirmation
only: sockproxy's connect-failure retry can mask a dead row, so they cannot
be the verdict.

## History

The defect this guards shipped once: the health loop returned from inside its
`HASH_ITER` body, so only the first pool of a service was ever touched — the
failed endpoint kept taking traffic while a healthy one was marked down in
its place (loxilb-ebpf #36/#37). The gateway half — passing a pool-local
index that means something different in every pool — is the same identity
class as the conversation-map fix (`scripts/check_conv_pool_identity.py`).
