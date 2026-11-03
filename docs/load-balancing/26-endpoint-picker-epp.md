# Endpoint Picker (EPP) integration: operator notes

A fullproxy rule that names an `eppEndpoint` asks a Gateway API Inference
Extension Endpoint Picker (llm-d's `llm-d-inference-scheduler`, or any
ext_proc server) where each request should go, and serves it there. The
rule fields are in the REST reference (`eppEndpoint`, `eppFailureMode`,
`eppTimeoutMs`, `eppPlaintext`). This page records the behaviours an
operator meets in a cluster and the questions they raise.

## What `eppTimeoutMs` covers

The deadline starts when the request is submitted to the EPP client and
ends when the decision arrives. It covers:

- connecting to the EPP when no connection is up (a dial the network drops
  silently, a pod with no answer) — the request fails at `eppTimeoutMs`,
  not at the gRPC connect timeout;
- sending the request headers and body;
- the wait for the EPP's request-phase decision.

Once a request times out without a single frame from the EPP, the next one
does the same; after two consecutive silent timeouts the cached connection
is dropped and the following request dials afresh (dead-peer detection).
An EPP that refuses the connection outright (no pod behind the Service)
fails in milliseconds. A failed request is answered by `eppFailureMode`:
`FailClose` gives `503 epp_unavailable`, `FailOpen` lets the rule's own
selector decide.

## The endpoint subset hint

Every request carries the endpoints the rule would accept right now
(configured, not marked down, healthy by the prober and the breaker) as
the ext_proc metadata `envoy.lb.subset_hint` /
`x-gateway-destination-endpoint-subset`, the form the Inference Extension
defines. **The EPP honours it only when its scheduling profile contains
the `subset-filter` plugin.** The llm-d charts' profiles (`pd-config.yaml`,
`default-plugins.yaml`) do not include it; an EPP configured that way may
name a pod the rule does not have — a pod that is not Ready yet, or one
the controller has not added — and the gateway then skips that candidate.
The reference Inference Extension EPP registers the filter; the llm-d
router image (`llm-d-router-endpoint-picker:main`, October 2026) does not
(`plugin type 'subset-filter' is not registered`, and the pod crash-loops),
so with that image the rule's membership is enforced by the gateway alone.
Where the filter is available, add it to the profile before the scorers:

```yaml
plugins:
- type: subset-filter
# ... the existing plugins ...
schedulingProfiles:
- name: default
  plugins:
  - pluginRef: subset-filter
  # ... the existing pluginRefs ...
```

The gateway's own rule is the authority over where a request may go: a
candidate that is not an endpoint of the rule, is disabled, unhealthy, at
capacity, or refuses the connection is skipped for the EPP's next
candidate. When no candidate is usable the rule's failure mode decides:
`FailClose` answers `503 epp_no_endpoint`, `FailOpen` falls back to the
rule's own selector. With the llm-d `max-score-picker` the EPP names one
candidate, so under `FailClose` a single stale pod in the EPP's view is a
`503` for that request; `FailOpen`, or the subset filter above, avoids it.

## An EPP on a prefill/decode rule (EPP-primary P/D)

A rule may name an EPP **and** set `pd_disagg_mode: true`, provided
`eppFailureMode` is `FailOpen`. The two never act on the same request:

- **The EPP answers.** Its destination (a decode pod's routing sidecar in the
  llm-d layout, `ep_role: 0`) is served plainly, header mutations such as
  `x-prefiller-host-port` included. The EPP and the sidecar run the prefill
  leg; the gateway's own prefill/decode machine stays out of that request.
- **The EPP gives no decision** (unreachable, timeout, `NOT_SERVING`, every
  candidate rejected). FailOpen hands the request to the rule's own ladder,
  which on a `pd_disagg_mode` rule is the prefill/decode ladder: a prefill
  endpoint (`ep_role: 1`) and a decode endpoint (`ep_role: 2`) are selected
  and the gateway runs both legs itself, exactly as on a rule without an EPP.

The endpoint list therefore carries three kinds of members for one decode
pod fleet: the engines the gateway drives directly (`ep_role: 1` prefill,
`ep_role: 2` decode, each with `nixl_port`) and the sidecar addresses the EPP
names (`ep_role: 0`). A candidate the EPP names must still be a member of the
rule, so the sidecar addresses have to be listed. `FailClose` is refused with
`pd_disagg_mode` because the ladder would then be unreachable and the P/D
members could never serve.

## Is the EPP up? Three read-only fields on the rule

`GET /netlox/v1/config/loadbalancer/all` (and the single-rule GET) report,
for every rule with an `eppEndpoint`, what the gateway currently sees of
that EPP:

| Field | Meaning |
|---|---|
| `eppState` | `up` — the gRPC connection to the EPP is ready. `connecting` — dialing, or idle and not yet proven. `down` — the dial fails and gRPC is backing off. `unknown` — no connection attempted yet. |
| `eppStateSince` | RFC3339 time `eppState` last changed. |
| `eppLastError` | The last request-phase error from this EPP (connection refused, deadline, `NOT_SERVING`, ...). Cleared once the connection is up again. |

The state is sampled every 5 seconds on every cached EPP connection whether
or not requests flow, so an idle EPP that dies shows `down` within a few
seconds, and a freshly created rule goes `connecting` → `up`/`down` on its
own. The fields are ignored on create and replace, so a GET body can be
re-POSTed unchanged. They describe the connection, not the EPP's own health
endpoint: an EPP that accepts connections but answers `NOT_SERVING` shows
`up` with the refusal in `eppLastError` after the next request.

## A listener kept after its last rule is deleted

Deleting the last rule of a VIP:port keeps the fullproxy listener socket
open: a client that connects gets an HTTP `503` instead of a refused
connection, and a rule created later on the same address takes the
listener over without a bind gap. While no rule is present the answer is

```
503 {"error":"no_route","detail":"no rule on this listener (kept open after its last rule was deleted)"}
```

Consequences for tooling: `ss -tln` still shows the port bound after the
delete, so "is the socket bound" is not "is the rule present" — check
`GET /config/loadbalancer/all`, or the error body.

## Restarting the gateway on a node that carries other traffic

loxilb attaches its tc eBPF programs to every interface that is not
blacklisted. A restart reloads them, and the conntrack state of flows the
programs were tracking goes with it; a TCP flow seen mid-stream with no
state is treated as a protocol error. On a host-network deployment this
includes the node's own connections on that interface — an SSH session to
the node may drop when the gateway pod restarts. Plan restarts
accordingly, or keep interfaces the gateway does not serve on out of its
attachment set with `--blacklist`.
