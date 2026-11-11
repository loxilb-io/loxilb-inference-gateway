# Prometheus in BGP peer-only mode

`--peer` (`-r`) runs a BGP speaker without initializing the native proxy or
load-balancer datapath. `--prometheus` (`-p`) still enables observability, as
does the runtime `/config/metrics` API.

System utilization, Go/process metrics and namespace listen-backlog counters
remain available. `loxilb_datapath_metrics_available` is `0` in peer-only mode.
Collectors registered as datapath-dependent omit their series: connection,
endpoint, firewall/security and native proxy/admission/P/D/KV snapshots.
Their absence is unavailable data, not measured zero. Go-state management/AI
metrics, including token quota, JWKS and key lookup, remain registered under
their own configuration/activity rules and may legitimately read zero.
Authentication and the metrics-disabled HTTP 503 remain unchanged.

The capability is derived from `mh.dpEbpf != nil`, after `DpEbpfInit` returns;
that function calls `loxilb_main` unconditionally. It describes initialized
native ownership, not traffic, sample freshness, kernel-hook health or every
collector's health. Proxy-only (`--proxyonlymode`, internally `disBPF`) still
initializes the native proxy; it is different from BGP peer-only. A capability
value of `1` is not an independent qualification of disBPF/kernel behavior.
`GetMetricsHealthSimple()` now reports this datapath capability, rather than
hook registration alone. `GetMetricsHealth()` can report load-balancer core
`UNAVAILABLE` while independent peer-only observability works.

Collection has three lifecycle states: off, running and stopping. Disable
immediately turns export off (503), cancels the worker generation and waits
outside the lifecycle mutex. Success joins all workers before re-enable resets
baselines. If the deadline expires, the generation remains stopping: POST
refuses enable with HTTP 503 and an error instructing the caller to retry disable first.
DELETE retries the drain; it succeeds after the in-flight operation finishes.
A pending stop leaves health/state queries responsive.

Normal process shutdown joins metrics before datapath detach. Metrics gets a
bounded part of the workers-stage budget so a failed drain does not skip BGP
recovery or KV subscriber cancellation. If a collector does not drain in time,
shutdown logs the generation and warns that a CGO call may still be in flight;
the bounded sequencer proceeds with detach. This timeout path does not promise
a join before detach or cancellation of an arbitrary native call.
