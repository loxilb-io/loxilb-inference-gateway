# DEC-007: TRT HTTP Drain Ownership

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

TensorRT-LLM exposes KV cache events over an HTTP endpoint (`/kv_cache_events`) whose read is destructive: events are removed from the server-side queue when fetched. Two consumers polling the same endpoint each see a disjoint, incomplete stream, and neither can detect the loss from its own view. This differs fundamentally from broadcast-style event transports used by other engines.

## Decision

- `/kv_cache_events` must be treated as a consuming (destructive) read: exactly one active consumer per engine endpoint is permitted.
- The gateway must own that consumer role and manage a cursor/epoch per endpoint recording consumption progress and ownership generation.
- Competing consumers, stale epochs, and sequence gaps must fence deterministically: a consumer holding a stale epoch must stop applying events, and a detected gap must invalidate the affected inventory rather than continue on a known-incomplete stream.
- On gateway HA failover, the new owner must acquire a fresh epoch before consuming; two nodes must never poll the same endpoint concurrently.

## Consequences

- KV inventory for TensorRT-LLM endpoints is either complete or explicitly invalidated — never silently partial.
- Operators must not point external tooling at `/kv_cache_events` on gateway-managed endpoints; doing so steals events and triggers gap fencing.
- The cursor/epoch mechanism adds state that must survive gateway restarts and HA transitions.
- Follow-up: expose per-endpoint consumer ownership and gap counters in metrics for drain-conflict diagnosis.
