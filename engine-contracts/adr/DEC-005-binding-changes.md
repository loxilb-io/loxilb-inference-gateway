# DEC-005: Binding Changes

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

A live rule's contract binding determines how the datapath and control plane interpret engine events for that rule. Mutating a binding in place would require re-interpreting in-flight state (KV inventory, P/D session affinity) under a different wire contract mid-stream. The gateway API already documents this immutability for the engine-type field, so codifying it carries zero migration cost.

## Decision

- Contract bindings on a live rule are immutable in the initial version. An update request that changes a rule's binding must be rejected.
- The only supported path to change a binding is: drain the rule, delete it, and recreate it with the new binding.
- The API must return a distinct error for attempted binding mutation, so callers can distinguish it from validation failures.
- This codifies the semantics already shipped for the engine-type field in the public API; no existing client behavior changes.

## Consequences

- In-flight KV/P/D state can never straddle two contracts, removing a whole class of re-interpretation bugs.
- Operators pay a drain/recreate cycle for engine migrations; automation should script the sequence.
- Zero migration cost: current API consumers already operate under these semantics.
- Follow-up: a future version may add an orchestrated "rebind" verb that performs drain/delete/recreate atomically on the server side.
