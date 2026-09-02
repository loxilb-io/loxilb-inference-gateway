# DEC-014: Cluster Rollout

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

The gateway runs in HA clusters, and contract profiles are embedded per release (DEC-012). During an upgrade, nodes transiently run different registries; if a profile activated on one node while a peer could not interpret it, failover would change traffic semantics mid-flight. Strict features additionally pin exact engine identities, which an engine-side rolling upgrade would violate one replica at a time.

## Decision

- A new contract profile must activate only after all gateway HA nodes agree on: gateway version, registry digest, catalog digest, and contract-schema version.
- While nodes disagree on any of these, activation requests must be rejected with a distinct cluster-skew reason code; existing admitted rules continue running.
- Rollout order must be gateway-first: upgrade and converge all gateway nodes, then move engines via blue/green sequencing.
- No in-place rolling upgrade may mix different exact engine identities within one strict service; the old and new identity must run as separate endpoint sets with an explicit cutover.

## Consequences

- Failover between HA nodes can never change how an active profile is interpreted, because activation implies cluster-wide agreement.
- Upgrades gain a convergence step; automation must poll for agreement before activating new profiles.
- Engine fleets serving strict services need blue/green capacity headroom instead of in-place rolling upgrades.
- Follow-up: expose the four agreement fields and current skew state through the cluster status API for upgrade tooling.
