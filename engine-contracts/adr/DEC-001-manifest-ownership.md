# DEC-001: Manifest Ownership

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

The engine-contract foundation needs machine-readable descriptions of engine wire protocols, a human-approved record of which exact engine builds are supported, and automated observations of upstream releases. Mixing these into one file would let an automated watcher silently widen the supported surface: an upstream release being observed must never imply gateway support.

## Decision

- `engine-contracts/contracts.yaml` must be code-owned. It defines implementable protocol profiles and is the single source of truth for compile-time artifacts (registry, generated enums, validation schemas).
- `engine-contracts/support-catalog.yaml` must be approval-owned. It records human-approved support status and evidence references for exact identity tuples, and must be guarded by CODEOWNERS so no change lands without maintainer review.
- `engine-contracts/observed-releases.json` must be bot-owned. It holds watcher snapshots of upstream releases and must never be compiled into the gateway or consulted for admission decisions.
- No tooling may promote an entry from `observed-releases.json` into `support-catalog.yaml` without the human approval flow defined in DEC-009.

## Consequences

- Support claims are auditable: every validated tuple traces to an approved catalog change, not a watcher event.
- Three files mean three update cadences; contributors must learn which artifact a change belongs to.
- The watcher can run fully automated without any blast radius on admission behavior.
- Follow-up: CI must verify the three files stay structurally disjoint (no support fields in observed data, no observations in the catalog).
