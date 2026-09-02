# DEC-010: Legacy Retirement Gate

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

Existing deployments configure engine integration through legacy flat fields that predate contract bindings. During the transition, the gateway can resolve both paths and compare outcomes in shadow mode. Retiring the legacy path too early would strand working configurations; retiring on a fixed calendar date would ignore what the telemetry actually shows.

## Decision

- Legacy flat-field configuration paths must be retired only after both of the following hold:
  - shadow-resolution telemetry and migration reports meet defined thresholds, and
  - a separate maintainer approval for the retirement itself is recorded.
- Thresholds are deliberately not set in this decision. They must be proposed together with the first shadow telemetry, so they are grounded in observed data rather than guesses.
- Until retirement, legacy and contract paths must resolve to identical effective configuration for the same input, verified continuously by the shadow comparison; divergence is a defect in the new path unless proven otherwise.
- Retirement must be a distinct, reviewable change — never a side effect of another feature landing.

## Consequences

- Operators get a data-backed retirement timeline instead of a surprise breaking release.
- The dual-path period costs maintenance: both resolvers stay tested until the gate passes.
- Threshold definition is deferred work that must accompany the first telemetry report, not trail it.
- Follow-up: the shadow comparison needs metrics for match rate, divergence classes, and remaining legacy-only rule count.
