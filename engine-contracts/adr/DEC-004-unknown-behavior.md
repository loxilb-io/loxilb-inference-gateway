# DEC-004: Unknown Behavior

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

The gateway will encounter engine identities and contract references it does not recognize: newer releases than the compiled registry knows, typos in rule configuration, or engines never validated. The failure modes differ by feature: KV/P/D features parse engine wire formats and can corrupt inventory silently, while ordinary L7 routing treats the engine as an opaque HTTP backend.

## Decision

- A request to create a new KV/P/D configuration referencing an unknown engine or contract identity must be rejected (fail closed). The rejection must carry a distinct reason code identifying the unknown identity.
- Ordinary L7 routing to an unrecognized engine may continue, but only under explicit warn-and-degrade: the degraded state must be visible in rule status and logged at warning level, never silently accepted.
- No configuration path may auto-map an unknown identity onto a "closest known" profile.
- Existing admitted rules must not be retroactively torn down when a registry update stops recognizing their identity; they must instead surface the degraded status.

## Consequences

- Wire-format mismatches are stopped at admission time instead of surfacing as stale inventory or misrouted P/D traffic.
- Operators upgrading engines ahead of the gateway lose strict features until a gateway release recognizes the new identity (see DEC-012).
- Plain load-balancing use cases keep working, preserving the gateway's general-purpose role.
- Follow-up: enumerate the reason codes for unknown-identity rejection and degraded routing in the public API.
