# DEC-013: Identity Trust

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

An engine's identity can be asserted by the rule author, reported by the deployment platform, or read from the engine's own runtime API — three sources with very different trust properties. Conflating them lets a caller type a digest into a rule and have it treated as if the platform had verified it, which would hollow out the exact-identity guarantees of DEC-003.

## Decision

- Three identity sources must be kept distinct and separately recorded:
  - `declared` — supplied by the rule or API caller;
  - `attested` — reported by OAM, Kubernetes, or another trusted deployment inventory (artifact identity);
  - `probed` — read from the engine's runtime API (runtime match).
- Strict activation must require that the support-catalog exact tuple, the attested artifact identity, and the probed runtime identity agree within the fields each source can verify.
- A declared-only value must never satisfy the attested or probed requirement; declaration can narrow expectations but never substitute for verification.
- Disagreement between sources must block strict activation with a reason code naming the disagreeing sources and fields.

## Consequences

- A typo or a stale declared digest cannot silently activate strict features against the wrong build.
- The gateway needs integrations with deployment inventories and engine runtime APIs; environments lacking both cannot reach strict activation.
- Per-source identity records make mismatch triage direct: status shows which source disagreed.
- Follow-up: define the per-engine probed-identity field sets, since engines differ in what their runtime APIs expose.
