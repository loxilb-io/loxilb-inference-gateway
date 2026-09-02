# DEC-003: Identity Strength

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

Version strings alone cannot capture protocol-level changes: the vLLM KV-event encoding switched between v0.23.0 and v0.24.0 with no other outward signal, and the gateway's TensorRT-LLM fixtures were captured from preview 1.3.0rc24, not stable v1.2.1 — two builds with the same nominal lineage but different verified behavior. Strict KV and P/D features depend on byte-level wire compatibility, so the identity a rule binds to must be as strong as the platform can supply.

## Decision

- New strict KV/P/D configurations must require the exact upstream revision (commit or release tag) plus the OCI image platform digest of the engine build.
- Where the platform cannot supply one of these (for example a bare-metal engine with no OCI digest), the strongest available identity must be recorded and the configuration must strongly prefer exact revision identity; the missing field must be reported, not silently defaulted.
- Preview builds (such as 1.3.0rc24) and stable releases (such as v1.2.1) must be treated as separate identity tuples with separate support-catalog entries and separate evidence.
- Identity tuples must be recorded verbatim in the support catalog; normalization must never collapse two distinct builds into one tuple.

## Consequences

- Strict features cannot be enabled against an engine whose exact build is unknown, eliminating a class of silent wire-format mismatches.
- Operators must capture image digests in their deployment pipelines, a new operational requirement.
- Fixture provenance becomes explicit: evidence captured on a preview build does not validate the stable build.
- Follow-up: define the reduced-assurance reporting for platforms that cannot supply a digest (see DEC-013 for how sources are trusted).
