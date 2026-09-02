# DEC-002: Version Selector

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

Contract profiles must state which engine builds they apply to. The gateway's compatibility risk is protocol-level, not version-string-level: the vLLM KV-event object switched from tagged-array to tagged-map encoding between v0.23.0 and v0.24.0 while the outer batch stayed an array, so a bare version comparison cannot express what actually changed on the wire. Not all engines are semver: llama.cpp historically shipped b<N> builds, and preview tags such as 1.3.0rc24 do not order cleanly against stable releases.

## Decision

- Selectors in `contracts.yaml` must be typed, not free-form strings.
- Engines with semver releases must use inclusive min/max range selectors (`minVersion`/`maxVersion`).
- Non-semver identities must use exact selectors: exact version string, upstream revision, or build ID (for example llama.cpp `b<N>` builds and preview tags like `1.3.0rc24`).
- A selector must never mix range and exact forms in one entry; validation must reject ambiguous selectors at build time.
- A range selector binds only to the protocol profile it appears in; the profile itself, not the range, is what admission checks.

## Consequences

- Wire-format breaks like the v0.23.0/v0.24.0 encoding switch are modeled as separate profiles with disjoint ranges, instead of being hidden inside one wide range.
- Preview and stable builds of the same nominal version can carry different profiles.
- Adding a new engine requires deciding its identity scheme up front.
- Follow-up: build-time validation must reject overlapping ranges that map to conflicting profiles.
