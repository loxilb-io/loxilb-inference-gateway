# DEC-012: Catalog Delivery

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

The contract manifest and support catalog gate what strict configurations the gateway will admit, so how they reach a running gateway is a trust question. A hot-reloadable catalog file on disk would let anyone with filesystem access widen the supported surface without review, defeating the approval chain established in DEC-001 and DEC-009.

## Decision

- `contracts.yaml` and the approved `support-catalog.yaml` must be validated and embedded into the gateway binary at build time.
- Unsigned hot reload of the catalog at runtime is prohibited in the initial version; the running gateway must consult only its embedded copy.
- Promoting a new engine version to validated therefore requires a new gateway release; there is no runtime shortcut.
- Build-time validation must fail the build on schema errors, unknown cross-references between catalog and manifest, or selector conflicts — invalid catalogs must be unshippable, not merely warned about.

## Consequences

- The admission surface is exactly as reviewed: what CI validated and maintainers approved is what runs, with no post-release drift.
- Support for a newly validated engine build waits on the gateway release cadence; urgent validations may motivate a patch release.
- The embedded catalog digest becomes part of release identity, which DEC-014 uses for cluster agreement.
- Follow-up: a future version may define a signed catalog update channel; the signing and verification design is out of scope here.
