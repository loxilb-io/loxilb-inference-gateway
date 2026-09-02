# DEC-011: Gateway Packaging

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

With compiled contract profiles per engine, one packaging option would be per-framework or per-version gateway builds (a "vLLM edition", an "SGLang edition"). That multiplies the release matrix, fragments testing, and forces operators running mixed engine fleets — a common deployment — to run multiple gateway flavors side by side.

## Decision

- There must be no framework-specific or engine-version-specific gateway packages.
- One gateway release for each supported OS/architecture must contain every compiled contract profile approved for that release.
- Artifact variants must remain limited to the existing OS/package-family and CPU-architecture dimensions; the contract registry must never become a packaging dimension.
- Which profiles a given release contains must be discoverable at runtime (version/metadata endpoint), since it is no longer encoded in the package name.

## Consequences

- Operators with mixed vLLM/SGLang/TensorRT-LLM/llama.cpp fleets run a single gateway build; the release matrix stays flat.
- Every release carries all profiles, so binary size grows with the profile count — accepted as negligible relative to the alternative's operational cost.
- All profiles must pass release gates together; one engine's failing validation can hold a release for all engines.
- Follow-up: surface the embedded profile inventory in the metadata API so tooling can check profile presence before configuring a rule.
