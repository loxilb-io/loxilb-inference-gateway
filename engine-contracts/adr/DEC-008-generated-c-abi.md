# DEC-008: Generated C ABI

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

The P/D datapath needs engine-dialect enums on the eBPF/C side that correspond to the Go control plane's engine identifiers. Today these are hand-maintained mirrors, which is a real drift risk: an ID added on one side and not the other misroutes silently. Worse, the current C dialect resolver falls back to the vLLM dialect for unknown values, so a drifted ID does not fail — it quietly applies the wrong wire semantics.

## Decision

- P/D dialect enums for the eBPF/C side must be generated from manifest IDs in `contracts.yaml`; the manifest is the single source of truth and hand-edited enum definitions are prohibited.
- Generated values must remain stable with today's defines: `PD_ENGINE_VLLM` = 0, `PD_ENGINE_SGLANG` = 1, `PD_ENGINE_TRTLLM` = 2. Existing map state and pinned objects stay valid across the switchover.
- Unknown enum values must fail closed in the C resolver: the default-to-vLLM fallback must be removed, and an unrecognized value must yield an explicit error path, not a dialect.
- CI must verify that the generated C header and the Go registry derive from the same manifest revision.

## Consequences

- Go/C ID drift becomes a build failure instead of a silent misroute.
- Enum value assignment moves under manifest governance; reordering manifest entries must never renumber existing IDs.
- Removing the vLLM fallback may surface latent misconfigurations that the fallback was masking — this is intended.
- Follow-up: add a datapath counter for fail-closed dialect rejections so operators can see them.
