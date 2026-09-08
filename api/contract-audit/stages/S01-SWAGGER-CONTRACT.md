# S01: original embedded Swagger contract preservation

Date: 2026-09-08. Result: PASS FOR THIS SCOPED STAGE.
Next state: WAITING FOR USER APPROVAL. Do not begin S02 automatically.

## Outcome and limits

UI-02 is resolved at the source/generation layer: the original SwaggerJSON now
preserves the source YAML contract, including the 29 previously missing zero
minima. The independent full-document verifier passes without dropping bounds,
descriptions or extensions. Its only semantic normalization is JSON object keys
and optional-parameter `required: false` (the Swagger default).

The actual pinned generator reproduces the failure on the controller; applying
the postprocessor repairs it. The nonempty FlatSwaggerJSON expression is exactly
unchanged. This is not a change to generated model validators or a proof of
Gateway request validation, security enforcement, routing or GPU qualification.

No new Gateway image was built or deployed in S01. The existing `make docker`
test-build image provided the Linux toolchain; frozen source was mounted into
unprivileged, network-isolated containers. Main checkout, running Gateway,
monitoring services, model caches and GPU-node configurations were not changed.
No commits, pushes, PRs or disk cleanup were performed.

## Implementation

- `api/cmd/sync-swagger`: strict single-document YAML intake, duplicate/colliding
  key rejection, generic JSON preservation of zero/false/null, safe Go literal
  encoding and AST-located replacement of only the original SwaggerJSON RHS.
- Require exactly one original and one flattened assignment. Fail check mode
  without writing. Reject symlink/non-regular output targets; replace regular
  files through a same-directory temporary file with preserved mode and atomic
  rename. Full-disk/crash durability was not fault-injected.
- `api/build_api.sh`: invoke the postprocessor after pinned generation and stop
  on generation/synchronization failure. The complete historical script, including
  its other server rewrites, was not run against the working checkout in this stage.
- `run-unit.sh`: add a contract gate for current-source images; baseline overlays
  explicitly record omitted Swagger, inventory and harness gates as NOT_RUN.
  The complete general unit runner/legacy overlay rail was not executed in S01.
- `run-swagger-contract.sh`: dedicated isolated Linux rail with input/image hashes,
  real generator reproduction, expected-RED checks and semantic repair proof.
- Independent Python oracle: distinguish actual missing numeric minima from
  formatting/prose drift and require nonempty unchanged flattened content. Its
  code/tests are hashed and its interpreter runs in the pinned test image.

## Final executed evidence

Controller evidence root (private operational location):
`/root/loxilb-ai-multitier-evidence/s01-swagger-20260908-2012/`.
Final complete run: `run-03/`; frozen input: `qualified-bundle/` and
`source-qualified/`. Earlier `run-01/` and `run-02/` are preserved, not overwritten.
Verify `run-03/SHA256SUMS` from `run-03/`. Verify its `input-sha256.txt` from
`source-qualified/`, the original working directory: the runner entry is relative
to that source root, while the other input entries are absolute controller paths.

| Gate | Result |
|---|---|
| Frozen bundle SHA256SUMS verification | PASS |
| Go unit tests | PASS: 8 top-level tests plus 11 subtests |
| Independent oracle tests | PASS: 8 tests, including false-positive negative controls |
| Fixed source contract check | PASS, exit 0 |
| Preserved pre-fix source check | EXPECTED RED, exit 1 and required contract-drift diagnostic |
| Real go-swagger 0.30.3 generation | PASS, exit 0 |
| Fresh raw-generator contract check | EXPECTED RED, exit 1 and required diagnostic |
| Synchronization and regenerated check | PASS, exit 0 |
| Semantic regression/repair and exact flattened preservation | PASS, exit 0 |
| Independent Ruby comparison of retrieved controller output against original YAML | PASS, zero remaining document differences after stated normalization |
| Running service identity list before/after | Unchanged |
| Evidence SHA256SUMS | PASS on controller |

The semantic RED oracle pins four concrete paths across P/D TTL, KV warm-up,
PII threshold and worker queue metrics. It requires missing minima before and
numeric zero after, with zero minima present in both flattened documents. This
specific negative control complements, not replaces, the full YAML parity check.

Go statement coverage is 78.8% for this small synchronization command only. It is
not argument coverage or product coverage. No tests are skipped in the scoped
Go or Python run. Scope exclusions above are explicit NOT RUN, not implicit PASS.

### Immutable identities

| Artifact | Identity |
|---|---|
| Gateway baseline | `f8e6ace22f0f2262d56829e781a83e4b7075fef7` plus archived WIP |
| eBPF baseline | `c5e468f28a2fa2acc6ea9110bfedc8de687b5fcb` plus archived WIP |
| Final full-run source archive SHA-256 | `e02fde019b528352462f6f501374aef7b8eb8205eb3089147d322ded17e0e9b2` |
| Test-build image ID | `sha256:023c34613f795ee5c9117a12f7fc75d9c47fa53e36f0f97c2b92a2b9026255e3` |
| go-swagger 0.30.3 image ID | `sha256:7591298bc3158d3f711b2f71bb083496af1a05807b9c1efea8c6c60be001811d` |
| Linux toolchain | Go 1.25.12 linux/amd64; Python 3.12.3 |
| Synchronizer main.go SHA-256 | `5ecccb4633b1edeff0d7afcda8d4037b3d9ba72dad546ec201aa232c04a16ad4` |
| Repaired embedded_spec.go SHA-256, local and controller | `6c9b2baca6d63065c5c654829f5dbcf677568700f39ba92e9b23758b3134d3f7` |
| Preserved flattened expression SHA-256 | `f025ec0716a4f2cadf0f43f1c5eae5ececef97159f6809508f1e87663061e4fb` |

A subsequent test-only fixture adjustment explicitly chmods its synthetic input
so a caller's umask cannot change the expected permission. It does not change
the synchronizer, generated document or harness implementation. Supplementary
`umask-final/` reran all Go tests in the same pinned Linux image under umask 077,
using the frozen source plus only that read-only test-file overlay: PASS, exit 0.
The final test-file SHA-256 is
`41d060cff52dba3b3d9c2b03ce8601708eedd3594d0c8c68db6573ac448f1428`.
This overlay is explicitly separate from the final full-run archive above.
Later report/document changes are not represented as tested executable changes.

## Failure classification and review corrections

| Observation | Classification | Disposition |
|---|---|---|
| Zero minima disappear in the pinned generator's original representation while flattened content retains them | API artifact-generation/toolchain defect; not a GPU algorithm failure | Reproduced with the actual generator; source-preserving postprocessing and contract gates added. Reviewed loader code clones OrigSpec via gob; no upstream dependency upgrade was made. |
| Initial expected-RED gate accepted any textual drift | Harness oracle weakness | Added specific semantic missing-minimum proof and description-only negative control. |
| Initial flattened hash extraction could accept empty output | Harness false-positive risk | Require exactly one nonempty parsed document and exact preserved expression; missing/duplicate/empty controls fail. |
| Initial synchronizer used truncating writes | New tool implementation robustness issue | Same-directory atomic replacement, mode/symlink checks and regression tests. |
| Baseline overlay omitted gate status rows | Harness reporting gap | Explicit NOT_RUN for all three omitted gates. |
| Oracle input hashes/interpreter were incomplete in earlier evidence | Harness provenance gap | Hash both Python files and execute tests/acceptance in the same pinned image. |
| Local Go cache access denied before assertions | Local sandbox/environment prerequisite failure | Preserve failed logs separately; permission-enabled local runs and isolated Linux runs pass. These failures were not counted as product RED evidence. |

Bounded independent review identified the five tool/harness concerns above; all
were addressed and re-reviewed with no remaining material finding in that scope.
The final Linux execution followed that review. Review is not a substitute for
runtime evidence, and these findings are not evidence of unrelated product fixes.

## Testbed state and next approval gate

Four existing monitoring/Gateway containers retained their identity across the
full run. The three approved profile files remain present: Qwen2.5-7B-Instruct,
Llama-3.1-8B-Instruct and EXAONE-3.5-7.8B-Instruct. Additional registered profiles
do not expand the approved qualification cohort. No live model-serving health or
GPU traffic qualification was attempted in this contract-only stage.

Disk headroom was about 8.4 GiB at initial inspection and 7.8 GiB after the final
full run. Scoped source/evidence was retained; active images, model caches and
recovery state were not deleted. This is below the historical full-build/GPU
campaign threshold. Resolve capacity before a later fresh `make docker` build;
do not extrapolate S01's small isolated execution budget to that workflow.

Proposed S02: validate fixed-buffer AI string arguments before Go-to-C conversion,
including UTF-8 byte length, NUL, exact boundaries and rejection without state
mutation. Implementation details and limits must be re-anchored to source at the
start of S02. This is a proposal, not authorization. Wait for the user's approval.
