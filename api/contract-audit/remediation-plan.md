# Contract remediation and campaign restart plan

Status: proposed work sequencing, not implemented behavior or runtime evidence.
Scope: the audited campaign worktree. Documents are English only.

Implementation status: S01 and S02 are complete for their explicitly bounded
scopes. S02 enforces the four LB fixed-string and composite endpoint-key limits,
defends the Go-to-C boundary and verifies packaged REST rejection. See
`stages/S02-FIXED-CSTRING-ADMISSION.md`. The live behavior, restore and legacy
recovery limits in that report remain planned work, not implied completion.

## 1. Resolve the contract before choosing the test oracle

Each finding needs a stable ID, current source evidence, intended behavior,
compatibility impact, implementation owner, independent expected result and
verification layer. A description of a current defect is not its acceptance
criterion. Keep API rejection, stored intent, effective configuration and runtime
behavior as separate assertions.

The user approved retaining CHWBL options and `kvWarmupSec`, and distinguishing
omission from explicit zero for the two P/D thresholds. The details below are
implementation plans, not an assertion that these controls are already wired.

### P/D thresholds: approved presence-aware updates (AI-06)

- Preserve presence through JSON binding and the internal update representation.
  Do not rely on a zero-valued Go scalar to distinguish omission from zero.
- On update, omission retains the previous value, explicit zero resets to the
  current system default, and a valid positive value replaces the previous one.
- Preserve the existing create default policy unless separately approved. Define
  null explicitly; do not silently treat null as an approved reset operation.
- Confirm which endpoints actually support these updates. A general LB POST
  replacement and the restricted endpoint PATCH must not be conflated.
- Validate the complete proposed state before changing stored or active state.
  Document the compatibility change for callers that formerly sent zero to retain.
- Add presence-binding unit tests and table-driven create/update tests for each
  threshold: omitted, null, zero, valid positive, boundary, out-of-range and wrong
  JSON type. Include non-default-to-zero and repeated-zero transitions.
- Add independent dataplane tests proving the effective defaults after reset,
  the Tier 0 bypass, the Tier 1 guard and both Tier 1.5 load-guard settings. Test
  values on either side of each selection boundary, not readback alone.
- Test persistence/restore and rollback separately; an old serialized zero must
  not accidentally become an unrelated update operation.

### CHWBL: retained options, missing propagation (AI-04/05)

- Ratify effective defaults before implementation: current C behavior and Swagger
  defaults disagree. Do not silently select either as the product contract.
- Trace every published option through binding, validation, storage, Go-to-C
  conversion, ring construction, reconfiguration and endpoint selection.
- Specify the scope and lifecycle of cache-salt identity. A flag or salt string
  alone is not tenant isolation; absent/untrusted identities need an explicit
  security policy before an isolation claim can be tested or published.
- Add table-driven option propagation tests, C configuration tests, deterministic
  selection tests with fixed inputs, boundary tests and ring-rebuild tests after
  endpoint/weight/option changes. Cover both applicable selectors independently.
- Include zero-load, saturated preferred endpoint, failed endpoint, endpoint
  recovery and concurrent configuration replacement. Distribution tests must use
  a specified workload, seed and tolerance instead of a vague balance assertion.

### KV warm-up: retained feature, lifecycle contract pending (AI-03)

- Define when warm-up starts for ZMQ connection, reconnect, SGLang rank addition
  and TensorRT-LLM HTTP discovery. Decide whether the state is per source, rank,
  endpoint or service and what zero means.
- Define routing during warm-up, event acceptance, partial-rank availability,
  early readiness, failure/reconnect and expiry. These are open lifecycle choices,
  not established by the existing field's presence.
- Use a controllable monotonic clock for unit tests. Cover just-before, exact and
  just-after expiry plus reconnect and configuration changes.
- Add a production-path integration test proving the timestamp is initialized by
  the real source lifecycle. Setting it directly in a C test is necessary for
  algorithm isolation but insufficient to prove the feature is reachable.

## 2. Prioritize safety and authoritative validation

Before any affected live slice, address or safely isolate fixed-buffer string
copies, unsafe numeric conversion, L7 condition truncation, ineffective requested
security controls, authentication principal handling, destructive import shapes
and unscoped deletion. See the domain reports for evidence and exact scope.

Do not run destructive reproductions on the shared GPU testbed. Use isolated
namespaces, disposable state or mocked command runners first. Any later live
experiment requires target ownership checks and a verified recovery procedure.

Security precedence and rejection of unappliable requested controls are approved
in `review.md`. L7 ownership on a shared listener remains a separate pending
decision. Other domain-specific decisions remain explicit rather than inferred
from bugs.

### Approved security precedence: planned acceptance tests

The following requirements are approved in principle; tests and enforcement
changes are NOT IMPLEMENTED by this document. Precedence is a logical guarantee,
not a demand to place every check at the same pipeline position. Authentication,
TLS handshakes and content inspection act at different stages, but no stage may
release traffic that violates its applicable mandatory security condition.

| ID | Scenario | Required oracle and planned test layer |
|---|---|---|
| SEC-01 | Configure a mandatory control unsupported by the build, protocol or active path, or with unusable required material | Reject before authoritative mutation/activation. Unit admission tests assert unchanged configuration and no dataplane work; isolated integration verifies no partially active rule. Do not confuse a temporary dependency outage with a permanently unsupported capability. |
| SEC-02 | Backend certificate verification required; valid and untrusted certificates offered | Valid trust case succeeds; untrusted case does not deliver an inference request. TLS integration must observe handshake outcome and backend application receipt, not stored flags alone. No verification-disabled retry. |
| SEC-03 | Frontend client certificate required; absent, untrusted and valid client certificates | Reject absent/untrusted certificates before inference forwarding; accept the valid case. Test actual enforcement, including the unsupported-build admission case. |
| SEC-04 | Mandatory AI inspection enabled with fail-closed; scanner timeout, transport failure or malformed response | Do not forward the affected request to the model backend. Unit tests cover scanner-result handling; integration asserts zero backend application requests. Distinguish inspection-unavailable from a completed threat decision. Error/status details remain to be specified. |
| SEC-05 | Security rejection combined with a Tier 0 session hit, Tier 1 affinity hit, Tier 1.5 KV hit, Tier 2 selection or applicable CHWBL path | Repeat the rejection cases across each reachable routing branch. Verify no unauthorized delivery through a hit, fallback, retry or failover. A routing hit must not act as security authorization. Cover the applicable engine/topology tuples, not impossible combinations. |
| SEC-06 | Preferred destination fails mandatory security checks while another destination is available | Secure fallback may proceed only to an authorized destination satisfying the same applicable protections. If none qualifies, fail the affected request. Never silently switch identity, tenant, trust policy or inspection requirements for load relief. |
| SEC-07 | Security configuration update fails, or protection becomes unavailable after activation | Rejected updates preserve the previous valid configuration and explicitly report failure. Runtime loss of a mandatory protection must not trigger silent bypass. Add fault-injection and state-transition tests; ratify in-flight/streaming and concurrent-update semantics before claiming complete lifecycle coverage. |

Apply these checks to enabled/applicable policies across traffic types; do not
force an AI body scanner onto an unrelated opaque protocol. A control that cannot
be enforced on its requested traffic scope must fail admission rather than be
ignored. Tests must also verify that failures do not unnecessarily disable
unrelated services. The security policy does not grant permission to alter the
shared GPU testbed or resume the campaign during the audit.

## 3. Publish an actionable API contract

After source reconciliation, update standard schema constraints only where
server behavior and compatibility have been decided. Extend the versioned
relationship rules beyond the initial AI subset, adding negative examples and
test references for prerequisites, exclusions, aggregate bounds and update rules.

The UI needs the pinned original specifications or an explicitly upgraded `/meta`
contract; current metadata projection drops important constraints and extensions.
Do not label a UI-side containment check as server enforcement. Review generated
bindings and embedded specifications with the pinned generator before vendoring.

## 4. Resume the campaign in bounded slices

1. Binding and admission unit tests: input presence, types, bounds and atomicity.
2. Configuration propagation tests: requested, stored and effective values.
3. Deterministic algorithm tests: selection, rejection, fallback and boundaries.
4. Lifecycle integration tests: replacement, deletion, reconnect and restore.
5. Qualified GPU tests on the approved testbed/model tuples, after earlier gates.

Use the existing `make docker` campaign workflow only when runtime testing is
explicitly resumed. Preserve exact Gateway/eBPF revisions, image digest, model
and tokenizer identity, engine version, serve arguments and topology in evidence.
Do not expand model compatibility beyond the three already-qualified tuples.

Each failure record must include the input, independent expected result, observed
result, minimal reproducer, logs, exact artifact identity and cleanup outcome.
Classify implementation, harness and environment failures using discriminating
checks; preserve UNKNOWN where the causal boundary is not established. A mocked
PASS, HTTP 2xx, readback equality or successful compilation is not GPU proof.
