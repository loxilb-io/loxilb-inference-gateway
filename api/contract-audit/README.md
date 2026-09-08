# Swagger contract audit

Status: IN PROGRESS. Inventory completeness is not implementation verification.

This audit covers `api/swagger.yml` and `api/swagger-extras.yml`, including
operations, parameters, schema properties, responses, security declarations,
generated bindings, raw routes, and relationships between fields. The baseline
is the `codex/ai-multitier-cicd` worktree at `f8e6ace2` plus its pre-existing WIP.
The main checkout at `7f352064` was compared before review; it is not modified.

The original audit evidence is static unless an individual record says otherwise.
The user subsequently approved the documents and resumed implementation in
separately approved stages; see [the stage tracker](stages/README.md). This is
not blanket approval to deploy, commit, push, implement UI changes or advance
automatically to the next stage. GPU traffic testing has not resumed in S01.

Start with [findings and open decisions](review.md),
[relationship metadata](relationships.md), and the
[remediation and restart plan](remediation-plan.md). Domain reports preserve
their read-only investigation checkpoint; subsequent description edits do not
turn those static findings into runtime verification.
See [original validation evidence](validation.md): the audit checkpoint preserved
29 zero-minimum differences as FAIL. Stage S01 addresses that finding separately;
the original failing evidence is not rewritten or waived.

## Decisions confirmed on 2026-09-08

- Keep the CHWBL options and `kvWarmupSec` as product features. Record missing
  runtime wiring and plan implementation; do not remove them to hide defects.
- For `pd_cache_threshold` and `pd_balance_abs_threshold`, the approved target
  update contract is omission = retain the current declaration, explicit zero =
  reset to the system default. The existing replace path does not implement this
  distinction. Document current behavior separately until it is implemented.
- The approved P/D session TTL contract is omission/zero = 300-second sliding idle
  TTL, positive = per-service override, with no no-expiry mode. It is Gateway
  endpoint affinity, not engine KV retention or transfer timeout.
- Security requirements take precedence over all traffic-control decisions.
  Reject an unappliable requested security configuration before activation or
  authoritative configuration mutation. At runtime, an applicable mandatory
  security condition must not be bypassed for availability, affinity or load
  balancing. This is an approved target contract, not a claim of current support.
  See SEC-01 through SEC-07 in the remediation plan for planned verification.

## Acceptance gates

1. Enumerate both specs without dropping duplicate keys or unresolved references.
2. Trace each operation and argument to binding, handler, domain validation, and
   consumer. Record explicit gaps rather than inferring correctness from readback.
3. Classify differences as documentation defects, implementation gaps, or product
   decisions. Do not make defective current behavior normative by copying it.
4. Publish English descriptions and relationship rules, distinguishing intended,
   enforced, and pending behavior. Standard Swagger constraints remain separate.
5. Review generated artifact drift and consumer compatibility. Descriptions and
   vendor extensions do not automatically implement server or UI validation.
6. Resume affected campaign tests only after their contract decisions and safety
   blockers are resolved. An inventory or source review is not runtime coverage.

## UI integration boundary

Swagger 2.0 standard constraints cover individual values but do not provide a
general conditional-validation language. Project-specific relationship metadata
must have an explicit version, scope, stable ID, evidence, and enforcement status.
The UI must opt in to interpreting it; generic OpenAPI tooling does not do so.
UI validation is advisory and never replaces authoritative server validation.

Reference: [OpenAPI Specification 2.0](https://spec.openapis.org/oas/v2.0.html).
