# Whole-API contract audit: review and disposition

Date: 2026-09-08. Status: IN PROGRESS; not a release approval.

Implementation follow-up: the user approved the documents and authorized one
stage at a time. [S01](stages/S01-SWAGGER-CONTRACT.md) repairs UI-02 at the
source/generation layer with isolated Linux evidence. It does not close `/meta`
projection, runtime deployment, security enforcement or the rest of this audit.
[S02](stages/S02-FIXED-CSTRING-ADMISSION.md) closes AI-01 for scoped admission
and Go-to-C conversion, with packaged-runtime evidence. Later stages remain
approval-gated.

## Baseline and authority

- Worktree: `loxilb-inference-gateway-ai-multitier-cicd`.
- Branch: `codex/ai-multitier-cicd`.
- Gateway HEAD: `f8e6ace22f0f2262d56829e781a83e4b7075fef7`, plus existing WIP.
- eBPF HEAD: `c5e468f28a2fa2acc6ea9110bfedc8de687b5fcb`, plus existing WIP.
- Main checkout: `7f352064`; compared, not modified by this audit. The two spec
  files differ from main through the pre-existing campaign fixes and this audit.
- CodeGraph was used for discovery only. Its branch/revision differed; exact
  local source was used for findings. No graph rebuild was performed.
- No runtime implementation, test harness behavior, GPU deployment, engine
  configuration, database, or testbed state was changed by this audit.

Both `swagger.yml` and `swagger-extras.yml` are in scope. There are initially
209 + 8 operation declarations; three OPA methods overlap, so this is 214 unique
method/path pairs, not 217 unique deployed endpoints. Initial inventory also
contains 170 named definitions, 221 parameter objects, 1297 property nodes and
1318 response declarations. Added documentation-only response fields may change
the final inventory; use the generated inventory's hashes and counts.

These counts are structural coverage, not completed semantic review. Reusable
schemas, raw middleware precedence, common error classification, build flags,
external capabilities and lifecycle paths must be reviewed separately. Reports
explicitly list exclusions. Unreviewed ledger rows must not be marked PASS merely
because their domain has a report.

## Audit records

- [Scope and approved decisions](README.md)
- [UI relationship semantics](relationships.md)
- [Approved-feature remediation and campaign restart plan](remediation-plan.md)
- [Static validation results and unresolved embedded drift](validation.md)
- [Raw middleware: all extras operations and definitions](review-extras.md)
- [LB non-AI arguments and L7 policies](review-lb-l7.md)
- [Networking: 70 assigned operations](review-networking.md)
- [Security/account/encryption: 58 assigned operations](review-security.md)
- [Operations/observability: 58 assigned operations](review-operations.md)

The domain reports preserve detailed source anchors, proposed corrections,
implementation gaps and open decisions. They are static review evidence, not
execution logs. Line numbers refer to the source read during review; function
anchors remain the more stable locator while descriptions are edited.

## AI contract findings and disposition

| ID | Finding | Classification and disposition | Source anchor |
|---|---|---|---|
| AI-01 | Unbounded model/session/path string copies into fixed C arrays | RESOLVED in S02 for admission and Go-to-C conversion: encoded-byte/NUL/UTF-8 and composite-key checks precede mutation, the bridge defends itself, and packaged REST tests pass. Live routing and restore remain outside this closure. | `pkg/loxinet/rules.go:validateLBFixedCStringFields`; `pkg/loxinet/dpebpf_linux.go:copyLBFixedCString`; `stages/S02-FIXED-CSTRING-ADMISSION.md` |
| AI-02 | kvBlockSize's uint32 schema ceiling conflicts with signed C iteration | Implementation/safety and domain-contract gap. Ratify actual engine geometry and safe arithmetic, not merely a storage-width bound. | `loxilb-ebpf/common/sockproxy_kv_exact.c:568,616` |
| AI-03 | kvWarmupSec has no production start-timestamp writer | Implementation gap. Keep feature, specify connect/reconnect/rank/HTTP lifecycle, then wire it. Synthetic timestamp injection is not lifecycle proof. | `loxilb-ebpf/common/sockproxy.h:633`; `sockproxy_kv_exact.c:735` |
| AI-04 | CHWBL declarations do not all reach active config; C uses 175/256 | Implementation gap and default decision. Keep options, fix propagation and ring reconfiguration; do not claim schema defaults 125/100 are effective. | `pkg/loxinet/rules.go:6333`; `dpebpf_linux.go:1562`; `sockproxy_http.c:2867` |
| AI-05 | Cache-salt flag does not enforce salt presence or tenant isolation | Security-contract/implementation gap. Remove unsupported isolation claim; design identity binding and failure policy. | Same CHWBL path as AI-04 |
| AI-06 | Threshold zero means default on create but retain on replace | Approved future contract: omitted update retains, explicit zero resets. Current descriptions distinguish pending implementation. | `pkg/loxinet/rules.go:3952,4133` |
| AI-07 | Balance guard is not common to all affinity tiers | Documentation correction: Tier 0 bypasses it; Tier 1 uses it; Tier 1.5 depends on LLB_KV_LOADGUARD. | `loxilb-ebpf/common/sockproxy_pd.c:1880,1942,1974` |
| AI-08 | Scalar validators skip zero despite minimum=1 | Schema/model-contract gap. Review presence-aware representations field by field; do not change all zero semantics uniformly. | `api/models/loadbalance_entry.go:1251,1267,1456` |
| AI-09 | P/D and Exact descriptions conflate topology with transport | Description correction: engine dialect and mode are independent; TRT uses HTTP, SGLang concurrent P/D differs from sequential flows. | `pkg/loxinet/rules.go:2777,3754`; engine-specific P/D dialect tables |
| AI-10 | Rank/port aggregate bound and non-default-only guards are underdocumented | Describe default resolution, SGLang-only count>1, base+count-1 bound, TRT accepted default declarations and SGLang nonzero bootstrap guard. | `pkg/loxinet/rules.go:2696,2731,2777,3409` |
| AI-11 | Exact admission requires model/tokenizer/seed/profile/API conditions | Describe dependencies; UI discovery remains advisory. Stage errors differ from runtime fallback. | `pkg/loxinet/rules.go:2999` |
| AI-12 | TRT geometry mismatch can deny KV poller rather than cause simple misses | Description correction; endpoint event admission and plain LB availability are separate outcomes. | `pkg/loxinet/ai_kv_trtllm_source.go:687` |
| AI-13 | Profile setDigest and bindingDigest identify different objects | Description correction. Compare registry-set digests only with later registry-set digests; compare profile identity/generation and enforced state after POST. | `api/restapi/handler/ai_model_profile.go:70`; `pkg/loxinet/rules.go:GetKvExactStatus` |
| AI-14 | KV status presence claims exclude restore/missing-binding cases | Description correction: hash identity exists on legacy too, enforcement exists on restored legacy, and strict faults may omit binding generations. | `pkg/loxinet/rules.go:GetKvExactStatus` |
| AI-15 | SSE duration is described as absolute wall-clock | Description correction: min(configured,86400), periodic enforcement, QoS parked-time anchor adjustment. | `loxilb-ebpf/common/sockproxy_health.c:452,484` |
| AI-16 | Circuit-breaker description promises reaction after one failure while threshold is five | Remove contradictory statement; do not conflate endpoint CB, probes, OPA CB, and DPU CB. | `loxilb-ebpf/common/sockproxy_health.c`; endpoint breaker initialization |
| UI-01 | /meta drops bounds/defaults and top-level relationship extensions | UI integration gap. Use pinned original specs or design a metadata API upgrade; description edits do not fix the projection. | `api/restapi/handler/metadata.go:35,167,235` |
| UI-02 | Generated SwaggerJSON omitted 29 zero-minimum constraints present in YAML | Original RED preserved. S01 source-preserving generation and independent parity checks now PASS; no deployed/UI or runtime-validator qualification implied. | `api/contract-audit/embedded-parity.txt`; `stages/S01-SWAGGER-CONTRACT.md`; `api/api.go:101` |

## Release-blocking examples outside AI arguments

These are not resolved by description edits. See the domain reports for detailed
evidence and limitations before implementation decisions:

- L7 conditions silently truncated during C encoding can broaden an AND match.
- Backend verification/inline mTLS declarations lack complete active-path wiring.
- LB intake/readback drops some lifecycle, connection-limit and TLS settings.
- L7 attachment ownership uses a narrower identity than the LB resource API.
- OPA fail_open is stored but unused, outbound URL protection is incomplete, and
  internal firewall requests lack a management credential.
- API-key model-list comma serialization is lossy; multi-field PATCH lacks an
  atomic transaction and can miss cache invalidation on partial failure.
- Direct browser PATCH is absent from the CORS allowed-method list.
- DPU filters and hardware-counter identity parsing do not match stored keys;
  empty/partial telemetry is not proof that hardware has no flows.
- Delimiter-based management-principal encoding can disagree with stored roles;
  Bearer logout hashes a different string from the authentication path.
- Legacy import can convert an unrecognized empty JSON shape into committed
  replacement of five empty domains. This is not an approved clear-all operation.
- Marked IPsec tunnel deletion issues namespace-wide XFRM flushes; neighbor and
  VLAN member deletion have insufficient target-ownership checks.
- Scanner configuration and fail-closed controls have incomplete active-path
  wiring. Statistics/health placeholders do not establish protection.

## Confirmed security precedence decision

The user confirmed that security requirements take precedence over all traffic
control. Reject requested security settings that cannot be applied before
authoritative mutation or activation; do not report storage as enforcement.
Applicable mandatory security checks must not be bypassed at runtime, including
session affinity, KV hits, CHWBL, retries, failover and overload fallback paths.
Fallback to another path is permitted only when that path satisfies the same
applicable security requirements. A required protection failure blocks the
affected operation or traffic; it does not imply stopping unrelated services.

This is policy approval, not implementation completion. Failure status codes,
effective-state reporting, in-flight transition semantics and capability delivery
still require detailed contracts. See the planned security-precedence tests in
`remediation-plan.md`. No implementation or runtime test was changed or executed
as part of recording this decision.

## Questions awaiting product decisions

The separate L7 ownership question remains unanswered: should policy ownership
be per LB resource with isolation between rules sharing a listener tuple
(recommended), or restricted to one policy per physical listener tuple?

Other policy topics are recorded in the domain reports rather than silently
decided: CHWBL effective defaults, warm-up lifecycle/fallback, OPA failure policy,
OAuth identity/role admission, secret-bearing viewer GETs, null/empty update
semantics, certificate ownership/rotation and shared whitelist-map ownership.
No requested runtime behavior is implemented by the documentation changes.

## Completion and campaign gates

Cross-report reconciliation at this checkpoint:

- `UpdateLicenseRequest` was examined by the security owner; its role/token
  semantics are not an unassigned operations finding anymore.
- Networking accounted for `K8sConntrackEntry` and its lack of a reference from
  the live conntrack operation. Together with `MetricEntity` and
  `HealthCheckResponse`, it remains an unused-schema ownership decision, not a
  missing runtime feature inferred from a generated model.
- Shared error-envelope and advertised-response mismatches are still open.
  Describing the mismatch does not reconcile response schemas or every generated
  middleware status. The raw extras authentication path also needs its own check.
- Domain source reviews do not close transitive kernel/SDK/engine behavior,
  feature-flag combinations or concurrency. The individual inventory rows remain
  `UNREVIEWED` until source-to-field dispositions are explicitly reconciled; the
  inventory tool deliberately does not convert a domain report into blanket PASS.

1. Finish all assigned operation/schema reviews, including shared response/auth
   handling and orphan schemas. Reconcile each report's exclusions explicitly.
2. Review intended contracts and outstanding product decisions. Do not approve
   current bugs by changing prose to describe them as supported behavior.
3. Update descriptions and structured relationships only for evidence-supported
   facts. Keep planned enforcement and UI-only containment distinguishable.
4. Reconcile generated models/embedded spec using pinned go-swagger 0.30.3;
   validate the YAML, references, relationship pointers, and semantic-only diff.
5. Before publishing/vendoring, obtain a reviewed disposition for every material
   finding and a source-pinned consumer handoff. No UI/OAM/CLI repo is updated here.
6. Before resuming affected tests, resolve their contract and safety blockers;
   then test admission, propagation, algorithm, lifecycle and qualified GPU tuples
   with independent oracles. A readback test is not a dataplane behavior test.

Global audit completion does not imply all defects are fixed. Conversely,
unrelated documentation cleanup need not block a safely isolated, contract-settled
test slice. The current campaign remains paused until an explicit reviewed slice
is ready; this audit does not resume it automatically.
