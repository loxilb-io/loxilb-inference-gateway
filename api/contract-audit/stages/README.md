# Approval-gated implementation campaign

The user approved the audit documents and resumed implementation/testing on the
existing controller on 2026-09-08. Authorization is one stage at a time. Report
implementation, harness/environment findings and evidence, then wait for explicit
approval before beginning the next stage. No automatic continuation across gates.

| Stage | Scope | State |
|---|---|---|
| S01 | UI-02 original embedded Swagger contract preservation, generation regression tests and isolated Linux verification | PASS for scoped source/generation checks; [report](S01-SWAGGER-CONTRACT.md); APPROVED |
| S02 | Bound fixed-buffer AI argument intake before Go-to-C conversion, with rejection/side-effect tests | PASS for scoped admission/conversion checks; [report](S02-FIXED-CSTRING-ADMISSION.md); APPROVED |
| S03 | Mandatory `api_key_auth` precedence across HTTP/1 and HTTP/2, credential non-forwarding and backend non-delivery | PASS for scoped security checks; [report](S03-MANDATORY-SECURITY-PRECEDENCE.md); APPROVED |
| S04 | Policy-owned `X-Api-Key` namespace, H1/H2 parity slice, MCP create/observe and mock semantic routing | PASS for scoped checks; [report](S04-APIKEY-OWNERSHIP-AND-SEMANTIC-ROUTING.md); AWAITING APPROVAL |
| Later | Argument wiring/defaults; tier interactions; three-model GPU qualification | NOT AUTHORIZED; split into separately approved slices |

S01 used the existing `make docker` test-build image, pinned by image ID, and the
pinned Swagger generator in isolated containers. It does not rebuild/deploy the
Gateway or alter running monitoring/model services. This stage establishes
contract-generation evidence, not packaged Gateway or GPU qualification. Disk
headroom was insufficient for the historical full-build/GPU campaign threshold.
The user-approved exact-image cleanup and S02 build/verification are recorded in
the S02 report; future stages must still recheck available space before building.

The original audit records remain historical evidence. A stage report supersedes
only the findings it explicitly closes; it never converts the whole audit or
coverage ledger into PASS. S04 closes the API-key namespace decision only;
other L7 ownership, protocol-parity and runtime-qualification work remains open.
