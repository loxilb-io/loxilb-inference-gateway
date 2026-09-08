# LB and L7 contract audit

The assigned surface has material contract and safety gaps. Several Swagger fields have no effective REST-to-dataplane path, and some accepted L7 inputs are truncated or interpreted differently in C. Documentation changes alone cannot establish support for those cases. Implementation follow-up: S02 closes the LB `host`, `path_prefix`, `session_header_name` and `model_name` fixed-string admission/Go-to-C defect with remote packaged-runtime evidence; it does not close the separate L7 fixed-field findings below.

Read-only audit of `/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd`, based on HEAD `f8e6ace22f0f2262d56829e781a83e4b7075fef7` plus existing working changes; eBPF HEAD `c5e468f28a2fa2acc6ea9110bfedc8de687b5fcb` plus working changes. Swagger changed concurrently during the audit, so references identify the source locations observed. No edits, tests, builds, SSH, or agents were performed. CodeGraph was used for discovery; findings were checked against this checkout.

**Reviewed scope and trace coverage**

All four L7 policy operations were traced:

| Operation | Handler/domain behavior |
|---|---|
| `POST /config/l7policy` | Model conversion → shared validation → LB lookup → synchronous C attach → registry insertion. Success `204`; validation/attach errors `400`; missing LB `404`; duplicate ID—including identical replay—or another policy for the same LB ID `409`. Generated model validation precedes the handler. |
| `GET /config/l7policy` | Registry deep copies, sorted by policy ID, serialized under `l7policyAttr`. |
| `GET /config/l7policy/id/{id}` | Registry lookup and serialization; missing ID `404`. |
| `DELETE /config/l7policy/id/{id}` | Detach when the referenced LB still exists, then remove registry entry; missing policy `404`; detach failure retains registry entry. |

Registration: [configure_loxilb_rest_api.go:127](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/configure_loxilb_rest_api.go:127). Handlers: [l7policy.go:133](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/l7policy.go:133). Registry: [l7policy.go:124](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/l7policy.go:124). Attach bridge: [apiclient.go:501](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/apiclient.go:501).

Every assigned L7 schema leaf was followed through inbound/outbound conversion and its applicable validator/C consumer:

| Schema fields | Observed source behavior |
|---|---|
| `L7Policy.id`, `name`, `lbId`, `rules`; `L7PolicyGetEntry.l7policyAttr` | ID/name stored and returned; absent ID minted; nonblank LB ID and at least one rule required. No update operation. |
| `L7Rule.position`, `matchSets[].conditions` | Position cast to C `int`, then `qsort`; OR between sets, AND within each set. Empty sets/routes do not match; unmatched requests receive `404`. |
| `L7Condition.field`, `op`, `key`, `value`, `invert` | All mapped. HEADER name lookup is case-insensitive; comparison primitives use case-sensitive string operations. Missing operand is false before inversion, so an inverted condition can match an absent field. FILE_TYPE extracts the extension without the dot. METHOD depends on `HAVE_HTTP_TRACE`. |
| `L7Action.kind`, `forward.poolId`, `forward.backendRefs[].ep`, `.weight` | All copied into IR; `poolId` is not consumed by pool resolution. References select base-pool endpoint slots; zero reference weight inherits member weight. |
| `redirect.scheme`, `host`, `port`, `pathOp`, `value`, `statusCode` | Scheme/host can derive from request; explicit default port omitted; full replacement implemented; prefix replacement is incorrect as described below. Status defaults to `302`, with the five-code allow-list. |
| `reject.statusCode` | Omitted object or zero status produces `403`; explicit REST status restricted to `400–499`. |
| `insertHeaders[].op`, `.name`, `.value` | Mapped, validated and applied through shared header-filter logic; maximum 8 filters, 63-byte names, 255-byte values. REMOVE values remain subject to validation even though emission ignores them. |
| `sessionPersistence` | REST accepts `HTTP_COOKIE`; marker reaches C cookie generation/readback. Shared validator also accepts APP_COOKIE/SOURCE_IP, but those are outside the REST enum. Its incompatibility check is policy-wide, not an actual pool-affinity lookup. |

Conversion: [handler/l7policy.go:228](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/l7policy.go:228). Validation: [common/l7policy.go:107](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/common/l7policy.go:107). C encoding: [dpebpf_linux.go:6009](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/dpebpf_linux.go:6009). Matching/actions: [sockproxy_l7policy.c:149](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_l7policy.c:149), [dispatch:730](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_l7policy.c:730), [headers:889](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_l7policy.c:889), [cookies:954](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_l7policy.c:954).

For `LoadbalanceEntry`, the reviewed non-AI field inventory is:

| Fields | Trace result |
|---|---|
| `serviceArguments.id`, `adminStateUp`, `projectId`, `connectionLimit`, `annotations` | Domain storage/lifecycle and REST mappings reviewed; missing intake/readback and lossy annotations identified below. |
| `externalIP`, `privateIP`, `port`, `portMax`, `protocol`, `block` | Handler casts → domain validation/key → LB2DP/C. `privateIP` affects dataplane addressing but is absent from normal GET reconstruction. |
| `sel`, `mode`, `security` | Enums, cross-field checks, LB2DP selection/NAT mapping and proxy TLS flags reviewed. AI selector algorithms excluded. |
| `bgp`, `managed`, `name`, `snat`, `oper`, `egress`, `proxyprotocolv2` | Handler/domain lifecycle and applicable hook/DP mapping reviewed. `snat` missing from POST; `managed` update assignment is commented out. `oper=1` behavior differs from append-only semantics. |
| `monitor`, `probetype`, `probeport`, `probereq`, `proberesp`, `probeTimeout`, `probeRetries`, `inactiveTimeOut` | Intake/readback → domain checks → probe construction or DP timeout. Probe type can force monitoring on. |
| `timeoutMemberConnect`, `timeoutMemberData`, `timeoutTcpInspect` | Intake → domain → LB2DP → C timeout consumers; GET mapping missing. |
| `host`, `path_prefix`, `path_match_mode`, `backend_protocol`, `session_header_name` | Key/config conversion and relevant proxy consumers reviewed. Shared listener identity and session-buffer issues identified below. |
| `trace_type` | Handler → stored catalog/config → LB2DP catalog mapping reviewed; capture/parser internals excluded. |
| `mtls_frontend.{client_cert_mode,client_ca_path,client_ca_cert_data,require_client_cn,client_cn_pattern,client_crl_path}` | All REST mappings, domain pointers, active mTLS encoder and C verification consumer reviewed; inline material wiring and CRL readback gaps identified. |
| `mtls_backend.{verify_server_cert,backend_ca_path,client_cert_path,client_key_path,client_cert_data,client_key_data}` | Stored and returned, but active backend configuration wiring is missing. |
| `vip_qos_policy_id` | POST → create-time policer association; update/readback/atomicity gaps identified. Policer algorithm itself excluded. |
| `alpn_protocols`, `tls_ciphers`, `tls_versions`, `hsts_max_age`, `hsts_include_subdomains`, `hsts_preload`, `backend_ca_cert_id`, `backend_client_cert_id` | Intake → domain → C fields/SSL_CTX or response consumers; normal GET mapping missing. Cert/SNI CRUD excluded. |
| `endpoints[].{endpointIP,weight,targetPort,backup,subnetId,monitorAddress}` | Intake → member storage/selection/probe target → readback. Existing-member metadata update gap identified. |
| `endpoints[].{httpMethod,urlPath,expectedCodes,httpVersion,domainName}` | Schema/model and probe-related domain facilities inspected; missing LB intake/domain-member wiring/readback. |
| `endpoints[].{state,counter}` | Derived output; not consumed as configuration. |
| `secondaryIPs[].secondaryIP` | SCTP intake → validated flat secondary-IP list → DP `pmhh`; readback present. |
| `secondaryVIPs[].{address,subnetId,portId,proto}` | Opaque storage/readback only; no SCTP consumption found. |
| `allowedSources[].prefix` | Handler → domain source-prefix association → source-check flag; readback present. |
| `offload_state`, `hw_pkts`, `hw_bytes` | Schema/model and common REST serializer reviewed; serializer does not populate them. Hardware telemetry producers excluded. |

Core LB references: [handler intake:53](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/loadbalancer.go:53), [serializer:520](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/loadbalancer.go:520), [domain intake:3518](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:3518), [domain readback:1138](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:1138), [LB2DP:6209](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:6209).

**Findings requiring implementation attention**

1. **RESOLVED S02 — LB session-name fixed-array admission and copy.**
   The original audit found an unchecked `len+1` copy into `session_header_name[128]`. S02 now rejects invalid UTF-8, embedded NUL and values above 127 encoded bytes before mutation, repeats validation at the Go-to-C boundary and uses a bounded direct copy. Exact-boundary and failure-side-effect cases pass in the packaged runtime. Session extraction behavior and restore remain separate open dimensions.
   Evidence: [S02 report](stages/S02-FIXED-CSTRING-ADMISSION.md), [rules.go](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go), [dpebpf_linux.go](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/dpebpf_linux.go).

2. **P1 — Backend verification and legacy mTLS material are not wired into the active create path.**
   `mtls_backend` is stored and queued, but `DpLBRuleSetMTLS` only encodes frontend path-based fields. `DpProxyConfigureMTLS`, which copies backend settings and inline frontend CA material, has no caller in the searched source. No assignment to active `backend_verify_cert` was found. Consequently, storing `verify_server_cert=true` is not evidence of backend certificate verification. `client_ca_cert_data` similarly does not reach the active frontend encoder.
   Evidence: [dpebpf_mtls.go:36](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/dpebpf_mtls.go:36), [active invocation:1854](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/dpebpf_linux.go:1854), [unused bridge:5713](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/dpebpf_linux.go:5713), [C verification gate:449](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_ssl.c:449).

3. **P1 — L7 admission permits silent policy truncation.**
   Shared validation does not bound match sets, conditions, backend references, condition strings, or reference weights. Conversion truncates to 8 sets, 8 conditions/set, 32 references, 63-byte keys and 255-byte values; weights narrow to `uint8`. Dropping an AND condition can broaden a match. GET returns the original registry policy, concealing the effective truncation.
   Evidence: [validation:117](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/common/l7policy.go:117), [encoding:6015](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/dpebpf_linux.go:6015).

4. **P1 — LB-ID isolation does not match L7 attachment identity.**
   The registry enforces one policy per `lbId`, but C attach identifies only VIP/port/protocol. Distinct LB rules can share that tuple while differing in host/path/block/model. Their policies can therefore replace the same attached C policy despite passing the per-LB-ID check. `privateIP` adds another mismatch: LB2DP can use translated private addressing, while L7 attach uses `lb.Serv.ServIP`. IPv6 attach is explicitly unsupported.
   Evidence: [registry check:162](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/l7policy.go:162), [LB key:3889](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:3889), [DP address:6230](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:6230), [attach key:5988](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/dpebpf_linux.go:5988), [C replacement:1197](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_l7policy.c:1197).

5. **P1 — Listener/policy lifecycle is not reconciled with LB deletion and replacement.**
   Correction to the preliminary hypothesis: C deletion keeps the listener and attached L7 state; it does not establish policy removal. On last-pool deletion it clears `arg_ptr`. Existing-listener addition returns without restoring that pointer or rebuilding listener TLS contexts. Thus a replacement can retain routes/old TLS context while losing timeout/HSTS argument access. Separately, deleting an L7 policy after its LB disappeared skips C detach, although the listener may still exist.
   Evidence: [FullProxy removal:4057](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:4057), [listener retained:912](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_conn.c:912), [argument cleared:961](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_conn.c:961), [existing-listener add:2261](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_http.c:2261), [conditional detach:206](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/l7policy.go:206).

6. **P1 — REST drops lifecycle and enforcement settings.**
   POST never copies `adminStateUp`, `connectionLimit`, or `snat`. A new rule submitted with `adminStateUp=false` reaches the domain with nil and resolves enabled. `connectionLimit` remains zero/unlimited through this intake. PATCH supports admin-state changes for L4 rules but has no connection-limit overlay.
   Evidence: [complete POST handler:53](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/loadbalancer.go:53), [domain defaults:4353](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:4353), [PATCH overlays:196](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/loadbalancer_octavia_patch.go:196).

7. **P1 — Normal GET is a lossy configuration export.**
   `serializeLBRule` omits `connectionLimit`, all three member/inspect timeouts, ALPN/TLS/HSTS settings, backend cert IDs, `vip_qos_policy_id`, and frontend `client_crl_path`. `privateIP` is missing from domain readback as well. A UI load/edit/save workflow cannot reconstruct those settings from GET.
   Evidence: [serializer:520](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/loadbalancer.go:520), [domain values available:1194](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:1194).

8. **P1 — Configured cipher failure reaches an assertion.**
   The same cipher string must pass both TLS 1.3 and TLS ≤1.2 configuration functions, even when only one protocol version is selected. Either failure returns NULL; listener creation then calls `assert(ssl_ctx)`. This is not a cleanly demonstrated REST validation failure and can terminate assertion-enabled builds.
   Evidence: [cipher validation:221](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_ssl.c:221), [assertion:2580](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_http.c:2580).

9. **P1 — H1 synthetic responses bypass the SSL write path.**
   REJECT and REDIRECT try the H2 responder, then use raw `send()` on the client FD without an H1 TLS branch. That does not establish correct encrypted H1 synthetic responses.
   Evidence: [reject:424](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_l7policy.c:424), [redirect:477](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_l7policy.c:477). Runtime impact remains untested.

10. **P1/P2 — Forward targets and redirect prefixes overstate supported semantics.**
    `poolId` is copied but ignored; references address internal endpoint slots, not arbitrary pools. Endpoint creation sorts by IP, so POST list order is not a reliable slot contract. Allocation failure in subset resolution returns the unrestricted base pool. `REPLACE_PREFIX` prepends the configured value to the whole request path rather than removing the matched prefix.
    Evidence: [sorting:3876](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:3876), [pool resolution/fallback:540](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_l7policy.c:540), [prefix implementation:690](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_l7policy.c:690).

11. **P2 — PATCH is a restricted overlay, not general merge-patch over this schema.**
    FullProxy is rejected. Many present schema fields are ignored. `probeTimeout` and `probeRetries` are checked as lowercase `probetimeout` and `proberetries`, so canonical requests miss those overlays. `serviceArguments:null` does nothing; empty/null endpoints are rejected.
    Evidence: [mode/presence handling:133](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/loadbalancer_octavia_patch.go:133), [wrong key casing:221](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/loadbalancer_octavia_patch.go:221), [empty endpoints:243](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/loadbalancer_octavia_patch.go:243).

12. **P2 — Member metadata and monitor updates are incomplete.**
    The five HTTP monitor fields are not copied by POST/PATCH/GET and are absent from the LB member construction. For an existing `(IP,port)` member, reconciliation updates weight but does not copy `backup`, `subnetId`, or `monitorAddress`. Their create-time wiring does not prove update support. Also, `oper=1` takes the same omission/removal branch as normal replacement; do not describe it as append-only.
    Evidence: [endpoint intake:279](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/loadbalancer.go:279), [member construction:3713](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:3713), [reconciliation:2523](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:2523).

13. **P2 — Structured VIPs and annotations have inaccurate fidelity claims.**
    `secondaryVIPs` is stored separately and never fed into SCTP `secIP`/`pmhh`; “SCTP consumes them” is unsupported. Annotations are limited to the first 32 sorted keys, and values are truncated to at most 256 UTF-8-safe bytes. “Stored verbatim” is therefore false for oversized input. Metadata-only updates can also hit the unchanged-rule return before metadata assignments.
    Evidence: [secondary separation:1262](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:1262), [DP flat list:6311](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:6311), [annotation truncation:1493](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:1493), [early return:4035](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:4035).

14. **P2 — Numeric narrowing and timeout bounds are missing.**
    Service/member ports narrow to `uint16`; member weights to `uint8`, without corresponding normal-field bounds. `timeoutMemberConnect` narrows unsigned milliseconds to signed `int` before `poll`; large values can become negative. Member-data rounding adds 999 in `uint32`, allowing overflow.
    Evidence: [port casts:62](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/loadbalancer.go:62), [member casts:287](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/loadbalancer.go:287), [connect cast:468](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_conn.c:468), [idle rounding:557](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_health.c:557).

15. **P2 — QoS association failure is not atomic with LB creation.**
    Association runs after LB creation/programming; its error returns without removing the created LB. The existing-rule update path returns before this association block. A failed request therefore does not establish “nothing created.”
    Evidence: [rules.go:4788](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/rules.go:4788).

16. **P2 — Validation/export claims exceed the active path.**
    Go validates REGEX with Go syntax, while C compiles POSIX extended syntax and truncates the operand to 1023 bytes. Equal positions have no defined stable tie order. The purported Gateway export guard has only test callers; POST performs no Gateway export. Header validation admits interior tabs in names that C subsequently skips, and operator filters can overwrite the synthesized `X-Forwarded-*` headers.
    Evidence: [Go regex:252](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/common/l7policy.go:252), [C regex:117](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_l7policy.c:117), [export helper:86](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/l7policy.go:86), [header ordering:889](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_l7policy.c:889).

**Documentation-only English replacement text**

These are proposed descriptions, not applied changes. Implementation warnings should remain visibly separate from the intended contract.

| Target | Replacement |
|---|---|
| L7 policy resource / POST | “Creates and attaches a policy to an existing sockproxy listener through the referenced load-balancer ID. The current attachment bridge supports IPv4. The API provides create, list, get and delete operations; it does not provide an update or Gateway API export operation. Duplicate policy IDs and a second policy for the same load-balancer ID return 409.” |
| L7 matching | “Routes are evaluated by ascending position. Match sets are OR-combined, and conditions within a set are AND-combined. Empty match sets do not match. A request matching no route receives a synthetic 404. Equal-position ordering is unspecified.” |
| `invert` | “Negates the comparison result. An absent request field is a non-match before inversion and therefore matches an inverted condition.” |
| REGEX `value` | “Patterns undergo Go regular-expression validation and POSIX extended compilation during attachment. These syntaxes are not equivalent. Dataplane matching uses bounded strings; successful admission does not establish full-length matching.” |
| `forward` | “Backend references select endpoint slots within the listener’s base pool. The current resolver does not use poolId to select another pool. A zero reference weight preserves the endpoint’s weight.” |
| `redirect.pathOp` | “NONE retains the request path; REPLACE_FULL uses the configured value. Implementation limitation: REPLACE_PREFIX currently joins the replacement value with the full request path and does not implement matched-prefix replacement.” |
| `insertHeaders` | “Applies up to eight ordered request-header operations. Header names are limited to 63 bytes and values to 255 bytes. REMOVE values are ignored when applying the operation but are still validated. The L7 path also synthesizes X-Forwarded-For, X-Forwarded-Port and X-Forwarded-Proto before applying configured operations.” |
| `sessionPersistence` | “HTTP_COOKIE enables generated-cookie affinity on matching routes. Omit to disable this route marker. The current REST API does not expose APP_COOKIE or SOURCE_IP values here and does not validate conflicts against the load-balancer’s session settings.” |
| `secondaryVIPs` | “Opaque additional-VIP metadata stored and returned for all protocols. This collection does not configure additional dataplane VIPs. SCTP secondary addressing uses secondaryIPs.” |
| `annotations` | “Opaque metadata. The current implementation retains up to 32 keys in sorted order and truncates values to at most 256 bytes without splitting UTF-8 characters.” |
| `timeoutMemberConnect` | “Backend connection timeout in milliseconds, used only when an L7 policy is attached. Zero uses 500 ms.” |
| `timeoutMemberData` | “L7 relay idle timeout in milliseconds, rounded up to whole seconds. A nonzero value overrides the existing idle deadline; zero leaves that deadline in use.” |
| `timeoutTcpInspect` | “Header-accumulation timeout in milliseconds on the L7 policy path. Zero uses 10000 ms. This field is not a general TCP inspection timeout.” |
| `alpn_protocols` | “Recognized values override backend_protocol through a shared HTTP/1.1/HTTP/2 capability setting. List order is not preserved as preference order. Unrecognized tokens are ignored by the current encoder.” |
| `tls_versions` | “Recognized versions are converted to an inclusive minimum-to-maximum range. Noncontiguous selections therefore include intermediate versions. Unknown tokens are ignored; an entirely unrecognized list falls back to default bounds.” |
| HSTS fields | “Injects HSTS on qualifying HTTPS responses when an L7 policy is attached and max age is nonzero. Zero disables injection; it does not emit max-age=0 to clear browser policy. Subdomain and preload flags affect the generated header only.” |
| Backend mTLS / cert IDs | “Implementation warning: stored backend verification and legacy path/inline-material settings are not fully wired into the active dataplane configuration path. Certificate ID resolution can fall back to system CA paths or no client certificate when material is unavailable. Do not treat successful configuration storage as proof of backend authentication.” |
| `session_header_name` | “Configures session-key extraction using a header name, cookie:NAME, query:NAME, or basic-auth. RR and persistence selection paths contain handling for this setting. The server rejects invalid UTF-8, embedded NUL and values above 127 encoded bytes before mutation; live extraction behavior remains separately qualified.” |
| PATCH operation | “Applies a restricted field overlay to an existing L4 rule. FullProxy rules and clearing all endpoints are rejected. This implementation does not apply every LoadbalanceEntry field and does not implement general recursive merge-patch semantics.” |

**UI cross-field rules**

The UI should distinguish enforced server constraints from temporary UI containment. UI validation cannot repair server-side gaps.

- Require `serviceArguments`, a valid external IP, protocol, and 1–32 endpoints for create. Validate ports before narrowing: `0–65535`; ICMP service/member ports must be zero; a nonzero `portMax` must be at least `port`.
- For DSR, require `sel=1` and endpoint target ports equal to the service port. Require TCP for `proxyprotocolv2`; require UDP for `sel=6`; `sel=5` requires FullProxy. Keep reserved `sel=7` unavailable.
- For `mode=5`, require an unspecified VIP. Treat `security=0` as “no proxy TLS,” not as a statement that every L4 service speaks HTTP.
- Explicit TCP/UDP/SCTP/HTTP/HTTPS probes require a nonzero `probeport`; ping/none require zero. A nonempty probe type other than none forces monitoring on. Inactivity zero resolves to 240 seconds for TCP/SCTP and 20 seconds otherwise; maximum is 86400.
- Expose L7 attachment only for an eligible IPv4 sockproxy listener, and flag shared VIP/port/protocol LB rules as unsafe until attachment ownership is resolved.
- Require unique, C-int-range positions; nonempty usable match sets; at most 8 sets, 8 conditions/set and 32 references. Enforce 63/255-byte condition string limits and reject embedded NULs. These are containment rules for current truncation, not proof that the API rejects oversized policies.
- Require keys for HEADER/COOKIE/QUERY; restrict FILE_TYPE operations; require the matching action object. Reject extraneous action objects in the UI because the server does not enforce a strict exclusive union.
- Disable claims of arbitrary-pool forwarding and correct `REPLACE_PREFIX`. Do not derive `ep` indices from the user’s original POST ordering.
- Restrict header operations to valid HTTP token names, byte bounds, and valid values. Clearly flag attempts to modify synthesized forwarding headers.
- Limit `session_header_name` to 127 UTF-8 bytes. Require a nonempty name after `cookie:` or `query:`. Present it only on the qualified proxy/selector combinations; do not market it as authentication.
- Gate frontend mTLS on FullProxy plus security 1/2, backend TLS settings on FullProxy plus security 2, and actual mTLS build capability. These combinations are not fully enforced by current admission.
- Do not show “verification enabled,” “connection limit enforced,” or “saved and restored” solely from a successful POST. Missing intake/readback fields need explicit unavailable/implementation-gap states.
- Disable PATCH for FullProxy and unsupported fields. Preserve canonical `probeTimeout`/`probeRetries` names; do not normalize the handler’s casing bug into a new API contract.
- Treat `state`, `counter`, lifecycle status and hardware counters as output-only in the UI. `projectId` filtering is a convenience filter, not tenant authorization.
- Keep backup/monitor-address editing unavailable or visibly unqualified for existing members until reconciliation is corrected.

**Policy decisions needed**

1. Is L7 policy ownership per LB resource, per host/path pool, or per physical listener tuple? Define collision handling and deletion/recreation behavior.
2. Should oversized policies, unknown TLS/ALPN tokens and unknown cert IDs fail admission? Silent truncation/fallback should not become the intended security contract by documentation.
3. Must backend verification fail closed when requested? Define material precedence between cert IDs, filesystem paths and inline fields, including missing-material behavior.
4. Which LB fields are mutable through POST versus PATCH, and which require listener/TLS-context reconstruction?
5. Is `oper=1` intended to preserve unspecified members? Are `backup`, subnet and monitor-address changes supported in place?
6. Should `poolId` identify a real independent pool, and should endpoint references use stable IDs rather than internal slots?
7. What is the intended no-match response, equal-position policy, REGEX syntax and catch-all representation?
8. May operators override `X-Forwarded-*`, and how should HTTP_COOKIE interact with LB session-header/IP affinity?
9. Should structured additional VIPs remain metadata or become active addresses? What are their validation and size bounds?
10. Is a failed QoS-associated LB create required to roll back the LB, or should the API return explicit partial-creation status?

**Unreviewed / evidence limits**

Excluded: AI P/D, KV, CHWBL/GPU/WRR-hash algorithms and related AI fields, API-key/SSE/circuit-breaker behavior, cert/SNI CRUD, external Octavia/Gateway controllers, snapshot/restore execution, full authentication middleware, BGP protocol internals, complete NAT/SCTP algorithms, hardware telemetry producers, and tracing parser internals. LB delete variants were inspected for key/lifecycle mapping; their entire generated response matrices were not exhaustively audited.

No runtime, TLS handshake, traffic, persistence, HA, Linux build, or conformance result is asserted. The sc-analyze/sc-document skills guided source tracing and the English replacement text; none of these findings were “fixed” through prose.
