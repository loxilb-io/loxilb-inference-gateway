# Operations and observability audit

## Checkpoint and evidence boundary

Stopped exploration. **No files edited, tests/builds executed, SSH used, or subagents launched.**

Reviewed checkout: `/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd`, HEAD `f8e6ace22f0f2262d56829e781a83e4b7075fef7` plus WIP. WIP changed externally during review; this is **not an immutable whole-checkout snapshot**.

Coverage reached **50 Swagger paths, 58 operations, and their 55 referenced definitions**, including inline request/response schemas. Review followed routing → handler → relevant validation/state/consumer code. This is **static contract evidence, not runtime qualification or closure of every subsystem gap**.

The most consequential findings are unsafe legacy-import shape handling, metadata constraints/extensions being dropped, parser discovery/assignment identifier mismatch, placeholder tracing statistics and conversation cleanup, unsupported GPU-toggle routing claims, and misleading metrics semantics.

## 1. Complete operation inventory

Paths are relative to `/netlox/v1`. Every entry below was reviewed. “Unwired” means the generated route remains on its default not-implemented handler.

```text
POST          /config/import
GET           /config/export
GET           /config/snapshot
POST          /config/restore
POST          /config/persist
GET           /meta

POST          /config/trace/enable
POST          /config/trace/disable
GET           /config/trace/status
GET, POST     /config/trace/otlp
GET           /config/trace/catalogs                         [unwired]
GET           /config/trace/parsers
GET, PUT,
  DELETE      /config/trace/catalog/{catalog_id}/parser

POST          /config/l4trace/enable
POST          /config/l4trace/disable
GET           /config/l4trace/status
PUT           /config/l4trace/sampling
POST          /config/l4trace/stats/reset

GET           /status/process
GET           /status/device
GET           /status/filesystem
GET           /status/ready
GET, PUT      /maintenance
GET           /diagnostics
GET, POST     /config/params

GET           /metrics
GET, POST,
  DELETE      /config/metrics
GET           /metrics/flowcount
GET           /metrics/hostcount
GET           /metrics/lbrulecount
GET           /metrics/newflowcount
GET           /metrics/requestcount
GET           /metrics/errorcount
GET           /metrics/processedtraffic
GET           /metrics/lbprocessedtraffic
GET           /metrics/epdisttraffic
GET           /metrics/servicedisttraffic
GET           /metrics/fwdrops
GET           /metrics/reqcountperclient

POST          /config/gpu/enable
POST          /config/gpu/disable
GET           /config/gpu/status
POST          /config/gpu/conversations/cleanup
GET, POST     /config/worker/metrics

GET           /logs
GET           /log-archives
GET           /log-archives/{filename}
GET           /nodegraph/all                                 [unwired]
GET           /nodegraph/{service}                           [unwired]
GET           /version
```

All twelve JSON metrics operations are explicitly wired at [configure_loxilb_rest_api.go:370](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/configure_loxilb_rest_api.go:370). Their `x-not-implemented: true` annotations are stale.

Catalog-list and nodegraph defaults remain `middleware.NotImplemented` at [loxilb_rest_api_api.go:361](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/operations/loxilb_rest_api_api.go:361) and [loxilb_rest_api_api.go:652](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/operations/loxilb_rest_api_api.go:652). Their descriptions must not promise usable results; the response contracts omit 501.

## 2. Findings and English replacement guidance

Categories: **doc-defect** = documentation contradicts source; **implementation-gap** = missing/broken implementation, not a behavior to endorse; **policy-needed** = intended contract requires an owner decision.

### A. Metadata extraction — extension passthrough is NOT implemented

**Doc-defect / implementation-gap if UI depends on these constraints.**

`/meta` selects **one operation per path**, prioritizing POST over PUT over PATCH. It is not an inventory of all methods or only required POST fields.

Crucially:

- Root and operation extensions are discarded by typed `SwaggerDoc`/`Operation` loading.
- Definition and inline-schema maps retain arbitrary keys during normalization, **but `processSchema` does not pass arbitrary extensions through to the response**.
- Therefore the newly observed root `x-loxilb-contract-relations` is **not exposed by `/meta`**.
- Minimum, maximum, default, pattern, additional-property constraints and cross-field relationships are not generally emitted.
- Primitive query/path/form parameters emit only `type` and `required`.
- Object flattening also loses some enclosing object type/required semantics.
- Primary Swagger wins over extras for overlapping definitions and methods.
- Extraction errors are logged, but the handler still returns its 200 responder.

Evidence: [metadata.go:34](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/metadata.go:34), [metadata.go:149](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/metadata.go:149), [metadata.go:163](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/metadata.go:163), [metadata.go:235](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/metadata.go:235).

**Replacement:**

> Returns simplified input-field metadata derived from the embedded main and supplemental Swagger documents. One operation is selected per path, preferring POST, then PUT, then PATCH. The result is advisory: it does not preserve all validation keywords, vendor extensions, authentication requirements, or cross-field rules.

UI must consume the full contract/relationship document separately; adding extensions alone does not implement a UI validator.

### B. Legacy import can reach destructive restore without validating a legacy document’s shape

**Implementation-gap; high priority.**

The file parameter is optional in Swagger but required by the handler. Recognized snapshots are accepted; other JSON is unmarshaled into the legacy dump structure without requiring recognizable configuration fields. Empty objects, and JSON null, can become a snapshot covering five empty domains and reach commit processing. That creates a destructive replacement path; this is not an approved “clear configuration” feature.

Import always commits, returns a `RestoreResult` rather than the declared `OperationResult`, and has additional 400/409/500 outcomes.

Evidence: [backup.go:133](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/backup.go:133), [backup.go:169](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/backup.go:169).

**Replacement, accompanied by an explicit implementation warning:**

> Deprecated multipart import operation. A configuration file is required. Recognized snapshot documents and supported legacy dumps are converted into a committed restore; this operation has no dry-run mode. Use POST /config/restore for preview and explicit commit control.

Do not resolve the shape-validation gap through wording alone.

### C. Export/snapshot coverage and version are stale

**Doc-defect; cluster-only selection is policy-needed.**

Snapshot schema is **1.5**, not 1.0. Current domains are:

`endpoint, loadbalancer, kvexactbinding, l7policy, firewall, policy, mirror, session, sessionulcl, ipfilter, securityrate, bfd, bgp, ipsec, cors, tracing, cert`.

Export delegates to the snapshot engine, adds deprecation headers, and ignores legacy `cluster`. A cluster-only selection becomes empty after filtering, which means all snapshot domains—an unexpected widening requiring policy.

Evidence: [doc.go:87](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/snapshot/doc.go:87), [backup.go:77](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/backup.go:77).

**Replacement:**

> Downloads a versioned, checksummed configuration snapshot. Omitted or empty components selects all supported snapshot domains. Coverage is reported by included_domains and excluded_domains; external secrets and runtime-only state are not a complete part of the snapshot.

For export, prepend “Deprecated compatibility wrapper for GET /config/snapshot.”

### D. Restore preview, replacement, and persistence need separate UI states

**Doc-defect / policy-needed.**

Dry-run validates document structure, checksum, compatibility, coverage and required dependencies, and produces a plan. It does **not execute all domain apply-time validation**.

- `compatible` is not “safe to apply”; it concerns schema compatibility.
- Selected domains are wiped/reapplied, not merged.
- Plan counts are delete/apply quantities, not a minimal diff.
- Required dependencies are checked across the document manifest before component selection.
- Commit failure can roll back or return `ROLLBACK-FAILED`.
- A successful apply can return HTTP 200 with `persisted:false`; write-through failure does not undo the applied configuration.
- `persisted` is absent for dry-run and unsuccessful commits; absence is not equivalent to false.

Evidence: [restore.go:400](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/snapshot/restore.go:400), [restore.go:612](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/snapshot/restore.go:612), [snapshot.go:198](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/snapshot.go:198).

**Replacement:**

> Defaults to dry-run, which performs pre-apply checks and reports the planned replacement of selected domains. A successful preview does not guarantee apply-time success. Explicit commit applies and verifies the configuration, attempts rollback on failure, and separately reports whether the resulting state was persisted.

### E. Persist does not make every successful mutation durable

**Doc-defect.**

Persistence covers snapshot domains, not every runtime setting. Auto-persist is asynchronous/debounced and configurable. Metrics enablement, log level, GPU mode, maintenance and trace/parser/L4 diagnostic overrides are not recovered through the snapshot.

OTLP configuration belongs to the tracing snapshot domain, but authentication header values remain node-local.

Evidence: [lifecycle.go:230](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/snapshot/lifecycle.go:230), [snapshot.go:510](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/snapshot.go:510), [persist.go:64](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/snapshot/persist.go:64).

**Replacement:**

> Atomically writes supported snapshot configuration to snapshot.json with mode 0600. Inspect included_domains, excluded_domains, external_dependencies, checksum and generation to determine the saved coverage and identity. Runtime-only settings and externally stored secrets are not made durable by this operation.

### F. Auth, maintenance and readiness errors are not one uniform contract

**Doc-defect.**

Within this scope, `/meta`, `/metrics`, and `/version` bypass management authentication. Other operations depend on configured authentication mode; authenticated viewers are GET-only, while administrators can mutate.

The freeze middleware precedes operation authentication:

- GETs bypass its mutation freezes.
- Boot unsettled can reject all mutations with 503.
- Restore freeze also blocks maintenance changes.
- Operator maintenance exempts restore/persist/maintenance, **not legacy import**.
- Therefore `cancellable:true` does not guarantee a leave request can pass every gate.
- `/status/ready` 503 may be a readiness body or an authentication/store error.
- Readiness/maintenance/diagnostics Swagger still omits applicable authorization/error alternatives.

Evidence: [auth.go:47](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/auth.go:47), [authz.go:112](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/authz/authz.go:112), [snapshot.go:71](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/snapshot.go:71).

**Replacement for `cancellable`:**

> The maintenance gate itself permits leaving maintenance. Independent boot or restore freezes, authentication and authorization may still reject the request.

Do not label every 503 “maintenance” or every 403 “capacity insufficient.”

### G. Readiness and diagnostics overstate live verification

**Doc-defect; redaction assurance needs implementation review.**

Readiness is configuration-recovery readiness—not inference readiness, GPU readiness, or complete datapath health. Maintenance and informational attachment failures do not directly gate it.

Some dependency “live” checks return success from configured/builtin state rather than probing an external service or certificate files. Diagnostics exposes cached map counts and includes raw boot, dependency and auto-persist error strings in nested fields/reasons. Therefore a universal “never connection strings” guarantee is not established.

Evidence: [opstate.go:139](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/snapshot/opstate.go:139), [recoverydeps.go:170](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/recoverydeps.go:170), [diagnostics.go:58](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/diagnostics.go:58).

**Replacement:**

> Reports configuration-recovery readiness and supporting observations. Dependency checks vary by dependency type; attachment observations and cached map utilization are informational. This verdict does not establish successful inference or end-to-end datapath operation.

Diagnostics normally returns 200 even when its embedded `ready` is false.

### H. Maintenance semantics mostly match, but it is not traffic draining

**Doc-defect clarification.**

`enabled` is required. Omitted/zero timeout means no deadline. Repeat enter preserves the original timeout, operation ID and start time; changing timeout requires leave/re-enter. Deadline expiry does not automatically exit maintenance. Only SSE streams are counted; new inference refusal is explicitly false.

Evidence: [maintenance.go:70](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/maintenance.go:70), [maintenance.go:101](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/maintenance/maintenance.go:101).

**Replacement:**

> Controls an ephemeral management-write maintenance episode. It does not itself refuse new inference traffic. Drain fields report open SSE streams and elapsed time, not completion of all requests.

### I. Process/device/filesystem and params descriptions need correction

**Doc-defect; process parsing has an implementation-gap.**

Process information combines `top` with CPU/memory values from `ps`. An unguarded `[7:]` slice can panic when `top` fails or emits short output. Rows require exactly twelve fields.

Device information reads Linux files directly; uptime is raw `/proc/uptime` content, including both values, not a formatted duration. `/proc/version_signature` is distribution-dependent. Filesystem sizes are human-readable `df -hT` strings; `size` incorrectly says “Boot ID.”

Params POST sets one runtime log level; it is not resource creation. GET has no observed 204 branch.

Evidence: [status.go:29](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/apiutils/status/status.go:29), [status.go:95](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/apiutils/status/status.go:95), [params.go:27](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/params.go:27).

**Replacements:** “Returns Linux process observations assembled from top and ps”; “Raw Linux device-identification fields”; “Filesystem capacity as a human-readable df value”; “Sets the runtime logging level.”

### J. HTTP tracing status and success responses are misleading

**Implementation-gap / doc-defect.**

Tracing status uses a C statistics stub returning zeros. Advertised event totals and ring utilization therefore are not functioning measurements. Runtime output also includes undeclared `otlp_use_tls` and `otlp_tls_verify`.

Enable/disable and several OTLP failure branches return `ResultResponse`, which does not set an error status; failure messages can arrive with HTTP 200.

Evidence: [configure_trace.go:37](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/configure_trace.go:37), [configure_trace.go:194](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/configure_trace.go:194), [common.go:45](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/common.go:45).

**Replacement:**

> Reports tracing enablement and exporter configuration. Event-counter and ring-utilization reporting is currently incomplete and must not be interpreted as measured zero traffic.

Retain a separate implementation issue for incorrect HTTP success statuses.

### K. OTLP POST replaces configuration; redacted GET is not round-trippable

**Doc-defect / implementation-gap.**

Endpoint and protocol are required. Omitted TLS fields reset to true/false defaults; omitted headers clear the header map. `tls_skip_verify` has no effect when TLS is disabled.

Header validation permits at most twenty entries, restricts names, rejects CR/LF and limits values to 1024 bytes. Endpoint validation does not perform the claimed DNS lookup or a complete numeric port-range check.

GET returns redaction/reprovision markers, not reusable credentials. `connected` tracks export outcomes rather than an active connectivity probe.

Configuration changes precede secret persistence/reconnection, so failure can leave partial state.

Evidence: [configure_trace.go:310](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/configure_trace.go:310), [configure_trace.go:389](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/configure_trace.go:389), [lxb_otlp_exporter.go:38](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/lxb_otlp_exporter.go:38).

**Replacement:**

> Replaces the OTLP exporter configuration. Supply the complete desired header map; omitted headers are cleared. Header values returned by GET are redacted and must not be submitted as credentials. Connection status reflects recorded export outcomes, not a fresh reachability test.

### L. Parser discovery cannot safely populate assignment options

**Implementation-gap; UI-breaking.**

Discovery returns metadata names `openai_v1`, `mcp_v1`, `mock_parser`; assignment uses registry keys `openai`, `mcp`, `mock`. `description` and `capabilities` are declared but not populated.

PUT validates the parser, not existence of the catalog. GET maps all mapping-lookup errors—including unavailable tracing—to 404, and can return a mapping without catalog metadata. DELETE succeeds when a mapping is absent. PUT success has **an empty body**, despite its `PostSuccess` schema.

Evidence: [dpebpf_linux.go:5624](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/dpebpf_linux.go:5624), [lxb_ring_consumer.go:287](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/lxb_ring_consumer.go:287), [trace_parser.go:104](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/trace_parser.go:104).

Catalog IDs are assigned from sorted loaded catalogs, not durable identities. YAML `catalog_name`, not filename, supplies the name. YAML body-size zero defaults to 16384 bytes, not unlimited; maximum is 10 MiB. Catalog-list remains unwired.

**Replacement:**

> Sets a runtime catalog-to-parser override using a registered assignment key. The override is not a YAML edit or persistent catalog identity. Discovery metadata names currently differ from assignment keys; clients must not use them interchangeably.

### M. L4 statistics and sampling promises exceed implementation

**Implementation-gap / doc-defect.**

Enable with absent body/field defaults sampling to 100; explicit zero is retained. Sampling PUT preserves enablement. Disable resets sampling to 100.

REST statistics read C globals; the inspected source has no call sites updating those globals. Actual Go consumer counters are separate. Reset clears the C statistics, not the Go consumer counters.

Kernel sampling includes cached decisions and special handling for uncached close/reset/error events; “same connection always gets the same decision” is too broad. Disable does not guarantee all in-flight spans complete. Builds without L4 tracing may return default-looking status while mutations fail.

Evidence: [lxb_l4_trace_config.go:148](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/lxb_l4_trace_config.go:148), [lxb_l4_trace.c:90](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/liblxb/lxb_l4_trace.c:90), [lxb_l4_ring_consumer.go:576](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/lxb_l4_ring_consumer.go:576), [llb_kern_ct.c:116](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/kernel/llb_kern_ct.c:116).

**Replacement:**

> Controls runtime L4 event emission and sampling. Availability depends on the build and loaded datapath maps. Current REST statistics/reset wiring is incomplete; returned counters do not establish measured event or loss totals.

### N. GPU cleanup is a placeholder; toggle does not prove routing changes

**Implementation-gap / policy-needed.**

Conversation cleanup ignores its computed cutoff and returns zero counts without deleting mappings.

Enable/disable manipulates a runtime flag, maps and cleanup thread. No source consumer was found connecting `routing_mode_map` to the claimed global GPU-aware/CHWBL switch. Per-service GPU selection and scraper-fed proxy scoring are separate paths.

Enable/disable are non-idempotent: already-in-state yields 400. Disable closes the cleanup channel before map update; a map-write failure leaves enablement true, so retry can close an already-closed channel.

Status `ebpf_map_loaded` checks only one map FD; worker count includes cached entries. Uncompiled mode returns `routing_mode:"disabled"`, absent from the description.

Evidence: [dpebpf_linux.go:4922](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/dpebpf_linux.go:4922), [dpebpf_linux.go:5126](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/dpebpf_linux.go:5126), [sockproxy_pd.c:2018](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/loxilb-ebpf/common/sockproxy_pd.c:2018).

**Replacement:**

> Controls the runtime GPU-monitoring facility. Success does not independently verify effective per-service routing behavior.

Cleanup must be explicitly marked unimplemented, not described as successfully deleting stale conversations.

### O. Worker telemetry replacement, identity and bounds are underspecified

**Implementation-gap / doc-defect.**

POST requires endpoint, queue and KV percentage; omitted optional counters become zero. Omitted/zero timestamp becomes now; samples over ten seconds old are rejected, but future timestamps have no upper bound.

Counters are cast from int64 to uint32 without corresponding maxima. Worker keys retain supplied strings, while GPU indexing strips the final colon suffix and uses IP-like identity: different ports can alias the map. Endpoint existence is not validated. Cache updates happen before map writes, permitting partial state on failure.

Builtin scraping stores **waiting requests**, contradicting the schema’s “running + waiting.” GET never assigns `monitoring_enabled`.

Evidence: [worker_metrics.go:200](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/worker_metrics.go:200), [dpebpf_linux.go:5163](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/dpebpf_linux.go:5163), [ai_vllm_scraper.go:155](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/pkg/loxinet/ai_vllm_scraper.go:155).

**Replacement:**

> Submits a complete worker telemetry sample, not a partial update. Omitted optional counters become zero. A successful response confirms ingestion, not endpoint registration or a verified routing decision.

Queue meaning, safe bounds, endpoint identity and future-clock tolerance need explicit policy.

### P. Metrics names do not consistently mean HTTP requests or rates

**Doc-defect.**

- `/metrics` is an unauthenticated Prometheus scrape, not JSON; disabled exporter returns plain-text 503.
- Config metrics POST/DELETE are idempotent runtime toggles, not create/delete of a metric resource.
- JSON endpoints read cached shared metrics without enforcing exporter enablement or freshness.
- `requestcount` counts observed conntrack flows, not HTTP requests.
- `newflowcount` is an observed collection-cycle quantity, not a rate.
- `errorcount` observes conntrack error states, not HTTP error responses.
- Processed traffic accumulates datapath rule-counter deltas; interaction breakdowns remain sampled conntrack-derived.
- `reqcountperclient` sums interaction **packets**, not requests.
- Firewall JSON values reflect current rule cumulative counters; they can fall when rules disappear/reset.
- Optional numeric fields may disappear at zero because of `omitempty`.

Evidence: [prometheus.go:39](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/prometheus.go:39), [metric.go:26](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/metric.go:26), [prometheus.go:990](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/prometheus/prometheus.go:990), [prometheus_sm.go:472](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/prometheus/prometheus_sm.go:472).

**Replacement pattern:**

> Returns cached [precise quantity and units] from [collector/source]. Values may be stale or unavailable when collection is disabled or has not completed. This is not an HTTP request counter or instantaneous rate.

Remove the twelve stale unimplemented markers; do not substitute availability assumptions for missing values.

### Q. Logs have pagination and resource-limit gaps

**Doc-defect / implementation-gap.**

`lines` is an unconstrained string: malformed/nonpositive values can produce an empty successful page; no maximum exists. Filters are case-sensitive substrings combined with AND.

Cursor use requires keeping `file`, level and keyword consistent. Cursor filename does not select the file; mismatch/truncation may silently restart at the tail. Gzip offsets refer to decompressed bytes, and each request decompresses again, capped at 64 MiB.

The advertised 32 MiB scan cap is checked between batches; reading a long line can exceed it. `scanned_bytes` is not an exact physical I/O counter.

Archive listing includes active `.log` files, not only rotated archives. Missing downloads currently return 500 rather than advertised 404.

Evidence: [log.go:196](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/log.go:196), [log.go:308](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/log.go:308), [log.go:451](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/log.go:451), [log.go:681](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/log.go:681).

**Replacement:**

> Returns matching nonblank log lines newest-first. Continue with next_cursor and the same explicit file and filters. has_more means further matches may exist. Archive cursors address the uncompressed stream.

Keep strict resource bounds and missing-file status correction as implementation issues.

### R. Nodegraph/version and shared envelopes

**Doc-defect / implementation-gap.**

Nodegraph is unwired. Dormant code also drops `meta` while converting the result and can emit duplicate interaction-derived edge IDs; wiring alone would not qualify the advertised topology contract.

Version is public build identity; `VersionGetEntry.version` incorrectly describes an instance name.

`OperationResult.result` is a free-form message, not a reliable success discriminator. `Error` fields are optional and different handler paths populate different subsets. Correlation-reference sanitization is not universal across all 500 responders.

Evidence: [nodegraph.go:65](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/nodegraph.go:65), [prometheus_sm.go:505](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/prometheus/prometheus_sm.go:505), [common.go:95](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/common.go:95).

**Replacements:** “Not implemented by the current router configuration”; “Gateway version string”; “Operation-specific outcome message; not a standardized success code.”

## 3. Definition coverage

All fields in these **55 referenced definitions** were read and compared with their relevant writers/validators or, for unwired operations, dormant producers. This does not imply every underlying subsystem was exhaustively validated.

| Area | Definitions reviewed |
|---|---|
| Snapshot/recovery | `RestorePlanItem`, `RestoreResult`, `PersistResult`, `ExternalDependencyStatus`, `ConfigOpRecord`, `BootStatus`, `AutoPersistStatus` |
| Readiness/diagnostics | `ReadyStatus`, `DiagnosticsStatus`, `DependencyDiagnostic`, `EbpfAttachmentStatus`, `MapUtilization` |
| Maintenance | `MaintenanceRequest`, `MaintenanceStatus` |
| System/params/version | `ProcessStatus`, `ProcessInfoEntry`, `DeviceInfoEntry`, `FilesystemStatus`, `FileSystemInfoEntry`, `OperParams`, `VersionGetEntry` |
| Shared envelopes | `OperationResult`, `Error`, `PostSuccess` |
| Tracing | `TraceCatalogEntry`, `TraceParserInfo`, `CatalogParserMapping`, `TraceParserUpdate`, `L4TraceStats`, `L4TraceStatusResponse` |
| GPU/worker | `GPUMonitoringStatus`, `GPUEnableResponse`, `WorkerMetricsEntry`, `WorkerMetricsResponse`, `WorkerMetricsUpdateResponse`, `ConversationCleanupResponse` |
| Metrics | `MetricsConfig`, `FlowCountMetrics`, `HostCountMetrics`, `LbRuleCountMetrics`, `NewFlowCountMetrics`, `RequestCountMetrics`, `ErrorCountMetrics`, `ProcessedTrafficMetrics`, `LbProcessedTrafficMetrics`, `EpDistTrafficMetrics`, `ServiceDistTrafficMetrics`, `FwDropsMetrics`, `ReqCountPerClientMetrics` |
| Logs | `Logs`, `LogArchives`, `LogArchiveInfo` |
| Nodegraph | `NodeGraphShcmea`, `Node`, `Edge` |

Inline coverage includes restore’s opaque object body; metadata’s open object response; HTTP tracing status; OTLP request/readback/header maps; L4 sampling bodies; parser-list wrapper; action result envelopes; and file/string download responses.

## 4. Explicit UNREVIEWED / unresolved ownership

- **Runtime verification: entirely UNREVIEWED.** No HTTP requests, authentication exercises, Linux command execution, datapath loading, trace export, GPU routing, persistence/reboot, restore rollback, or log-pagination execution was performed.
- **Snapshot domain internals:** networking, main LB, security, IPsec and extras domain validators/consumers remain with their assigned owners. Restore orchestration was reviewed; every nested domain field and hook was not re-audited here.
- **Native trace/parser internals:** protocol parsing correctness, redaction correctness, complete span lifecycle/export behavior and every build-flag combination remain UNREVIEWED.
- **GPU routing linkage:** no consumer establishing the toggle’s global routing claim was found. Full selector semantics remain a handoff to the main-LB owner, not a proven runtime failure or success.
- **Generated contract synchronization:** complete byte-for-byte WIP Swagger/embedded-spec/generated-model parity was not established.
- **All Prometheus families/PromQL/dashboard semantics:** not part of this checkpoint; scoped REST metrics producers were reviewed.
- **`UpdateLicenseRequest`: supplemental review completed, ownership unresolved.** It is referenced by `/auth/token/upgrade`, not orphaned. Handler writes `license_key` as the manual token and echoes it; it does not validate a license entitlement. Assign to the authentication/security owner. Evidence: [auth.go:267](/Users/gongseoghwan/go/src/loxilb-inference-gateway-ai-multitier-cicd/api/restapi/handler/auth.go:267).
- **Unreferenced definitions:** `MetricEntity` and Swagger `HealthCheckResponse` were inspected; no scoped live REST producer was found. Decide retain/remove ownership. The similarly named protobuf health response is a different type.
- **`K8sConntrackEntry`: explicitly UNREVIEWED**, networking ownership; unreferenced by current main Swagger.
- **`/config/metrics/all`: not a current Swagger/routed operation.** Old generated artifacts do not establish a served endpoint.
- **New external WIP audit artifacts/extensions:** their full correctness and UI consumption remain UNREVIEWED. Only the observed `/meta` non-passthrough behavior is established here.

**Checkpoint disposition:** scoped inventory and actionable static findings delivered; implementation gaps remain open. No description edits are authorized or performed yet.
