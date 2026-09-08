# Raw middleware contract audit

Audit completed in an isolated campaign worktree at HEAD `f8e6ace22f0f2262d56829e781a83e4b7075fef7` plus the local WIP. All findings below are **static source findings**, not runtime verification. No files were edited, tests/builds run, SSH used, or agents started.

The most consequential issues are ineffective OPA `fail_open`, incomplete SSRF protection, DPU filters that do not implement their documented identities, malformed hardware-counter identity parsing, and non-atomic API-key PATCH updates.

Reviewed scope: the entire 613-line extras file, read in three chunks; **5 paths, 8 operations, 4 named definitions**, including every nested property and inline request/response schema.

| Path, relative to `/netlox/v1` | Operations | Extras lines |
|---|---|---|
| `/config/ai/kv/inventory` | GET | 41–108 |
| `/config/dpu/debug` | GET, POST | 110–220 |
| `/config/dpu/hwcounters` | GET | 222–270 |
| `/config/opa/watcher` | GET, POST, DELETE | 272–394 |
| `/config/ai/apikey/{key_id}` | PATCH | 396–451 |
| Definitions | `RawError`, `ManagementError`, `SimpleError`, `DpuDebugResponse` | 453–613 |

Classification: `doc-defect` means source-supported documentation/schema correction; `implementation-gap` means implementation cannot substantiate the promised behavior; `policy-needed` means the intended contract requires a decision. P1 indicates substantial security, correctness, or integration impact; P2 indicates material contract ambiguity or incomplete observability.

1. **P1 · doc-defect — Management authentication is absent from the machine-readable extras contract.**

   Extras declares neither `securityDefinitions` nor `security`, despite all eight operations passing through `RequireManagementAuth`. Listing 401/403 responses does not describe how clients authenticate.

   The credential is the management `Authorization` header, conventionally `Bearer <token>`. Data-plane API keys are not management identities. In role-bearing modes, `viewer` may execute these GET operations; mutations require `admin`. Manual-token principals are unrestricted after validation. With all authentication modes disabled, no credential is required. Thus KV’s “admin endpoint” wording must not imply an admin-only role restriction.

   Evidence: [raw dispatch and authentication](../../api/restapi/configure_loxilb_rest_api.go:603), [credential validation](../../api/restapi/handler/auth.go:191), [role rules](../../pkg/authz/authz.go:112), [authentication-disabled behavior](../../api/restapi/handler/auth.go:55).

   Proposed shared English description:

   > “Management-plane endpoint. When management authentication is enabled, supply the management credential in the Authorization header as Bearer <token>. In role-based modes, viewers may read and administrators may modify these resources. Data-plane API keys are not management credentials. Authentication-disabled deployments do not require a credential.”

   Add the existing primary spec’s `BearerAuth` header scheme and security requirement, with the deployment-mode caveat above.

2. **P2 · doc-defect — Three 503 responses declare the wrong envelope coverage.**

   KV GET and DPU debug GET/POST declare only `SimpleError` for 503. Authentication can return 503 **before** those handlers, using `ManagementError`.

   Required coverage:

   | Operation | Handler-level 503 | Authentication-level 503 |
   |---|---|---|
   | KV GET | `{"error":"kv inventory provider not registered"}` | Management envelope |
   | DPU debug GET | Filtered path: `{"error":"DPU manager not initialized"}` | Management envelope |
   | DPU debug POST | `{"error":"DPU manager not initialized"}` | Management envelope |
   | Hardware counters GET | None | Management envelope |
   | OPA GET/POST/DELETE | None | Management envelope |
   | API-key PATCH | `{"error":"ai_key_store_unconfigured"}` or `ai_key_store_unavailable` | Management envelope |

   PATCH already uses `RawError` appropriately for this dual shape. Apply equivalent coverage to the first three operations.

   Evidence: [authentication store failure](../../api/restapi/handler/auth.go:79), [authentication envelope](../../api/restapi/handler/auth.go:228), [API-key store envelopes](../../api/restapi/handler/ai_apikey.go:45).

3. **P2 · doc-defect — The preamble incorrectly states that all extras endpoints are absent from `swagger.yml`.**

   OPA GET/POST/DELETE already exist there as `x-raw-middleware: true` stubs. Actual dispatch still reaches the raw handlers first. The extras preamble at lines 20–23 contradicts the checked-out source and obscures the duplicate contract.

   Evidence: [OPA generated-spec stubs](../../api/swagger.yml:7700), [middleware precedence](../../api/restapi/configure_loxilb_rest_api.go:603).

   Replacement:

   > “This companion specification documents handlers dispatched directly by global middleware. These requests bypass generated request binding and validation. Some operations, including the OPA watcher operations, also have marked stubs in swagger.yml; this document describes their raw-handler contract.”

4. **P2 · doc-defect — Unsupported methods return plain text; OPTIONS is a separate exception.**

   KV, DPU debug, hardware counters, and OPA use `http.Error(..., 405)`, producing a plain-text body such as `Method not allowed\n`, rather than a JSON error envelope. Global `produces: application/json` does not describe this exception.

   Authentication runs before the method rejection. OPTIONS returns empty HTTP 200 before authentication or handler dispatch. PATCH’s other methods are delegated to the generated API; they must not be described as universally rejected by this raw handler.

   Evidence: [KV method guard](../../api/restapi/handler/ai_kv_inventory.go:75), [DPU method dispatch](../../api/restapi/handler/dpu_debug.go:260), [OPA dispatch](../../api/restapi/handler/opa_watcher.go:66), [OPTIONS handling](../../api/restapi/configure_loxilb_rest_api.go:576).

5. **P2 · doc-defect — KV input bounds and inventory-registration dependency are incomplete.**

   `service_id` is parsed as base-10 uint32: **0–4294967295**. Both query parameters are required in practice because missing/empty values fail parsing. `ep_idx` uses signed Go `int` parsing; there is no explicit nonnegative check. A negative parseable value reaches inventory lookup and normally produces 404, rather than a bounds-specific 400.

   Importantly, 404 means no registered KV service/inventory for the pair; it does not prove the load-balancer service or endpoint itself is absent. Subscribers are created selectively: mode 1 targets prefill endpoints, while single-role mode uses its selected endpoint targets. The service ID comes from `r.ruleNum`, not the opaque load-balancer ID.

   Evidence: [query parsing](../../api/restapi/handler/ai_kv_inventory.go:90), [inventory lookup](../../pkg/loxinet/ai_kv_subscriber.go:2298), [WIP subscriber registration](../../pkg/loxinet/rules.go:4686).

   Replacements:

   > `service_id`: “Numeric internal service identifier used by the KV subscriber registry, derived from the load-balancer rule number. Accepts decimal values from 0 through 4294967295; this is not the opaque load-balancer ID.”

   > `ep_idx`: “Endpoint index in the service’s KV inventory registry. A parseable index without a registered inventory returns 404.”

   > `404`: “No registered KV service or endpoint inventory exists for the supplied pair.”

   **Policy-needed:** establish an explicit nonnegative `ep_idx` admission rule and portable upper bound before publishing them as server-enforced constraints.

6. **P2 · doc-defect — KV response omits `admission` and overstates `hash_algo` authority.**

   The actual response has optional `admission`, populated from the TRT-LLM `/server_info` admission verdict. It is omitted when no verdict exists, including ZMQ engines or a gate awaiting its first answer.

   When the service’s stored algorithm is empty, the provider substitutes `sha256_cbor`. Consequently, the reported algorithm can be a fallback assumption, not an observed engine assertion.

   `blocks` is always an array; an empty registered inventory returns `blocks: []`, `total: 0`. `block_idx` is correctly documented as synthetic, and ranges from 0 to `total-1`. The block set is copied under the inventory lock, but algorithm/admission are read separately; the response has no generation or freshness proof.

   Evidence: [actual response struct](../../api/restapi/handler/ai_kv_inventory.go:48), [algorithm fallback and response construction](../../pkg/loxinet/ai_kv_subscriber.go:2317).

   Replacements:

   > `admission`: “TRT-LLM server-info admission verdict for this endpoint. Omitted when no verdict is available. This field alone does not establish KV-exact readiness.”

   > `hash_algo`: “Hash algorithm recorded for the service. The provider reports sha256_cbor when the stored algorithm is empty.”

   > Operation: “Returns the gateway’s tracked KV hash set for a registered service/endpoint inventory. This diagnostic response does not attest engine freshness, endpoint generation, or dataplane readiness.”

7. **P2 · doc-defect — DPU GET mode selection and `flows` precedence are underspecified.**

   Filtered mode is selected when **any value** of `pipe`, `svc`, `ep`, or `limit` is nonempty. Merely supplying `?pipe=` does not select it.

   Filtered mode takes precedence over `flows=1`. For example, `?flows=1&limit=200` performs the filtered query and skips all four bulk enumerations. A client that automatically serializes Swagger’s default `limit: 200` silently changes the operation from aggregate to filtered mode.

   Evidence: [mode selection](../../api/restapi/handler/dpu_debug.go:276), [early filtered return](../../api/restapi/handler/dpu_debug.go:337), [bulk enumeration](../../api/restapi/handler/dpu_debug.go:349).

   Replacement:

   > “A nonempty pipe, svc, ep, or limit value selects filtered detail mode. Filtered mode takes precedence over flows=1 and skips bulk flow, FDB, route, and ACL enumeration. Empty filter values do not select filtered mode. To request the aggregate response, omit all four filter parameters.”

8. **P2 · doc-defect / policy-needed — DPU limit normalization is not the declared simple bound.**

   In filtered mode:

   - Omitted, empty, zero, negative, nonnumeric, or integer-overflowing `limit` → 200.
   - Positive parseable values above 2000 → 2000.
   - Values 1–2000 → unchanged.
   - No malformed-limit 400 is emitted.

   `flows` is recognized only when exactly `"1"`; other strings are ignored rather than enum-validated. `ep` requires a final colon and a parseable port **1–65535**, but the address portion is not validated or required to be nonempty. `svc` has no validation beyond being a query string.

   Evidence: [DPU parameter checks](../../api/restapi/handler/dpu_debug.go:290).

   Replacement for `limit`:

   > “Effective filtered-query limit. Omitted, empty, nonpositive, or unparseable values use 200; positive values above 2000 are clamped to 2000. A nonempty limit also selects filtered detail mode.”

   Do not declare malformed endpoints valid merely because the handler accepts them. Strict address validation and rejection versus normalization remain policy decisions.

9. **P1 · implementation-gap — DPU `svc`, `ep`, and `pipe` do not implement the documented filters.**

   The concrete BF2 query searches `d.entries` and performs case-sensitive substring matching against the raw map key for both `svc` and `ep`. It performs no service-name lookup or endpoint-identity comparison.

   The normal key is concatenated destination IP, source IP, ports, protocol and identity values **without the documented separators**. Normal IPv4 `addr:port` text therefore does not occur in the key.

   Both `ct_fwd_5tuple` and `ct_rev_5tuple` match the same `pipeKey == "ct"` entries, despite forward/reply direction being stored separately. Other allowlisted pipe names are compared directly against logical entry keys. FDB and ACL entries reside in separate maps that this query does not enumerate.

   Evidence: [actual query/filter logic](../../pkg/loxinet/dpu_doca_bf2_metrics.go:559), [actual CT key](../../pkg/loxinet/dpbroker.go:563), [direction bookkeeping](../../pkg/loxinet/dpu_doca_bf2.go:1504), [separate FDB enumeration](../../pkg/loxinet/dpu_doca_bf2.go:2653), [separate ACL enumeration](../../pkg/loxinet/dpu_doca_bf2.go:2756).

   **Disposition:** repair identity-aware filtering and pipe coverage, or explicitly redesign the public filter contract. Replacing “service name” with “substring” would describe the current mechanism but would silently ratify broken intended behavior. Until resolved, the UI must not present these filters as reliable service/endpoint/direction selectors.

10. **P2 · implementation-gap / doc-defect — Filtered DPU results have no completeness signal.**

   `doca_entry_details` uses `omitempty`, so it disappears for empty results—even after a filtered query. Disabled/no-BF2/non-DOCA cases can also produce no rows.

   Individual hardware-query errors skip entries. Selection stops at the limit before querying hardware, so failures can yield fewer rows without backfilling. Order follows map iteration. No cursor, total, truncation flag, or per-row error status is returned.

   The handler’s hard-error branch logs an error and still returns 200. Its comment mentions a warning header, but no such header is written. The current production adapter always returns a nil error, so that branch is not evidence of an operational warning mechanism.

   Evidence: [filtered response and error branch](../../api/restapi/handler/dpu_debug.go:440), [adapter](../../pkg/loxinet/dpu_debug_adapter.go:166), [selection and skipped queries](../../pkg/loxinet/dpu_doca_bf2_metrics.go:584).

   Safe interim description:

   > “Optional filtered query results. Omitted when no rows are returned. Results may be partial because failed hardware queries are skipped; the response provides no completeness or truncation indicator.”

   **Policy-needed:** distinguish unsupported capability, empty inventory, partial results, and query failure.

11. **P2 · doc-defect / implementation-gap — Several DPU detail fields are placeholders or lose identity.**

   - `doca_entry_details.age_ms` is always assigned **0** by the adapter.
   - `5_tuple` receives the raw concatenated CT key; it is not a formatted five-tuple.
   - BF2 `route_entries` can be populated. Their `dst` and `next_hop_mac` are `""`, and `port` is **0**, because that metadata is not stored.
   - BF2 ACL rows assign `action`, counters, but no `RuleID`; serialized `rule_id` is therefore **0**.
   - BF2 ACL actions are `"DROP"` and `"ALLOW"` in the actual implementation.

   Evidence: [age assignment](../../pkg/loxinet/dpu_debug_adapter.go:173), [detail key assignment](../../pkg/loxinet/dpu_doca_bf2_metrics.go:600), [route placeholders](../../pkg/loxinet/dpu_doca_bf2.go:2726), [ACL row construction](../../pkg/loxinet/dpu_doca_bf2.go:2778).

   Safe English additions:

   > `age_ms`: “Reserved age estimate. The current BF2 adapter returns 0 because entry age is not queried.”

   > `route_entries`: “Hardware counters for tracked routed CT flows. Current BF2 rows do not provide destination, next-hop MAC, or egress-port metadata; those fields are empty or zero.”

   > `rule_id`: “The current BF2 collector does not populate the rule identifier and returns 0.”

   The UI must not interpret these zeros as measured age, port identity, or firewall rule identity. Populating the missing identities remains implementation work.

12. **P2 · doc-defect — DPU `cb_force` does not pin the breaker closed.**

   `"open"` sets a forced-open override. `"close"` clears that override, resets failures, and restores ordinary breaker operation; later failures can reopen it.

   The operation applies to all registered CB-capable plugins. With none, it succeeds as a no-op, and `circuit_breaker_open` can remain false even after `"open"`.

   Evidence: [manager fan-out/no-op](../../pkg/loxinet/dpu_manager.go:344), [force-open/close implementation](../../pkg/loxinet/dpu_doca_bf2.go:99).

   Replacement:

   > “For cb_force, mode=open forces supported plugin circuit breakers open. mode=close clears the forced-open override, closes the breaker, and restores normal automatic behavior. The action applies to registered plugins implementing circuit-breaker control; with none, it is a no-op. The response reports the observed aggregate breaker state.”

13. **P2 · policy-needed / implementation-gap — DPU action success does not prove successful unload or atomic multi-plugin control.**

   `unregister` requires a nonempty plugin string and exact name matching. An unknown name is a successful no-op. Shutdown errors are logged, but the plugin is removed and HTTP 200 returned.

   For `cb_force`, a later plugin error returns 400 after earlier plugins may already have changed state. The 400 description should include provider-reported action errors; it must not imply that every rejection is pre-mutation validation.

   Evidence: [action handler](../../api/restapi/handler/dpu_debug.go:509), [unregister lifecycle](../../pkg/loxinet/dpu_manager.go:230), [multi-plugin early return](../../pkg/loxinet/dpu_manager.go:348).

   Decide whether unknown-plugin unregister is intentionally idempotent and whether shutdown/action failures need distinct status and outcome reporting. Do not claim “unload completed” from the current 200 alone.

14. **P1 · implementation-gap — Hardware-counter protocol/IP parsing does not match the real BF2 key.**

   `parseFlowKey` expects `protocol|src:port->dst:port`. BF2 stores `DpCtInfo.Key()`, which has neither `|` nor `->`. The source path therefore leads normal BF2 rows to:

   ```json
   {"protocol":"unknown","src_ip":"","dst_ip":""}
   ```

   The raw `flow_id` and counters remain available. The implementation also drops the provider’s direction metadata, so `total_flows` counts returned hardware entry rows, potentially forward and reply separately, rather than unique logical connections.

   Evidence: [parser and projection](../../api/restapi/handler/dpu_hwcounters.go:44), [BF2 row source](../../pkg/loxinet/dpu_doca_bf2.go:2597), [key format](../../pkg/loxinet/dpbroker.go:563).

   **Disposition:** repair the identity projection. Do not retain the current description promising parsed IPs, or silently define empty identities as successful parsing.

15. **P2 · doc-defect — Hardware-counter “all flows” overstates completeness.**

   Failed hardware queries are skipped. `total_flows` equals the returned array length. Missing provider returns `flows: []`, `total_flows: 0`, as documented; the same empty shape can also result from no supported rows or all queries failing.

   Evidence: [hardware query skip](../../pkg/loxinet/dpu_doca_bf2.go:2616), [response count](../../api/restapi/handler/dpu_hwcounters.go:93).

   Replacement:

   > “Returns successfully collected per-entry hardware counters from registered flow-stat providers. Failed hardware queries may be omitted. total_flows is the number of returned rows, not a completeness guarantee or a unique connection count.”

16. **P1 · implementation-gap — OPA `fail_open` is accepted and reported but has no effect on failure behavior.**

   The handler copies the boolean into configuration, and GET echoes it. The watcher’s fetch-failure path records an error and returns; it does not inspect `FailOpen` or remove rules to allow traffic. The complete watcher implementation contains no execution branch using the flag.

   Evidence: [configuration copy](../../api/restapi/handler/opa_watcher.go:113), [failure handling](../../pkg/opa/watcher.go:194).

   Do not preserve “Allow traffic when OPA is unreachable” as a supported feature.

   Interim limitation text:

   > “The current watcher stores and reports this setting but does not implement distinct fail-open behavior. Fetch failures preserve the existing applied state regardless of this value.”

   The intended fail-open/fail-closed behavior requires implementation and policy resolution. Omitted/null `fail_open` currently becomes false; false must not be advertised as an implemented deny-all fallback.

17. **P1 · implementation-gap — OPA SSRF protection is materially narrower than described.**

   The guard blocks only five IPv4 ranges: `169.254/16`, `127/8`, and the three RFC1918 ranges. It does not implement a general reserved/private-address policy, IPv6 loopback/ULA/link-local blocking, HTTP(S)-only validation, or rejection on failed DNS resolution.

   Fetching subsequently uses an ordinary HTTP client without a guarded dialer or redirect policy. DNS answers are not pinned between validation and fetching, and redirects are not revalidated by this guard.

   Evidence: [CIDR list and admission guard](../../api/restapi/handler/opa_watcher.go:182), [HTTP client and fetch](../../pkg/opa/fetcher.go:45).

   **Disposition:** retain this as a security implementation gap. Merely narrowing the wording to the five ranges is not a resolution of the claimed protection.

   Safe interim disclosure:

   > “Configuration currently checks resolved addresses against a limited IPv4 blocklist. This check does not provide comprehensive private/reserved-address, redirect, or DNS-rebinding protection.”

18. **P2 · doc-defect / implementation-gap — OPA defaults and interval bounds are incomplete.**

   - `opa_url`: required and nonempty; must parse and contain a hostname. The guard does not verify successful OPA access.
   - `policy_path`: omitted, null, or empty → `loxilb/l4`.
   - `poll_interval_sec`: omitted, null, zero, or negative → 30.
   - Positive intervals have no explicit upper bound before multiplication by `time.Second`.
   - On a 64-bit build, sufficiently large positive integers can overflow `time.Duration`; a resulting negative interval reaches `time.NewTicker` and can panic in the background goroutine.
   - Initial polling delay is 10 seconds and is not exposed in this request.

   Evidence: [request normalization](../../api/restapi/handler/opa_watcher.go:104), [watcher defaults](../../pkg/opa/watcher.go:80), [ticker creation](../../pkg/opa/watcher.go:158).

   Replacements:

   > `poll_interval_sec`: “Polling interval in seconds. Omitted or nonpositive values use 30 seconds. The first poll starts after the watcher’s initial delay, currently 10 seconds.”

   > `policy_path`: “OPA data policy path. Omitted or empty values use loxilb/l4. The fetcher removes leading slashes and appends the path after /v1/data/.”

   **Implementation needed:** overflow-safe validation. The mathematical duration ceiling is not automatically an appropriate product maximum.

19. **P1 · implementation-gap — OPA cannot apply changes through an authenticated management API as currently wired.**

   The raw POST may authenticate its caller successfully, but creates an applier targeting `http://localhost:11111`. That applier sends firewall POST/DELETE requests without management credentials. The caller’s credential is neither forwarded nor replaced with a service identity.

   In management-authenticated deployments, these downstream operations therefore lack the credential required by the generated management API. The exposed OPA request also provides no alternative management URL, TLS, or credential configuration.

   Evidence: [watcher/applier construction](../../pkg/opa/watcher.go:90), [DELETE request](../../pkg/opa/applier.go:136), [POST request](../../pkg/opa/applier.go:176), [global management security](../../api/swagger.yml:12907).

   **Disposition:** define an authenticated internal application mechanism. HTTP 200 from watcher configuration must not be presented as successful policy enforcement.

20. **P2 · doc-defect / policy-needed — OPA success and status fields overstate synchronization guarantees.**

   POST replaces the singleton and starts a background goroutine, then returns `{"result":"Success"}`. It does not wait for fetching or application.

   `status: running` means the background watcher was started. `rules_count` is the cache size, including state loaded from disk; it is not a live firewall readback.

   `last_sync_at` is updated even when `applyResult.Errors > 0`, directly contradicting “last successful sync.” Cache-save failures are only logged. The timestamp does not prove complete application or durable state.

   Circuit-breaker values are **0=closed, 1=open, 2=half-open**. Extras omits the mapping; the overlapping main spec currently reverses 1 and 2.

   Evidence: [POST acknowledgment](../../api/restapi/handler/opa_watcher.go:120), [status/cache semantics](../../pkg/opa/watcher.go:148), [partial failure and timestamp](../../pkg/opa/watcher.go:232), [breaker enum](../../pkg/opa/types.go:48), [conflicting overlapping description](../../api/swagger.yml:12900).

   Replacements:

   > POST 200: “Watcher configuration accepted and background polling started. This response does not confirm a successful policy fetch or firewall application.”

   > `status`: “Watcher lifecycle state. running does not imply a successful synchronization.”

   > `rules_count`: “Number of rules in the watcher’s local cache; this is not a live dataplane readback.”

   > `circuit_breaker_state`: “Policy-fetch circuit-breaker state: 0=closed, 1=open, 2=half-open.”

   **Policy-needed:** either implement a genuine last-success timestamp or explicitly rename/redefine `last_sync_at`. Current-behavior wording would be “timestamp of the latest cycle reaching the end of the apply stage, including partial apply failures.”

21. **P2 · doc-defect / implementation-gap — OPA DELETE cancels polling but does not remove applied rules or guarantee quiescence.**

   DELETE calls `Stop`, clears the singleton, and returns success; repeated DELETE succeeds. `Stop` cancels the context and marks the status stopped but does not join the goroutine.

   There is no firewall cleanup or persisted-cache deletion. Replacement POST similarly stops the old watcher without waiting for it to exit before constructing a new one. In-flight work can still be unwinding; source inspection does not establish atomic replacement.

   Evidence: [DELETE implementation](../../api/restapi/handler/opa_watcher.go:159), [Stop implementation](../../pkg/opa/watcher.go:135).

   Replacement:

   > “Cancels polling and removes the in-memory watcher configuration. Previously applied firewall rules and the persisted rule cache are retained. Succeeds when no watcher is configured.”

   If “stopped” is intended to mean all outstanding work has completed, joining/quiescence is an implementation requirement.

22. **P1 · doc-defect — API-key PATCH omits security-significant empty/null semantics.**

   The source distinguishes omitted/null from an explicit empty array:

   | Input | Current effect |
   |---|---|
   | `allowed_models` omitted or `null` | Keep existing model restriction |
   | `allowed_models: []` | Clear restriction: allow all models, subject to other controls |
   | Nonempty model array | Replace restriction; matching is exact and case-sensitive |
   | `enabled` omitted or `null` | Keep current enabled state |
   | `enabled: false` | Disable |
   | `enabled: true` | Enable; does not change expiration |
   | `{}` or top-level `null` | Existing-key lookup and cache invalidation, no field update; can return 204 |

   Evidence: [PATCH decoding](../../api/restapi/handler/ai_apikey.go:202), [non-nil update branches](../../pkg/aikey/service.go:592), [empty-model storage/readback](../../pkg/aikey/service.go:527), [model and expiry enforcement](../../pkg/loxinet/ai_gateway_dp.go:239).

   Replacements:

   > `allowed_models`: “Replacement model allowlist. Omitted or null leaves the current value unchanged. An empty array removes the model restriction and allows all models, subject to other gateway controls. Nonempty entries are matched exactly and case-sensitively.”

   > `enabled`: “Enables or disables the key. Omitted or null leaves the current state unchanged. Enabling does not change or remove the key’s expiration time.”

   **Policy-needed:** whether top-level null and empty patches should remain valid. Do not invent a server-enforced “at least one field” requirement.

23. **P1 · implementation-gap — API-key PATCH does not preserve arbitrary model-string identity.**

   Models are stored using `strings.Join(allowedModels, ",")` and reconstructed using `strings.Split`.

   Thus `["a,b"]` becomes two allowed models after readback. `[""]` becomes an empty stored string and subsequently an unrestricted list. Null array elements decode to zero-value strings and can reach the same issue. There is no model existence, nonempty-item, delimiter, uniqueness, or length validation in this PATCH path.

   Evidence: [serialization](../../pkg/aikey/service.go:602), [deserialization](../../pkg/aikey/service.go:527), [raw input type](../../api/restapi/handler/ai_apikey.go:202).

   **Disposition:** use lossless storage or explicitly validate a ratified model-name grammar. Do not silently advertise arbitrary strings while corrupting them, or represent UI-only restrictions as backend validation.

24. **P1 · implementation-gap — Multi-field API-key PATCH can partially persist and leave cached state stale.**

   The service updates model restrictions first and `enabled` second using separate SQL statements, without a transaction. If the second update fails, the first can remain committed, while cache eviction is skipped because execution returns early.

   Consequently, a 500 does not guarantee unchanged state. Concurrent deletion after the initial key lookup is also not detected through `RowsAffected`.

   Evidence: [sequential statements and delayed invalidation](../../pkg/aikey/service.go:597).

   **Disposition:** implementation correction is required for an atomic PATCH contract. The UI should not infer rollback from failure; re-read state before presenting a definitive outcome.

   On the successful path, local cache eviction is synchronous; peer invalidation is best-effort, not cluster-wide acknowledgment. Evidence: [invalidation semantics](../../pkg/aikey/invalidate.go:36).

25. **P1 · implementation-gap — Browser CORS does not allow the documented PATCH operation.**

   Global `Access-Control-Allow-Methods` lists `GET, POST, PUT, DELETE, OPTIONS`, omitting PATCH. A direct cross-origin browser PATCH cannot obtain the advertised method permission even when its origin is allowed.

   Evidence: [CORS method list](../../api/restapi/configure_loxilb_rest_api.go:538).

   This is an implementation issue affecting direct-browser integration. Same-origin access or a server-side OAM proxy is a different deployment path and was not exercised here.

26. **P2 · policy-needed — Raw JSON validation differs from generated schema validation.**

   All three body-bearing raw handlers decode one JSON value into Go structs. They do not call generated schema validators, disallow unknown fields, or check for trailing JSON values.

   Notable consequences:

   - Cross-action DPU fields are ignored when irrelevant.
   - PATCH `{}` and `null` are accepted as described above.
   - Type mismatches generally produce 400, but null scalar values can become zero values.
   - The declared media types do not establish generated 415/406 enforcement.
   - PATCH `key_id` rejects only empty/whitespace-only values, then uses the original untrimmed identifier. Prefix dispatch does not validate that the suffix is exactly one path segment.

   Evidence: [DPU decoder](../../api/restapi/handler/dpu_debug.go:503), [OPA decoder](../../api/restapi/handler/opa_watcher.go:82), [PATCH decoder and identifier](../../api/restapi/handler/ai_apikey.go:195), [PATCH prefix routing](../../api/restapi/configure_loxilb_rest_api.go:639).

   Decide strict-object, unknown-field, trailing-content, null, and identifier policies before adding purported backend guarantees.

27. **P2 · doc-defect / policy-needed — Response presence and integer semantics need explicit schemas.**

   None of the response object schemas declares required properties, despite deterministic field emission. The four named definitions and all nested fields were checked:

   | Definition | Reviewed properties and disposition |
   |---|---|
   | `RawError` | `code`, `error`, `fields`, `message`, `result`: names/types match the two actual envelope families. It is a permissive union; all five must **not** be required together. Describe the two exclusive shapes. |
   | `ManagementError` | `code`, `fields`, `message`, `result`: emitted by the raw authentication helper. `fields` is `[]`, `code` is the HTTP status, and `message == result`. Mark these required for this helper’s envelope. |
   | `SimpleError` | `error`: matches raw JSON failures; mark required. It does not cover plain-text 405. |
   | `DpuDebugResponse` | All 14 top-level properties match the struct. The 12 properties other than `flows` and `doca_entry_details` are always emitted. Those two arrays are omitted when empty. All 23 nested entry properties were checked; identity/placeholder defects are findings 11 and 14. |

   Additional required/presence rules:

   - KV success: `service_id`, `ep_idx`, `hash_algo`, `blocks`, `total` always present; `admission` optional. Both block properties always present.
   - Hardware counters: `flows`, `total_flows`, and all six row properties always present.
   - DPU POST: `status: "ok"` always present on 200; `circuit_breaker_open` only for `cb_force`.
   - OPA GET: all properties except `last_sync_at` and `last_error` always present. In `not_configured`, string configuration fields are `""`, numeric fields are 0, and `fail_open` is false.
   - OPA POST/DELETE: `result: "Success"` is always present.
   - API-key PATCH success: 204 with no response body is correct.

   Numeric schema corrections:

   - Service IDs and ACL rule IDs are uint32: minimum 0, maximum 4294967295.
   - FDB/route `port` fields are uint16 hardware-port metadata: 0–65535, **not TCP/UDP service ports**.
   - Counters and hashes are unsigned 64-bit integers; the per-pipe success/failure map values currently omit corresponding width information.
   - Active counts and per-pipe active values are signed int64; do not add unsigned bounds merely because negative counts seem undesirable.
   - Counts such as `total` and `total_flows` are nonnegative returned-array lengths.
   - `format: uint64` does not itself guarantee lossless JavaScript handling. The wire currently sends JSON numbers; clients must preserve integers beyond `2^53-1`, particularly KV hashes. Changing them to strings would be a separate wire-contract decision.

   Evidence: [DPU response types](../../api/restapi/handler/dpu_debug.go:30), [collection normalization](../../api/restapi/handler/dpu_debug.go:406), [OPA response types and absent watcher](../../api/restapi/handler/opa_watcher.go:48), [management envelope](../../api/restapi/handler/auth.go:228).

   Per-pipe map names are logical families `ct`, `udp_ct`, `route`, `fdb`, `acl`, distinct from the GET query’s hardware-pipe enum. With a registered manager, active maps additionally contain `total`; the no-provider response uses empty maps. Scalars and maps are sampled separately, so do not promise atomic equality during updates. Evidence: [per-pipe sampling](../../pkg/loxinet/dpu_manager.go:312).

The following UI rules can be expressed now without inventing backend guarantees:

| Form/read model | UI rule grounded in current source |
|---|---|
| Management operations | Viewers may access GETs; mutations require an authorized management identity. Do not offer data-plane keys as management credentials. |
| KV inventory | Require both identifiers. Explain that an existing LB endpoint may have no registered inventory. Treat empty inventory, missing admission, and readiness as distinct states. |
| DPU GET mode | Offer explicit aggregate, bulk, and filtered modes. Aggregate/bulk modes must omit `pipe`, `svc`, `ep`, and `limit`, including automatically inserted defaults. |
| DPU filtered mode | Supply an effective limit in 1–2000; default locally to 200 only after filtered mode is selected. Do not promise working identity/pipe filters until finding 9 is resolved. |
| DPU unregister | Show and require a plugin value when `action=unregister`; omit `mode`. Populate choices from `plugins`, while recognizing server behavior for unknown names remains unresolved. |
| DPU circuit breaker | Require `mode` when `action=cb_force`; omit `plugin`. Label close as “clear forced-open override and resume normal operation.” Show the returned state. |
| DPU result display | Missing `flows`/`doca_entry_details` means no returned rows, not proof of zero hardware entries. Render placeholder identity/age fields as unavailable. |
| OPA configuration | Treat POST as full singleton replacement. Omitted optional fields reset to defaults; they do not preserve the previous watcher configuration. |
| OPA status | `running` is lifecycle only. Use `last_error` alongside timestamp/cache count; do not show “healthy” from running or HTTP 200 alone. |
| OPA fail-open | Do not present the flag as an effective traffic safety control until implemented. |
| API-key model permissions | Separate “leave unchanged,” “allow all models” (`[]`), and “replace allowlist.” Never substitute an empty array for an omitted field. |
| API-key enabled | Preserve three states: unchanged, enabled, disabled. A false value is an update, not absence. |
| API-key failure | Do not assume failed multi-field PATCH rolled back. Refresh state before declaring the resulting permissions. |

Outstanding decisions and verification boundaries:

- Ratify OPA fail-open behavior, comprehensive outbound URL policy, authenticated rule application, interval bounds, timestamp meaning, and replacement/delete quiescence.
- Repair or redesign DPU filter identities, pipe coverage, hardware-counter identity parsing, and completeness reporting.
- Define DPU action failure/idempotency semantics and populate unavailable metadata where required.
- Make PATCH storage lossless and updates atomic; establish model-name/null/empty-patch validation and fix CORS.
- Resolve Swagger response-required fields, union-envelope representation, and lossless uint64 client handling.
- Raw dispatch returns before the generated snapshot-freeze/auto-persist middleware. Whether these mutations should participate is a lifecycle-policy question; do not document those protections for extras without resolving it. Evidence: [middleware composition](../../api/restapi/configure_loxilb_rest_api.go:459), [generated middleware wrappers](../../api/restapi/configure_loxilb_rest_api.go:502).
- Hardware behavior, database failure outcomes, browser requests, OPA connectivity/enforcement, and concurrency were **not executed**. No runtime PASS or readiness claim follows from this audit.
