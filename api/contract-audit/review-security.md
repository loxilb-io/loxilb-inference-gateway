# Security/account and encryption audit checkpoint

Read-only review in an isolated campaign worktree at verified HEAD `f8e6ace22f0f2262d56829e781a83e4b7075fef7` plus live WIP.

**58 assigned operations were inventoried and their handlers examined.** The review also examined their named schemas, domain validation, and relevant consumers described below. This is a checkpoint—not a claim that all defects are resolved or that every security property has been proved.

No edits, tests, builds, SSH, or subagents were performed. Swagger changed concurrently during the review; source references below identify observed implementation evidence, not an immutable WIP snapshot.

## 1. Reviewed operation inventory

Paths below are relative to `/netlox/v1`. Every listed method was examined. Handler references are relative to `api/restapi/handler/`.

| Area | Reviewed methods and paths | Handler evidence |
|---|---|---|
| Account | POST `/auth/login`; POST `/auth/logout` | `auth.go:106`, `auth.go:141` |
| Account | GET and POST `/auth/users`; PUT and DELETE `/auth/users/{id}` | `user.go:118`, `user.go:49`, `user.go:144`, `user.go:106` |
| Token | POST `/auth/token/upgrade` | `auth.go:267` |
| OAuth | GET `/oauth/{provider}`; GET `/oauth/{provider}/callback`; GET `/oauth/{provider}/token` | `oauth2.go:166`, `oauth2.go:196`, `oauth2.go:313` |
| CORS | GET `/config/cors/all`; POST `/config/cors`; DELETE `/config/cors/{cors_url}` | `cors.go:28`, `cors.go:49`, `cors.go:77` |
| AI keys | POST and GET `/config/ai/apikey`; GET and DELETE `/config/ai/apikey/{key_id}` | `ai_apikey.go:70`, `:124`, `:153`, `:173` |
| Tenant quota | POST `/config/ai/tenant/ratelimit`; GET `/config/ai/tenant/ratelimit/{tenant_id}` | `ai_apikey.go:233`, `:266` |
| Managed TLS certificates | POST `/config/cert`; PUT, DELETE and GET `/config/cert/{certId}` | `cert.go:264`, `:306`, `:350`, `:389` |
| SNI certificates | POST, DELETE and GET `/sni/certificates` | `sni.go:110`, `:156`, `:186` |
| IPsec global | GET and POST `/config/ipsec` | `ipsec.go:52`, `:79` |
| IPsec tunnels | GET `/config/ipsec/tunnels/all`; POST `/config/ipsec/tunnels` | `ipsec.go:105`, `:181` |
| IPsec tunnel | GET, PUT and DELETE `/config/ipsec/tunnels/{name}` | `ipsec.go:332`, `:248`, `:423` |
| IPsec action/export | POST `/config/ipsec/tunnels/{name}/action`; GET `/config/ipsec/tunnels/{name}/peerconfig` | `ipsec.go:315`, `:401` |
| IPsec telemetry | GET `/config/ipsec/sas/all`; GET and DELETE `/config/ipsec/stats` | `ipsec.go:438`, `:475`, `:506` |
| IPsec leaf certificates | GET `/config/ipsec/certificates/all`; POST `/config/ipsec/certificates`; GET and DELETE `/config/ipsec/certificates/{name}` | `ipsec.go:521`, `:551`, `:589`, `:614` |
| IPsec validation | POST `/config/ipsec/certificates/validate` | `ipsec.go:629` |
| IPsec CA certificates | GET `/config/ipsec/ca-certificates/all`; POST `/config/ipsec/ca-certificates`; GET and DELETE `/config/ipsec/ca-certificates/{name}` | `ipsec.go:658`, `:686`, `:720`, `:743` |
| PII | POST `/config/pii/enable`, `/configure`, `/url-patterns`; GET `/config/pii/status`, `/stats` | `pii.go:19`, `:52`, `:131`, `:199`, `:261` |
| LlamaFirewall | POST `/config/llamafirewall/enable`, `/configure`, `/scanners`; GET `/config/llamafirewall/status`, `/stats`; POST `/config/llamafirewall/health` | `llamafirewall.go:21`, `:57`, `:112`, `:158`, `:211`, `:293` |

## 2. Findings and actionable replacement descriptions

Classification:

- **doc-defect:** documentation/schema does not describe the observed contract.
- **implementation-gap:** validation, persistence, response, or enforcement does not satisfy the advertised capability.
- **policy-needed:** intended behavior needs an explicit security/product decision.

Replacement text below documents limitations where necessary. It must not turn a defect into an approved long-term contract.

### A. Authentication and account management

**A1 — implementation-gap: username delimiters can change interpreted authorization roles.**

User creation validates the role and password, but does not reject `|` in usernames. Session principals are assembled as `username + "|" + role`; authorization trusts component index 1. Therefore, a stored viewer account with a delimiter-bearing username can be interpreted as another role. This is a static authorization mismatch, not a runtime-tested exploit.

Evidence: [user.go:199](../../pkg/user/user.go:199), [user_util.go:411](../../pkg/user/user_util.go:411), [authz.go:82](../../pkg/authz/authz.go:82). `pkg/user/schema.go:57` has an unrestricted text username column.

**Disposition:** fix principal encoding/decoding and username validation. Do not claim that the role enum alone establishes role isolation.

**A2 — implementation-gap: normal Bearer logout does not target the stored token hash.**

The handler forwards the entire `Authorization` header. Logout hashes that entire string, while authentication strips `Bearer ` and token storage hashes the raw token. A successful deletion affecting zero rows still returns success.

Evidence: [auth.go:141](../../api/restapi/handler/auth.go:141), [user.go:508](../../pkg/user/user.go:508), `handler/auth.go:50`.

**Replacement:** “Requests invalidation of the presented management session. Known implementation limitation: the current Bearer-header logout path does not normalize the token consistently with authentication; a successful response must not be treated as verified revocation.”

**A3 — doc-defect and implementation-gap: account requests and responses are conflated.**

- Login returns an **opaque random management token**, not JWT claims.
- User creation returns HTTP **200 `{"result":"Success"}`**, not 201 with `User`.
- PUT and DELETE also return the result envelope.
- Logout returns 200 without the documented message payload.
- PUT copies username/password/path ID but **drops `role`**; the domain consequently preserves the previous role.
- `User.username` and `password` are required even for PUT; role-only update is not available through this handler.
- Creation requires a valid role in the domain although Swagger does not require it.

Evidence: [user.go:144](../../api/restapi/handler/user.go:144), `handler/user.go:37,101,113`; [user_util.go:69](../../pkg/user/user_util.go:69), `pkg/user/user.go:445`.

**Replacements:**

- Login: “Authenticate a local management account and return an opaque bearer session token. The token contains no client-readable identity or role claims.”
- Create: “Create an account with a username, password and explicit `admin` or `viewer` role. Returns an operation-result envelope.”
- Update: “Update the account identified by the path ID. Username and password are required. Role updates are currently not forwarded by this endpoint.”

Password policy is at least **9 bytes**, upper/lowercase, number, punctuation/symbol, not equal to username, and no three consecutive identical runes. Previous-password comparison uses the **submitted username**, so renaming can bypass comparison with the original account’s password. Evidence: `pkg/user/user_util.go:256,331`.

**A4 — doc-defect and policy-needed: deployment/authentication dependencies need explicit documentation.**

Authentication precedence is local user service → OAuth → manual token → unrestricted mode. Viewer permits every GET and POST logout; it is not tenant-scoped. Account handlers are installed only with `UserServiceEnable`; OAuth handlers only with `Oauth2Enable`. Otherwise generated unimplemented handlers remain.

Bootstrap creation requires no credential, a loopback transport peer, and an empty user table. An invalid supplied credential cannot fall back to bootstrap. However, authenticated create flattens credential-store failures into 401.

Evidence: [configure_loxilb_rest_api.go:393](../../api/restapi/configure_loxilb_rest_api.go:393), `handler/auth.go:47`, `handler/user.go:69`, `pkg/authz/authz.go:112`.

**Replacement:** “Requires the applicable management authentication mode. `viewer` authorizes read operations globally, not per tenant. Initial local-account bootstrap is permitted only from a loopback transport peer while the account table is empty.”

**Policy decisions:** first-account viewer creation, deletion of the last administrator, and viewer access to secret-bearing GET operations.

**A5 — doc-defect and policy-needed: token upgrade is a file replacement, not license validation.**

`license_key` is written verbatim to the configured manual-token file and echoed in the response. There is no license-format validation, nonblank validation, or requirement that manual-token authentication be active.

Evidence: [auth.go:267](../../api/restapi/handler/auth.go:267).

**Replacement:** “Replace the configured manual management-token file with `license_key`. This operation does not validate a license or change the active authentication mode.”

### B. OAuth

**O1 — doc-defect: authorization initiation returns 307, not the documented 302 JSON response.**

Evidence: [oauth2.go:166](../../api/restapi/handler/oauth2.go:166).

**Replacement:** “Start provider authorization using HTTP 307 and a `Location` header. No `OauthMessageResponse` JSON success payload is returned.”

**O2 — implementation-gap: provider and refresh behavior are not ready for an unconditional support claim.**

GitHub configuration uses `google.Endpoint` and Google-style scopes. Google user-info fields use unchecked string assertions. Refresh requires the original access-token entry to remain in the cache, whose lifetime follows access-token expiry; consequently the documented “refresh after expiry” workflow is unsupported by this path. Refresh errors become 500, and the response omits a potentially rotated refresh token.

Evidence: [oauth2.go:133](../../api/restapi/handler/oauth2.go:133), `:233`, `:313`; [oauth_user.go:71](../../pkg/user/oauth_user.go:71), `:98`.

**Replacement:** “Refresh using the cached access-token/refresh-token pair. Current limitations include cache-lifetime dependence, incomplete refresh-token rotation reporting, and an incorrect GitHub provider configuration.”

**O3 — policy-needed: OAuth grants administrator authority and state is process-local.**

Stored OAuth credentials are assigned `admin` unconditionally. State is single-use with a ten-minute TTL, but the map records neither initiating browser/session nor provider. Tokens/state are not an established multi-node authorization flow.

Evidence: [oauth_user.go:92](../../pkg/user/oauth_user.go:92), `handler/oauth2.go:41,73`.

**Replacement:** “Successful OAuth admission currently creates an administrator principal. State validation depends on the originating process. Identity admission, role mapping, browser binding and multi-node handling require explicit deployment policy.”

### C. CORS

**C1 — doc-defect and implementation-gap: CORS descriptions and browser capabilities disagree with implementation.**

`CorsEntry.cors` contains origin strings, not interface names. POST adds entries sequentially; a later error does not undo earlier additions. Empty input is a no-op. `"*"` is rejected by CRUD. Removing the final explicit entry leaves deny-all rather than restoring factory wildcard behavior.

The middleware allows wildcard without credentials or exact configured origins with credentials. Its advertised methods omit PATCH; allowed headers omit `X-Api-Key`.

Evidence: [cors.go:49](../../api/restapi/handler/cors.go:49), `common/cors.go:87`; [configure_loxilb_rest_api.go:538](../../api/restapi/configure_loxilb_rest_api.go:538).

**Replacements:**

- `cors`: “Origin strings to add to the management API CORS allowlist. Entries are trimmed; empty origins and `*` are rejected. Additions are sequential, not atomic.”
- DELETE: “Remove the exact configured origin. Encode the origin as one path parameter. Removing the final explicit origin leaves an empty allowlist.”
- GET: “Return the effective origin configuration in `corsAttr`.”

Remove copied BFD/VLAN/Kubernetes error descriptions. PATCH behavior itself remains outside this assignment.

### D. AI API keys and tenant quotas

**K1 — doc-defect and implementation-gap: key import and per-key limits need corrected contracts.**

Imported keys accept 16–512 printable non-space ASCII bytes. An imported create response emits `raw_key: ""`, rather than omitting it. Generated keys return their secret once. `burst_size` is total bucket capacity, **not capacity above RPS**. Nonpositive burst defaults to RPS; nonpositive RPS skips that limiter.

Per-key `tokens_per_min` is stored and returned, but the examined token-accounting consumer uses tenant and tenant/model quotas—not this field.

Evidence: [service.go:416](../../pkg/aikey/service.go:416), `handler/ai_apikey.go:116`; [ratelimit.go:343](../../pkg/ratelimit/ratelimit.go:343), `pkg/loxinet/ai_gateway_dp.go:538,604`.

**Replacements:**

- `api_key`: “Optional imported credential; empty or omitted generates a new key. Imported values must contain 16–512 printable non-space ASCII bytes.”
- `raw_key`: “Generated credential returned at creation; currently an empty string for imported credentials.”
- `burst_size`: “Total request-bucket capacity. Zero uses the configured per-key RPS.”
- Per-key `tokens_per_min`: “Stored metadata; per-key token-quota enforcement is not connected in the reviewed consumer.”

**K2 — doc-defect and implementation-gap: omission can remove aggregate protection.**

POST tenant rate limit is not PATCH. Omitted aggregate `rps`, `tokens_per_min`, and `burst_pct` become zero and are written. Model entries are individual upserts/deletions; omitted or empty `model_limits` preserves existing model rows. A model TPM of zero or negative deletes that row. Aggregate write occurs before model writes without a transaction spanning the request.

Evidence: [ai_apikey.go:233](../../api/restapi/handler/ai_apikey.go:233), [apiclient.go:1849](../../pkg/loxinet/apiclient.go:1849), `pkg/aikey/service.go:714`.

**Replacement:** “Replace aggregate quota values and apply the supplied per-model changes. Omitted aggregate numbers become zero. Omitted/empty `model_limits` leaves existing model quotas unchanged; a zero model quota removes that entry. The operation is not atomic across aggregate and model records.”

**K3 — implementation-gap and policy-needed: normalization, validation and enforcement boundaries are incomplete.**

- `allowed_models` is comma-joined/split; embedded commas change its meaning.
- Empty allowlists are unrestricted; comparison is exact, not wildcard matching.
- Key creation rejects whitespace-only tenant IDs but retains surrounding whitespace.
- Tenant-quota POST checks only a non-nil tenant pointer.
- `enabled` omission/null defaults true; explicit false is honored.
- Omitted/zero-time/epoch expiry means no expiry; other past timestamps are accepted.
- Imported-key charset errors and missing model names fall through to generic 500; length errors match 400.
- Quotas only affect traffic associated with rules requiring API-key authentication.

Evidence: `pkg/aikey/service.go:475,527`; `handler/ai_apikey.go:75,93,99,244`; [common.go:154](../../api/restapi/handler/common.go:154), `pkg/loxinet/apiclient.go:1861`.

**Replacement:** “These management endpoints configure data-plane credentials and quotas; management Bearer authorization is separate. Configuration alone does not enable enforcement on a service.”

### E. Managed TLS and SNI certificates

**T1 — implementation-gap: duplicate upload can remove existing persisted certificate material.**

POST persists files before duplicate registration is rejected; registration failure then removes that managed directory. PUT similarly overwrites persisted material before successful rotation, without rollback.

Evidence: [cert.go:283](../../api/restapi/handler/cert.go:283), `:326`; [sockproxy_ssl.c:927](../../loxilb-ebpf/common/sockproxy_ssl.c:927).

**Disposition:** implementation fix required. Do not describe upload/rotation as transactional.

**T2 — implementation-gap and policy-needed: hostname ownership and rotation guarantees are overstated.**

Registration counts an existing hostname as success and records it under the new cert ID. Rotation operates on the old hostname set, does not rederive changed SANs, and can succeed after partial swaps. Handler hostname reporting also reads the previous stored certificate before replacing it.

Evidence: [sockproxy_ssl.c:946](../../loxilb-ebpf/common/sockproxy_ssl.c:946), `:994`; `handler/cert.go:334,404`.

**Replacement:** “Rotate certificate material under the path `certId`. Current implementation retains the existing hostname registration set and does not provide an all-or-nothing multi-host rotation guarantee.”

**T3 — doc-defect and implementation-gap: certificate identity, response shape and SNI error handling.**

- Server-minted `certId` is not returned: POST sends empty 201.
- PUT path ID overrides body ID.
- GET returns no private-key material, but shared `Cert` requires `keyPem`; generated serialization permits `keyPem: null`.
- IDs are limited to 63 **bytes**, reject separators and any `..`; NUL is not explicitly rejected before C conversion.
- SNI GET returns `sniAttr[].hostname/certPath`, not documented `certificates`, `refCount`, and `totalCertificates`.
- SNI mutations return 200 result strings for both success and failure.
- SNI registration is a node-filesystem operation, not PEM upload; DELETE unregisters without deleting files.
- The SNI loader is called with mTLS disabled; merely providing `rootCA.crt` does not establish mTLS enforcement.

Evidence: [cert.go:137](../../api/restapi/handler/cert.go:137), `:301`; `api/models/cert.go:35`; [sni.go:133](../../api/restapi/handler/sni.go:133), `:223`; `sockproxy_ssl.c:660`.

**Replacements:** “`certPath` identifies a certificate directory on the gateway node.” “`hostnames` is output-only and ignored on writes.” “SNI success must currently be determined from the result string, not HTTP 200 alone.”

### F. IPsec

**I1 — implementation-gap: tunnel deletion issues unfiltered XFRM flushes.**

For a nonzero mark, deletion executes `ip xfrm state flush` and `ip xfrm policy flush` without a mark/tunnel filter. The commands can affect unrelated state in the same network namespace.

Evidence: [ipsec.go:356](../../pkg/loxinet/ipsec.go:356).

**Replacement warning:** “Known implementation limitation: deleting a marked tunnel currently issues namespace-wide XFRM flush commands. Do not describe this operation as isolated to the named tunnel.”

**I2 — doc-defect and implementation-gap: omission/default semantics and inactive fields.**

- Global POST forwards pointers for every value field; omission overwrites with false/zero/empty.
- The seven global controls are stored, without established enforcement consumers.
- `supportedAlgorithms` is a hard-coded list, not negotiated capability discovery; hardware capabilities are not populated.
- Tunnel PUT is replacement-like, with omitted optional settings reset/defaulted; PSK is specially preserved when remaining in PSK mode.
- `mark: 0` becomes 100, contrary to “0 = no mark.”
- DPD timeout defaults to 120, not Swagger’s 150.
- `caCertName` is neither required nor validated for cert authentication and is not consumed by generated tunnel configuration.
- Selector protocol/ports are retained but not emitted into strongSwan configuration.

Evidence: [handler/ipsec.go:79](../../api/restapi/handler/ipsec.go:79), `pkg/loxinet/ipsec.go:139,215,393,676,772`.

**Replacements:** “POST replaces the supplied global configuration value set; omission does not preserve individual values.” “Selector protocol and port fields are currently metadata-only.” “DPD timeout: omitted or zero selects 120 seconds.”

**I3 — implementation-gap: IPsec observability is partly stubbed.**

SA enumeration returns an empty stub. Statistics report tunnel count, zero up, all down, and zero traffic/error counters. Reset clears stub state. Tunnel state uses best-effort `ipsec status`, throttled to two seconds; failure leaves previous state. Tunnel timestamps, SA timestamps and stats timestamp are not mapped into responses.

Evidence: [ipsec.go:1778](../../pkg/loxinet/ipsec.go:1778), `:1323`; `handler/ipsec.go:143,449,486`.

**Replacement:** “Telemetry is incomplete: SA enumeration and aggregate counters are placeholders. Missing/zero values do not prove an absence of installed SAs or traffic. Tunnel state is a cached, best-effort daemon observation.”

**I4 — implementation-gap and policy-needed: certificate validation and secret export.**

Certificate names reach filesystem paths without traversal bounds. Passphrase is accepted but unused; encrypted-key decryption is absent. Key matching fails to reject mismatched key *types*. Leaf serial/SAN/key-usage metadata is unfinished; dates are omitted by handlers. CA upload checks `IsCA` but not the leaf validator’s date policy. Deletes do not enforce documented in-use conflicts.

Peer configuration includes PSK and is available to viewer GET authorization. Cert-mode peer output contains installation placeholders, not a ready-to-run configuration.

Evidence: [ipsec.go:1427](../../pkg/loxinet/ipsec.go:1427), `:1441`, `:1586`, `:1626`, `:1653`; `handler/ipsec.go:629`; `pkg/loxinet/ipsec.go:538`.

**Replacement:** “Validate parseable certificate/key material and implemented local checks; this is not chain-trust or tunnel-readiness validation. Passphrase-protected key support is not implemented.” Mark peer output explicitly **secret-bearing**.

### G. PII

**P1 — implementation-gap: accepted settings do not reach the promised behavior.**

The handler drops `scan_mode`, `enable_v2`, `default_operator`, `encryption_key`, and `batch_size`. The Go reconfiguration bridge does not apply the timeout argument; RPCs use the client’s five-second timeout. Separate anonymizer endpoint behavior is not implemented by that client. Legacy Analyze uses threshold 0.5, while AnonymizeJSON reads the configured threshold.

Evidence: [pii.go:52](../../api/restapi/handler/pii.go:52), [pii_detection.go:328](../../pkg/loxinet/pii_detection.go:328), `:369`, `:653`.

**Replacement:** “The listed v2/encryption settings and `scan_mode` are not applied by this endpoint.” Remove “40% faster”; no supporting qualification was established.

**P2 — doc-defect and implementation-gap: zero values, pattern order and bounds matter.**

Circuit-breaker/retry zero values are accepted but ignored by the manager, so zero cannot disable retries. Numeric int64 settings are narrowed to uint32 without upper bounds. URLs/patterns are truncated into fixed-size storage. Pattern matching is first-match-wins; a nonempty list becomes an include list, meaning an exclude-only list scans nothing. Null pattern elements pass generated validation but are dereferenced by the handler. More than 64 patterns currently maps to generic 500.

Evidence: `pkg/presidio/config.go:264,273,299`; [sockproxy_presidio.c:342](../../loxilb-ebpf/common/sockproxy_presidio.c:342); `api/models/p_i_i_url_patterns_entry.go:103`; `handler/pii.go:158,183`.

**Replacement:** “Pattern order is significant: the first match determines inclusion/exclusion. Empty configuration scans all eligible URLs. `clear` ignores patterns; `replace` with omitted/empty patterns clears the list.”

Large-body truncation uses configured `max_body_size`, not invariably 64 KB; eligibility checks include HTTP-buffer length and content-type checks (`sockproxy_presidio.c:460`).

**P3 — implementation-gap: status and statistics cannot establish protection.**

Status omits `scan_mode`. Stats are hard-coded zero and serialize as `{}`. Without the `piidetection` build, configuration/status encounter a nil manager, but statistics still return their placeholder.

Evidence: [pii.go:240](../../api/restapi/handler/pii.go:240), `:265`; `pkg/presidio/stub.go:18`.

**Replacement:** “Returns stored configuration, not scanner readiness. Statistics collection is not implemented; empty/zero output is not an observed scan count.”

### H. LlamaFirewall

**L1 — implementation-gap: scanner/policy/performance controls are disconnected.**

Pattern arrays are discarded. Zero block threshold and zero cache TTL are ignored. Scanner flags are stored, but request scanning hard-codes `prompt_guard,regex`; no response-scanner caller was found. Fail policy/threshold use a separate C configuration whose setter has no located production caller. Timeout remains 15 seconds; cache and connection-pool settings do not configure the examined RPC client.

Evidence: [config.go:189](../../pkg/llamafirewall/config.go:189), [sockproxy_llamafirewall.c:228](../../loxilb-ebpf/common/sockproxy_llamafirewall.c:228), `:456`; `pkg/loxinet/ai_security.go:186`.

**Replacement:** “These fields currently describe stored configuration, not verified active scanner policy. URL filtering, scanner selection and advertised performance controls are not connected end-to-end.”

**L2 — implementation-gap: fail-closed is not reliable in the HTTP consumer.**

Scan errors return a nonzero result; the HTTP caller logs and continues instead of enforcing the returned block decision. Combined method/path/body content exceeding the 8192-byte buffer also follows an allow/error path.

Evidence: [sockproxy_http.c:6847](../../loxilb-ebpf/common/sockproxy_http.c:6847), `sockproxy_llamafirewall.c:210,240`.

**Disposition:** fix implementation before claiming fail-closed protection.

**L3 — implementation-gap and policy-needed: health, telemetry and transport claims.**

Management status/stats use separate unpopulated globals; updater callers were not found. Health reads that state rather than probing the server, and unhealthy results become generic errors rather than the advertised health payload. The disabled build returns inert status/stats. Scanner RPC uses insecure transport credentials.

Evidence: [config.go:400](../../pkg/llamafirewall/config.go:400), `handler/llamafirewall.go:293`, `pkg/llamafirewall/config_stub.go:141`, `pkg/loxinet/ai_security.go:205`.

**Replacement:** “Reports currently tracked state; this endpoint does not perform a live scanner probe. Telemetry is not connected to the scanner counters.” Define the trusted-network/TLS deployment policy separately.

## 3. Schema-field coverage ledger

The following **48 domain definitions plus six shared definitions** were examined. Grouped fields share the disposition identified above; inclusion here does not mean implementation support.

| Definitions | Fields accounted for |
|---|---|
| `User`, `UserSummary` | `username`, `password`—request only, `role`, `id`, `created_at`; body ID/time ignored on writes, path ID authoritative; A1–A4 |
| `LoginResponse`, `UpdateLicenseRequest` | `token`; `license_key`; A3/A5 |
| Four OAuth responses | `message`; login `id`, `token`, `refreshtoken`, `expiresin`; refresh `token`, `expiresin`; O1–O3 |
| `CorsEntry` | `cors` and each origin item; C1 |
| `ApiKeyCreateRequest` | `tenant_id`, `name`, `api_key`, `allowed_models`, `rate_limit_rps`, `burst_size`, `tokens_per_min`, `expires_at`, `enabled`; K1–K3 |
| `ApiKeyCreateResponse`, `ApiKeySummary` | `raw_key`, `key_id`; summary `key_id`, `tenant_id`, `name`, `allowed_models`, `rate_limit_rps`, `burst_size`, `tokens_per_min`, `created_at`, `expires_at`, `enabled`; false enabled is explicitly serialized |
| `TenantRateLimitMod`, `TenantRateLimitEntry`, `TenantModelRateLimit` | `tenant_id`, `rps`, `tokens_per_min`, `burst_pct`, `model_limits`; response `updated_at`; model `model`, `tokens_per_min`; K2/K3 |
| `Cert`, `SNICertificateEntry` | `certId`, `certPem`, `keyPem`, `chainPem`, `hostnames`; `hostname`, `certPath`; T1–T3 |
| `IPsecConfig`, `IPsecConfigMod` | `fastPathEnabled`, `hwOffloadEnabled`, `hwOffloadType`, `antiReplayEnabled`, `saLifetimeWarnSeconds`, `seqOverflowAction`, `mtu`; response `supportedAlgorithms`, `hwCapabilities.qatAvailable/qatDevices/dpaa2Available`; I2 |
| `IPsecTunnelMod` | `name`, `localIp`, `remoteIp`, `authMode`, `psk`, `localId`, `remoteId`, `certName`, `caCertName`, `ikeVersion`, `ikeEncryption`, `ikeIntegrity`, `ikeDhGroup`, `ikeLifetime`, `espEncryption`, `espIntegrity`, `espDhGroup`, `espLifetime`, `mark`, `tunnelMode`, `installPolicy`, `compress`, `mobike`, `rekey`, `reauth`, `auto`, `compatFallback`, `selector`, `dpd` |
| `IPsecSelector`, `IPsecDPD` | `srcCidr`, `dstCidr`, `protocol`, `srcPort`, `dstPort`; `action`, `delay`, `timeout`; I2 |
| `IPsecTunnel` | Corresponding tunnel configuration fields except PSK; `state`, `installedAt`, `bytesIn`, `bytesOut`, `packetsIn`, `packetsOut`, `lastRekeyAt`, `sasInstalled`; I3 |
| `IPsecTunnelActionMod`, `IPsecPeerConfig` | `action`; `tunnelName`, `ipsecConf`, `ipsecSecrets`, `notes`; I1/I4 |
| `IPsecSA` | `spi`, `tunnelName`, `direction`, `localIp`, `remoteIp`, `encryption`, `integrity`, `state`, `bytesIn`, `bytesOut`, `packetsIn`, `packetsOut`, `createdAt`, `expiresAt`, `sequenceNumber`, `replayWindow`; stubbed |
| `IPsecStats` | `totalTunnels`, `tunnelsUp`, `tunnelsDown`, `totalSas`, `totalBytesIn/Out`, `totalPacketsIn/Out`, `encryptErrors`, `decryptErrors`, `authErrors`, `replayErrors`, `seqOverflows`, `lastUpdated`; I3 |
| Five IPsec certificate definitions | Request `name`, `certificate`, `privateKey`, `passphrase`, `description`; metadata `name`, `subject`, `issuer`, `serial`, `notBefore`, `notAfter`, `san`, `keyUsage`, `installedAt`, `description`; validation `valid`, `errors`, `warnings`, `subject`, `issuer`, `notBefore`, `notAfter`, `keyAlgorithm`, `keySize`; CA request/response applicable subsets; I4 |
| `PIIConfigEntry` | `mode`, `direction`, `fail_mode`, `scan_mode`, `analyzer_url`, `anonymizer_url`, `score_threshold`, `timeout_ms`, `max_body_size`, `min_body_size`, `circuit_breaker`, `retry`, `enable_v2`, `default_operator`, `encryption_key`, `batch_size`; P1/P2 |
| `PIICircuitBreaker`, `PIIRetry` | `threshold`, `timeout_sec`, `success_threshold`; `max_retries`, `backoff_ms` |
| `PIIURLPatternsEntry`, `PIIURLPattern` | `mode`, `patterns`; `pattern`, `is_exclude`; P2 |
| `PIIStatusResponse`, `PIIStatsResponse` | `enabled`, base configuration fields through `retry`, `url_patterns`, `url_pattern_count`; `total_scans`, `pii_detected`, `pii_blocked`, `errors`; P3 |
| `LlamaFirewallConfigEntry` | `server_url`, `timeout_sec`, `fail_closed`, `block_threshold`, `cache_enabled`, `cache_ttl_sec`, `connection_pool_size`, `scan_patterns`, `skip_patterns`; L1/L2 |
| `LlamaFirewallScannersEntry`, `LlamaFirewallScannersStatus` | `prompt_guard`, `code_shield`, `regex`, `hidden_ascii`, `agent_alignment`, `pii_detection`; L1 |
| `LlamaFirewallStatusResponse` | `enabled`, `server_url`, `connected`, `fail_closed`, `block_threshold`, `scanners`, `cache_enabled`, `cache_ttl_sec`, `scan_patterns`, `skip_patterns`, `last_health_check`; timeout/pool readback absent |
| Four LlamaFirewall statistics definitions | `total_scans`, `requests_scanned`, `responses_scanned`, `threats_detected`, `requests_blocked`, `scan_errors`, `avg_latency_ms`, `cache_hits`, `scanner_stats`, `decisions`; six scanner members above, each `scans/detections/avg_latency_ms/errors`; decisions `allow/block/hitl`; L3 |
| `LlamaFirewallHealthResponse` | `healthy`, `server_url`, `connected`, `latency_ms`, `message`, `timestamp`; L3 |
| Shared definitions | `OperationResult.result`; `Error.code/sub-code/message/fields/details/result`; `PostSuccess.code/message`; `ErrorResponse.message`, `MessageResponse.message`, `SuccessResponse.message` |

Also reviewed: `BearerAuth`, shared management 401/403/503 responses, inline `enabled` request fields, list wrappers, and SNI’s documented inline count/reference fields.

**Shared doc correction:** PII/LlamaFirewall and several other mutations return `{"result":"Success"}`, not `PostSuccess.code/message`. Error bodies vary between generated middleware, shared `Error`, OAuth `message`, and SNI HTTP-200 error strings. The message-based classifier is not a stable typed error contract: `handler/common.go:95`.

## 4. Explicit UNREVIEWED / not established at this checkpoint

- **Excluded operations:** extras PATCH routes, main LB/operational areas owned elsewhere, and all other unassigned operations.
- **Unreviewed verification:** runtime authentication/revocation, browser OAuth/CORS, TLS handshakes/rotation, strongSwan/XFRM, scanner RPCs, GPU/Linux behavior, restart recovery and HA propagation.
- **Unreviewed dependency internals:** complete third-party middleware validation/error serialization. Exact generated binding-error status coverage is therefore not certified.
- **Incomplete security assurance:** exhaustive concurrency, crash consistency, filesystem/symlink attacks, certificate-chain policy, protocol/parser bypasses and every alternate dataplane call path.
- **Unresolved policy:** OAuth identity admission/admin mapping; secret-bearing viewer GET access; last-admin/bootstrap restrictions; negative quota values; certificate ownership/deletion dependencies; scanner transport trust.
- **No immutable WIP closure:** concurrent Swagger changes were observed. A final source/spec reconciliation is still needed after other owners finish.

No assigned operation was left unidentified in the inventory. However, this checkpoint should be reported as **static review delivered, documentation corrections pending, implementation gaps open, runtime qualification unperformed**—not “audit passed.”
