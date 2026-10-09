# REST API Reference (LB rules / AI gateway / TLS)

> Consolidated endpoint + field reference for the load-balancing features.
> Base URL: `http://<host>:11111/netlox/v1`. Authoritative schema: `api/swagger.yml`
> (code-generated surface) plus `api/swagger-extras.yml` (raw configuration/debug
> endpoints — DPU debug and hardware counters, AI KV inventory, OPA policy watcher —
> served by the API middleware outside go-swagger codegen). Note: the AI API-key `PATCH`
> operation also lives in `api/swagger-extras.yml` (hand-maintained extras), not the main spec.
> Auth is **off in CICD**; production applies LoxiLB's auth middleware (token / OAuth2).

When in doubt about a field name for a specific build, grep `api/swagger.yml` — this page summarizes
the stable surface but the spec is canonical.

---

## 1. Load balancer

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/config/loadbalancer` | Create/upsert a rule (accepts client-supplied `id`) |
| `GET` | `/config/loadbalancer/all` | List all (`?projectId=<id>` to filter) |
| `GET` | `/config/loadbalancer/externalipaddress/{ip}/port/{port}/protocol/{proto}` | Get by composite key |
| `GET` | `/config/loadbalancer/id/{id}` | Get by stable id |
| `GET` | `…/protocol/{proto}/status` | Operating status |
| `GET` | `…/protocol/{proto}/stats` | Live statistics |
| `PATCH` | `…/protocol/{proto}` | RFC 7386 merge-patch (in-place mutation) |
| `DELETE` | `…/protocol/{proto}` | Delete (drops in-flight) |

Instance-wide snapshot / persistence surface (all config domains, not just LB):

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/config/snapshot` | Download the versioned, checksummed instance snapshot document |
| `POST` | `/config/persist` | Dump live config to `{config-path}/snapshot.json` (atomic write; survives daemon restart) |
| `POST` | `/config/restore` | Staged restore of a snapshot document — dry-run by default, commit is explicit (rollback on failure) |

IPv6 in the path: bracket the literal — `…/externalipaddress/[2001:db8:aa::1]/port/2020/protocol/tcp`
(use `curl -g`).

### `serviceArguments` fields (selected)

| Field | Type | Mutable via PATCH | Notes |
|---|---|---|---|
| `externalIP`, `port`, `protocol` | — | ❌ immutable | composite key |
| `mode` | int | ❌ | `4` = fullproxy (required for L7/TLS/AI) |
| `security` | int | ❌ | `1` = TLS termination · `2` = end-to-end HTTPS (backend re-encrypt) |
| `id` | string | ❌ | client-supplied or minted UUIDv4 |
| `name` | string | ✅ | |
| `sel` | int | ✅ | LB algorithm: `0` rr · `3` persist · `8` CHWBL · `10` wrr-hash (weighted CHWBL) |
| `adminStateUp` | `*bool` | ✅ | absent→enabled; `false`→drain |
| `connectionLimit` | uint32 | ✅ | per-rule concurrent ceiling; `0`=unlimited. NAT rules: refused by drop at SYN time in the datapath. Fullproxy (`mode:4`) rules: enforced by the listener at accept — the (N+1)th client connection is reset immediately — and read back as `activeConnections` in `/stats` from the same gauge |
| `inactiveTimeOut` | uint32 | ✅ | seconds |
| `probeRetries`, `probeTimeout`, `probereq`, `proberesp` | — | ✅ | health probe (`probereq`/`proberesp` are lowercase here; the camelCase `probeReq`/`probeResp` forms belong to the `/config/endpoint` model only) |
| `allowedSources` | array | ✅ | `[{"prefix":"<cidr>"}]`. NAT rules: fw mark + source check in the datapath. Fullproxy (`mode:4`) rules: a per-VIP TC firewall fence (`allow <cidr>→VIP/32:port` pref 65000 per source, `drop 0.0.0.0/0→VIP/32:port` pref 64999) so a non-allowed SYN never reaches the kernel socket; the fence follows the rule's sources on replace and goes with the rule on delete, and is excluded from snapshots like every auto-generated source-check rule. Refused with 400 in proxy-only mode (no datapath to enforce it) |
| `projectId` | string | — | tenant/project; filterable |
| `annotations` | map | — | opaque; ≤32 keys / ≤256-char values |
| `timeoutMemberConnect` | uint32 (ms) | ✅ | |
| `timeoutMemberData` | uint32 (ms) | ✅ | |
| `timeoutTcpInspect` | uint32 (ms) | ✅ | |
| `alpn_protocols` | []string | — | `["h2","http/1.1"]` |
| `tls_versions` | []string | — | `["TLSv1.2","TLSv1.3"]` |
| `tls_ciphers` | string | — | OpenSSL cipher string |
| `hsts_max_age` | uint32 | — | seconds; `0`=off |
| `hsts_include_subdomains`, `hsts_preload` | bool | — | |
| `vip_qos_policy_id` | string | — | ref to `/config/policy` |
| `backend_ca_cert_id`, `backend_client_cert_id` | string | — | backend CA bundle (`/config/cert` usage `ca`, required with `mtls_backend.verify_server_cert`) / backend client certificate (usage `client`) by certId. An unknown ID or an entry of the wrong usage is refused (`400`). See [Backend TLS verification](25-backend-tls-verification.md) |
| `backend_tls_server_name` | string | — | DNS host name sent as SNI to the endpoints and, with verification on, required among the DNS names of their certificate. Empty: no SNI, a verified endpoint must carry its own address |
| `backend_tls_effective` | object | — | read-only, `mode=4` rules with `security=2`: the backend TLS policy the listener has installed, read from the data plane on every `GET` (`status` `applied` · `pending` · `failed` · `unsupported`, `verify`, `ca`, `client_cert`, `client_cert_id`, `server_name`, `generation`). Ignored on input. See [Backend TLS verification](25-backend-tls-verification.md#6-reading-what-is-installed) |
| `mtls_frontend` | object | — | frontend (client → gateway) mTLS: client-cert mode, CA/CRL paths, CN/SAN pattern |
| `mtls_backend` | object | — | backend (gateway → backend) TLS request: `verify_server_cert` only. `true` requires `backend_ca_cert_id` (`400` without it). The former path and inline-material keys are retired: refused on POST, never returned |
| `backend_protocol` | string | — | backend ALPN capability: `http1` (default) · `http2` · `both` |
| `half_close_mode` | string | — | fullproxy: a client that half-closes after its request. `hold` keeps it open until its answer is out (plaintext connections the kernel was never given to carry; with `sockMapMode` set, a client whose FIN comes before acceleration is not accelerated); `off` cuts it at its FIN; `inherit`/omitted runs on the process default (`defaultMode` at [`/config/halfclose`](#half-close-holds), `off` unless set) where the service could take `hold` itself, and `off` elsewhere. The bound and the allow/block switch are there too; GET's read-only `half_close_effective` says the mode in force and where it came from. `hold+parked` is refused (`400`) until available; `hold` is refused on other modes, on TLS services (`security` 1 or 2) and on P/D services (`pd_disagg_mode`), judged on the rule as a replace leaves it. Replace and `null` semantics as `fc_mode`; a change of this field alone applies in place. |

### `serviceArguments` — AI gateway fields

All of these require `mode: 4` (fullproxy). ⚠️ Casing is significant and mixed by design:
snake_case (`pd_disagg_mode`, `sse_mode`, `model_name`, …) vs camelCase (`kvExactMode`,
`kvZmqPort`, …) — a mis-cased field is silently dropped.

**Cache-affinity (CHWBL) — no engine integration needed**

| Field | Type | Notes |
|---|---|---|
| `chwbl_prefix_hash_level` | int | prompt-prefix hash depth (`1`–`3`); used with `sel: 8`/`10` |
| `chwbl_prefix_hash_flags` | int | bitmask of optional fields folded into the prefix hash (LoRA / image / audio / cache_salt / tools / session / RAG); `0` = auto-detect |
| `chwbl_enable_cache_salt` | bool | require a non-empty `cache_salt` (max 63 bytes) as a cache-key namespace input; this is not authentication or tenant isolation |
| `chwbl_mean_load_factor` | int | bounded-load spill threshold, % of mean (default `175` = 1.75×) |
| `chwbl_replication` | int | CHWBL virtual nodes per endpoint, or WRR_HASH exact total vnode budget (default `256`) |

> **What a bounded-load unit is.** The spill threshold is compared against one
> unit per unit of work the selector routed: a connection on HTTP/1.1
> (released when the connection closes) and a **stream** on HTTP/2 (released
> when that stream's backend mapping closes, or with the session if the
> connection goes first). A multiplexed HTTP/2 connection therefore never
> weighs more than the streams it has in flight, and closing it leaves the
> endpoint's load exactly where its remaining streams put it.

**Prefill/Decode disaggregation**

| Field | Type | Notes |
|---|---|---|
| `pd_disagg_mode` | bool | split requests into prefill + decode legs (roles via `endpoints[].ep_role`). The orchestration flavor derives from `kvEngineType`: empty/`"vllm"` = sequential vLLM machine (prefill → extract `kv_transfer_params` → decode); `"sglang"` = concurrent dual-dispatch (bootstrap triple injected, same body to both legs, decode streamed to the client, prefill drained); `"trtllm"` = sequential TensorRT-LLM machine (`context_only` prefill → extract `disaggregated_params` → `generation_only` decode, with context early-exit — [doc 20](20-tensorrt-llm-kv-cache-aware-routing.md)) |
| `pdBootstrapPort` | int | SGLang P/D only: the `--disaggregation-bootstrap-port` on every prefill EP; omitted/`0` resolves to `8998`, positive values are bounded to 1..65535. JSON null is rejected; PATCH does not support this field. Rejected unless `pd_disagg_mode` + `kvEngineType:"sglang"`. |
| `pd_cache_aware_mode` | bool | trie-based cache-affinity prefill selection |
| `pd_session_ttl_sec` | int32 | Tier-0 P/D sliding idle TTL in seconds; omitted/`0` uses 300s, positive values override it. Independent of `pd_cache_aware_mode`; not an engine KV or request timeout. No no-expiry mode. |
| `pd_prefill_timeout_sec` | int32 | P/D only: longest wait in seconds for the prefill stage before the Gateway answers 504 `pd_prefill_timeout`; omitted/`0` uses the process default (30 s, or `LLB_PD_PREFILL_TIMEOUT_SEC`), positive values up to `3600` override it for this rule. Changeable on a live rule by a replace POST. JSON null is rejected; PATCH does not support this field. Rejected unless `pd_disagg_mode`. |
| `pd_cache_threshold` | int | cache-match threshold `0`–`100`; lower = more aggressive cache routing. Create omission/`0` uses effective `20`; on replace/PATCH omission retains, explicit `0` resets to `20`, and explicit `null` is rejected. |
| `pd_balance_abs_threshold` | int | if max−min active connections exceeds this, bypass cache affinity. Create omission/`0` uses effective `3`; on replace/PATCH omission retains, explicit `0` resets to `3`, and explicit `null` is rejected. |

**Capacity admission queue** (AI-gateway services; the gate itself is described in [doc 23](23-ai-admission-flow-control.md))

| Field | Type | Notes |
|---|---|---|
| `fc_max_queue_depth` | int32 | requests that may wait for a capacity unit instead of being refused `429` when the pool's ceilings are reached; `0`/omitted leaves the process default (`LLB_FC_MAX_QUEUE_DEPTH`) in force; ceiling `65536`. HTTP/1.1 requests wait, HTTP/2 streams never do. Each waiter parks its client connection (about 1 MiB of receive buffer), so the depth is a memory bound: depth × 1 MiB; a WARNING is logged at apply when that exceeds half of the node's memory. Runtime-changeable by a replace `POST` (omission retains, explicit `0` resets to the default); `PATCH` does not reach FullProxy rules; explicit `null` is rejected. |
| `fc_max_queue_wait_ms` | int32 | the longest a request may wait, in milliseconds, before `504 admission_queue_timeout` (body carries `queued_ms`); required, greater than `0`, whenever `fc_max_queue_depth` is set; ceiling `3600000`; `0`/omitted with no depth leaves `LLB_FC_MAX_QUEUE_WAIT_MS` in force. Replace and `null` semantics as the depth. |
| `fc_mode` | string | the capacity admission gate's mode: `off`, `observe` or `enforce`; `inherit` or omitted on create runs on `LLB_FC_MODE`. On a replace an omitted mode is kept and `inherit` returns to the process default; `null` is rejected. Read back only when declared. |
| `fc_max_outstanding` | int32 | pool-wide ceiling on executing inference requests; `0`/omitted leaves `LLB_FC_MAX_OUTSTANDING` in force; at most `100000`. Replace and `null` semantics as the queue depth. |
| `fc_ep_max_inflight` | int32 | per-endpoint ceiling, normal role; `0`/omitted leaves `LLB_FC_EP_MAX_INFLIGHT` in force; at most `100000`. |
| `fc_prefill_max_inflight` | int32 | per-endpoint ceiling on prefill legs; `0`/omitted leaves `LLB_FC_PREFILL_MAX_INFLIGHT` (else `LLB_PD_MAX_INFLIGHT_PER_EP`) in force; at most `100000`. |
| `fc_decode_max_inflight` | int32 | per-endpoint ceiling on decode legs; `0`/omitted leaves `LLB_FC_DECODE_MAX_INFLIGHT` in force; at most `100000`. |
| `fc_telemetry_stale_ms` | int32 | how long the P/D scorers trust an endpoint's scraped queue depth without a refresh; `0`/omitted leaves `LLB_FC_TELEMETRY_STALE_MS`, else `30000`, in force; at most `3600000`. |
| `fc_adaptive` | string | `on` lets the pool-wide ceiling follow the engines: four fifths a second while an endpoint reports waiting requests or a time to first token over `fc_ttft_target_ms`, one unit back a second when fresh reports are clear, held (never widened) when they go stale; never above `fc_max_outstanding` nor below a quarter of it. `off` keeps it fixed; `inherit`/omitted runs on `LLB_FC_ADAPTIVE`. Replace and `null` semantics as `fc_mode`. |
| `fc_warmup_ms` | int32 | an endpoint back in service ramps its per-endpoint ceilings from a quarter to all of them over this window; `0`/omitted leaves `LLB_FC_WARMUP_MS` (else no ramp) in force; at most `3600000`. |
| `fc_tenant_max_share_pct` | int32 | the most of the service ceiling and of the queue depth one tenant (the credential-resolved tenant id; no id is one tenant) may hold, in percent, rounded up, at least one; over it a request waits for its own tenant's unit or is refused `429 admission_tenant_share` while other tenants admit. Needs `fc_max_outstanding`; `100` is no share; `0`/omitted leaves `LLB_FC_TENANT_MAX_SHARE_PCT` (else no share) in force; at most `100`. |
| `fc_expose_headers` | string | `on` puts `X-Loxilb-Admission-Inflight`, `-Queued` and `-Limit` on the head of every admitted inference response (HTTP/1.1 and HTTP/2, streamed ones included), the pool's counts as the head goes out; fields of those names from the backend are replaced. `off` leaves responses as sent; `inherit`/omitted runs on `LLB_FC_EXPOSE_HEADERS`. Refused (`400`) with `sockMapMode` `both` or `response`. Replace and `null` semantics as `fc_mode`. |
| `fc_ttft_target_ms` | int32 | with `fc_adaptive` on, a streamed response's time from admission to its first data event above this (an eighth-weighted average per endpoint) is backpressure; buffered responses are not measured; `0`/omitted leaves `LLB_FC_TTFT_TARGET_MS` (else TTFT unused) in force; at most `3600000`. |
| `fc_effective` | object (read-only) | on `GET` for AI-gateway services: the gate's resolved state on the rule's model pool as the data plane holds it: `mode` (`off`/`observe`/`enforce`), `max_outstanding`, `ep_max_inflight`, `prefill_max_inflight`, `decode_max_inflight`, `queue_depth`, `queue_wait_ms`, live `inflight` and `queued`, `queue_memory_bound_mib` (`queue_depth` × 1 MiB), `telemetry_stale_ms`, `adaptive`, `warmup_ms`, `ttft_target_ms`, `effective_max_outstanding` (the ceiling in force now), `adapt_state` (`off`/`open`/`tightened`/`frozen`), `adapt_reason` (`none`/`queued`/`ttft`/`clear`/`stale`), `warming_endpoints`, `tenant_max_share_pct` and live `tenants_active`, `expose_headers` (`on`/`off`), and `source` naming where each value came from (`rule`, `env` or `default`). Ignored on input. |

> **Always set `monitor: true` on a P/D rule.** Endpoint health is what
> demotes a dead role member out of P/D selection: without monitoring (and
> without a circuit-breaker policy) a prefill endpoint that dies keeps being
> selected, and every request answers `503 pd_pool_unavailable` indefinitely
> while the healthy decode endpoint sits idle. With monitoring on (TCP rules
> default to a TCP-connect probe on each endpoint's target port), the dead
> member is demoted within the probe cycle. Note the demotion outcome is
> deliberate fail-closed for a P/D-only pool: a pool with no healthy prefill
> (or no healthy decode) answers a typed `503 pd_pool_unavailable` rather
> than silently serving converged traffic on the surviving role — only
> pools that also carry `ep_role: 0` members fall back to normal-mode
> serving on those members.

**Resilience**

| Field | Type | Notes |
|---|---|---|
| `cb_enable` | bool | per-endpoint circuit breaker (fullproxy): 5 consecutive backend connect failures skip the endpoint until a 30s open-timeout expires and a half-open probe succeeds |

**Engine-exact KV routing (KV-cache events — ZMQ for vLLM/SGLang, HTTP drain for TensorRT-LLM)**

| Field | Type | Notes |
|---|---|---|
| `kvExactMode` | int | `1` = P/D topology (vLLM, or SGLang/TensorRT-LLM P/D with the matching `kvEngineType`) · `3` = single pool (SGLang or TensorRT-LLM converged) |
| `kvZmqPort` | int | base port of the engine's `--kv-events-config` publisher (vLLM/SGLang only). Omitted/`0` resolves to 5557; positive values are bounded to 1..65535. JSON null is rejected; PATCH does not support this field. TensorRT-LLM admits only the default declaration because its events drain over HTTP on the serving port. |
| `kvBlockSize` | int | `0`/omitted resolves to 16; positive values are bounded to 1..4096 and must equal vLLM `--block-size` / SGLang `--page-size` / TensorRT-LLM `tokens_per_block` (TRT default 32; enforced per endpoint via `/server_info` admission). JSON null is rejected; PATCH does not support this field. |
| `kvHashAlgo` | string | `"sha256_cbor"` for vLLM; omit for SGLang and TensorRT-LLM (engine defaults — `"blockhash_trtllm"` is implied by `kvEngineType:"trtllm"`) |
| `kvEngineType` | string | `"sglang"`, `"trtllm"` or `"llamacpp"` selects that engine's contract; empty = vLLM. Immutable after create. `"llamacpp"` is **plain-LB-only**: it admits no KV/P/D field at all (the engine has no KV event plane and no P/D disaggregation — every `kvExactMode`/`pd_disagg_mode`/`kvZmqPort`/`kvDpRankCount`/`kvBlockSize`/`kvHashAlgo` combination is rejected loudly); typing the rule buys the config-time guards plus the `/props` admission warn-probe — [doc 21](21-llamacpp-load-balancing.md) |
| `kvDpRankCount` | int | SGLang DP ranks (= `--dp-size`); omitted/`0` resolves to 1 and positive values are bounded to 1..8. Rank *N* subscribes at `kvZmqPort`+*N*, and the inclusive last port must not exceed 65535. JSON null is rejected; PATCH does not support this field. Must be 1 for `"trtllm"`. |
| `kvWarmupSec` | int | grace period before KV-exact selection engages |

**Streaming, sessions & model routing**

| Field | Type | Notes |
|---|---|---|
| `sse_mode` | bool | SSE-aware streaming (idle-timeout suppression, `[DONE]` detection); also arms API-key/rate-limit enforcement on the rule |
| `max_stream_duration_sec` | int | hard wall-clock cap per stream |
| `backend_keepalive_interval_sec` | int | TCP keepalive toward backend during streams |
| `session_header_name` | string | header-keyed stickiness (`"mcp-session-id"`, `"X-Conversation-Id"`) |
| `trace_type` | string | `"mcp"` tags proxy traces as MCP traffic |
| `model_name` | string | route by requested model (`X-Model` header or body `model`); `""` = catch-all; requires `path_prefix` + `path_match_mode` |
| `path_prefix`, `path_match_mode` | string | e.g. `"/"` + `"prefix"` |

**Deleting an L7-keyed rule.** `host`, `path_prefix`, `path_match_mode` and `model_name` are part of
the rule key, so a rule created with them is only matched by a delete that repeats them — use the
`/config/loadbalancer/hosturl/{host}/externalipaddress/{ip}/port/{port}/protocol/{proto}` route with
`path_prefix`, `path_match_mode` and `model_name` as query parameters (or `loxicmd delete lb --host
--path-prefix --path-match-mode --model-name`). A delete that omits a component the rule carries does
not match it and returns 404 `no-rule error`. Omitting `model_name` matches only a model-less rule:
with two rules on one VIP:port, one naming a model and one not, a delete without `model_name` removes
the catch-all and leaves the model rule serving. `DELETE /config/loadbalancer/name/{lb_name}` bypasses
the key and removes every rule with that name.


Guides: [KV/P·D tuning](11-hierarchical-kv-routing-config-tuning.md) ·
[SGLang](17-sglang-config-tuning.md) · [MCP](18-mcp-gateway.md) ·
[gateway controls](19-ai-gateway-controls.md). API-key / tenant-rate-limit endpoints
(`/config/ai/apikey`, `/config/ai/tenant/ratelimit`) are documented in
[19-ai-gateway-controls.md](19-ai-gateway-controls.md).

### `endpoints[]` (member) fields

| Field | Type | Notes |
|---|---|---|
| `endpointIP`, `targetPort` | — | identity key for reconcile |
| `ep_role` | int | AI/P·D pool role: `1` = prefill · `2` = decode · omit/`0` = plain |
| `nixl_port` | int | worker's NIXL side channel (= its `VLLM_NIXL_SIDE_CHANNEL_PORT`) |
| `weight` | int | `0` drains (no new conns, in-flight survive) |
| `backup` | bool | backup tier — active only when all primaries down |
| `monitorAddress` | string | probe a different address than traffic IP |
| `subnetId` | string | opaque round-trip |
| `httpMethod`, `urlPath`, `expectedCodes`, `httpVersion`, `domainName` | string | content health monitor |

Per-endpoint probe type/port (including `tls-hello`) are configured on the separate
`/config/endpoint` resource (`probeType`, `probePort`), not on the LB `endpoints[]` item.

### `secondaryVIPs[]`

`address` / `subnetId` / `portId` / `proto` — opaque structured round-trip (SCTP consumes at dataplane).

### Status / Stats response

```json
// /status
{ "adminStateUp": true, "operatingStatus": "ONLINE", "lastUpdated": "2026-06-03T12:34:56Z" }
// /stats
{ "activeConnections": 5, "bytesIn": 102400, "bytesOut": 204800, "totalConnections": 127 }
```

`operatingStatus` ∈ `ONLINE` / `OFFLINE` / `DEGRADED` / `ERROR` / `NO_MONITOR`. Status/stats values are
in-memory (reset on restart).

### Half-close holds

A client that sends its request and then shuts down its write side (a half-close) is saying
"that was my last request", not "forget the answer". On a fullproxy service whose
`half_close_mode` is `hold`, such a client is kept open until its answer is out, where the
gateway relays the answer itself: a plaintext connection whose traffic the kernel was never
given to carry (a TLS connection, or one already accelerated, is cut at its FIN as before).
A held client is closed once its answers are written, once the backend ends the answer's
connection, when no answer byte has reached it for the bound below, or on a release.

A FIN does not say why it was sent: a client that half-closed after its request and a
client that closed its socket and left look the same to the gateway. Under `hold` the one
that left is held like any other, its backend request runs to its end or to the bound, and
the usage of that answer is charged to the tenant as if it had been delivered. Do not set
`hold` on a service with token quotas or billing. Clients should not shut down their write
side before they have read the answer; under the default `off` the gateway cuts the
connection at the FIN.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/config/halfclose` | The settings in force: `{"allow": true, "capSeconds": 240, "defaultMode": "off"}` until set |
| `POST` | `/config/halfclose` | Set any of `allow` (new holds allowed or blocked, on every service), `capSeconds` (the idle bound, `1`–`3600`) and `defaultMode` (`off` or `hold`: the mode of the services that leave their own `half_close_mode` unset); an omitted field keeps its value, any other field is refused (`400`), and so are a `null`, `inherit` or `hold+parked` `defaultMode`; answers with the settings in force once applied; persisted |
| `POST` | `/config/halfclose/release` | Close every held client at the next pass (within a second); stores nothing |

Blocking stops new holds only; the clients already held finish as they started. To stop
everything at once, block, then release. The bound is on idleness: it restarts with every
write of the answer, so a long answer that keeps coming is never cut by it.

`defaultMode` reaches only the services that could take `hold` themselves: fullproxy, with
plaintext clients, not P/D. The others run `off` whatever it is. A change applies at once to
every service it reaches, for half-closes from then on. In force, a service's mode is decided
in this order: blocked (`allow` false) over its own `half_close_mode`, its own over the default.
A fullproxy service's GET carries it, read-only:

```json
"half_close_effective": {"mode": "off", "source": "default",
                         "not_applied": "not available on a P/D (pd_disagg_mode) service yet"}
```

`source` is `blocked`, `rule` or `default`; `not_applied` says why the default does not reach the
service.

Metrics: `loxilb_proxy_halfclose_held` (held now), `loxilb_proxy_halfclose_held_oldest_seconds`,
`loxilb_proxy_halfclose_hold_total`, `loxilb_proxy_halfclose_hold_ended_total{reason}` (`answered`,
`backend_first`, `expired`, `released`, `reset` — a client that reset while held, i.e. a cancel
that was waited on — `other`), `loxilb_proxy_halfclose_hold_expired_total{answer_started,stream}`,
`loxilb_proxy_halfclose_hold_refused_total{reason}`, `loxilb_proxy_halfclose_accel_skipped_total`
(connections left unaccelerated so that they could be held),
`loxilb_proxy_halfclose_hold_spurious_wakeups_total{kind}` (`eof_reentry` should stay 0), and the
settings as `loxilb_proxy_halfclose_hold_allowed` / `loxilb_proxy_halfclose_hold_cap_seconds` /
`loxilb_proxy_halfclose_hold_default_mode` (1 while the default is `hold`).

The L7 Proxy dashboard's collapsed "Half-close holds" row plots them, with the client FINs that
had an answer owed (`loxilb_proxy_halfclose_fin_total{outcome="owed"}`: the clients a hold is
for). Its first stats count over the dashboard's time range: holds taken, FINs with an answer
owed, holds that expired before their answer began, and EOF re-entries. The shipped alert rules
(`deploy/monitoring/prometheus/rules/loxilb-alerts.yml`, group `loxilb-halfclose`) fire on:

| Alert | Fires on | Do |
|---|---|---|
| `LoxilbHalfCloseHoldExpiredBeforeAnswer` | A held client closed by the bound before any byte of its answer reached it | The first byte is slower than the bound (raise `capSeconds`), or the FIN was a cancel; do not set `defaultMode` to `hold` while it fires |
| `LoxilbHalfCloseHoldEofReentry` | A held client's EOF handled a second time | A defect: report it with the gateway log; block and release if it repeats |
| `LoxilbHalfCloseHoldLongLived` | The oldest hold older than an hour and twice the bound, for 5m | A client fed very slowly, or a hold that does not end; block and release if the held count keeps rising |

---

## 2. Certificates (certId registry)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/config/cert` | Upload PEM under a certId (certId optional → minted); returns `201 Created` |
| `PUT` | `/config/cert/{certId}` | Atomic zero-downtime rotation |
| `GET` | `/config/cert/{certId}` | One cert's metadata + public cert/chain (never the key) |
| `DELETE` | `/config/cert/{certId}` | Remove material + SNI registration |

```jsonc
// POST/PUT body — model: Cert
{ "certId": "my-tls-cert",          // 1-63 chars, no path traversal
  "certPem": "-----BEGIN CERTIFICATE-----\n...",
  "keyPem":  "-----BEGIN PRIVATE KEY-----\n...",
  "chainPem": "..." }               // optional intermediates
// GET /config/cert/{certId} adds output-only:
//   "hostnames": ["example.com","*.example.com"]   (auto-derived from SAN/CN)
```

Errors: `400` malformed PEM / bad certId / rotation failure · `404` unknown certId
(PUT/GET/DELETE). A `POST` with an existing certId silently overwrites the stored material.

---

## 3. Common response codes

| Code | Meaning |
|---|---|
| `200` | OK |
| `201` | Created (`POST /config/cert`, `POST /config/ai/apikey`) |
| `204` | Deleted |
| `400` | Validation error / immutable field / malformed body |
| `401` | Auth (production) |
| `404` | Resource not found |
| `503` | Backend/CGO operation failed — **or** the boot-config gate (below) |

**Boot-config gate:** after a gateway restart, **all mutating REST calls** return `503` with a
`Retry-After: 5` header until the boot snapshot replay settles. This is expected, not an
outage — retry after the indicated interval; read-only GETs are unaffected.

---

## 4. Quick curl cheatsheet

```bash
H='Content-Type: application/json'
MP='Content-Type: application/merge-patch+json'
B=http://localhost:11111/netlox/v1

# LB rules: create, mutate, inspect, drain
curl -X POST $B/config/loadbalancer -H "$H" -d @rule.json
curl -X PATCH $B/config/loadbalancer/externalipaddress/20.20.20.1/port/2020/protocol/tcp -H "$MP" \
     -d '{"serviceArguments":{"sel":1}}'
curl -s $B/config/loadbalancer/externalipaddress/20.20.20.1/port/2020/protocol/tcp/stats
curl -X PATCH $B/config/loadbalancer/externalipaddress/20.20.20.1/port/2020/protocol/tcp -H "$MP" \
     -d '{"serviceArguments":{"adminStateUp":false}}'   # drain

# TLS cert lifecycle
curl -X POST $B/config/cert -H "$H" -d @cert.json
curl -X PUT  $B/config/cert/my-tls-cert -H "$H" -d @cert-new.json    # rotate
curl -X DELETE $B/config/cert/my-tls-cert
```
