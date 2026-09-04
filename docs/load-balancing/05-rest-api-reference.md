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
| `connectionLimit` | uint32 | ✅ | per-rule concurrent ceiling; `0`=unlimited |
| `inactiveTimeOut` | uint32 | ✅ | seconds |
| `probeRetries`, `probeTimeout`, `probereq`, `proberesp` | — | ✅ | health probe (`probereq`/`proberesp` are lowercase here; the camelCase `probeReq`/`probeResp` forms belong to the `/config/endpoint` model only) |
| `allowedSources` | array | ✅ | |
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
| `backend_ca_cert_id`, `backend_client_cert_id` | string | — | backend re-encryption |
| `mtls_frontend` | object | — | frontend (client → gateway) mTLS: client-cert mode, CA/CRL paths, CN/SAN pattern |
| `mtls_backend` | object | — | backend (gateway → backend) mTLS: server-cert verification, CA bundle, client cert/key |
| `backend_protocol` | string | — | backend ALPN capability: `http1` (default) · `http2` · `both` |

### `serviceArguments` — AI gateway fields

All of these require `mode: 4` (fullproxy). ⚠️ Casing is significant and mixed by design:
snake_case (`pd_disagg_mode`, `sse_mode`, `model_name`, …) vs camelCase (`kvExactMode`,
`kvZmqPort`, …) — a mis-cased field is silently dropped.

**Cache-affinity (CHWBL) — no engine integration needed**

| Field | Type | Notes |
|---|---|---|
| `chwbl_prefix_hash_level` | int | prompt-prefix hash depth (`1`–`3`); used with `sel: 8`/`10` |
| `chwbl_prefix_hash_flags` | int | bitmask of optional fields folded into the prefix hash (LoRA / image / audio / cache_salt / tools / session / RAG); `0` = auto-detect |
| `chwbl_enable_cache_salt` | bool | require a `cache_salt` field in requests (strict multi-tenant isolation) |
| `chwbl_mean_load_factor` | int | bounded-load spill threshold, % of mean (`125` = spill at 1.25×) |
| `chwbl_replication` | int | virtual nodes per endpoint on the hash ring |

**Prefill/Decode disaggregation**

| Field | Type | Notes |
|---|---|---|
| `pd_disagg_mode` | bool | split requests into prefill + decode legs (roles via `endpoints[].ep_role`). The orchestration flavor derives from `kvEngineType`: empty/`"vllm"` = sequential vLLM machine (prefill → extract `kv_transfer_params` → decode); `"sglang"` = concurrent dual-dispatch (bootstrap triple injected, same body to both legs, decode streamed to the client, prefill drained); `"trtllm"` = sequential TensorRT-LLM machine (`context_only` prefill → extract `disaggregated_params` → `generation_only` decode, with context early-exit — [doc 20](20-tensorrt-llm-kv-cache-aware-routing.md)) |
| `pdBootstrapPort` | int | SGLang P/D only: the `--disaggregation-bootstrap-port` on every prefill EP; `0` = SGLang's default `8998`. Rejected unless `pd_disagg_mode` + `kvEngineType:"sglang"` |
| `pd_cache_aware_mode` | bool | trie-based cache-affinity prefill selection |
| `pd_session_ttl_sec` | int | session-stickiness TTL (seconds) for P/D cache-aware routing; `0` = no automatic expiry |
| `pd_cache_threshold` | int | cache-match threshold `0`–`100`; lower = more aggressive cache routing (default `20`) |
| `pd_balance_abs_threshold` | int | if max−min active connections exceeds this, bypass cache affinity (default `3`) |

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
| `kvZmqPort` | int | base port of the engine's `--kv-events-config` publisher (vLLM/SGLang only; rejected for `"trtllm"`, whose events drain over HTTP on the serving port) |
| `kvBlockSize` | int | must equal vLLM `--block-size` / SGLang `--page-size` / TensorRT-LLM `tokens_per_block` (default 32; enforced per endpoint via `/server_info` admission) |
| `kvHashAlgo` | string | `"sha256_cbor"` for vLLM; omit for SGLang and TensorRT-LLM (engine defaults — `"blockhash_trtllm"` is implied by `kvEngineType:"trtllm"`) |
| `kvEngineType` | string | `"sglang"`, `"trtllm"` or `"llamacpp"` selects that engine's contract; empty = vLLM. Immutable after create. `"llamacpp"` is **plain-LB-only**: it admits no KV/P/D field at all (the engine has no KV event plane and no P/D disaggregation — every `kvExactMode`/`pd_disagg_mode`/`kvZmqPort`/`kvDpRankCount`/`kvBlockSize`/`kvHashAlgo` combination is rejected loudly); typing the rule buys the config-time guards plus the `/props` admission warn-probe — [doc 21](21-llamacpp-load-balancing.md) |
| `kvDpRankCount` | int | SGLang DP ranks (= `--dp-size`); rank *N* subscribes at `kvZmqPort`+*N*. Must be 1 for `"trtllm"` |
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
