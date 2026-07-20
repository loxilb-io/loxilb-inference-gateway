# REST API Reference (LB rules / AI gateway / TLS)

> Consolidated endpoint + field reference for the load-balancing features.
> Base URL: `http://<host>:11111/netlox/v1`. Authoritative schema: `api/swagger.yml`
> (code-generated surface) plus `api/swagger-extras.yml` (raw configuration/debug
> endpoints — DPU debug and hardware counters, AI KV inventory, OPA policy watcher —
> served by the API middleware outside go-swagger codegen).
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
| `sel` | int | ✅ | LB algorithm: `0` rr · `3` persist · `8` CHWBL · `10` CHWBL-WRR |
| `adminStateUp` | `*bool` | ✅ | absent→enabled; `false`→drain |
| `connectionLimit` | uint32 | ✅ | per-rule concurrent ceiling; `0`=unlimited |
| `inactiveTimeout`, `persistTimeout` | uint32 | ✅ | seconds |
| `probeRetries`, `probeTimeout`, `probeReq`, `probeResp` | — | ✅ | health probe |
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
| `cert_id` | string | — | listener TLS material by certId |
| `backend_ca_cert_id`, `backend_client_cert_id` | string | — | backend re-encryption |
| `mtls_frontend` | object | — | `mode`/`client_ca_path`/`client_crl_path`/`client_cn_pattern`/`require_client_cn` |

### `serviceArguments` — AI gateway fields

All of these require `mode: 4` (fullproxy). ⚠️ Casing is significant and mixed by design:
snake_case (`pd_disagg_mode`, `sse_mode`, `model_name`, …) vs camelCase (`kvExactMode`,
`kvZmqPort`, …) — a mis-cased field is silently dropped.

**Cache-affinity (CHWBL) — no engine integration needed**

| Field | Type | Notes |
|---|---|---|
| `chwbl_prefix_hash_level` | int | prompt-prefix hash depth (`1`–`3`); used with `sel: 8`/`10` |
| `chwbl_mean_load_factor` | int | bounded-load spill threshold, % of mean (`125` = spill at 1.25×) |
| `chwbl_replication` | int | virtual nodes per endpoint on the hash ring |

**Prefill/Decode disaggregation**

| Field | Type | Notes |
|---|---|---|
| `pd_disagg_mode` | bool | split requests into prefill + decode legs (roles via `endpoints[].ep_role`) |
| `pd_cache_aware_mode` | bool | trie-based cache-affinity prefill selection |

**Engine-exact KV routing (ZMQ KV-cache events)**

| Field | Type | Notes |
|---|---|---|
| `kvExactMode` | int | `1` = P/D topology (vLLM) · `3` = single pool (SGLang) |
| `kvZmqPort` | int | base port of the engine's `--kv-events-config` publisher |
| `kvBlockSize` | int | must equal vLLM `--block-size` / SGLang `--page-size` |
| `kvHashAlgo` | string | `"sha256_cbor"` for vLLM; omit for SGLang (engine default) |
| `kvEngineType` | string | `"sglang"` selects the SGLang contract; immutable after create |
| `kvDpRankCount` | int | SGLang DP ranks (= `--dp-size`); rank *N* subscribes at `kvZmqPort`+*N* |
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
| `probeType` | string | `ping`/`tcp`/`http`/`https`/`tls-hello` |
| `probePort` | int | |
| `probeCAPath` | `*string` | custom CA for this probe |
| `probeVerify` | `*bool` | `nil`/`true`=verify; `false`=skip |
| `httpMethod`, `urlPath`, `expectedCodes`, `httpVersion`, `domainName` | string | content health monitor |

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
| `POST` | `/config/cert` | Upload PEM under a certId (certId optional → minted) |
| `PUT` | `/config/cert/{certId}` | Atomic zero-downtime rotation |
| `GET` | `/config/cert` | List (metadata only) |
| `GET` | `/config/cert/{certId}` | One cert's metadata + public cert/chain (never the key) |
| `DELETE` | `/config/cert/{certId}` | Remove material + SNI registration |

```jsonc
// POST/PUT body — model: Cert
{ "certId": "my-tls-cert",          // 1-63 chars, no path traversal
  "certPEM": "-----BEGIN CERTIFICATE-----\n...",
  "keyPEM":  "-----BEGIN PRIVATE KEY-----\n...",
  "chainPEM": "..." }               // optional intermediates
// response adds output-only:
//   "hostnames": ["example.com","*.example.com"]   (auto-derived from SAN/CN)
```

Errors: `400` malformed PEM / bad certId · `404` unknown certId (PUT/GET/DELETE) · `409` already
exists (POST — use PUT to rotate) · `503` registry/rotate CGO failure.

---

## 3. Common response codes

| Code | Meaning |
|---|---|
| `200` | OK |
| `204` | Deleted |
| `400` | Validation error / immutable field / malformed body |
| `401` | Auth (production) |
| `404` | Resource not found |
| `409` | Conflict (cert already exists) |
| `503` | Backend/CGO operation failed |

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
