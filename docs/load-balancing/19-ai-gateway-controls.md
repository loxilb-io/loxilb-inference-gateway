# AI Gateway Controls — API Keys, Rate Limiting, Model Routing, SSE Quotas

> **Audience:** operators exposing OpenAI-compatible LLM endpoints to multiple teams, tenants,
> or customers, who need authentication, quota, and per-model traffic policy **at the gateway**
> instead of inside every serving engine.
> **Scope:** API-key management and enforcement, per-tenant rate limiting, model-name routing,
> and SSE stream quotas.
>
> **For exact rule fields, treat the matching `cicd/ai-*/config.sh` and `validation.sh` as the
> source of truth** — they are the gated, working configurations and track the current build.

---

## 1. The control surfaces at a glance

| Control | What it does | Config surface | CICD scenario |
|---|---|---|---|
| **API keys** | Issue/revoke `lxb_…` keys; clients authenticate with `X-Api-Key`; per-key model allow-list + rate/burst/token limits | `POST/GET/PATCH/DELETE /netlox/v1/config/ai/apikey` (`PATCH` is defined in `api/swagger-extras.yml`, not the main spec) | [`cicd/ai-apikey`](../../cicd/ai-apikey) |
| **Tenant rate limits** | Aggregate RPS / tokens-per-minute ceiling across all keys of a tenant | `POST/GET /netlox/v1/config/ai/tenant/ratelimit` | [`cicd/ai-apikey`](../../cicd/ai-apikey) |
| **Model-name routing** | Route by the request's model (`X-Model` header or JSON body `model`) to different endpoint pools | `model_name` + `path_prefix` + `path_match_mode` on the LB rule | [`cicd/ai-model-routing`](../../cicd/ai-model-routing) |
| **SSE stream quotas** | Keep streams alive past idle timeouts, cap runaway streams, backend keepalive | `sse_mode`, `max_stream_duration_sec`, `backend_keepalive_interval_sec` on the LB rule | [`cicd/ai-sse-quota`](../../cicd/ai-sse-quota) |

All of these run on **fullproxy** rules (`mode: 4`). Model routing and SSE quotas are pure
rule fields with no extra infrastructure; API keys and tenant limits additionally need the
user-service database (§2.1).

---

## 2. API-key management & enforcement

### 2.1 Prerequisites

API keys are persisted in the gateway's user-service database. Start loxilb with:

```bash
loxilb --userservice --databasehost <mysql-ip>
```

backed by a MySQL/MariaDB instance. Administrative calls use the JWT auth flow:

```bash
# one-time: create an admin user, then log in for a Bearer token
curl -s -X POST http://127.0.0.1:11111/netlox/v1/auth/users -d '{...}'
TOKEN=$(curl -s -X POST http://127.0.0.1:11111/netlox/v1/auth/login \
  -d '{"username":"...","password":"..."}' | jq -r .token)
```

### 2.2 Turning on data-plane enforcement

Enforcement (key validation + rate limiting) engages on any fullproxy rule with
`sse_mode: true`:

```json
{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 2020, "protocol": "tcp",
    "mode": 4, "sse_mode": true, "inactiveTimeOut": 60, "host": "10.10.10.254"
  },
  "endpoints": [ { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 } ]
}
```

### 2.3 Key lifecycle (admin, Bearer-authenticated)

**Create** — returns the raw key exactly once:

```bash
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/ai/apikey \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "tenant_id": "team-a", "name": "prod-key",
  "allowed_models": ["llama-70b", "mistral-7b"],
  "rate_limit_rps": 50, "burst_size": 100, "tokens_per_min": 100000,
  "enabled": true }'
# → 201 { "key_id": "…", "raw_key": "lxb_…", … }   raw_key is shown only here
```

**List / get / update / delete:**

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:11111/netlox/v1/config/ai/apikey?tenant_id=team-a"      # list
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:11111/netlox/v1/config/ai/apikey/<key_id>               # get (never returns key material)
curl -s -X PATCH -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:11111/netlox/v1/config/ai/apikey/<key_id> \
  -d '{"allowed_models":["llama-70b"]}'                                     # update
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:11111/netlox/v1/config/ai/apikey/<key_id>               # → 204
```

### 2.4 Client-side usage & enforcement results

Clients send the key (and optionally the model) as headers to the VIP:

```bash
curl -s http://10.10.10.254:2020/v1/chat/completions \
  -H 'X-Api-Key: lxb_…' -H 'X-Model: llama-70b' -d '{...}'
```

| Condition | Response |
|---|---|
| Valid key, allowed model, within limits | `200` (proxied) |
| Missing/unknown key | `401` `invalid_api_key` |
| Model not in the key's `allowed_models` | `403` `model_not_allowed` |
| Per-key or per-tenant rate/token limit exceeded | `429` |

Backend connectivity failures surface through the same VIP and are easy to mistake for
quota errors: `502 backend_unreachable` / `503 no_healthy_backend` come from the proxy's
connect-failover path, not from key enforcement — see the
[troubleshooting guide](06-troubleshooting.md) §5.

## 3. Per-tenant rate limiting

Tenant-level ceilings apply across **all** keys of a tenant, on top of per-key limits:

```bash
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/ai/tenant/ratelimit \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"tenant_id": "team-a", "rps": 100, "tokens_per_min": 500000}'

curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:11111/netlox/v1/config/ai/tenant/ratelimit/team-a       # read back
```

Both layers return `429` on breach; per-key limits trip first if they are tighter.

---

## 4. Model-name routing

Route requests to different endpoint pools based on the model they ask for — the gateway reads
the `X-Model` header or the JSON body's `model` field. One rule per model on the same VIP/port
family; an empty `model_name` is the wildcard catch-all.

```bash
# llama-70b pool
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/loadbalancer -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 2020, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "10.10.10.254",
    "path_prefix": "/", "path_match_mode": "prefix",
    "model_name": "llama-70b", "inactiveTimeOut": 30 },
  "endpoints": [ { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 } ]}'

# mistral-7b pool → port 2021 with "model_name": "mistral-7b"
# catch-all      → port 2022 with "model_name": ""
```

Five fields are required per model-routing rule: `mode: 4`, `host`, `path_prefix`,
`path_match_mode`, `model_name`. No database or user-service is needed.

Combined with per-key `allowed_models` (§2), this gives tenant-scoped model access **and**
model-scoped backend pools from one gateway.

---

## 5. SSE stream quotas

LLM responses stream over SSE and can outlive any sane idle timeout — or run away entirely.
Three rule fields govern streaming behavior:

```json
{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 2020, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "10.10.10.254",
    "path_prefix": "/", "path_match_mode": "prefix", "model_name": "sse-test",
    "sse_mode": true,
    "max_stream_duration_sec": 120,
    "backend_keepalive_interval_sec": 30,
    "inactiveTimeOut": 60
  },
  "endpoints": [ { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 } ]
}
```

| Field | Meaning |
|---|---|
| `sse_mode: true` | Detect SSE responses; suppress `inactiveTimeOut` while a stream is active; recognize the `data: [DONE]` terminator |
| `max_stream_duration_sec` | Hard wall-clock cap per stream — terminates runaway streams |
| `backend_keepalive_interval_sec` | TCP keepalive interval toward the backend during long streams |

This is a **stream-duration** quota; token-count budgets are enforced per key/tenant via
`tokens_per_min` (§2–§3).

---

## 6. Try it

```bash
cd cicd/ai-model-routing   # no DB needed — model routing only
./config.sh && ./validation.sh && ./rmconfig.sh

cd ../ai-sse-quota         # SSE quota behaviors incl. the 10s runaway-cap probe
./config.sh && ./validation.sh && ./rmconfig.sh

cd ../ai-apikey            # full key lifecycle + 401/403/429 enforcement (brings up MariaDB)
./config.sh && ./validation.sh && ./rmconfig.sh
```

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `POST /config/ai/apikey` fails | loxilb started without `--userservice --databasehost` | Restart with both flags + reachable MySQL/MariaDB |
| Mutating calls return `503` + `Retry-After: 5` right after a gateway restart | Boot-config gate: writes are held until the boot snapshot replay settles | Expected — retry after the `Retry-After` interval; not an outage |
| Keys accepted but not enforced at the VIP | Rule lacks `sse_mode: true` / not `mode: 4` | Enforcement runs in the fullproxy AI path only |
| Requests hit the wrong model pool | Field casing | `model_name`, `path_prefix`, `path_match_mode` are snake_case — a mis-cased field is silently dropped |
| Streams cut at ~`inactiveTimeOut` | `sse_mode` not set | Set `sse_mode: true` on streaming rules |
| Long streams die at exactly N seconds | `max_stream_duration_sec` cap | Raise the cap; it is the intended runaway guard |
