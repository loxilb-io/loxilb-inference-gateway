# AI API Key Management CICD Scenario

## Overview

Tests the AI Gateway API key management via the control-plane REST API.

> **Important:** Data-plane enforcement (HTTP 401/403 on invalid keys, HTTP 429
> on rate-limit exceeded) requires `llb_ai_validate_key` and
> `llb_ai_ratelimit_check` to be wired as call sites in
> `loxilb-ebpf/common/sockproxy.c`.  Those call sites are currently only
> referenced in a code comment (line 2674).  This scenario therefore tests
> **control-plane CRUD correctness only**.

## Topology

```
l3h1 (10.10.10.1) ──── llb1 (VIP 10.10.10.254) ──── l3ep1 (31.31.31.1:8080)
                         │
                    pg-ai (PostgreSQL 18.6)
                    (started on Docker bridge network)
```

- **llb1**: LoxiLB Enterprise with `--userservice` plus the `--mgmt-db-*` and `--aikey-db-*` stores
- **l3h1**: Test client
- **l3ep1**: Minimal HTTP backend (`tcp_server.js server1`)
- **LB rule**: VIP `10.10.10.254:2020` → `31.31.31.1:8080` (fullproxy, TCP)

## Tests

| # | Name | Endpoint | Expected |
|---|------|----------|----------|
| T1 | Create API key | `POST /netlox/v1/config/ai/apikey` | 201 + `raw_key: lxb_*` + `key_id` |
| T2 | Create a second key for another tenant | `POST /netlox/v1/config/ai/apikey` | 201 |
| T3 | List keys by tenant | `GET /netlox/v1/config/ai/apikey?tenant_id=cicd-tenant` | key name present, other-tenant absent |
| T4 | Get key by ID | `GET /netlox/v1/config/ai/apikey/{key_id}` | 200, has tenant_id & name, no key_hash |
| T5 | Set tenant rate limit | `POST /netlox/v1/config/ai/tenant/ratelimit` | 2xx |
| T6 | Get tenant rate limit | `GET /netlox/v1/config/ai/tenant/ratelimit/{tenant_id}` | rps=50, tokens_per_min=2000 |
| T7 | Basic connectivity | `curl http://10.10.10.254:2020/` | `server1` response |
| T8 | Revoke key + verify 404 | `DELETE /netlox/v1/config/ai/apikey/{key_id}` then GET | DELETE→204, GET→404 |

## Running

```bash
# From cicd/ai-apikey/
./config.sh               # set up containers + LB rule
./validation.sh           # run tests (exits 0 on success)
./rmconfig.sh             # tear down
```

## Cleanup if aborted

```bash
docker stop mysql-ai llb1 l3h1 l3ep1 2>/dev/null
docker rm   mysql-ai llb1 l3h1 l3ep1 2>/dev/null
rm -rf llb1_config
