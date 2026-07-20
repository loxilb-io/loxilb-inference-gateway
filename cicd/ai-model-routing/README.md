# AI Model Routing CICD Scenario

## Overview

Tests AI Gateway model-name based routing.  LoxiLB inspects either
the `X-Model` HTTP header or the `"model"` field in an OpenAI-compatible JSON
request body, then selects the matching backend pool.  Falls back to a wildcard
pool if no exact match exists; returns HTTP 503 if no rule matches at all.

The routing logic is **fully wired** in data plane (`find_endpoint_lpm` in
`loxilb-ebpf/common/sockproxy.c`).

## Topology

```
l3h1 (10.10.10.1)
      │
      └──── llb1 (VIP 10.10.10.254)
                 ├── port 2020 model_name=llama-70b  ──── l3ep1 (31.31.31.1:8080)
                 ├── port 2021 model_name=mistral-7b ──── l3ep2 (32.32.32.1:8080)
                 └── port 2022 model_name=""  (wildcard)   ──── l3ep3 (33.33.33.1:8080)
```

- **llb1**: LoxiLB Enterprise with `--userservice --databasehost <mysql_ip>`
- **l3h1**: Test client
- **l3ep{1,2,3}**: Minimal HTTP backends returning `server-{llama,mistral,wild}`

## LB Rules

| Port | `model_name` | Pool |
|------|--------------|------|
| 2020 | `llama-70b`      | l3ep1 |
| 2021 | `mistral-7b`     | l3ep2 |
| 2022 | `` (wildcard)    | l3ep3 |

## Tests

| # | Name | Input | Expected |
|---|------|-------|----------|
| T1 | X-Model header → llama-70b | `X-Model: llama-70b` on port 2020 | `server-llama` |
| T2 | JSON body → mistral-7b | `{"model":"mistral-7b",…}` on port 2021 | `server-mistral` |
| T3 | No model → wildcard | plain GET on port 2022 | `server-wild` |
| T4 | Unknown model → 503 | `X-Model: unknown-xyz` on port 2020 | HTTP 503 + `model_unavailable` |
| T5 | X-Model overrides JSON body | `X-Model: llama-70b` + `{"model":"mistral-7b"}` on port 2020 | `server-llama` |
| T6 | Concurrent requests | parallel to ports 2020/2021/2022 | separate backends |
| T7 | Empty X-Model → wildcard | `X-Model: ` on port 2022 | `server-wild` |
| T8 | Delete rule → 503/404 | delete llama-70b rule, request to port 2020 | HTTP 503 or 404 |
| T9 | Slash in model name | `llama/3.1` on port 2021 | 200/404/503 (not 500) |
| T10 | Wrong case (MISTRAL-7B) | `MISTRAL-7B` on port 2021 | not 200 (case-sensitive) |

## Running

```bash
./config.sh
./validation.sh
./rmconfig.sh
```

## Cleanup if aborted

```bash
docker stop llb1 l3h1 l3ep1 l3ep2 l3ep3 2>/dev/null
docker rm   llb1 l3h1 l3ep1 l3ep2 l3ep3 2>/dev/null
rm -rf llb1_config
```
