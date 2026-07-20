# AI SSE Lifecycle and Token Quota CICD Scenario

## Overview

Tests AI Gateway SSE lifecycle features:

1. **`inactiveTimeOut` suppression** — when `sse_mode=true`, loxilb does NOT
   kill an SSE connection that appears idle (no bytes) during a chunked stream.
   Without this, a long LLM response would be cut off mid-stream.

2. **`[DONE]` terminator detection** — loxilb's SSE scanner detects the
   `data: [DONE]` sentinel and triggers a clean connection close, preventing
   keep-alive sockets from hanging indefinitely.

3. **Stream lifecycle bookkeeping** — `llb_ai_stream_start`, `llb_ai_stream_end`,
   `llb_ai_token_quota_consume`, and `llb_ai_record_request` are called at the
   correct points in sockproxy.c.

### Wiring Status

| Feature | C call site | Status |
|---------|-------------|--------|
| SSE inactiveTimeOut suppression | sockproxy.c ~line 1720 | **WIRED** |
| `[DONE]` scanner | sockproxy.c ~line 1780 | **WIRED** |
| `llb_ai_stream_start` | sockproxy.c line 1724 | **WIRED** |
| `llb_ai_token_quota_consume` | sockproxy.c line 1785 | **WIRED** |
| `llb_ai_stream_end` | sockproxy.c line 1788 | **WIRED** |
| `llb_ai_record_request` | sockproxy.c line 1790 | **WIRED** |
| `llb_ai_ratelimit_check` (429) | NOT called from sockproxy.c | **NOT WIRED** |

## Topology

```
l3h1 (10.10.10.1) ──── llb1 (VIP 10.10.10.254:2020) ──── l3ep1 (31.31.31.1:8000)
                         │                                    │
                    mysql-ai                         sse_mock_server.py
                   (MariaDB 10.11)                  (OpenAI-compat SSE)
```

**LB rule:**
- `sse_mode=true`
- `inactiveTimeOut=8` (low, to make suppression observable)
- `max_stream_duration_sec=120`
- `backend_keepalive_interval_sec=30`

## Mock Server

`sse_mock_server.py` is a minimal OpenAI-compatible SSE server with query
parameters to control test behaviour:

| Query param | Default | Meaning |
|-------------|---------|---------|
| `delay_ms` | 500 | ms between chunks |
| `chunks` | 10 | number of content chunks |
| `hang_sec` | 0 | slow-drip mode: emit 1 chunk/sec for N seconds |
| `fail_with` | 0 | return HTTP error code immediately |
| `model` | `mock-model` | model name echoed in response |
| `prompt_tokens` | 20 | reported usage |
| `completion_tokens` | 50 | reported usage |

Example:
```bash
# 15-second drip stream (tests inactiveTimeOut suppression)
curl -N -X POST http://10.10.10.254:2020/v1/chat/completions?hang_sec=15 \
  -H "Content-Type: application/json" \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"test"}]}'
```

## Tests

| # | Name | What checks |
|---|------|-------------|
| T1 | `inactiveTimeOut` suppression | 15s stream with 8s timeout. Elapsed ≥14s + `[DONE]` present |
| T2 | `[DONE]` clean close | 5-chunk stream completes, curl exits 0 |
| T3 | Usage tokens in final chunk | `usage.total_tokens=100` present |
| T4 | Sequential SSE requests | 3 back-to-back requests all complete |
| T5 | Token quota 429 (limitation) | Requests COMPLETE because `llb_ai_ratelimit_check` is not wired |
| T6 | `max_stream_duration_sec` smoke test | 5s stream < 120s cap completes normally |

## Running

```bash
./config.sh
./validation.sh
./rmconfig.sh
```

## Cleanup if aborted

```bash
docker stop mysql-ai llb1 l3h1 l3ep1 2>/dev/null
docker rm   mysql-ai llb1 l3h1 l3ep1 2>/dev/null
rm -rf llb1_config /tmp/sse_raw_key.txt
