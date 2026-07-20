---
scenario: "vllm-fullproxy"
github_url: "https://github.com/loxilb-io/loxilb/blob/main/cicd/vllm-fullproxy/README.md"
---

# vLLM Fullproxy Load Balancing Test

This test validates loxilb's fullproxy mode with HTTPS termination for vLLM (Very Large Language Model) inference servers.

## Test Overview

### Architecture

```
┌──────────┐  HTTPS (2020-2023)  ┌──────────┐    HTTP (8000)    ┌──────────┐
│          │ ───────────────────>│          │ ─────────────────>│  vLLM    │
│  Client  │                     │  LoxiLB  │                   │  Server  │
│  (l3h1)  │ <───────────────────│  (llb1)  │ <─────────────────│  Pool    │
│          │    HTTPS Response   │          │    HTTP Response  │ (2 nodes)│
└──────────┘                     └──────────┘                   └──────────┘
10.10.10.1                       10.10.10.254                   31.31.31.1
                                                                32.32.32.1
```

### Components

- **Client (l3h1)**: Test client using `ghcr.io/loxilb-io/nettest:latest` with curl
- **LoxiLB (llb1)**: Load balancer with HTTPS termination, VIP `10.10.10.254`
- **vLLM Servers (l3ep1, l3ep2)**: Two vLLM inference servers running on HTTP port 8000
  - Model: Qwen/Qwen3-0.6B (small model for fast testing)
  - Device: CPU (core 0 for ep1, core 1 for ep2)
  - Max tokens: 1024
  - KV cache: `VLLM_CPU_KVCACHE_SPACE=1`, `VLLM_USE_V1=0`

### Load Balancing Configuration

Four LB rules are created, all in FullProxy mode (mode=4) with HTTPS (security=1):

| Port | Algorithm | CHWBL Parameters | Purpose |
|------|-----------|-----------------|---------|
| 2020 | Round-robin (sel=0) | — | Baseline / Error Handling / Resilience tests |
| 2021 | CHWBL (sel=8) | `prefix_hash_level=1` | Level 1: model-name hash |
| 2022 | CHWBL (sel=8) | `prefix_hash_level=2`, `mean_load_factor=125`, `replication=100` | Level 2: model+prompt prefix |
| 2023 | CHWBL (sel=8) | `prefix_hash_level=3`, `mean_load_factor=250`, `replication=200` | Level 3: full prefix hash |

All rules: `probetype=http`, `probeport=8000`, `probereq=/v1/models`, `probeTimeout=10`, `probeRetries=1`

## Running the Test

### Prerequisites

1. **Build vLLM Docker image** (first time only):
   ```bash
   cd ../common/vllm
   ./docker-build.sh
   # This takes 15-30 minutes
   ```

2. **Set HuggingFace token** (optional, recommended):
   ```bash
   export HF_TOKEN="hf_YOUR_TOKEN_HERE"
   ```

### Run Test

```bash
cd cicd/vllm-fullproxy
./config.sh && ./validation-all.sh && ./rmconfig.sh
```

**Duration**: ~35–45 minutes
- Setup + model loading: ~4–5 minutes (sequential: ep1 waits 90s, ep2 waits 60s)
- Level 1 suite + 90s sleep: ~8 min
- Level 2 suite + 60s sleep: ~5 min
- Level 3 suite + 60s sleep: ~12 min
- Failover suite + 30s sleep: ~10 min
- Error Handling suite + 30s sleep: ~5 min
- Concurrency suite + 30s sleep: ~8 min
- Resilience suite: ~8 min

### Step-by-Step Execution

```bash
# 1. Setup environment
./config.sh

# 2. Run full validation suite (7 categories)
./validation-all.sh

# 3. Run individual test categories
./validation-level1.sh     # CHWBL Level 1
./validation-level2.sh     # CHWBL Level 2
./validation-level3.sh     # CHWBL Level 3
./validation-failover.sh   # EP failover + re-stick
./validation-errorhandling.sh  # Error inputs + TLS
./validation-concurrency.sh    # Parallel requests
./validation-resilience.sh     # Large tokens, SSE, Unicode

# 4. Cleanup
./rmconfig.sh
```

## What Gets Tested

The full validation suite (`validation-all.sh`) runs 7 categories with inter-suite sleeps:

### 1. Level 1 — Basic CHWBL (port 2021, `prefix_hash_level=1`)

Tests that identical model+prompt requests are consistently routed to the same backend (KV-cache locality).

- Warmup: 3 requests to bring vLLM out of cold state
- 8 sequential same-prompt requests → all must reach ONE endpoint (delta on the other = 0)
- 5 sequential different-prompt requests → may distribute across both endpoints

### 2. Level 2 — Extended Hash (port 2022, `prefix_hash_level=2`, `mean_load_factor=125`, `replication=100`)

Same consistency checks with a wider hash prefix and bounded-load factor.

### 3. Level 3 — Full Hash (port 2023, `prefix_hash_level=3`, `mean_load_factor=250`, `replication=200`)

Full prefix hash with high replication count. Also tests temperature variation, max_tokens variation, high-load burst (10 requests), chat completions, and CHWBL with replication.

### 4. Failover (port 2021)

- **F1**: EP2 killed → loxilb detects unhealthy within ~10 s → all traffic → EP1
- **F2**: EP2 restored → loxilb detects healthy → traffic resumes to EP2
- **F3**: EP1 killed → all traffic → EP2 (single-EP operation)
- **F4/F4b**: After full recovery, CHWBL re-sticks same-prompt requests to one EP

### 5. Error Handling (port 2020)

- **E1**: Invalid JSON → HTTP 400
- **E2**: Plain HTTP to HTTPS port → rejected
- **E3**: GET to `/v1/completions` → HTTP 405
- **E4**: Missing required fields → HTTP 400/422
- **E5–E7**: Oversized payload, unknown endpoint, malformed Content-Type

### 6. Concurrency (port 2021)

- **P1a**: 20 parallel same-prompt requests → ≥18/20 succeed
- **P1b**: All 20 parallel same-prompt requests route to ONE backend (CHWBL strict hash)

### 7. Resilience (port 2020)

- **R1**: Large token response (64 tokens)
- **R2**: Unicode / multibyte content
- **R3**: SSE streaming (`stream: true`)
- **R4–R7**: Various Content-Type headers, extra headers, rapid-fire requests

### 8. HA pair (PHASE_L_HA=1, port 2020)

Opt-in HA-pair mode invoked via `PHASE_L_HA=1 ./config.sh && ./validation-ha.sh`. The harness spawns a 2-loxilb HA pair — llb1 at `10.10.10.254` (initial MASTER) + llb2 at `10.10.10.253` (initial BACKUP) — wired by keepalive over port 22222 with proxy-ARP on l3h1 + each EP netns. The bringup automatically deploys the locally-built `./loxilb` binary into both containers via `docker cp` (closing the harness-fidelity gap — the stale registry image has no SockproxySync code), using the same pattern as `scripts/probe-sockproxy-sync-wiring.sh`.

- **HA1**: llb1 (MASTER) emits `[SOCKPROXY_SYNC] consumerLoop start peer=` ≥ 1 within 10 s of bringup (fix verification — OnStateChange MASTER promotion respawns per-peer consumers).
- **HA2**: Both nodes establish bidirectional `XSync netRPC ... Connected`.
- **HA3**: Abrupt kill of the llb1 container → llb2 promotes to MASTER within 30 s, then emits a NEW `consumerLoop start peer=` line for the new peer set (proving the fix fires on every MASTER transition, not just at boot).

```bash
PHASE_L_HA=1 bash ./config.sh && bash ./validation-ha.sh; bash ./rmconfig.sh
```

This mode is NOT included in `validation-all.sh` — the HA topology has a different bringup contract (2 loxilbs + binary overlay) that the default single-loxilb validation flow does not satisfy. Design rationale and pattern derivation: see `.planning/phases/70.2-sockproxysync-consumer-respawn-on-master-promotion-harness-h/70.2-RESEARCH.md`.

## Test Validation Criteria

The full suite passes if all 7 categories pass:

✓ **Level 1**: Same-prompt requests consistently reach ONE backend  
✓ **Level 2**: Same consistency with hash level 2 and load factor 125%  
✓ **Level 3**: Same consistency with hash level 3 and replication 200  
✓ **Failover**: EP down detected in ≤10 s; traffic re-routed; CHWBL re-sticks after recovery  
✓ **Error Handling**: Invalid/malformed requests rejected with correct HTTP status codes  
✓ **Concurrency**: 20 parallel same-prompt requests → ≥18 succeed AND all route to ONE backend  
✓ **Resilience**: Large tokens, Unicode, SSE streaming, varied headers all handled correctly  

## Configuration Details

### Network Setup

| Component | IP Address | Port | Protocol |
|-----------|------------|------|----------|
| Client (l3h1) | 10.10.10.1 | — | — |
| LoxiLB VIP | 10.10.10.254 | 2020 | HTTPS (RR) |
| LoxiLB VIP | 10.10.10.254 | 2021 | HTTPS (CHWBL L1) |
| LoxiLB VIP | 10.10.10.254 | 2022 | HTTPS (CHWBL L2) |
| LoxiLB VIP | 10.10.10.254 | 2023 | HTTPS (CHWBL L3) |
| LoxiLB mgmt | — | 11111 | HTTP |
| vLLM Server 1 | 31.31.31.1 | 8000 | HTTP |
| vLLM Server 2 | 32.32.32.1 | 8000 | HTTP |

### vLLM Server Configuration

```bash
python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen3-0.6B \
  --device cpu \
  --dtype float32 \
  --max-model-len 1024 \
  --host 0.0.0.0 \
  --port 8000
```

Environment variables:
- `VLLM_CPU_KVCACHE_SPACE=1` - KV cache size (1GB, reduced for CPU c5.4xlarge)
- `VLLM_CPU_OMP_THREADS_BIND=0` or `1` - CPU core binding (ep1=core 0, ep2=core 1)
- `VLLM_USE_V1=0` - Use stable V0 engine
- `HF_TOKEN` / `HUGGINGFACE_HUB_TOKEN` - HuggingFace token (optional)

### TLS Certificates

Generated using `minica` with IP SAN for `10.10.10.254`:
- **CA cert**: `minica.pem` (copied to client and LoxiLB)
- **Server cert**: `10.10.10.254/cert.pem`
- **Server key**: `10.10.10.254/key.pem`

## Troubleshooting

### vLLM Servers Not Starting

**Symptom**: Servers fail to start or model loading times out

**Solutions**:
1. Check Docker memory limit (needs 8GB+ per server)
   ```bash
   docker stats
   ```
2. Verify HuggingFace access
   ```bash
   export HF_TOKEN="hf_YOUR_TOKEN"
   ```
3. Check server logs
   ```bash
   docker exec l3ep1 tail -f /tmp/vllm-server1.log
   ```
4. Try with smaller model or fewer servers

### Model Download Issues

**Symptom**: "Connection timeout" or "Rate limit exceeded"

**Solutions**:
1. Set HuggingFace token: `export HF_TOKEN="..."`
2. Check internet connectivity
3. Use HuggingFace mirror (if in certain regions):
   ```bash
   export HF_ENDPOINT="https://hf-mirror.com"
   ```
4. Pre-download model to cache

### Connection Failures

**Symptom**: "Connection refused" or "timeout" errors

**Solutions**:
1. Wait longer for model loading (90+ seconds)
2. Check server status:
   ```bash
   docker exec l3ep1 curl -s http://localhost:8000/v1/models
   ```
3. Verify network connectivity:
   ```bash
   docker exec l3h1 ping 31.31.31.1
   ```
4. Check LoxiLB rules:
   ```bash
   docker exec llb1 loxicmd get lb
   ```

### TLS Certificate Errors

**Symptom**: "certificate verify failed" or "SSL handshake failed"

**Solutions**:
1. Regenerate certificates:
   ```bash
   ./rmconfig.sh
   ./config.sh
   ```
2. Use `-k` flag to skip verification (testing only):
   ```bash
   curl -sk https://10.10.10.254:2020/v1/models
   ```
3. Check certificate paths in LoxiLB

### Slow Inference

**Symptom**: Requests take very long time

**Solutions**:
1. First request is always slower (model warm-up)
2. Reduce context length: `--max-model-len 512`
3. Use smaller model for testing
4. Adjust CPU thread binding
5. Consider GPU deployment for production

### Out of Memory

**Symptom**: vLLM crashes with OOM errors

**Solutions**:
1. Increase Docker memory limit to 12GB+
2. Reduce cache size: `VLLM_CPU_KVCACHE_SPACE=1` (already set)
3. Use smaller model
4. Reduce max context length (`--max-model-len 512`)

## Performance Notes

### Expected Latencies (CPU Mode)

- **Model loading**: 60-120 seconds (one-time per server)
- **First inference**: 5-15 seconds (warm-up)
- **Subsequent inferences**: 1-5 seconds (depending on prompt length)
- **Models endpoint**: <100ms (no inference)

### Resource Usage

Per vLLM server (Qwen3-0.6B on CPU):
- **RAM**: 4-6GB
- **CPU**: 50-100% during inference
- **Disk**: 1-2GB (model cache)

### Scaling Considerations

For production deployments:
- Use GPU for 10-100x faster inference
- Increase model cache size for longer contexts
- Consider model quantization (INT8/INT4) for efficiency
- Use larger instance types for bigger models
- Implement request queuing for burst traffic

## References

- [vLLM Documentation](https://docs.vllm.ai/)
- [vLLM OpenAI Compatible Server](https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html)
- [LoxiLB Fullproxy Mode](https://docs.loxilb.io/)
- [Qwen Models](https://huggingface.co/Qwen)

## Related Tests

- **httpsproxy**: Basic HTTPS fullproxy without CHWBL
- **e2ehttpsproxy**: End-to-end HTTPS with client cert verification
- **httpsproxy-mtls**: Mutual TLS fullproxy
- **ai-model-routing**: Model-based routing for AI inference
- **ai-sse-quota**: Streaming + quota for AI workloads
