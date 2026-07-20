---
scenario: "vllm-fullproxy-wrr"
github_url: "https://github.com/loxilb-io/loxilb-inference-gateway/blob/main/cicd/vllm-fullproxy-wrr/README.md"
---

# vLLM Fullproxy Load Balancing Test

This test validates loxilb's fullproxy mode with HTTPS termination for vLLM (Very Large Language Model) inference servers.

## Test Overview

### Architecture

```
┌──────────┐    HTTPS (2020)    ┌──────────┐    HTTP (8000)    ┌──────────┐
│          │ ───────────────────>│          │ ─────────────────>│  vLLM    │
│  Client  │                     │  LoxiLB  │ ─────────────────>│  Server  │
│  (l3h1)  │ <───────────────────│  (llb1)  │ <─────────────────│  Pool    │
│          │    HTTPS Response   │          │    HTTP Response  │ (3 nodes)│
└──────────┘                     └──────────┘                   └──────────┘
10.10.10.1                       10.10.10.254                   31.31.31.1
                                                                32.32.32.1
                                                                33.33.33.1
```

### Components

- **Client (l3h1)**: Test client using `ghcr.io/loxilb-io/nettest:latest` with curl and jq
- **LoxiLB (llb1)**: Load balancer with HTTPS termination at `10.10.10.254:2020`
- **vLLM Servers (l3ep1-3)**: Three vLLM inference servers running on HTTP port 8000
  - Model: Qwen/Qwen3-0.6B (small model for fast testing)
  - Device: CPU
  - Max tokens: 1024

### Load Balancing Configuration

- **Frontend**: HTTPS on `10.10.10.254:2020` (TLS termination)
- **Backend**: HTTP to three vLLM servers:
  - `31.31.31.1:8000` (weight: 1)
  - `32.32.32.1:8000` (weight: 1)
  - `33.33.33.1:8000` (weight: 1)
- **Mode**: Fullproxy (mode=4)
- **Security**: HTTPS with TLS termination (security=1)
- **Algorithm**: Round-robin distribution

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
./config.sh && ./validation.sh && ./rmconfig.sh
```

**Duration**: ~5-8 minutes
- Setup: ~2 minutes
- Model loading: ~2-3 minutes (per server)
- Testing: ~2-3 minutes

### Step-by-Step Execution

```bash
# 1. Setup environment
./config.sh

# 2. Run validation tests
./validation.sh

# 3. Cleanup
./rmconfig.sh
```

## What Gets Tested

### 1. vLLM API Endpoints

#### `/v1/models` - List Available Models
```bash
curl -sk https://10.10.10.254:2020/v1/models | jq .
```
- Tests: 6 requests to verify load balancing
- Expected: Model list containing "Qwen/Qwen3-0.6B"

#### `/v1/completions` - Text Completion
```bash
curl -sk https://10.10.10.254:2020/v1/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen/Qwen3-0.6B",
    "prompt": "What is 2+2?",
    "max_tokens": 32,
    "temperature": 0.2
  }' | jq .
```
- Tests: 3 different prompts
- Expected: Completion with generated text

#### `/v1/chat/completions` - Chat Completion
```bash
curl -sk https://10.10.10.254:2020/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen/Qwen3-0.6B",
    "messages": [{"role": "user", "content": "Hello!"}],
    "max_tokens": 32
  }' | jq .
```
- Tests: 3 chat interactions
- Expected: Chat response with message content

### 2. Load Balancing Verification

- **Round-robin distribution**: 12 rapid requests to verify even distribution
- **Backend health**: Direct access test to each backend server
- **Statistics**: LoxiLB connection statistics and distribution metrics

### 3. HTTPS/TLS Testing

- **Certificate verification**: Client verifies server certificate using CA cert
- **TLS termination**: HTTPS frontend, HTTP backend communication
- **Secure inference**: All client-to-LB traffic encrypted

## Test Validation Criteria

The test passes if:

✓ All 3 vLLM servers start successfully  
✓ `/v1/models` endpoint returns model information  
✓ `/v1/completions` generates text completions  
✓ `/v1/chat/completions` generates chat responses  
✓ Requests are distributed across all backends  
✓ HTTPS certificate validation succeeds  
✓ No connection errors or timeouts  

## Configuration Details

### Network Setup

| Component | IP Address | Port | Protocol |
|-----------|------------|------|----------|
| Client (l3h1) | 10.10.10.1 | - | - |
| LoxiLB VIP | 10.10.10.254 | 2020 | HTTPS |
| LoxiLB mgmt | - | 11111 | HTTP |
| vLLM Server 1 | 31.31.31.1 | 8000 | HTTP |
| vLLM Server 2 | 32.32.32.1 | 8000 | HTTP |
| vLLM Server 3 | 33.33.33.1 | 8000 | HTTP |

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
- `VLLM_CPU_KVCACHE_SPACE=4` - KV cache size (4GB)
- `VLLM_CPU_OMP_THREADS_BIND=0-N` - CPU thread binding
- `VLLM_USE_V1=0` - Use stable V0 engine
- `HF_TOKEN` - HuggingFace token (optional)

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
2. Reduce cache size: `VLLM_CPU_KVCACHE_SPACE=2`
3. Use smaller model
4. Run fewer concurrent servers (test with 2 instead of 3)
5. Reduce max context length

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

- **vllm-lb**: Basic load balancing without TLS
- **vllm-e2ehttps**: End-to-end HTTPS encryption
- **mcp-fullproxy**: Similar test pattern for MCP servers
- **grpc-fullproxy**: gRPC with HTTP/2 fullproxy
