# vLLM CICD Tests

This directory contains CICD infrastructure for loxilb load balancing with vLLM (Very Large Language Model) servers.

## Quick Start

**First time setup - Build Docker image:**
```bash
cd cicd/common/vllm
./docker-build.sh
```

**Note:** Building vLLM from source takes 15-30 minutes. The image will be cached for subsequent tests.

See [BUILD.md](BUILD.md) for detailed build instructions.

## Overview

These tests validate loxilb's ability to:
- Load balance across multiple vLLM inference servers
- Handle HTTP/1.1 and HTTP/2 traffic to vLLM OpenAI-compatible API
- Distribute inference requests using various load balancing algorithms
- Maintain session persistence for multi-turn conversations
- Handle large model serving workloads

## Architecture

### vLLM (Very Large Language Model Inference Engine)

We use [vLLM](https://github.com/vllm-project/vllm) for LLM inference because:
- **High throughput** - PagedAttention for efficient memory management
- **OpenAI-compatible API** - Drop-in replacement for OpenAI API
- **CPU support** - Can run on CPU-only environments for testing
- **Production-ready** - Used in production by many companies
- **Model flexibility** - Supports various model architectures (GPT, LLaMA, Qwen, etc.)

### Docker Images

We use pre-built Docker images (similar to gRPC/MCP tests) for reliability:
- **ghcr.io/loxilb-io/vllm-server:latest** - vLLM inference server (CPU-optimized)
- **ghcr.io/loxilb-io/nettest:latest** - Client for testing (with curl, jq, etc.)

See [BUILD.md](BUILD.md) for building and pushing images.

### vLLM Configuration

The server is configured for:
- **Model:** Qwen/Qwen3-0.6B (small model for testing)
- **Device:** CPU (no GPU required)
- **Max length:** 1024 tokens
- **API:** OpenAI-compatible REST API

## vLLM API Endpoints

The vLLM server exposes OpenAI-compatible endpoints:

### List Models
```bash
curl http://server:8000/v1/models
```

### Generate Completion
```bash
curl -X POST http://server:8000/v1/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen/Qwen3-0.6B",
    "prompt": "Explain vLLM in one sentence.",
    "max_tokens": 64,
    "temperature": 0.2
  }'
```

### Chat Completion
```bash
curl -X POST http://server:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen/Qwen3-0.6B",
    "messages": [
      {"role": "user", "content": "Hello!"}
    ],
    "max_tokens": 64
  }'
```

## Test Scenarios

```
├── vllm-lb/                # Basic load balancing across vLLM servers
├── vllm-fullproxy/         # Full proxy mode with session persistence
└── vllm-e2ehttps/          # End-to-end HTTPS with vLLM backends
```

## Running Tests

### Basic Load Balancing Test
```bash
cd cicd/vllm-lb
./config.sh && ./validation.sh && ./rmconfig.sh
```
- Tests round-robin distribution across multiple vLLM servers
- Validates model listing and completion endpoints
- Duration: ~3-5 minutes (includes model loading time)

### Full Proxy Test
```bash
cd cicd/vllm-fullproxy
./config.sh && ./validation.sh && ./rmconfig.sh
```
- Tests full proxy mode with session persistence
- Validates multi-turn conversations
- Duration: ~3-5 minutes

### End-to-End HTTPS Test
```bash
cd cicd/vllm-e2ehttps
./config.sh && ./validation.sh && ./rmconfig.sh
```
- Tests HTTPS encryption for vLLM API
- Validates secure inference endpoints
- Duration: ~3-5 minutes

## Performance Considerations

### CPU Mode
- vLLM is configured for CPU inference (no GPU required)
- Model loading takes ~30-60 seconds per server
- First inference request may be slower (warm-up)
- Subsequent requests are faster due to KV cache

### Model Selection
- Uses Qwen3-0.6B (600M parameters) for fast testing
- Larger models can be configured via `--model` parameter
- Adjust `--max-model-len` based on use case

### Environment Variables
- `VLLM_CPU_KVCACHE_SPACE=4` - KV cache size (GB)
- `VLLM_CPU_OMP_THREADS_BIND` - CPU thread binding for performance
- `VLLM_USE_V1=0` - Use stable V0 engine
- `HF_TOKEN` - Hugging Face token for private models

## Integration with common.sh

The vLLM server can be spawned in CICD tests using:

```bash
spawn_docker_host -t vllm-server -d vllm1
```

This will be integrated into `cicd/common.sh` similar to grpc and mcp servers.

## Troubleshooting

### Build Issues
- Ensure Docker BuildKit is enabled: `export DOCKER_BUILDKIT=1`
- Build may require 8GB+ RAM and takes 15-30 minutes
- Check disk space (requires ~10GB)

### Runtime Issues
- Model download requires internet connection
- First startup downloads model from Hugging Face (~1-2GB)
- Set `HF_TOKEN` for private models or rate limit avoidance
- Increase `--shm-size` if out of memory errors occur

### API Testing
- Wait 30-60 seconds after server start for model loading
- Check logs: `docker logs <container-name>`
- Verify port 8000 is accessible
- Use `jq` for pretty-printing JSON responses

## References

- [vLLM GitHub](https://github.com/vllm-project/vllm)
- [vLLM Documentation](https://docs.vllm.ai/)
- [OpenAI API Reference](https://platform.openai.com/docs/api-reference)
- [Qwen Models](https://huggingface.co/Qwen)
