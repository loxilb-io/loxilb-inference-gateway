# vLLM Quick Start Guide

This guide gets you running vLLM server quickly for testing.

## Prerequisites

- Docker installed
- 8GB+ RAM
- Internet connection (for downloading models)
- Optional: Hugging Face token for private models

## Step 1: Build Image (First Time Only)

```bash
cd cicd/common/vllm
./docker-build.sh
```

**Note:** This takes 15-30 minutes and only needs to be done once.

## Step 2: Start vLLM Server

### Basic Setup (No Token)

```bash
docker run --rm --name vllm1 \
  -p 8000:8000 \
  -e VLLM_CPU_OMP_THREADS_BIND=0-$(($(nproc)-2)) \
  --cap-add SYS_NICE \
  --security-opt seccomp=unconfined \
  --shm-size=4g \
  ghcr.io/loxilb-io/vllm-server:latest -lc '
    python -m vllm.entrypoints.openai.api_server \
      --model Qwen/Qwen3-0.6B \
      --device cpu \
      --dtype float32 \
      --max-model-len 1024'
```

### With Hugging Face Token (Recommended)

```bash
docker run --rm --name vllm1 \
  -p 8000:8000 \
  -e HF_TOKEN="hf_YOUR_TOKEN_HERE" \
  -e HUGGINGFACE_HUB_TOKEN="hf_YOUR_TOKEN_HERE" \
  -e VLLM_CPU_OMP_THREADS_BIND=0-$(($(nproc)-2)) \
  --cap-add SYS_NICE \
  --security-opt seccomp=unconfined \
  --shm-size=4g \
  ghcr.io/loxilb-io/vllm-server:latest -lc '
    python -m vllm.entrypoints.openai.api_server \
      --model Qwen/Qwen3-0.6B \
      --device cpu \
      --dtype float32 \
      --max-model-len 1024'
```

**Wait 30-60 seconds** for model to load. Watch logs:

```bash
docker logs -f vllm1
```

Look for: `Application startup complete` or `Uvicorn running on http://0.0.0.0:8000`

## Step 3: Test the Server

### List Models

```bash
curl -s http://localhost:8000/v1/models | jq .
```

Expected output:
```json
{
  "object": "list",
  "data": [
    {
      "id": "Qwen/Qwen3-0.6B",
      "object": "model",
      ...
    }
  ]
}
```

### Generate Completion

```bash
curl -s http://localhost:8000/v1/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen/Qwen3-0.6B",
    "prompt": "Explain vLLM in one short sentence.",
    "max_tokens": 64,
    "temperature": 0.2
  }' | jq .
```

### Chat Completion

```bash
curl -s http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen/Qwen3-0.6B",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ],
    "max_tokens": 64
  }' | jq .
```

## Step 4: Stop Server

```bash
docker stop vllm1
```

## Quick Test Script

Save this as `test-vllm.sh`:

```bash
#!/bin/bash

echo "Testing vLLM server..."
echo ""

echo "1. Listing models..."
curl -s http://localhost:8000/v1/models | jq '.data[0].id'
echo ""

echo "2. Generating completion..."
curl -s http://localhost:8000/v1/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen/Qwen3-0.6B",
    "prompt": "What is 2+2?",
    "max_tokens": 10
  }' | jq -r '.choices[0].text'
echo ""

echo "3. Chat completion..."
curl -s http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen/Qwen3-0.6B",
    "messages": [{"role": "user", "content": "Say hello"}],
    "max_tokens": 10
  }' | jq -r '.choices[0].message.content'

echo ""
echo "Test complete!"
```

Run it:
```bash
chmod +x test-vllm.sh
./test-vllm.sh
```

## Common Issues

### Server doesn't start
- Check Docker has 8GB+ memory allocated
- Ensure ports 8000 is available: `lsof -i :8000`
- Check logs: `docker logs vllm1`

### Model download fails
- Set Hugging Face token: `-e HF_TOKEN="your_token"`
- Check internet connection
- Try with smaller model first

### Out of memory
- Increase Docker memory limit
- Reduce cache size: `-e VLLM_CPU_KVCACHE_SPACE=2`
- Use smaller model

### Slow inference
- First request is always slower (warm-up)
- Adjust thread binding: `-e VLLM_CPU_OMP_THREADS_BIND=0-7`
- Consider GPU deployment for production

## Next Steps

- Read [README.md](README.md) for full documentation
- Explore CICD test scenarios in `cicd/vllm-*` directories
- Review [BUILD.md](BUILD.md) for custom builds
- Check vLLM documentation: https://docs.vllm.ai/

## Getting Hugging Face Token

1. Create account at https://huggingface.co/
2. Go to Settings > Access Tokens
3. Create new token with "Read" permission
4. Copy token (starts with `hf_...`)
5. Use in `-e HF_TOKEN="hf_..."`
