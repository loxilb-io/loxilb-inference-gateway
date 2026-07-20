# Building vLLM Docker Images

This guide explains how to build and push vLLM Docker images for CICD testing.

## Prerequisites

- Docker with BuildKit support
- 8GB+ RAM for building
- 10GB+ free disk space
- Internet connection for downloading vLLM and models
- Access to push to `ghcr.io/loxilb-io` registry (for pushing images)

## Building Images

### Build vLLM Server Image

```bash
cd cicd/common/vllm
./docker-build.sh
```

This will:
1. Clone vLLM repository (v0.9.0.1)
2. Build vLLM from source with CPU support
3. Install dependencies and utilities
4. Create `ghcr.io/loxilb-io/vllm-server:latest`

**Build time:** 15-30 minutes (depends on system)

### Build Process Details

The Dockerfile performs these steps:

1. **Base Stage:**
   - Uses Ubuntu 20.04 as base
   - Installs build dependencies (git, python3, build-essential)

2. **vLLM Build:**
   - Clones vLLM v0.9.0.1
   - Builds using CPU-optimized Dockerfile
   - Targets `vllm-openai` stage (includes OpenAI API server)

3. **Final Stage:**
   - Based on vLLM build
   - Updates transformers library (<4.54.0)
   - Installs utilities (curl, jq, netcat)
   - Sets CPU-specific environment variables

## Pushing Images to Registry

### Prerequisites for Pushing

1. **Authenticate with GitHub Container Registry:**
   ```bash
   echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
   ```

2. **Ensure you have write access to netlox-dev organization**

### Push Server Image

```bash
docker push ghcr.io/loxilb-io/vllm-server:latest
```

## Testing Built Images Locally

### Test vLLM Server

```bash
# Start server (may take 30-60 seconds to load model)
docker run --rm --name vllm-test \
  -p 8000:8000 \
  -e HF_TOKEN="your_token_here" \
  -e HUGGINGFACE_HUB_TOKEN="your_token_here" \
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

### Test API Endpoints

```bash
# Wait for server to be ready (check logs)
docker logs vllm-test

# Test models endpoint
curl -s http://localhost:8000/v1/models | jq .

# Test completion endpoint
curl -s http://localhost:8000/v1/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen/Qwen3-0.6B",
    "prompt": "Explain vLLM in one sentence.",
    "max_tokens": 64,
    "temperature": 0.2
  }' | jq .
```

### Test with nettest Client

```bash
# Start test client
docker run --rm -it --network host \
  ghcr.io/loxilb-io/nettest:latest bash

# Inside container
curl -s http://localhost:8000/v1/models | jq .
```

## Customization

### Using Different Models

Edit `Dockerfile.server` and change the default model:

```dockerfile
# Change model in startup command
CMD python -m vllm.entrypoints.openai.api_server \
    --model meta-llama/Llama-2-7b-hf \  # Different model
    --device cpu \
    --dtype float32 \
    --max-model-len 2048  # Adjust context length
```

### Optimizing for Different CPUs

Adjust environment variables in Dockerfile:

```dockerfile
ENV VLLM_CPU_KVCACHE_SPACE=8  # Increase cache (if you have more RAM)
ENV VLLM_CPU_OMP_THREADS_BIND=0-15  # Use all CPU cores
```

### GPU Support (Future)

To build with GPU support, modify Dockerfile.server:

```dockerfile
# Use GPU dockerfile instead
RUN DOCKER_BUILDKIT=1 docker build -f docker/Dockerfile \
    --tag vllm-gpu-env \
    --target vllm-openai .
```

## Image Sizes

- **vllm-server:** ~8-10GB (includes Python, vLLM, and dependencies)
- Model files are downloaded at runtime (~1-2GB for Qwen3-0.6B)

## Troubleshooting

### Build Fails with OOM

```bash
# Increase Docker memory limit
# Docker Desktop: Settings > Resources > Memory (set to 8GB+)

# Or use swap during build
docker build --memory-swap -1 -f Dockerfile.server .
```

### Build is Too Slow

```bash
# Use BuildKit cache
export DOCKER_BUILDKIT=1

# Build with cache mount
docker build --cache-from ghcr.io/loxilb-io/vllm-server:latest \
  -f Dockerfile.server -t ghcr.io/loxilb-io/vllm-server:latest .
```

### Model Download Issues

```bash
# Set Hugging Face token to avoid rate limits
export HF_TOKEN="your_token_here"

# Or use mirror (for certain regions)
export HF_ENDPOINT="https://hf-mirror.com"
```

### Permission Issues When Pushing

```bash
# Re-authenticate
docker logout ghcr.io
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Ensure package permissions in GitHub
# Settings > Packages > vllm-server > Manage Actions access
```

## CI/CD Integration

For automated builds in CI/CD:

```yaml
- name: Build vLLM Server
  run: |
    cd cicd/common/vllm
    ./docker-build.sh

- name: Push to Registry
  run: |
    echo ${{ secrets.GITHUB_TOKEN }} | docker login ghcr.io -u ${{ github.actor }} --password-stdin
    docker push ghcr.io/loxilb-io/vllm-server:latest
```

## Version Management

### Tag Specific Versions

```bash
# Build with version tag
docker build -f Dockerfile.server \
  -t ghcr.io/loxilb-io/vllm-server:v0.9.0.1 \
  -t ghcr.io/loxilb-io/vllm-server:latest .

# Push both tags
docker push ghcr.io/loxilb-io/vllm-server:v0.9.0.1
docker push ghcr.io/loxilb-io/vllm-server:latest
```

### Update vLLM Version

Edit Dockerfile.server:

```dockerfile
# Change version
RUN git clone https://github.com/vllm-project/vllm.git && \
    cd vllm && \
    git checkout v0.10.0  # Update version here
```

## References

- [vLLM Docker Documentation](https://docs.vllm.ai/en/latest/serving/deploying_with_docker.html)
- [vLLM CPU Backend](https://docs.vllm.ai/en/latest/getting_started/cpu-installation.html)
- [Docker BuildKit](https://docs.docker.com/build/buildkit/)
