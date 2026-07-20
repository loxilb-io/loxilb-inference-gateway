#!/bin/bash

# Build Docker image for vLLM server

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "========================================="
echo "Building vLLM Docker Image"
echo "========================================="
echo ""

echo "Building vLLM CPU server image..."
echo "Note: This build may take 15-30 minutes as it compiles vLLM from source"
echo ""

docker build -f Dockerfile.server -t ghcr.io/loxilb-io/vllm-server:latest .

if [ $? -ne 0 ]; then
    echo "✗ Error: Failed to build vLLM server image"
    exit 1
fi
echo "✓ vLLM server image built successfully"
echo ""

echo "========================================="
echo "Build Complete!"
echo "========================================="
echo ""
echo "Image created:"
echo "  • ghcr.io/loxilb-io/vllm-server:latest"
echo ""
echo "Usage examples:"
echo ""
echo "Run vLLM Server:"
echo "  docker run -p 8000:8000 \\"
echo "    -e HF_TOKEN=\"your_token\" \\"
echo "    -e HUGGINGFACE_HUB_TOKEN=\"your_token\" \\"
echo "    -e VLLM_CPU_OMP_THREADS_BIND=0-\$((nproc-2)) \\"
echo "    --cap-add SYS_NICE \\"
echo "    --security-opt seccomp=unconfined \\"
echo "    --shm-size=4g \\"
echo "    ghcr.io/loxilb-io/vllm-server:latest -lc '"
echo "      python -m vllm.entrypoints.openai.api_server \\"
echo "        --model Qwen/Qwen3-0.6B \\"
echo "        --device cpu \\"
echo "        --dtype float32 \\"
echo "        --max-model-len 1024'"
echo ""
echo "Test with curl (from ghcr.io/loxilb-io/nettest:latest):"
echo "  # List models"
echo "  curl -s http://server:8000/v1/models | jq ."
echo ""
echo "  # Generate completion"
echo "  curl -s http://server:8000/v1/completions \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"model\": \"Qwen/Qwen3-0.6B\", \"prompt\": \"Hello\", \"max_tokens\": 64}' | jq ."
echo ""
echo "To push image to registry:"
echo "  docker push ghcr.io/loxilb-io/vllm-server:latest"
