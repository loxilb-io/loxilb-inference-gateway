#!/bin/bash

# Build the header-reflecting echo backend image used by the L7 / KV-cache CICD scenarios.
# Tagged ghcr.io/loxilb-io/reflect-echo:latest and spawned via the `reflect-echo` dock-type
# in cicd/common.sh. Deps are vendored, so the build needs no network. Idempotent (layer cache).

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "Building reflect-echo backend Docker image..."
docker build -f Dockerfile -t ghcr.io/loxilb-io/reflect-echo:latest .

if [ $? -ne 0 ]; then
    echo "Error: Failed to build reflect-echo image"
    exit 1
fi

echo ""
echo "Docker image built successfully!"
echo "  Image: ghcr.io/loxilb-io/reflect-echo:latest"
echo ""
echo "Behaviour is driven per-container via env vars (ECHO_NAME / HEALTHZ_CODE / SLOW_MS / LISTEN_PORT)."
echo "To test:"
echo "  docker run --rm -e ECHO_NAME=server0 -p 8080:80 ghcr.io/loxilb-io/reflect-echo:latest"
