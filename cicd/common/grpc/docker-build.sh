#!/bin/bash

# Build Docker images for gRPC server and client

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "Building gRPC server Docker image..."
docker build -f Dockerfile.server -t ghcr.io/loxilb-io/grpc-h2server:latest .

if [ $? -ne 0 ]; then
    echo "Error: Failed to build server image"
    exit 1
fi

echo ""
echo "Building gRPC client Docker image..."
docker build -f Dockerfile.client -t ghcr.io/loxilb-io/grpc-h2client:latest .

if [ $? -ne 0 ]; then
    echo "Error: Failed to build client image"
    exit 1
fi

echo ""
echo "Building HTTP server Docker image..."
docker build -f Dockerfile.http-server -t ghcr.io/loxilb-io/grpc-h1server:latest .

if [ $? -ne 0 ]; then
    echo "Error: Failed to build HTTP server image"
    exit 1
fi

echo ""
echo "Building HTTP client Docker image..."
docker build -f Dockerfile.http-client -t ghcr.io/loxilb-io/grpc-h1client:latest .

if [ $? -ne 0 ]; then
    echo "Error: Failed to build HTTP client image"
    exit 1
fi

echo ""
echo "Docker images built successfully!"
echo "  TLS Server image: ghcr.io/loxilb-io/grpc-h2server:latest"
echo "  TLS Client image: ghcr.io/loxilb-io/grpc-h2client:latest"
echo "  HTTP Server image: ghcr.io/loxilb-io/grpc-h1server:latest"
echo "  HTTP Client image: ghcr.io/loxilb-io/grpc-h1client:latest"
echo ""
echo "To test (TLS):"
echo "  1. Generate certificates: ./generate-certs.sh"
echo "  2. Run server: docker run -v \$(pwd)/certs:/certs -p 8080:8080 ghcr.io/loxilb-io/grpc-h2server:latest -host server1 -cert /certs/server.crt -key /certs/server.key"
echo "  3. Run client: docker run -v \$(pwd)/certs:/certs --network host ghcr.io/loxilb-io/grpc-h2client:latest -host localhost:8080 -cacert /certs/ca.crt"
echo ""
echo "To test (HTTP):"
echo "  1. Run server: docker run -p 8080:8080 ghcr.io/loxilb-io/grpc-h1server:latest -host server1 -port 8080"
echo "  2. Run client: docker run --network host ghcr.io/loxilb-io/grpc-h1client:latest -host localhost:8080"