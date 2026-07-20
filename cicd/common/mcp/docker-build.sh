#!/bin/bash

# Build Docker images for MCP server and client

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "========================================="
echo "Building MCP Docker Images"
echo "========================================="
echo ""

echo "Building MCP HTTP server image..."
docker build -f Dockerfile.server -t ghcr.io/loxilb-io/mcp-server:latest .

if [ $? -ne 0 ]; then
    echo "✗ Error: Failed to build MCP server image"
    exit 1
fi
echo "✓ MCP HTTP server image built successfully"
echo ""

echo "Building MCP HTTPS server image..."
docker build -f Dockerfile.server-https -t ghcr.io/loxilb-io/mcp-server-https:latest .

if [ $? -ne 0 ]; then
    echo "✗ Error: Failed to build MCP HTTPS server image"
    exit 1
fi
echo "✓ MCP HTTPS server image built successfully"
echo ""

echo "Building MCP client image..."
docker build -f Dockerfile.client -t ghcr.io/loxilb-io/mcp-client:latest .

if [ $? -ne 0 ]; then
    echo "✗ Error: Failed to build MCP client image"
    exit 1
fi
echo "✓ MCP client image built successfully"
echo ""

echo "========================================="
echo "Build Complete!"
echo "========================================="
echo ""
echo "Images created:"
echo "  • ghcr.io/loxilb-io/mcp-server:latest (HTTP)"
echo "  • ghcr.io/loxilb-io/mcp-server-https:latest (HTTPS)"
echo "  • ghcr.io/loxilb-io/mcp-client:latest"
echo ""
echo "Usage examples:"
echo ""
echo "HTTP Server:"
echo "  docker run -p 8080:8080 ghcr.io/loxilb-io/mcp-server:latest"
echo "  docker run -p 8080:8080 ghcr.io/loxilb-io/mcp-server:latest python3 server.py my-server 8080"
echo ""
echo "HTTPS Server:"
echo "  docker run -p 8443:8443 ghcr.io/loxilb-io/mcp-server-https:latest"
echo ""
echo "Client:"
echo "  docker run ghcr.io/loxilb-io/mcp-client:latest python3 client.py http://server:8080/mcp health"
echo "  docker run ghcr.io/loxilb-io/mcp-client:latest python3 client.py https://server:8443/mcp full"
echo ""
echo "To push images to registry:"
echo "  docker push ghcr.io/loxilb-io/mcp-server:latest"
echo "  docker push ghcr.io/loxilb-io/mcp-server-https:latest"
echo "  docker push ghcr.io/loxilb-io/mcp-client:latest"
