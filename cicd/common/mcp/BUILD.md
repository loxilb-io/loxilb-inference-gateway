# Building MCP Docker Images

## Prerequisites

- Docker installed and running
- A checkout of the loxilb-inference-gateway repository

## Build Instructions

### Quick Build (All Images)

```bash
cd cicd/common/mcp
./docker-build.sh
```

This will build all three images:
- `ghcr.io/loxilb-io/mcp-server:latest` (HTTP server)
- `ghcr.io/loxilb-io/mcp-server-https:latest` (HTTPS server with minica)
- `ghcr.io/loxilb-io/mcp-client:latest` (Client)

### Build Individual Images

#### HTTP Server
```bash
cd cicd/common/mcp
docker build -f Dockerfile.server -t ghcr.io/loxilb-io/mcp-server:latest .
```

#### HTTPS Server
```bash
cd cicd/common/mcp
docker build -f Dockerfile.server-https -t ghcr.io/loxilb-io/mcp-server-https:latest .
```

#### Client
```bash
cd cicd/common/mcp
docker build -f Dockerfile.client -t ghcr.io/loxilb-io/mcp-client:latest .
```

## Image Details

### mcp-server (HTTP)
- **Base**: python:3.11-slim
- **Includes**: fastmcp, curl, netcat, net-tools
- **Entrypoint**: `python3 server.py [server_name] [port]`
- **Default Port**: 8080
- **Application**: `/app/server.py`

### mcp-server-https (HTTPS)
- **Base**: python:3.11-slim
- **Includes**: fastmcp, curl, netcat, net-tools, minica
- **Entrypoint**: `python3 server.py [server_name] [port] [ssl_options]`
- **Default Port**: 8443
- **Application**: `/app/server.py`
- **Features**: Certificate generation with minica

### mcp-client
- **Base**: python:3.11-slim
- **Includes**: fastmcp, curl, ping, net-tools
- **Entrypoint**: `python3 client.py [url] [test_type]`
- **Application**: `/app/client.py`

## Testing Images Locally

### Test HTTP Server
```bash
# Start server
docker run -d --name test-mcp-server -p 8080:8080 \
  ghcr.io/loxilb-io/mcp-server:latest

# Test with curl
curl http://localhost:8080/

# Test with client
docker run --rm --network container:test-mcp-server \
  ghcr.io/loxilb-io/mcp-client:latest \
  python3 client.py http://localhost:8080/mcp health

# Cleanup
docker stop test-mcp-server
docker rm test-mcp-server
```

### Test HTTPS Server
```bash
# Start server with custom name
docker run -d --name test-mcp-https -p 8443:8443 \
  ghcr.io/loxilb-io/mcp-server-https:latest \
  python3 server.py my-server 8443

# Test with curl (insecure)
curl -k https://localhost:8443/

# Cleanup
docker stop test-mcp-https
docker rm test-mcp-https
```

## Pushing to Registry

```bash
# Login to GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Push images
docker push ghcr.io/loxilb-io/mcp-server:latest
docker push ghcr.io/loxilb-io/mcp-server-https:latest
docker push ghcr.io/loxilb-io/mcp-client:latest
```

## Using Images in CICD Tests

The images are automatically used by the test scripts:

### HTTP Direct Test
```bash
cd cicd/mcp-direct-test
./config.sh  # Uses ghcr.io/loxilb-io/mcp-server:latest and mcp-client:latest
```

### HTTPS Direct Test
```bash
cd cicd/mcp-direct-test-https
./config.sh  # Uses ghcr.io/loxilb-io/mcp-server-https:latest and mcp-client:latest
```

## Rebuilding After Changes

If you modify the MCP server or client code:

1. **Rebuild the images**:
   ```bash
   cd cicd/common/mcp
   ./docker-build.sh
   ```

2. **Remove old containers** (if needed):
   ```bash
   docker ps -a | grep mcp | awk '{print $1}' | xargs docker rm -f
   ```

3. **Run tests** with new images:
   ```bash
   cd cicd/mcp-direct-test
   ./config.sh && ./validation.sh
   ```

## Troubleshooting

### Build Failures

**Issue**: "No module named 'fastmcp'"
```bash
# Solution: Check requirements.txt exists and is correctly formatted
cat cicd/common/mcp/requirements.txt
# Should contain: fastmcp>=2.0.0
```

**Issue**: "COPY failed"
```bash
# Solution: Make sure you're building from the correct directory
cd cicd/common/mcp
pwd  # Should show: .../loxilb-inference-gateway/cicd/common/mcp
```

### Runtime Issues

**Issue**: Container exits immediately
```bash
# Check logs
docker logs <container_name>

# Run interactively for debugging
docker run -it --entrypoint /bin/bash ghcr.io/loxilb-io/mcp-server:latest
```

**Issue**: "Port already in use"
```bash
# Find what's using the port
lsof -i :8080

# Or use different port
docker run -p 8081:8080 ghcr.io/loxilb-io/mcp-server:latest
```

### fastmcp Installation Issues

**Issue**: pip install fails
```bash
# The Dockerfile uses --no-cache-dir to avoid cache issues
# If problems persist, try:
docker build --no-cache -f Dockerfile.server -t ghcr.io/loxilb-io/mcp-server:latest .
```

## Image Sizes

Approximate sizes:
- **mcp-server**: ~200MB
- **mcp-server-https**: ~220MB (includes minica)
- **mcp-client**: ~200MB

## Development Workflow

1. **Modify code**: Edit files in `cicd/common/mcp/mcp-server/` or `mcp-client/`
2. **Rebuild images**: Run `./docker-build.sh`
3. **Test locally**: Use `docker run` commands above
4. **Run CICD tests**: Execute test scripts in `cicd/mcp-direct-test/`
5. **Push images**: Once validated, push to registry

## Environment Variables

The server supports these environment variables:

- `SERVER_NAME`: Override default server name (default: from CLI arg or "server")
- `PORT`: Override default port (default: from CLI arg or 8080)

Example:
```bash
docker run -e SERVER_NAME=prod-server -e PORT=9090 \
  ghcr.io/loxilb-io/mcp-server:latest
```

## Advanced Usage

### Custom Server Name and Port
```bash
docker run -p 9000:9000 ghcr.io/loxilb-io/mcp-server:latest \
  python3 server.py custom-server 9000
```

### HTTPS with Custom Certificates
```bash
docker run -p 8443:8443 \
  -v /path/to/certs:/app/certs \
  ghcr.io/loxilb-io/mcp-server-https:latest \
  python3 server.py my-server 8443 \
  --ssl-certfile /app/certs/cert.pem \
  --ssl-keyfile /app/certs/key.pem
```

### Client with Different Tests
```bash
# Health check
docker run --rm ghcr.io/loxilb-io/mcp-client:latest \
  python3 client.py http://server:8080/mcp health

# Full test suite
docker run --rm ghcr.io/loxilb-io/mcp-client:latest \
  python3 client.py http://server:8080/mcp full

# Specific tests
docker run --rm ghcr.io/loxilb-io/mcp-client:latest \
  python3 client.py http://server:8080/mcp echo

docker run --rm ghcr.io/loxilb-io/mcp-client:latest \
  python3 client.py http://server:8080/mcp models
```
