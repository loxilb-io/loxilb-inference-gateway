# MCP Multi-Server Fullproxy CICD Tests

This directory contains CICD tests for loxilb fullproxy load balancing with multiple MCP (Model Context Protocol) servers.

## Quick Start

**First time setup - Build Docker images:**
```bash
cd cicd/common/mcp
./docker-build.sh
```

See [BUILD.md](BUILD.md) for detailed build instructions.

## Overview

These tests validate loxilb's ability to:
- Load balance across multiple fastmcp servers
- Terminate HTTPS at the load balancer (HTTPS → HTTP)
- Perform end-to-end HTTPS encryption (HTTPS → HTTPS)
- Distribute requests using round-robin algorithm
- Handle MCP protocol tools, resources, and endpoints

## Test Sequence (Recommended Order)

**Before testing loxilb integration, validate basic MCP functionality:**

### 1. Direct Communication Test (mcp-direct-test)
```bash
cd cicd/mcp-direct-test
./config.sh && ./validation.sh && ./rmconfig.sh
```
- **Purpose**: Validate MCP client/server communication without loxilb (HTTP)
- **What it tests**: Basic networking, fastmcp installation, all MCP endpoints
- **Duration**: ~50 seconds
- **Why run first**: Isolates MCP components from loxilb complexity

See [../../mcp-direct-test/README.md](../../mcp-direct-test/README.md) for details.

### 2. Direct HTTPS Communication Test (mcp-direct-test-https)
```bash
cd cicd/mcp-direct-test-https
./config.sh && ./validation.sh && ./rmconfig.sh
```
- **Purpose**: Validate MCP client/server HTTPS/TLS communication without loxilb
- **What it tests**: TLS certificates, HTTPS transport, encrypted MCP communication
- **Duration**: ~65 seconds
- **Why run second**: Validates HTTPS functionality before loxilb integration

See [../../mcp-direct-test-https/README.md](../../mcp-direct-test-https/README.md) for details.

### 3. Full Proxy Test (mcp-fullproxy)
```bash
cd cicd/mcp-fullproxy
./config.sh && ./validation.sh && ./rmconfig.sh
```
- **Purpose**: Test HTTPS termination at loxilb with HTTP backends
- **What it tests**: HTTPS → HTTP load balancing, certificate handling, round-robin
- **Duration**: ~2 minutes
- **Run after**: mcp-direct-test-https passes

### 4. End-to-End HTTPS Test (mcp-e2ehttps)
```bash
cd cicd/mcp-e2ehttps
./config.sh && ./validation.sh && ./rmconfig.sh
```
- **Purpose**: Test end-to-end HTTPS encryption
- **What it tests**: HTTPS → HTTPS load balancing, backend TLS, certificate verification
- **Duration**: ~2 minutes
- **Run after**: mcp-fullproxy passes

---

**Recommended test order**: 
`mcp-direct-test` → `mcp-direct-test-https` → `mcp-fullproxy` → `mcp-e2ehttps`

## Architecture

### fastmcp (Python MCP Framework)

We use [fastmcp](https://github.com/jlowin/fastmcp) instead of Go-based MCP servers because:
- **Native HTTP/HTTPS support** - Built-in web server with Starlette/Uvicorn
- **Production-ready** - 21K+ stars, actively maintained by Prefect
- **MCP standard compliance** - Based on Anthropic's official MCP specification
- **Rich features** - OAuth, authentication, testing utilities
- **Python ecosystem** - Easy integration with AI/ML workloads

### Docker Images

We use pre-built Docker images (similar to gRPC tests) for reliability:
- **ghcr.io/loxilb-io/mcp-server:latest** - HTTP MCP server
- **ghcr.io/loxilb-io/mcp-server-https:latest** - HTTPS MCP server (with minica)
- **ghcr.io/loxilb-io/mcp-client:latest** - MCP client for testing

See [BUILD.md](BUILD.md) for building and pushing images.

### Test Scenarios

```
├── mcp-direct-test/        # Direct HTTP client→server (no loxilb)
├── mcp-direct-test-https/  # Direct HTTPS client→server (no loxilb)
├── mcp-fullproxy/          # HTTPS → HTTP (TLS termination at LB)
└── mcp-e2ehttps/           # HTTPS → HTTPS (end-to-end TLS)
```

## Test Setup

### Network Topology

```
┌─────────────┐
│   Client    │  HTTPS Request
│   (l3h1)    │  https://10.10.10.254:2020/mcp
└──────┬──────┘
       │
       │ HTTPS (TLS)
       ▼
┌─────────────────────────────────┐
│   LoxiLB (llb1)                 │
│   - Fullproxy Mode              │
│   - TLS Termination/Pass-through│
│   - Load Balancing              │
│   - VIP: 10.10.10.254:2020      │
└──────┬──────┬──────┬────────────┘
       │      │      │
       │ HTTP │ HTTP │ HTTP (mcp-fullproxy)
       │ or   │ or   │ or
       │ HTTPS│ HTTPS│ HTTPS (mcp-e2ehttps)
       ▼      ▼      ▼
  ┌────────┬────────┬────────┐
  │ MCP    │ MCP    │ MCP    │
  │ Server1│ Server2│ Server3│
  │ :8080  │ :8080  │ :8080  │
  │31.31.1 │32.32.1 │33.33.1 │
  └────────┴────────┴────────┘
```

### IP Configuration

| Host | IP Address | Role |
|------|------------|------|
| l3h1 | 10.10.10.1 | Client |
| llb1 | 10.10.10.254 | LoxiLB VIP |
| l3ep1 | 31.31.31.1 | MCP Server 1 |
| l3ep2 | 32.32.32.1 | MCP Server 2 |
| l3ep3 | 33.33.33.1 | MCP Server 3 |

## MCP Server Implementation

### Location
```
cicd/common/mcp/
├── mcp-server/
│   └── mcp-server.py      # FastMCP server with tools
└── mcp-client/
    └── mcp-client.py      # Test client
```

### MCP Server Tools

The MCP server exposes the following tools:

1. **health()** - Health check endpoint
2. **echo(message)** - Echo with server identification
3. **get_models()** - List available AI models
4. **chat_completion(prompt, model)** - Mock chat completion
5. **get_server_info()** - Server metadata

### MCP Server Resources

1. **config://info** - Server configuration
2. **status://health** - Server status

## Test Scenarios

### 1. mcp-fullproxy (HTTPS → HTTP)

**Purpose:** Test HTTPS termination at load balancer with HTTP backends

**Configuration:**
- Frontend: HTTPS on 10.10.10.254:2020
- Backend: HTTP on port 8080
- LB Mode: fullproxy
- Security: https (TLS termination)

**Tests:**
- Health check round-robin (12 requests)
- Echo endpoint validation
- Get models endpoint
- Chat completion endpoint
- Server info endpoint
- Full test suite
- Load distribution verification

**Run:**
```bash
cd cicd/mcp-fullproxy
./config.sh      # Setup
./validation.sh  # Test
./rmconfig.sh    # Cleanup
```

### 2. mcp-e2ehttps (HTTPS → HTTPS)

**Purpose:** Test end-to-end HTTPS encryption

**Configuration:**
- Frontend: HTTPS on 10.10.10.254:2020
- Backend: HTTPS on port 8080 (with uvicorn SSL)
- LB Mode: fullproxy
- Security: e2ehttps (end-to-end TLS)

**Tests:**
- End-to-end HTTPS health checks
- Echo endpoint with E2E encryption
- Model listing with E2E TLS
- Chat completion with E2E TLS
- Backend certificate verification
- Load distribution verification

**Run:**
```bash
cd cicd/mcp-e2ehttps
./config.sh      # Setup
./validation.sh  # Test
./rmconfig.sh    # Cleanup
```

## MCP Client Usage

### Command-line Interface

```bash
# Health check
python3 mcp-client.py https://10.10.10.254:2020/mcp health

# Echo test
python3 mcp-client.py https://10.10.10.254:2020/mcp echo

# Get models
python3 mcp-client.py https://10.10.10.254:2020/mcp models

# Chat completion
python3 mcp-client.py https://10.10.10.254:2020/mcp chat

# Server info
python3 mcp-client.py https://10.10.10.254:2020/mcp info

# Full test suite
python3 mcp-client.py https://10.10.10.254:2020/mcp full
```

## Dependencies

### MCP Servers (l3ep1, l3ep2, l3ep3)
- Python 3.8+
- fastmcp (pip install fastmcp)
- uvicorn[standard] (for HTTPS support)

### MCP Client (l3h1)
- Python 3.8+
- fastmcp (pip install fastmcp)
- curl (for direct HTTP testing)

### LoxiLB (llb1)
- TLS certificates (auto-generated by minica)
- Fullproxy mode support
- HTTPS/E2EHTTPS security modes

## Certificate Management

Certificates are automatically generated using `minica`:

**mcp-fullproxy:**
- Frontend: 10.10.10.254 (loxilb only)

**mcp-e2ehttps:**
- Frontend: 10.10.10.254 (loxilb)
- Backends: 31.31.31.1, 32.32.32.1, 33.33.33.1 (all MCP servers)

## Expected Results

### Successful Test Output

```
SCENARIO-mcp-fullproxy
Health: OK
Health: OK
Health: OK
...
Echo: server1:test-message
Echo: server2:test-message
Echo: server3:test-message
Models: ['server1-gpt-4', 'server1-gpt-3.5-turbo', 'server1-claude-3']
Chat: {"server": "server1", "model": "test-model", ...}
Test Summary
Passed: 6/6
  ✓ health
  ✓ echo
  ✓ models
  ✓ chat
  ✓ server_info
  ✓ resources
SCENARIO-mcp-fullproxy [OK]
```

### Load Distribution

Round-robin distribution should show requests distributed evenly across:
- server1 (31.31.31.1:8080)
- server2 (32.32.32.1:8080)
- server3 (33.33.33.1:8080)

Verify with:
```bash
docker exec -i llb1 loxicmd get lb -o wide
```

## Troubleshooting

### MCP Server Not Starting

Check logs:
```bash
docker exec -i l3ep1 cat /tmp/mcp-server1.log
```

Verify Python and fastmcp:
```bash
docker exec -i l3ep1 python3 --version
docker exec -i l3ep1 pip3 list | grep fastmcp
```

### Connection Refused

Check if MCP server is listening:
```bash
docker exec -i l3ep1 curl http://localhost:8080/mcp
docker exec -i l3ep1 netstat -tlnp | grep 8080
```

### Certificate Errors

Regenerate certificates:
```bash
rm -rf *.pem 10.10.10.254 31.31.31.1 32.32.32.1 33.33.33.1
./minica -ip-addresses 10.10.10.254
```

### Import Errors

Reinstall fastmcp:
```bash
docker exec -i l3ep1 pip3 install --break-system-packages --force-reinstall fastmcp
```

## Comparison with Existing Tests

### Similar Tests
- `httpsproxy/` - HTTPS → HTTP (Node.js tcp_server.js)
- `e2ehttpsproxy/` - HTTPS → HTTPS (Node.js tcp_server.js)
- `http2ep/` - HTTP/2 servers (Go-based)

### Key Differences
- **Protocol:** MCP (Model Context Protocol) vs HTTP/TCP
- **Framework:** fastmcp (Python) vs Node.js/Go
- **Features:** Tools, resources, prompts vs simple request/response
- **Use Case:** AI/LLM services vs generic HTTP services

## Future Enhancements

Potential additional test scenarios:

1. **mcp-fullproxy-persist/** - Session persistence testing
2. **mcp-fullproxy-prefix/** - Path prefix routing
3. **mcp-fullproxy-ha/** - High availability with 2 loxilb instances
4. **mcp-auth/** - OAuth/authentication testing
5. **mcp-grpc/** - gRPC-based MCP servers

## References

- [fastmcp GitHub](https://github.com/jlowin/fastmcp)
- [fastmcp Documentation](https://gofastmcp.com/)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [LoxiLB Documentation](https://docs.loxilb.io/)
