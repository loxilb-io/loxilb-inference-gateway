# Quick Start Guide - MCP CICD Tests

## What Was Implemented

Complete CICD test suite for loxilb fullproxy with multiple fastmcp servers:

### 1. FastMCP Server Application
**Location:** `cicd/common/mcp/mcp-server/mcp-server.py`

Python-based MCP server using the fastmcp framework with:
- Health check tool
- Echo tool (with server identification)
- Get models tool
- Chat completion tool
- Server info tool
- Config and status resources

### 2. FastMCP Client Application
**Location:** `cicd/common/mcp/mcp-client/mcp-client.py`

Test client for validating MCP endpoints:
- Individual test modes: health, echo, models, chat, info, resources
- Full test suite mode
- Supports HTTPS connections
- Command-line interface

### 3. Test Scenario: mcp-fullproxy (HTTPS → HTTP)
**Location:** `cicd/mcp-fullproxy/`

Tests loxilb HTTPS termination with HTTP backends:
- **config.sh** - Setup 3 MCP servers, loxilb with HTTPS VIP
- **validation.sh** - Run all MCP endpoint tests
- **rmconfig.sh** - Cleanup

### 4. Test Scenario: mcp-e2ehttps (HTTPS → HTTPS)
**Location:** `cicd/mcp-e2ehttps/`

Tests end-to-end HTTPS encryption:
- **config.sh** - Setup 3 HTTPS MCP servers, loxilb with HTTPS VIP
- **validation.sh** - Run all MCP endpoint tests
- **rmconfig.sh** - Cleanup

## Quick Test Commands

### Run mcp-fullproxy Test
```bash
cd cicd/mcp-fullproxy
./config.sh       # Setup (takes ~30 seconds)
./validation.sh   # Test (takes ~60 seconds)
./rmconfig.sh     # Cleanup
```

### Run mcp-e2ehttps Test
```bash
cd cicd/mcp-e2ehttps
./config.sh       # Setup (takes ~45 seconds)
./validation.sh   # Test (takes ~60 seconds)
./rmconfig.sh     # Cleanup
```

## Manual Testing

### Test Individual Endpoints

Once config.sh is running:

```bash
# From host machine or l3h1 container

# Health check
curl -k https://10.10.10.254:2020/mcp

# Or using the Python client
docker exec -i l3h1 python3 /root/mcp-client.py https://10.10.10.254:2020/mcp health
docker exec -i l3h1 python3 /root/mcp-client.py https://10.10.10.254:2020/mcp echo
docker exec -i l3h1 python3 /root/mcp-client.py https://10.10.10.254:2020/mcp models
docker exec -i l3h1 python3 /root/mcp-client.py https://10.10.10.254:2020/mcp chat
docker exec -i l3h1 python3 /root/mcp-client.py https://10.10.10.254:2020/mcp full
```

### Check LoxiLB Statistics
```bash
docker exec -i llb1 loxicmd get lb -o wide
```

### Check MCP Server Logs
```bash
docker exec -i l3ep1 cat /tmp/mcp-server1.log
docker exec -i l3ep2 cat /tmp/mcp-server2.log
docker exec -i l3ep3 cat /tmp/mcp-server3.log
```

## Architecture Summary

```
Client (l3h1) 
    ↓ HTTPS
LoxiLB (llb1) - VIP: 10.10.10.254:2020
    ↓ HTTP (mcp-fullproxy) or HTTPS (mcp-e2ehttps)
3x MCP Servers (l3ep1, l3ep2, l3ep3)
    - server1: 31.31.31.1:8080
    - server2: 32.32.32.1:8080
    - server3: 33.33.33.1:8080
```

## What Makes This Different

### vs. httpsproxy/e2ehttpsproxy
- **Protocol:** MCP (Model Context Protocol) vs plain HTTP
- **Framework:** fastmcp (Python) vs Node.js
- **Endpoints:** Tools, resources, prompts vs simple echo
- **Use Case:** AI/LLM services vs generic HTTP

### vs. http2ep
- **Transport:** HTTP/1.1 vs HTTP/2
- **Language:** Python (fastmcp) vs Go
- **Complexity:** Full MCP framework vs simple HTTP/2 server

## Expected Test Output

```
SCENARIO-mcp-fullproxy
#########################################
Testing MCP server health (round-robin)
#########################################
Test 1...
Health: OK
Test 2...
Health: OK
...
#########################################
Testing echo endpoint
#########################################
Echo test 1...
Echo: server1:test-message
...
#########################################
SCENARIO-mcp-fullproxy [OK]
#########################################
```

## Files Created

```
cicd/
├── common/
│   └── mcp/
│       ├── README.md              # Comprehensive documentation
│       ├── mcp-server/
│       │   └── mcp-server.py      # FastMCP server (118 lines)
│       └── mcp-client/
│           └── mcp-client.py      # FastMCP client (220 lines)
├── mcp-fullproxy/
│   ├── config.sh                  # HTTPS → HTTP setup
│   ├── validation.sh              # Test suite
│   └── rmconfig.sh                # Cleanup
└── mcp-e2ehttps/
    ├── config.sh                  # HTTPS → HTTPS setup
    ├── validation.sh              # Test suite
    └── rmconfig.sh                # Cleanup
```

## Next Steps for You

1. **Run the tests:**
   ```bash
   cd cicd/mcp-fullproxy
   ./config.sh && ./validation.sh && ./rmconfig.sh
   ```

2. **Check for issues:**
   - Python/pip installation in containers
   - fastmcp package installation
   - Certificate generation
   - Network connectivity
   - LoxiLB rule creation

3. **Debug if needed:**
   - Check MCP server logs: `/tmp/mcp-server*.log`
   - Verify Python version: `python3 --version` (need 3.8+)
   - Test direct backend: `curl http://31.31.31.1:8080/mcp`
   - Test LB VIP: `curl -k https://10.10.10.254:2020/mcp`

## Support

For detailed documentation, see:
- `cicd/common/mcp/README.md` - Full documentation
- [fastmcp docs](https://gofastmcp.com/) - Framework reference
- [MCP spec](https://modelcontextprotocol.io/) - Protocol details

Happy testing! 🚀
