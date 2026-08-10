# MCP Gateway — Load-Balancing Model Context Protocol Servers

> **Audience:** operators putting a fleet of MCP (Model Context Protocol) servers behind one
> stable, TLS-terminating, session-sticky endpoint.
> **Scope:** the three MCP proxy deployment shapes (HTTP, TLS-terminating, end-to-end HTTPS),
> MCP session stickiness, and the runnable CICD scenarios that validate each shape.
>
> **For exact rule fields, treat the matching `cicd/mcp-*/config.sh` as the source of truth** —
> they are the gated, working configurations and track the current build.

---

## 1. Why put a gateway in front of MCP servers

MCP servers speak the streamable-HTTP transport: a client opens a session, receives an
`mcp-session-id`, and every subsequent JSON-RPC call must land on the server that owns that
session. Load-balancing this naively breaks sessions. The inference gateway solves it at L7:

- **Session stickiness** — the sockproxy keys routing on the `mcp-session-id` response/request
  header, so all calls of one MCP session stay on one backend.
- **TLS termination or end-to-end HTTPS** — expose `https://` to clients regardless of whether
  the MCP servers themselves run TLS.
- **Health failover & scaling** — standard endpoint liveness and weighted selection across a
  pool of identical MCP servers.
- **MCP-aware tracing** — `trace_type: "mcp"` tags the proxy's trace records for MCP traffic.

```
MCP client ──► VIP :2020 ──► [sockproxy: mcp-session-id stickiness] ──► mcp-server pool :8080
```

All MCP rules are **fullproxy** rules (`mode: 4`) — the L7 sockproxy must terminate the
connection to observe the session header.

---

## 2. Deployment shapes

| Shape | Frontend → backend | `security` | CICD scenario |
|---|---|---|---|
| Plain HTTP proxy | HTTP → HTTP | absent (0) | [`cicd/mcp-httpproxy`](../../cicd/mcp-httpproxy) |
| TLS-terminating proxy | **HTTPS** → HTTP | `1` | [`cicd/mcp-fullproxy`](../../cicd/mcp-fullproxy) |
| End-to-end HTTPS | **HTTPS** → **HTTPS** | `2` | [`cicd/mcp-e2ehttps`](../../cicd/mcp-e2ehttps) |

Two more scenarios — [`cicd/mcp-direct-test`](../../cicd/mcp-direct-test) and
[`cicd/mcp-direct-test-https`](../../cicd/mcp-direct-test-https) — validate raw client↔server
MCP connectivity without any LB rule, and are useful for isolating backend problems.

### 2.1 Plain HTTP MCP proxy

Round-robin across two MCP servers with MCP session stickiness:

```bash
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 2020, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "10.10.10.254",
    "session_header_name": "mcp-session-id"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1 }
  ]}'
```

For hash-persistent (source-sticky) selection instead of round-robin, use `"sel": 3`.

### 2.2 TLS-terminating MCP proxy (HTTPS in, HTTP out)

Adds `security: 1` (frontend TLS, plain HTTP to the backends) and MCP trace tagging:

```bash
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 2020, "protocol": "tcp",
    "sel": 0, "mode": 4, "security": 1,
    "session_header_name": "mcp-session-id",
    "host": "10.10.10.254", "trace_type": "mcp"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1 }
  ]}'
```

The equivalent `loxicmd` form (loxicmd — separate repository):

```bash
loxicmd create lb 10.10.10.254 --tcp=2020:8080 --select=rr --mode=fullproxy \
  --security=https --session-header-name=mcp-session-id --host=10.10.10.254 \
  --endpoints=31.31.31.1:1,32.32.32.1:1
```

The frontend certificate is served from the gateway's certificate store. There is **no per-rule
certificate field**: uploaded certs are registered under hostnames auto-derived from the leaf
cert's SAN/CN, and the listener selects the matching certificate at handshake time by SNI. See
[L7 TLS](03-l7-tls.md) for certificate upload/rotation (`certId` management).

### 2.3 End-to-end HTTPS (HTTPS in, HTTPS out)

When the MCP servers themselves terminate TLS (e.g. launched with
`--ssl-certfile/--ssl-keyfile`), set `security: 2` — the gateway re-encrypts toward the
backend:

```bash
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 2020, "protocol": "tcp",
    "sel": 0, "mode": 4, "security": 2,
    "session_header_name": "mcp-session-id", "host": "10.10.10.254"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8443, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8443, "weight": 1 },
    { "endpointIP": "33.33.33.1", "targetPort": 8443, "weight": 1 }
  ]}'
```

---

## 3. Field reference (MCP-relevant)

| Field | Values | Meaning |
|---|---|---|
| `mode` | `4` | **Required.** Fullproxy — the L7 sockproxy handles the connection |
| `sel` | `0` rr · `3` persist | Endpoint selection for *new* sessions (existing sessions follow the header) |
| `session_header_name` | `"mcp-session-id"` | Header that keys session stickiness; all requests carrying the same value route to the same endpoint |
| `security` | absent/`0` · `1` · `2` | Plain HTTP · TLS-terminate · end-to-end HTTPS |
| `trace_type` | `"mcp"` | Tags proxy trace records as MCP traffic |
| `host` | VIP address | Must be local to the gateway node (sockproxy binds the VIP) |

Streaming (SSE/streamable-HTTP responses) is proxied natively by the fullproxy path — no
MCP-specific streaming flag is needed.

---

## 4. Try it

```bash
cd cicd/mcp-fullproxy
./config.sh        # gateway + 2 fastmcp servers, TLS-terminating rule
./validation.sh    # MCP session open + tool calls through the VIP, stickiness asserted
./rmconfig.sh
```

Each `validation.sh` drives a real MCP client through the VIP: it initializes a session,
verifies the `mcp-session-id` round-trip, issues JSON-RPC tool calls, and asserts every call of
a session landed on the same backend.

---

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Session breaks mid-conversation | `session_header_name` missing on the rule | Add `"session_header_name": "mcp-session-id"` |
| Rule created but nothing listens | VIP not local | `host`/`externalIP` must be an address on the gateway node |
| TLS handshake fails at client | `security` mismatch | `1` for HTTPS-in/HTTP-out, `2` only when backends serve TLS |
| Backend works direct, fails via VIP | Isolate with the no-LB scenarios | Run `cicd/mcp-direct-test(-https)` against the backend first |

See [Troubleshooting](06-troubleshooting.md) for general L7/fullproxy diagnostics.
