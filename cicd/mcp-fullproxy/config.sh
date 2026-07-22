#!/bin/bash
# minica (github.com/jsha/minica) is fetched on demand — no binary is committed.
MINICA="$(command -v minica || echo "$(go env GOPATH)/bin/minica")"
[ -x "$MINICA" ] || { go install github.com/jsha/minica@latest; MINICA="$(go env GOPATH)/bin/minica"; }


source ../common.sh

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type mcp-client --dock-name l3h1
spawn_docker_host --dock-type mcp-server --dock-name l3ep1
spawn_docker_host --dock-type mcp-server --dock-name l3ep2
spawn_docker_host --dock-type mcp-server --dock-name l3ep3

echo "#########################################"
echo "Connecting and configuring hosts"
echo "#########################################"

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1
connect_docker_hosts l3ep3 llb1

sleep 5

# L3 configuration
# config_docker_host --host1 l3h1 --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
# config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
# config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
# config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24 --gw 33.33.33.254
config_docker_host --host1 l3h1 --host2 llb1 --ptype phy --addr 10.10.10.1/24 
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24
config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24
config_docker_host --host1 llb1 --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1 --host2 l3ep3 --ptype phy --addr 33.33.33.254/24

add_route l3h1 31.31.31.0/24 10.10.10.254
add_route l3h1 32.32.32.0/24 10.10.10.254
add_route l3h1 33.33.33.0/24 10.10.10.254
add_route l3ep1 10.10.10.0/24 31.31.31.254
add_route l3ep2 10.10.10.0/24 32.32.32.254
add_route l3ep3 10.10.10.0/24 33.33.33.254

$dexec llb1 ip addr add 10.10.10.3/32 dev lo

echo "#########################################"
echo "Preparing TLS certificates"
echo "#########################################"

# Generate certificates for loxilb (HTTPS frontend) with IP SAN
"$MINICA" --ip-addresses 10.10.10.254
docker cp minica.pem llb1:/opt/loxilb/cert/rootCA.crt
docker cp 10.10.10.254/cert.pem llb1:/opt/loxilb/cert/server.crt
docker cp 10.10.10.254/key.pem llb1:/opt/loxilb/cert/server.key

# Copy CA certificate to client for verification
docker cp minica.pem l3h1:/app/minica.pem

echo "#########################################"
echo "Starting MCP servers on endpoints"
echo "#########################################"

# Start MCP servers on each endpoint (HTTP on port 8080)
# fastmcp is already installed in the Docker images
echo "Starting MCP server on l3ep1..."
$dexec -d l3ep1 bash -c "cd /app && python3 server.py server1 8080 > /tmp/mcp-server1.log 2>&1"

echo "Starting MCP server on l3ep2..."
$dexec -d l3ep2 bash -c "cd /app && python3 server.py server2 8080 > /tmp/mcp-server2.log 2>&1"

echo "Starting MCP server on l3ep3..."
$dexec -d l3ep3 bash -c "cd /app && python3 server.py server3 8080 > /tmp/mcp-server3.log 2>&1"

sleep 10

echo "#########################################"
echo "Verifying MCP servers are running"
echo "#########################################"

# Check if MCP servers are responding
for ep in l3ep1 l3ep2 l3ep3; do
    echo "Checking $ep..."
    $dexec $ep curl -s http://localhost:8080/mcp || echo "$ep: MCP server may not be ready yet"
done

echo "#########################################"
echo "Creating LoxiLB load balancer rule"
echo "#########################################"

# Create LB rule: HTTPS (frontend) -> HTTP (backend)
# VIP: 10.10.10.254:2020 (HTTPS)
# Backends: 31.31.31.1:8080, 32.32.32.1:8080, 33.33.33.1:8080 (HTTP)
# $dexec llb1 loxicmd create lb 10.10.10.254 --tcp=2020:8080 --select=rr --mode=fullproxy --security=https --session-header-name=mcp-session-id --host 10.10.10.254 --endpoints=31.31.31.1:1,32.32.32.1:1
# $dexec llb1 loxicmd create lb 10.10.10.254 --tcp=2021:8080 --select=persist --mode=fullproxy --security=https --session-header-name=mcp-session-id --host 10.10.10.254 --endpoints=31.31.31.1:1,32.32.32.1:1
# port 2020 -> round-robin
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2020,
    "protocol": "tcp",
    "sel": 0,
    "mode": 4,
    "security": 1,
    "session_header_name": "mcp-session-id",
    "host": "10.10.10.254",
    "trace_type": "mcp"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1 }
  ]
}'

# port 2021 -> persist
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2021,
    "protocol": "tcp",
    "sel": 3,
    "mode": 4,
    "security": 1,
    "session_header_name": "mcp-session-id",
    "host": "10.10.10.254",
    "trace_type": "mcp"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1 }
  ]
}'

echo "#########################################"
echo "Configuration complete"
echo "#########################################"
echo "LoxiLB VIP: https://10.10.10.254:2020/mcp"
echo "Backend MCP servers:"
echo "  - server1: http://31.31.31.1:8080/mcp"
echo "  - server2: http://32.32.32.1:8080/mcp"
echo "  - server3: http://33.33.33.1:8080/mcp"
