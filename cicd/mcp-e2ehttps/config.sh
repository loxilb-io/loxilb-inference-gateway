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
spawn_docker_host --dock-type mcp-hserver --dock-name l3ep1
spawn_docker_host --dock-type mcp-hserver --dock-name l3ep2
spawn_docker_host --dock-type mcp-hserver --dock-name l3ep3

echo "#########################################"
echo "Connecting and configuring hosts"
echo "#########################################"

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1
connect_docker_hosts l3ep3 llb1

sleep 5

# L3 configuration
config_docker_host --host1 l3h1 --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24 --gw 33.33.33.254
config_docker_host --host1 llb1 --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1 --host2 l3ep3 --ptype phy --addr 33.33.33.254/24

$dexec llb1 ip addr add 10.10.10.3/32 dev lo

echo "#########################################"
echo "Preparing TLS certificates"
echo "#########################################"

# Clean up old certificates
rm -rf 10.10.10.254 31.31.31.1 32.32.32.1 33.33.33.1 loxilb.io minica*.pem

# Generate certificate for loxilb (HTTPS frontend) with IP SAN
"$MINICA" --ip-addresses 10.10.10.254
mv 10.10.10.254/cert.pem 10.10.10.254/server.crt
mv 10.10.10.254/key.pem 10.10.10.254/server.key

docker cp minica.pem llb1:/opt/loxilb/cert/rootCA.crt
docker cp 10.10.10.254/server.crt llb1:/opt/loxilb/cert/server.crt
docker cp 10.10.10.254/server.key llb1:/opt/loxilb/cert/server.key

# Copy CA certificate to client for verification
docker cp minica.pem l3h1:/app/minica.pem

echo "#########################################"
echo "Generating certificates for HTTPS backends"
echo "#########################################"

# Generate certificates for backend MCP servers with IP SAN
$dexec l3ep1 bash -c "cd /app && mkdir -p certs && cd certs && minica --ip-addresses 31.31.31.1 > /dev/null 2>&1"
$dexec l3ep2 bash -c "cd /app && mkdir -p certs && cd certs && minica --ip-addresses 32.32.32.1 > /dev/null 2>&1"
$dexec l3ep3 bash -c "cd /app && mkdir -p certs && cd certs && minica --ip-addresses 33.33.33.1 > /dev/null 2>&1"

echo "#########################################"
echo "Starting HTTPS MCP servers on endpoints"
echo "#########################################"

# Start HTTPS MCP servers on each endpoint
echo "Starting HTTPS MCP server on l3ep1..."
$dexec -d l3ep1 bash -c "cd /app && python3 server.py server1 8080 --ssl-certfile /app/certs/31.31.31.1/cert.pem --ssl-keyfile /app/certs/31.31.31.1/key.pem > /tmp/mcp-server1.log 2>&1"

echo "Starting HTTPS MCP server on l3ep2..."
$dexec -d l3ep2 bash -c "cd /app && python3 server.py server2 8080 --ssl-certfile /app/certs/32.32.32.1/cert.pem --ssl-keyfile /app/certs/32.32.32.1/key.pem > /tmp/mcp-server2.log 2>&1"

echo "Starting HTTPS MCP server on l3ep3..."
$dexec -d l3ep3 bash -c "cd /app && python3 server.py server3 8080 --ssl-certfile /app/certs/33.33.33.1/cert.pem --ssl-keyfile /app/certs/33.33.33.1/key.pem > /tmp/mcp-server3.log 2>&1"

sleep 15

echo "#########################################"
echo "Verifying HTTPS MCP servers are running"
echo "#########################################"

# Check if MCP servers are responding
for ep in l3ep1 l3ep2 l3ep3; do
    echo "Checking $ep..."
    $dexec $ep curl -k https://localhost:8080/ || echo "$ep: MCP server may not be ready yet"
done

echo "#########################################"
echo "Creating LoxiLB load balancer rule"
echo "#########################################"

# Create LB rule: HTTPS (frontend) -> HTTPS (backend) - End-to-End TLS
# VIP: 10.10.10.254:2020 (HTTPS)
# Backends: 31.31.31.1:8080, 32.32.32.1:8080, 33.33.33.1:8080 (HTTPS)
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2020,
    "protocol": "tcp",
    "security": 2,
    "mode": 4,
    "host": "10.10.10.254",
    "session_header_name": "mcp-session-id"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1 },
    { "endpointIP": "33.33.33.1", "targetPort": 8080, "weight": 1 }
  ]
}'

echo "#########################################"
echo "Configuration complete"
echo "#########################################"
echo "LoxiLB VIP: https://10.10.10.254:2020/mcp"
echo "Backend MCP servers (all HTTPS):"
echo "  - server1: https://31.31.31.1:8080/mcp"
echo "  - server2: https://32.32.32.1:8080/mcp"
echo "  - server3: https://33.33.33.1:8080/mcp"