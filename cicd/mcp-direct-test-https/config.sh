#!/bin/bash

source ../common.sh

echo "#########################################"
echo "Configuring MCP Direct HTTPS Test"
echo "#########################################"

# Disconnect previously connected docker network
disconnect_docker_hosts l3h1 mserver
disconnect_docker_hosts l3h1 mclient

# Delete old containers if they exist
delete_docker_host mserver
delete_docker_host mclient

# Cleanup old temp files
sudo rm -f /tmp/mcp-server.log

echo "Creating MCP server container using HTTPS image..."
spawn_docker_host --dock-type mcp-hserver --dock-name mserver

echo "Creating MCP client container..."
spawn_docker_host --dock-type mcp-client --dock-name mclient

echo "Connecting hosts..."
connect_docker_hosts mclient mserver

sleep 3

echo "Configuring network (192.168.100.0/24)..."
# Simple point-to-point network
config_docker_host --host1 mclient --host2 mserver --ptype phy --addr 192.168.100.10/24
config_docker_host --host1 mserver --host2 mclient --ptype phy --addr 192.168.100.20/24

echo "Generating self-signed certificates with IP SAN..."
$dexec mserver mkdir -p /app/certs
# Use minica with --ip-addresses flag to include IP in SAN
$dexec mserver bash -c "cd /app/certs && minica --ip-addresses 192.168.100.20 > /dev/null 2>&1"

# Check if certificates were generated
if $dexec mserver test -f /app/certs/192.168.100.20/cert.pem; then
    echo "✓ Certificates generated successfully with IP SAN"
else
    echo "✗ Certificate generation failed"
    exit 1
fi

echo "Copying root CA certificate to client..."
$dexec mserver cat /app/certs/minica.pem | $dexec mclient tee /app/minica.pem > /dev/null

echo "Starting MCP server with HTTPS (port 8443)..."
# Start detached (docker exec -d) rather than `bash -c "... &"`: the backgrounded
# form is tied to the exec session and can be reaped the moment docker exec
# returns (seen as an empty server log + "failed to start").
$dexec -d mserver bash -c "cd /app && python3 server.py test-server 8443 --ssl-certfile /app/certs/192.168.100.20/cert.pem --ssl-keyfile /app/certs/192.168.100.20/key.pem > /tmp/mcp-server.log 2>&1"

echo "Waiting for MCP server to start..."
# Poll for the listener instead of a single fixed sleep: TLS startup can lag a
# hard-coded 5s on a loaded runner, which caused an intermittent false failure.
started=0
for _ in $(seq 1 30); do
    if $dexec mserver netstat -tlnp 2>/dev/null | grep -q ":8443"; then started=1; break; fi
    sleep 1
done

if [[ $started == 1 ]]; then
    echo "✓ MCP server started successfully on port 8443"
else
    echo "✗ MCP server failed to start"
    echo "Server logs:"
    $dexec mserver cat /tmp/mcp-server.log
    exit 1
fi

echo ""
echo "========================================="
echo "MCP Direct HTTPS Test Setup Complete"
echo "========================================="
echo "Server: 192.168.100.20:8443 (HTTPS)"
echo "Client: 192.168.100.10"
echo "CA Certificate: /app/minica.pem"
echo ""
echo "Images used:"
echo "  Server: ghcr.io/loxilb-io/mcp-server-https:latest"
echo "  Client: ghcr.io/loxilb-io/mcp-client:latest"
echo ""
echo "Run './validation.sh' to test"
echo "========================================="
