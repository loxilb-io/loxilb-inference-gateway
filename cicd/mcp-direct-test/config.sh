#!/bin/bash

source ../common.sh

echo "#########################################"
echo "MCP Direct Communication Test - Setup"
echo "#########################################"

echo "Spawning Docker hosts using MCP images..."
spawn_docker_host --dock-type mcp-server --dock-name mserver 
spawn_docker_host --dock-type mcp-client --dock-name mclient 

echo "Connecting hosts..."
connect_docker_hosts mclient mserver

sleep 3

echo "Configuring network..."
# Simple point-to-point network
config_docker_host --host1 mclient --host2 mserver --ptype phy --addr 192.168.100.10/24
config_docker_host --host1 mserver --host2 mclient --ptype phy --addr 192.168.100.20/24

echo "#########################################"
echo "Starting MCP server"
echo "#########################################"

# Start HTTP MCP server (fastmcp already installed in the image)
echo "Starting MCP server on 192.168.100.20:8080 (HTTP)..."
$dexec -d mserver bash -c "cd /app && python3 server.py test-server 8080 > /tmp/mcp-server.log 2>&1"

sleep 10

echo "#########################################"
echo "Verifying MCP server is running"
echo "#########################################"

# Check if server is listening
$dexec mserver netstat -tlnp | grep 8080 || echo "Warning: Server may not be listening"

# Test direct connection
echo "Testing local connection on server..."
$dexec mserver curl -s http://localhost:8080/ || echo "Server health check on localhost"

echo "#########################################"
echo "Setup complete"
echo "#########################################"
echo "MCP Server: http://192.168.100.20:8080/mcp"
echo "MCP Client: 192.168.100.10"
echo ""
echo "Test network connectivity:"
echo "#########################################"
echo "Setup complete"
echo "#########################################"
echo "MCP Server: http://192.168.100.20:8080/mcp"
echo "MCP Client: 192.168.100.10"
echo ""
echo "Images used:"
echo "  Server: ghcr.io/loxilb-io/mcp-server:latest"
echo "  Client: ghcr.io/loxilb-io/mcp-client:latest"
echo ""
echo "Test network connectivity:"
echo "  docker exec -i mclient ping -c 3 192.168.100.20"
echo ""
echo "Run validation:"
echo "  ./validation.sh"