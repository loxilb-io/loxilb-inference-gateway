#!/bin/bash
source ../common.sh

echo "#########################################"
echo "Cleaning up mcp-e2ehttps test"
echo "#########################################"

# Stop MCP servers
echo "Stopping MCP servers..."
$dexec l3ep1 killall -9 python3 > /dev/null 2>&1
$dexec l3ep2 killall -9 python3 > /dev/null 2>&1
$dexec l3ep3 killall -9 python3 > /dev/null 2>&1

# Delete Docker hosts
echo "Deleting Docker hosts..."
delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2
delete_docker_host l3ep3

# Clean up certificates
echo "Cleaning up certificates..."
rm -rf 10.10.10.254 31.31.31.1 32.32.32.1 33.33.33.1 minica*.pem loxilb.io /tmp/mcp-server-https.py 2>/dev/null

echo "Cleanup complete"
