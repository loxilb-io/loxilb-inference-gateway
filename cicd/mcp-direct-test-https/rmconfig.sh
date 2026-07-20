#!/bin/bash
source ../common.sh

echo "#########################################"
echo "Cleaning up mcp-direct-test"
echo "#########################################"

# Stop MCP server
echo "Stopping MCP server..."
$dexec mserver killall -9 python3 > /dev/null 2>&1

# Delete Docker hosts
echo "Deleting Docker hosts..."
delete_docker_host mserver
delete_docker_host mclient

# Clean up temp files
echo "Cleaning up temporary files..."
rm -rf /tmp/mcp-server.log 2>/dev/null

echo "Cleanup complete"
