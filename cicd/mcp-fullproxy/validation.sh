#!/bin/bash
source ../common.sh

echo SCENARIO-mcp-fullproxy

code=0

echo "#########################################"
echo "Verifying MCP client is ready"
echo "#########################################"

# MCP client is already installed in the Docker image
echo "MCP client ready (using ghcr.io/loxilb-io/mcp-client:latest)"

echo "#########################################"
echo "Testing MCP server health (round-robin)"
echo "#########################################"

# Test health checks multiple times to verify round-robin distribution
# We expect to see responses from server1, server2, and server3
declare -A server_responses
server_responses["server1"]=0
server_responses["server2"]=0
server_responses["server3"]=0

for i in {1..12}; do
    echo "Test $i..."
    result=$($dexec l3h1 python3 /app/client.py https://10.10.10.254:2020/mcp health --ca-cert /app/minica.pem 2>&1)
    echo "$result"
    
    # Check if health check returned OK
    if [[ $result != *"Health: OK"* ]]; then
        echo "Health check failed on iteration $i"
        code=1
    fi
    
    sleep 1
done


echo "#########################################"
echo "Testing get_models endpoint over Round-Robin"
echo "#########################################"

result=$($dexec l3h1 python3 /app/client.py https://10.10.10.254:2020/mcp models --ca-cert /app/minica.pem 2>&1)
echo "$result"

if [[ $result != *"Models:"* ]]; then
    echo "Get models test failed"
    code=1
fi

echo "#########################################"
echo "Testing chat_completion endpoint over Round-Robin"
echo "#########################################"

result=$($dexec l3h1 python3 /app/client.py https://10.10.10.254:2020/mcp chat --ca-cert /app/minica.pem 2>&1)
echo "$result"

if [[ $result != *"response"* ]]; then
    echo "Chat completion test failed"
    code=1
fi

echo "#########################################"
echo "Testing server_info endpoint over Round-Robin"
echo "#########################################"

result=$($dexec l3h1 python3 /app/client.py https://10.10.10.254:2020/mcp info --ca-cert /app/minica.pem 2>&1)
echo "$result"

if [[ $result != *"name"* ]]; then
    echo "Server info test failed"
    code=1
fi

echo "#########################################"
echo "Running full test suite"
echo "#########################################"

result=$($dexec l3h1 python3 /app/client.py https://10.10.10.254:2020/mcp full --ca-cert /app/minica.pem 2>&1)
echo "$result"

if [[ $result != *"Test Summary"* ]]; then
    echo "Full test suite failed"
    code=1
fi

echo "#########################################"
echo "Testing persist mode with session affinity"
echo "#########################################"

# Test persistent session to VIP 10.10.10.254:2021
# All requests from same client should go to same backend server
echo "Testing session persistence (port 2021)..."

first_server=""
for i in {1..10}; do
    echo "Persist test $i..."
    result=$($dexec l3h1 python3 /app/client.py https://10.10.10.254:2021/mcp models --ca-cert /app/minica.pem 2>&1)
    echo "$result"
    
    # Extract server name from models list (e.g., "server2-gpt-4" → "server2")
    if [[ $result =~ server([1-3])- ]]; then
        current_server="${BASH_REMATCH[1]}"
        echo "Request $i routed to: server$current_server"
        
        if [[ -z "$first_server" ]]; then
            first_server="$current_server"
            echo "First request established session with server$first_server"
        elif [[ "$current_server" != "$first_server" ]]; then
            echo "ERROR: Session persistence broken! Expected server$first_server, got server$current_server"
            code=1
        else
            echo "✓ Session maintained to server$first_server"
        fi
    else
        echo "ERROR: Could not parse server name from response"
        code=1
    fi
    
    sleep 1
done

if [[ -n "$first_server" && $code == 0 ]]; then
    echo "✓ Persist mode working: All 10 requests routed to server$first_server"
else
    echo "✗ Persist mode test failed"
    code=1
fi

echo "#########################################"
echo "Verifying load distribution"
echo "#########################################"

# Check loxilb load balancer statistics
echo "LoxiLB statistics:"
$dexec llb1 loxicmd get lb -o wide

if [[ $code == 0 ]]; then
    echo "#########################################"
    echo "SCENARIO-mcp-fullproxy [OK]"
    echo "#########################################"
else
    echo "#########################################"
    echo "SCENARIO-mcp-fullproxy [FAILED]"
    echo "#########################################"
fi

# Cleanup MCP servers
echo "Cleaning up MCP servers..."
$dexec l3ep1 killall -9 python3 > /dev/null 2>&1
$dexec l3ep2 killall -9 python3 > /dev/null 2>&1
$dexec l3ep3 killall -9 python3 > /dev/null 2>&1

exit $code
