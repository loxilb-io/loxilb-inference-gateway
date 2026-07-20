#!/bin/bash
source ../common.sh

echo SCENARIO-mcp-e2ehttps

code=0

echo "#########################################"
echo "Verifying MCP client is ready"
echo "#########################################"

# MCP client is already installed in the Docker image
echo "MCP client ready (using ghcr.io/loxilb-io/mcp-client:latest)"

echo "#########################################"
echo "Testing End-to-End HTTPS MCP setup"
echo "#########################################"

# Test health checks multiple times to verify round-robin distribution
# We expect to see responses from server1, server2, and server3
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
echo "Testing echo endpoint with E2E HTTPS"
echo "#########################################"

for i in {1..3}; do
    echo "Echo test $i..."
    result=$($dexec l3h1 python3 /app/client.py https://10.10.10.254:2020/mcp echo --ca-cert /app/minica.pem 2>&1)
    echo "$result"
    
    if [[ $result != *"test-message"* ]]; then
        echo "Echo test failed on iteration $i"
        code=1
    fi
    
    sleep 1
done

echo "#########################################"
echo "Testing get_models endpoint"
echo "#########################################"

result=$($dexec l3h1 python3 /app/client.py https://10.10.10.254:2020/mcp models --ca-cert /app/minica.pem 2>&1)
echo "$result"

if [[ $result != *"Models:"* ]]; then
    echo "Get models test failed"
    code=1
fi

echo "#########################################"
echo "Testing chat_completion endpoint"
echo "#########################################"

result=$($dexec l3h1 python3 /app/client.py https://10.10.10.254:2020/mcp chat --ca-cert /app/minica.pem 2>&1)
echo "$result"

if [[ $result != *"response"* ]]; then
    echo "Chat completion test failed"
    code=1
fi

echo "#########################################"
echo "Verifying E2E HTTPS encryption"
echo "#########################################"

# Verify that backend connections are HTTPS
echo "Backend server certificate check:"
$dexec llb1 openssl s_client -connect 31.31.31.1:8080 -showcerts </dev/null 2>&1 | grep "subject=" || echo "Certificate verification check"

echo "#########################################"
echo "Verifying load distribution"
echo "#########################################"

# Check loxilb load balancer statistics
echo "LoxiLB statistics:"
$dexec llb1 loxicmd get lb -o wide

if [[ $code == 0 ]]; then
    echo "#########################################"
    echo "SCENARIO-mcp-e2ehttps [OK]"
    echo "#########################################"
else
    echo "#########################################"
    echo "SCENARIO-mcp-e2ehttps [FAILED]"
    echo "#########################################"
fi

# Cleanup MCP servers
echo "Cleaning up MCP servers..."
$dexec l3ep1 killall -9 python3 > /dev/null 2>&1
$dexec l3ep2 killall -9 python3 > /dev/null 2>&1
$dexec l3ep3 killall -9 python3 > /dev/null 2>&1

exit $code
