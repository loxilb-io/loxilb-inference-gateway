#!/bin/bash

source ../common.sh

code=0

echo "========================================="
echo "MCP Direct HTTPS Communication Test"
echo "========================================="
echo ""

#########################################
echo "#########################################"
echo "Step 1: Network Connectivity Test"
echo "#########################################"
echo "Testing ping from client to server..."
$dexec mclient ping -c 3 192.168.100.20
if [ $? -eq 0 ]; then
    echo "✓ Network connectivity OK"
else
    echo "✗ Network connectivity FAILED"
    code=1
fi
echo ""

#########################################
echo "#########################################"
echo "Step 2: HTTPS Connection Test"
echo "#########################################"
echo "Testing HTTPS connection with curl..."
$dexec mclient curl -k -s -o /dev/null -w "%{http_code}" https://192.168.100.20:8443/ 
if [ $? -eq 0 ]; then
    echo ""
    echo "✓ HTTPS connection OK"
else
    echo ""
    echo "✗ HTTPS connection FAILED"
    echo "Debug: Check server logs"
    $dexec mserver cat /tmp/mcp-server.log | tail -20
    code=1
fi
echo ""

#########################################
echo "#########################################"
echo "Step 3: HTTPS with CA Certificate Test"
echo "#########################################"
echo "Testing HTTPS connection with CA certificate..."
$dexec mclient curl --cacert /app/minica.pem -s -o /dev/null -w "%{http_code}" https://192.168.100.20:8443/
if [ $? -eq 0 ]; then
    echo ""
    echo "✓ HTTPS with CA certificate OK"
else
    echo ""
    echo "✗ HTTPS with CA certificate FAILED"
    code=1
fi
echo ""

#########################################
echo "#########################################"
echo "Step 4: MCP Health Check Test (HTTPS)"
echo "#########################################"
echo "Testing MCP health endpoint over HTTPS..."
result=$($dexec mclient python3 /app/client.py https://192.168.100.20:8443/mcp health --ca-cert /app/minica.pem)
if echo "$result" | grep -q "Health: OK"; then
    echo "$result"
    echo "✓ MCP health check PASSED"
else
    echo "$result"
    echo "✗ MCP health check FAILED"
    echo "Debug: Run 'docker exec -i mclient python3 /app/client.py https://192.168.100.20:8443/mcp health --ca-cert /app/minica.pem'"
    code=1
fi
echo ""

#########################################
echo "#########################################"
echo "Step 5: MCP Echo Test (HTTPS)"
echo "#########################################"
echo "Testing MCP echo endpoint over HTTPS..."
result=$($dexec mclient python3 /app/client.py https://192.168.100.20:8443/mcp echo --ca-cert /app/minica.pem)
if echo "$result" | grep -q "Echo:"; then
    echo "$result"
    echo "✓ MCP echo test PASSED"
else
    echo "$result"
    echo "✗ MCP echo test FAILED"
    code=1
fi
echo ""

#########################################
echo "#########################################"
echo "Step 6: MCP Get Models Test (HTTPS)"
echo "#########################################"
echo "Testing MCP get_models endpoint over HTTPS..."
result=$($dexec mclient python3 /app/client.py https://192.168.100.20:8443/mcp models --ca-cert /app/minica.pem)
if echo "$result" | grep -q "Models:"; then
    echo "$result"
    echo "✓ MCP get_models test PASSED"
else
    echo "$result"
    echo "✗ MCP get_models test FAILED"
    code=1
fi
echo ""

#########################################
echo "#########################################"
echo "Step 7: MCP Chat Completion Test (HTTPS)"
echo "#########################################"
echo "Testing MCP chat_completion endpoint over HTTPS..."
result=$($dexec mclient python3 /app/client.py https://192.168.100.20:8443/mcp chat --ca-cert /app/minica.pem)
if echo "$result" | grep -q "Chat:"; then
    echo "$result"
    echo "✓ MCP chat_completion test PASSED"
else
    echo "$result"
    echo "✗ MCP chat_completion test FAILED"
    code=1
fi
echo ""

#########################################
echo "#########################################"
echo "Step 8: MCP Server Info Test (HTTPS)"
echo "#########################################"
echo "Testing MCP get_server_info endpoint over HTTPS..."
result=$($dexec mclient python3 /app/client.py https://192.168.100.20:8443/mcp info --ca-cert /app/minica.pem)
if echo "$result" | grep -q "Server Info:"; then
    echo "$result"
    echo "✓ MCP server_info test PASSED"
else
    echo "$result"
    echo "✗ MCP server_info test FAILED"
    code=1
fi
echo ""

#########################################
echo "#########################################"
echo "Step 9: MCP Resources Test (HTTPS)"
echo "#########################################"
echo "Testing MCP resources endpoints over HTTPS..."
result=$($dexec mclient python3 /app/client.py https://192.168.100.20:8443/mcp resources --ca-cert /app/minica.pem)
if echo "$result" | grep -q "Config:"; then
    echo "$result"
    echo "✓ MCP resources test PASSED"
else
    echo "$result"
    echo "✗ MCP resources test FAILED"
    code=1
fi
echo ""

#########################################
echo "#########################################"
echo "Step 10: Full MCP Test Suite (HTTPS)"
echo "#########################################"
echo "Running complete MCP test suite over HTTPS..."
result=$($dexec mclient python3 /app/client.py https://192.168.100.20:8443/mcp full --ca-cert /app/minica.pem)
echo "$result"
if echo "$result" | grep -q "Passed: 6/6"; then
    echo "✓ Full MCP test suite COMPLETED"
    echo "✓ All 6 tests passed!"
else
    echo "✗ Full MCP test suite FAILED"
    echo "Some tests did not pass"
    code=1
fi
echo ""

#########################################
echo "#########################################"
echo "Test Summary"
echo "#########################################"
echo ""

if [ $code -eq 0 ]; then
    echo "========================================="
    echo "  SCENARIO-mcp-direct-test-https [OK]"
    echo "========================================="
    echo ""
    echo "✓ All direct HTTPS communication tests passed!"
    echo "✓ MCP server and client working correctly over TLS"
    echo "✓ Certificate validation working"
    echo "✓ Ready to proceed with loxilb HTTPS integration tests"
else
    echo "========================================="
    echo "  SCENARIO-mcp-direct-test-https [FAILED]"
    echo "========================================="
    echo ""
    echo "✗ Some tests failed"
    echo ""
    echo "Troubleshooting commands:"
    echo "  docker exec -i mserver cat /tmp/mcp-server.log"
    echo "  docker exec -i mserver netstat -tlnp | grep 8443"
    echo "  docker exec -i mclient python3 /app/client.py https://192.168.100.20:8443/mcp full --ca-cert /app/minica.pem"
fi

exit $code
