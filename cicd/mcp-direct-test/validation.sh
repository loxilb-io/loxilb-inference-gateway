#!/bin/bash
source ../common.sh

echo "========================================="
echo "MCP Direct Communication Test"
echo "========================================="

code=0

echo ""
echo "#########################################"
echo "Step 1: Network Connectivity Test"
echo "#########################################"

echo "Testing ping from client to server..."
ping_result=$($dexec mclient ping -c 3 -W 2 192.168.100.20 2>&1)
echo "$ping_result"

if [[ $ping_result == *"3 packets transmitted, 3 received"* ]] || [[ $ping_result == *"3 received"* ]]; then
    echo "✓ Network connectivity OK"
else
    echo "✗ Network connectivity FAILED"
    code=1
fi

echo ""
echo "#########################################"
echo "Step 2: HTTP Connection Test"
echo "#########################################"

echo "Testing HTTP connection with curl..."
http_result=$($dexec mclient curl -s -m 5 http://192.168.100.20:8080/ 2>&1)
echo "$http_result"

if [[ $http_result == *"html"* ]] || [[ $http_result != "" ]]; then
    echo "✓ HTTP connection OK"
else
    echo "✗ HTTP connection FAILED"
    code=1
fi

echo ""
echo "#########################################"
echo "Step 3: MCP Health Check Test"
echo "#########################################"

echo "Testing MCP health endpoint..."
health_result=$($dexec mclient python3 /app/client.py http://192.168.100.20:8080/mcp health 2>&1)
echo "$health_result"

if [[ $health_result == *"Health: OK"* ]]; then
    echo "✓ MCP health check PASSED"
else
    echo "✗ MCP health check FAILED"
    code=1
fi

echo ""
echo "#########################################"
echo "Step 4: MCP Echo Test"
echo "#########################################"

echo "Testing MCP echo endpoint..."
echo_result=$($dexec mclient python3 /app/client.py http://192.168.100.20:8080/mcp echo 2>&1)
echo "$echo_result"

if [[ $echo_result == *"test-message"* ]]; then
    echo "✓ MCP echo test PASSED"
else
    echo "✗ MCP echo test FAILED"
    code=1
fi

echo ""
echo "#########################################"
echo "Step 5: MCP Get Models Test"
echo "#########################################"

echo "Testing MCP get_models endpoint..."
models_result=$($dexec mclient python3 /app/client.py http://192.168.100.20:8080/mcp models 2>&1)
echo "$models_result"

if [[ $models_result == *"test-server"* ]] && [[ $models_result == *"gpt"* ]]; then
    echo "✓ MCP get_models test PASSED"
else
    echo "✗ MCP get_models test FAILED"
    code=1
fi

echo ""
echo "#########################################"
echo "Step 6: MCP Chat Completion Test"
echo "#########################################"

echo "Testing MCP chat_completion endpoint..."
chat_result=$($dexec mclient python3 /app/client.py http://192.168.100.20:8080/mcp chat 2>&1)
echo "$chat_result"

if [[ $chat_result == *"response"* ]] && [[ $chat_result == *"test-server"* ]]; then
    echo "✓ MCP chat_completion test PASSED"
else
    echo "✗ MCP chat_completion test FAILED"
    code=1
fi

echo ""
echo "#########################################"
echo "Step 7: MCP Server Info Test"
echo "#########################################"

echo "Testing MCP get_server_info endpoint..."
info_result=$($dexec mclient python3 /app/client.py http://192.168.100.20:8080/mcp info 2>&1)
echo "$info_result"

if [[ $info_result == *"name"* ]] && [[ $info_result == *"test-server"* ]]; then
    echo "✓ MCP server_info test PASSED"
else
    echo "✗ MCP server_info test FAILED"
    code=1
fi

echo ""
echo "#########################################"
echo "Step 8: MCP Resources Test"
echo "#########################################"

echo "Testing MCP resources endpoints..."
resources_result=$($dexec mclient python3 /app/client.py http://192.168.100.20:8080/mcp resources 2>&1)
echo "$resources_result"

if [[ $resources_result == *"Config"* ]] || [[ $resources_result == *"test-server"* ]]; then
    echo "✓ MCP resources test PASSED"
else
    echo "✗ MCP resources test FAILED"
    code=1
fi

echo ""
echo "#########################################"
echo "Step 9: Full MCP Test Suite"
echo "#########################################"

echo "Running complete MCP test suite..."
full_result=$($dexec mclient python3 /app/client.py http://192.168.100.20:8080/mcp full 2>&1)
echo "$full_result"

if [[ $full_result == *"Test Summary"* ]]; then
    echo "✓ Full MCP test suite COMPLETED"
    
    # Count passed tests
    if [[ $full_result == *"Passed: 6/6"* ]]; then
        echo "✓ All 6 tests passed!"
    else
        echo "⚠ Some tests may have failed - check output above"
        code=1
    fi
else
    echo "✗ Full MCP test suite FAILED"
    code=1
fi

echo ""
echo "#########################################"
echo "Test Summary"
echo "#########################################"

if [[ $code == 0 ]]; then
    echo ""
    echo "========================================="
    echo "  SCENARIO-mcp-direct-test [OK]"
    echo "========================================="
    echo ""
    echo "✓ All direct communication tests passed!"
    echo "✓ MCP server and client are working correctly"
    echo "✓ Ready to proceed with loxilb integration tests"
    echo ""
else
    echo ""
    echo "========================================="
    echo "  SCENARIO-mcp-direct-test [FAILED]"
    echo "========================================="
    echo ""
    echo "✗ Some tests failed - check output above"
    echo ""
    echo "Debug commands:"
    echo "  docker exec -i mserver cat /tmp/mcp-server.log"
    echo "  docker exec -i mserver netstat -tlnp | grep 8080"
    echo "  docker exec -i mclient ping -c 3 192.168.100.20"
    echo "  docker exec -i mclient curl -v http://192.168.100.20:8080/"
    echo ""
fi

# Cleanup
echo "Cleaning up MCP server..."
$dexec mserver killall -9 python3 > /dev/null 2>&1

exit $code
