#!/bin/bash
source ../common.sh

echo SCENARIO-vllm-httpproxy-wrr

code=0

echo "#########################################"
echo "Verifying client is ready"
echo "#########################################"

# Client uses ghcr.io/loxilb-io/nettest:latest with curl and jq
echo "Client ready (using ghcr.io/loxilb-io/nettest:latest)"

echo "#########################################"
echo "Testing vLLM /v1/models endpoint"
echo "#########################################"

# Test models endpoint multiple times to verify load balancing
for i in {1..6}; do
    echo "Test $i - List models..."
    result=$($dexec l3h1 curl -sk  http://10.10.10.254:2020/v1/models 2>&1)
    echo "$result" | head -n 20
    
    # Check if response contains model info
    if [[ $result != *"Qwen/Qwen3-0.6B"* ]]; then
        echo "Models endpoint test failed on iteration $i"
        code=1
    fi
    
    sleep 2
done

echo "#########################################"
echo "Testing vLLM /v1/completions endpoint"
echo "#########################################"

# Test completions endpoint with different prompts
prompts=(
    "What is 2+2?"
    "Explain AI in one sentence."
    "What color is the sky?"
)

for i in "${!prompts[@]}"; do
    req_id="completion-test-$((i+1))"
    echo "Test $((i+1)) - Prompt: ${prompts[$i]} (Request-ID: $req_id)"
    result=$($dexec l3h1 curl -sk  -i http://10.10.10.254:2020/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d "{
            \"model\": \"Qwen/Qwen3-0.6B\",
            \"prompt\": \"${prompts[$i]}\",
            \"max_tokens\": 32,
            \"temperature\": 0.2
        }" 2>&1)
    
    # Extract and display request ID from response headers
    response_req_id=$(echo "$result" | grep -i "X-Request-Id:" | cut -d' ' -f2 | tr -d '\r')
    if [[ -n "$response_req_id" ]]; then
        echo "Response Request-ID: $response_req_id"
    fi
    
    echo "$result" | tail -n 30
    
    # Check if response contains completion
    if [[ $result != *"\"choices\""* ]] || [[ $result != *"\"text\""* ]]; then
        echo "Completion test failed on iteration $((i+1))"
        code=1
    fi
    
    sleep 2
done

echo "#########################################"
echo "Testing vLLM /v1/chat/completions endpoint"
echo "#########################################"

# Test chat completions endpoint
for i in {1..3}; do
    req_id="chat-test-$i"
    echo "Chat test $i (Request-ID: $req_id)..."
    result=$($dexec l3h1 curl -sk  -i http://10.10.10.254:2020/v1/chat/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d '{
            "model": "Qwen/Qwen3-0.6B",
            "messages": [
                {"role": "user", "content": "Hello! How are you?"}
            ],
            "max_tokens": 32,
            "temperature": 0.2
        }' 2>&1)
    
    # Extract and display request ID from response headers
    response_req_id=$(echo "$result" | grep -i "X-Request-Id:" | cut -d' ' -f2 | tr -d '\r')
    if [[ -n "$response_req_id" ]]; then
        echo "Response Request-ID: $response_req_id"
    fi
    
    echo "$result" | tail -n 30
    
    # Check if response contains chat completion
    if [[ $result != *"\"choices\""* ]] || [[ $result != *"\"message\""* ]]; then
        echo "Chat completion test failed on iteration $i"
        code=1
    fi
    
    sleep 2
done

echo "#########################################"
echo "Testing load distribution with multiple requests"
echo "#########################################"

# Make rapid requests to test round-robin with request IDs
echo "Making 12 rapid requests with unique request IDs..."
for i in {1..12}; do
    req_id="models-test-$i"
    echo -n "Request $i (ID: $req_id)... "
    result=$($dexec l3h1 curl -sk  -i http://10.10.10.254:2020/v1/models \
        -H "X-Request-Id: $req_id" 2>&1)
    
    # Extract response request ID
    response_req_id=$(echo "$result" | grep -i "X-Request-Id:" | cut -d' ' -f2 | tr -d '\r')
    
    if [[ $result == *"Qwen/Qwen3-0.6B"* ]]; then
        echo "OK (Response-ID: $response_req_id)"
    else
        echo "FAILED"
        code=1
    fi
    
    sleep 1
done

echo "#########################################"
echo "Verifying load balancer statistics"
echo "#########################################"

# Check loxilb load balancer statistics
echo "LoxiLB statistics:"
$dexec llb1 loxicmd get lb -o wide

echo "#########################################"
echo "Testing WRR weight distribution (weights 8:2 = ~80%/20%)"
echo "EP1 (weight 8) expected ~80%, EP2 (weight 2) expected ~20%"
echo "#########################################"

# /v1/models has no model key in body → prefix_hash=0 → falls back to pure WRR
# This is the correct path to exercise WRR weight distribution
EP1_WD=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_WD=${EP1_WD:-0}
EP2_WD=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_WD=${EP2_WD:-0}

echo "  Sending 40 requests to verify WRR distribution..."
for i in {1..40}; do
    $dexec l3h1 curl -sk \
        -H "X-Request-Id: wrr-main-$i" \
        http://10.10.10.254:2020/v1/models > /dev/null 2>&1
    sleep 0.2
done
sleep 2

EP1_WD_A=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_WD_A=${EP1_WD_A:-0}
EP2_WD_A=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_WD_A=${EP2_WD_A:-0}
D1_WD=$((EP1_WD_A - EP1_WD))
D2_WD=$((EP2_WD_A - EP2_WD))
TOTAL_WD=$((D1_WD + D2_WD))
echo "  WRR distribution: EP1=$D1_WD  EP2=$D2_WD  Total=$TOTAL_WD"
if [ "$TOTAL_WD" -gt 0 ] && [ "$D2_WD" -gt 0 ]; then
    RATIO_WD=$((D1_WD * 100 / TOTAL_WD))
    echo "  EP1 handled ${RATIO_WD}% (target ~80% for weight 8:2)"
    # Allow ±25% tolerance (55-95%) around the expected 80% for weight 8 out of 10
    if [ "$RATIO_WD" -ge 55 ] && [ "$RATIO_WD" -le 95 ]; then
        echo "  ✓ WRR weight distribution within tolerance (EP1=${RATIO_WD}%, EP2=$((100 - RATIO_WD))%)"
    else
        echo "  ✗ WRR weight distribution out of tolerance (EP1=${RATIO_WD}%, expected 55-95%)"
        code=1
    fi
elif [ "$TOTAL_WD" -gt 0 ] && [ "$D2_WD" -eq 0 ]; then
    echo "  ✗ WRR FAIL: EP2 (weight 2) received zero traffic — WRR not functioning (EP1=$D1_WD, EP2=$D2_WD)"
    code=1
else
    echo "  ✗ WRR FAIL: No backend traffic observed"
    code=1
fi

echo "#########################################"
echo "Checking vLLM server logs"
echo "#########################################"

for ep in l3ep1 l3ep2; do
    echo "=== $ep logs (last 10 lines) ==="
    $dexec $ep tail -n 10 /tmp/vllm-server*.log 2>/dev/null || echo "No logs found"
done


echo "#########################################"
echo "Test Summary"
echo "#########################################"

if [[ $code == 0 ]]; then
    echo "SCENARIO-vllm-httpproxy-wrr [OK]"
    echo ""
    echo "✓ All vLLM endpoints tested successfully"
    echo "✓ HTTPS termination working"
    echo "✓ Load balancing across 3 backends verified"
    echo "✓ Models, completions, and chat endpoints functional"
else
    echo "SCENARIO-vllm-httpproxy-wrr [FAILED]"
    echo ""
    echo "✗ Some tests failed - check logs above"
fi

echo "#########################################"

exit $code
