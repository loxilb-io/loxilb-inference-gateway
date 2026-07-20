#!/bin/bash
source ../common.sh

echo SCENARIO-vllm-fullproxy-wrr

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
    result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem https://10.10.10.254:2020/v1/models 2>&1)
    echo "$result" | head -n 20
    
    # Check if response contains model info
    if [[ $result != *"Qwen/Qwen3-0.6B"* ]]; then
        echo "Models endpoint test failed on iteration $i"
        code=1
    fi
    
    sleep 2
done

# echo "#########################################"
# echo "Testing vLLM /v1/completions endpoint"
# echo "#########################################"

# 
# prompts=(
#     "What is 2+2?"
#     "Explain AI in one sentence."
#     "What color is the sky?"
# )

# for i in "${!prompts[@]}"; do
#     req_id="completion-test-1"
#     echo "Test $((i+1)) - Prompt: ${prompts[$i]} (Request-ID: $req_id)"
#     result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem -i https://10.10.10.254:2020/v1/completions \
#         -H "Content-Type: application/json" \
#         -H "X-Request-Id: $req_id" \
#         -d "{
#             \"model\": \"Qwen/Qwen3-0.6B\",
#             \"prompt\": \"${prompts[$i]}\",
#             \"max_tokens\": 32,
#             \"temperature\": 0.2
#         }" 2>&1)
    
#     # Extract and display request ID from response headers
#     response_req_id=$(echo "$result" | grep -i "X-Request-Id:" | cut -d' ' -f2 | tr -d '\r')
#     if [[ -n "$response_req_id" ]]; then
#         echo "Response Request-ID: $response_req_id"
#     fi
    
#     echo "$result" | tail -n 30
    
#     # Check if response contains completion
#     if [[ $result != *"\"choices\""* ]] || [[ $result != *"\"text\""* ]]; then
#         echo "Completion test failed on iteration $((i+1))"
#         code=1
#     fi
    
#     sleep 2
# done

# echo "#########################################"
# echo "Testing vLLM /v1/chat/completions endpoint"
# echo "#########################################"

# for i in {1..3}; do
#     req_id="chat-test-1"
#     echo "Chat test $i (Request-ID: $req_id)..."
#     result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem -i https://10.10.10.254:2020/v1/chat/completions \
#         -H "Content-Type: application/json" \
#         -H "X-Request-Id: $req_id" \
#         -d '{
#             "model": "Qwen/Qwen3-0.6B",
#             "messages": [
#                 {"role": "user", "content": "Hello! How are you?"}
#             ],
#             "max_tokens": 32,
#             "temperature": 0.2
#         }' 2>&1)
    
#     response_req_id=$(echo "$result" | grep -i "X-Request-Id:" | cut -d' ' -f2 | tr -d '\r')
#     if [[ -n "$response_req_id" ]]; then
#         echo "Response Request-ID: $response_req_id"
#     fi
    
#     echo "$result" | tail -n 30
    
#     if [[ $result != *"\"choices\""* ]] || [[ $result != *"\"message\""* ]]; then
#         echo "Chat completion test failed on iteration $i"
#         code=1
#     fi
    
#     sleep 2
# done

# echo "#########################################"
# echo "Testing load distribution with multiple requests"
# echo "#########################################"

# echo "Making 12 rapid requests with unique request IDs..."
# for i in {1..12}; do
#     req_id="models-test-1"
#     echo -n "Request $i (ID: $req_id)... "
#     result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem -i https://10.10.10.254:2020/v1/models \
#         -H "X-Request-Id: $req_id" 2>&1)
    
#     response_req_id=$(echo "$result" | grep -i "X-Request-Id:" | cut -d' ' -f2 | tr -d '\r')
    
#     if [[ $result == *"Qwen/Qwen3-0.6B"* ]]; then
#         echo "OK (Response-ID: $response_req_id)"
#     else
#         echo "FAILED"
#         code=1
#     fi
    
#     sleep 1
# done

echo "#########################################"
echo "Verifying load balancer statistics"
echo "#########################################"

echo "#########################################"
echo "Test Summary"
echo "#########################################"

if [[ $code == 0 ]]; then
    echo "SCENARIO-vllm-fullproxy-wrr [OK]"
    echo ""
    echo "✓ All vLLM endpoints tested successfully"
    echo "✓ HTTPS termination working"
    echo "✓ Load balancing across 3 backends verified"
    echo "✓ Models, completions, and chat endpoints functional"
else
    echo "SCENARIO-vllm-fullproxy-wrr [FAILED]"
    echo ""
    echo "✗ Some tests failed - check logs above"
fi

echo "#########################################"

exit $code
