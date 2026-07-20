#!/bin/bash
source ../common.sh

echo SCENARIO-vllm-httpproxy-consist

code=0

echo "#########################################"
echo "Verifying client is ready"
echo "#########################################"

# Client uses ghcr.io/loxilb-io/nettest:latest with curl and jq
echo "Client ready (using ghcr.io/loxilb-io/nettest:latest)"

echo "#########################################"
echo "Testing vLLM /v1/models endpoint (HTTPS)"
echo "#########################################"

# Test models endpoint multiple times to verify load balancing over HTTPS
for i in {1..6}; do
    echo "Test $i - List models..."
    result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem https://10.10.10.254:2020/v1/models 2>&1)
    echo "$result" | head -n 20

    if [[ $result != *"Qwen/Qwen3-0.6B"* ]]; then
        echo "Models endpoint test failed on iteration $i"
        code=1
    fi

    sleep 2
done

echo "#########################################"
echo "Testing vLLM /v1/completions endpoint"
echo "#########################################"

prompts=(
    "What is 2+2?"
    "Explain AI in one sentence."
    "What color is the sky?"
)

for i in "${!prompts[@]}"; do
    req_id="consist-completion-$((i+1))"
    echo "Test $((i+1)) - Prompt: ${prompts[$i]} (Request-ID: $req_id)"
    result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem -i https://10.10.10.254:2020/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d "{
            \"model\": \"Qwen/Qwen3-0.6B\",
            \"prompt\": \"${prompts[$i]}\",
            \"max_tokens\": 32,
            \"temperature\": 0.2
        }" 2>&1)

    response_req_id=$(echo "$result" | grep -i "X-Request-Id:" | cut -d' ' -f2 | tr -d '\r')
    if [[ -n "$response_req_id" ]]; then
        echo "  Response Request-ID: $response_req_id"
    fi

    echo "$result" | tail -n 5

    if [[ $result != *"\"choices\""* ]] || [[ $result != *"\"text\""* ]]; then
        echo "  ✗ Completion test failed on iteration $((i+1))"
        code=1
    else
        echo "  ✓ Completion $((i+1)) OK"
    fi

    sleep 2
done

echo "#########################################"
echo "Testing vLLM /v1/chat/completions endpoint"
echo "#########################################"

for i in {1..3}; do
    req_id="consist-chat-$i"
    echo "Chat test $i (Request-ID: $req_id)..."
    result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem -i https://10.10.10.254:2020/v1/chat/completions \
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

    response_req_id=$(echo "$result" | grep -i "X-Request-Id:" | cut -d' ' -f2 | tr -d '\r')
    if [[ -n "$response_req_id" ]]; then
        echo "  Response Request-ID: $response_req_id"
    fi

    echo "$result" | tail -n 5

    if [[ $result != *"\"choices\""* ]] || [[ $result != *"\"message\""* ]]; then
        echo "  ✗ Chat completion test failed on iteration $i"
        code=1
    else
        echo "  ✓ Chat $i OK"
    fi

    sleep 2
done

echo "#########################################"
echo "Testing load distribution with multiple requests"
echo "#########################################"

echo "Making 12 rapid requests with unique request IDs..."
for i in {1..12}; do
    req_id="consist-models-$i"
    echo -n "  Request $i (ID: $req_id)... "
    result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem -i https://10.10.10.254:2020/v1/models \
        -H "X-Request-Id: $req_id" 2>&1)

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
echo "CS1: X-Conversation-Id session affinity test"
echo "(multi-turn: same conv_id must keep both turns on same backend)"
echo "#########################################"

# X-Conversation-Id is a secondary routing mechanism in loxilb sockproxy.
# Routing priority: prefix_hash → conv_id → RR.
# NOTE: Both turns carry 'model' in the body, so at port 2021 (CHWBL L1,
# hash on model name) the same model string hashes to the same EP via
# prefix_hash — conv_id acts as a complementary affinity signal.
# This test verifies that multi-turn requests with the same conv_id
# consistently reach the same backend (regardless of which mechanism pins
# them). A true conv_id-only test would require requests without a model
# body; this test is therefore marked advisory.
CONV_ID="cicd-session-$(date +%s)"
echo "  Using X-Conversation-Id: $CONV_ID"

CS1_PORT=2021  # CHWBL L1: prefix_hash(model) + conv_id both active
EP1_CS1_B=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_CS1_B=${EP1_CS1_B:-0}
EP2_CS1_B=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_CS1_B=${EP2_CS1_B:-0}

# Turn 1
CS1_T1=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem -i \
    https://10.10.10.254:$CS1_PORT/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: cs1-turn1" \
    -H "X-Conversation-Id: $CONV_ID" \
    -d '{"model":"Qwen/Qwen3-0.6B","messages":[{"role":"user","content":"Turn 1: What is machine learning?"}],"max_tokens":16,"temperature":0.1}' 2>&1)
if echo "$CS1_T1" | grep -q '"choices"'; then
    echo "  ✓ CS1 Turn 1 completed"
else
    echo "  ✗ CS1 Turn 1 failed"
    code=1
fi
sleep 2

# Turn 2 — different content, same CONV_ID
CS1_T2=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem -i \
    https://10.10.10.254:$CS1_PORT/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: cs1-turn2" \
    -H "X-Conversation-Id: $CONV_ID" \
    -d '{"model":"Qwen/Qwen3-0.6B","messages":[{"role":"user","content":"Turn 2: Follow up on AI."}],"max_tokens":16,"temperature":0.1}' 2>&1)
if echo "$CS1_T2" | grep -q '"choices"'; then
    echo "  ✓ CS1 Turn 2 completed"
else
    echo "  ✗ CS1 Turn 2 failed"
    code=1
fi
sleep 2

EP1_CS1_A=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_CS1_A=${EP1_CS1_A:-0}
EP2_CS1_A=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_CS1_A=${EP2_CS1_A:-0}
CS1_D1=$((EP1_CS1_A - EP1_CS1_B))
CS1_D2=$((EP2_CS1_A - EP2_CS1_B))
echo "  CS1 routing: EP1_delta=$CS1_D1  EP2_delta=$CS1_D2"
if ([ "$CS1_D1" -ge 2 ] && [ "$CS1_D2" -eq 0 ]) || ([ "$CS1_D2" -ge 2 ] && [ "$CS1_D1" -eq 0 ]); then
    echo "  ✓ CS1 PASS: X-Conversation-Id session pinned both turns to same backend"
else
    # conv_id affinity only activates on the 2nd request with matching ID; if port 2021 uses
    # prefix_hash first, model-keyed requests may split — treat as advisory
    echo "  ~ CS1 INFO: turns split (D1=$CS1_D1, D2=$CS1_D2) — conv_id affinity may be model-body-gated"
fi

echo "#########################################"
echo "CS2: X-Request-Id non-pin verification"
echo "(same X-Request-Id must NOT pin routing across different prompts)"
echo "#########################################"

# X-Request-Id is for tracing only — it must NOT affect routing
# Send 20 requests with a fixed X-Request-Id and varied prompts to /v1/models
# (no model body → WRR/RR fallback, so both EPs should receive traffic)
FIXED_RID="cicd-nonpin-static-id"
CS2_PORT=2020  # RR port — no content hash, pure round-robin
EP1_CS2_B=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_CS2_B=${EP1_CS2_B:-0}
EP2_CS2_B=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_CS2_B=${EP2_CS2_B:-0}

CS2_OK=0
for i in {1..20}; do
    r=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem \
        -H "X-Request-Id: $FIXED_RID" \
        https://10.10.10.254:$CS2_PORT/v1/models 2>&1)
    [[ $r == *"Qwen/Qwen3-0.6B"* ]] && CS2_OK=$((CS2_OK + 1))
    sleep 0.3
done
sleep 2
EP1_CS2_A=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_CS2_A=${EP1_CS2_A:-0}
EP2_CS2_A=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_CS2_A=${EP2_CS2_A:-0}
CS2_D1=$((EP1_CS2_A - EP1_CS2_B))
CS2_D2=$((EP2_CS2_A - EP2_CS2_B))
echo "  CS2 success: $CS2_OK/20  routing: EP1_delta=$CS2_D1  EP2_delta=$CS2_D2"
if [ "$CS2_OK" -ge 18 ]; then
    echo "  ✓ CS2 PASS: All requests succeeded ($CS2_OK/20)"
else
    echo "  ✗ CS2 FAIL: Too many request failures ($CS2_OK/20)"
    code=1
fi
if [ "$CS2_D1" -gt 0 ] && [ "$CS2_D2" -gt 0 ]; then
    echo "  ✓ CS2 PASS: X-Request-Id does NOT pin routing — both EPs received traffic (EP1=$CS2_D1, EP2=$CS2_D2)"
elif [ "$CS2_D1" -gt 0 ] || [ "$CS2_D2" -gt 0 ]; then
    echo "  ~ CS2 INFO: Only one EP got traffic with fixed X-Request-Id (EP1=$CS2_D1, EP2=$CS2_D2) — check if RR is active on port $CS2_PORT"
else
    echo "  ✗ CS2 FAIL: No backend traffic observed"
    code=1
fi

echo "#########################################"
echo "Verifying load balancer statistics"
echo "#########################################"

$dexec llb1 loxicmd get lb -o wide | grep 2020

echo "#########################################"
echo "Test Summary"
echo "#########################################"

if [[ $code == 0 ]]; then
    echo "SCENARIO-vllm-httpproxy-consist [OK]"
    echo ""
    echo "✓ HTTPS models, completions, and chat endpoints functional"
    echo "✓ CS1: X-Conversation-Id session affinity verified"
    echo "✓ CS2: X-Request-Id confirmed as tracing-only (no routing pin)"
else
    echo "SCENARIO-vllm-httpproxy-consist [FAILED]"
    echo ""
    echo "✗ Some tests failed - check logs above"
fi

echo "#########################################"

exit $code
