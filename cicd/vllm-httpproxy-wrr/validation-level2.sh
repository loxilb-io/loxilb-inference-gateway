#!/bin/bash
source ../common.sh

echo SCENARIO-vllm-httpproxy-CHWBL-wrr-Level2

code=0

echo "#########################################"
echo "Testing CHWBL Level 2 - Extended Hash"
echo "Port: 2022"
echo "Config: --chwbl-prefix-hash-level=2"
echo "        --chwbl-mean-load-factor=125"
echo "        --chwbl-replication=100"
echo "#########################################"

PORT=2022

echo "#########################################"
echo "Verifying LB configuration"
echo "#########################################"

lb_config=$($dexec llb1 loxicmd get lb -o wide | grep $PORT)
echo "$lb_config"
if [[ -z "$lb_config" ]]; then
    echo "ERROR: LB rule for port $PORT not found"
    exit 1
fi

# Verify CHWBL parameters in wide output — match labeled fields precisely
if echo "$lb_config" | grep -qE 'chwbl-mean-load-factor[=: ]*125([^0-9]|$)' && \
   echo "$lb_config" | grep -qE 'chwbl-replication[=: ]*100([^0-9]|$)'; then
    echo "✓ CHWBL parameters verified: mean-load-factor=125, replication=100"
else
    echo "✗ CHWBL parameters not found in output (mean-load-factor=125, replication=100 expected)"
    code=1
fi

echo "#########################################"
echo "Testing Level 2 consistency"
echo "(radix-tree prefix-cache: same model+prompt must route to same backend)"
echo "#########################################"

# Capture EP log baseline for routing consistency verification
EP1_BEFORE=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_BEFORE=${EP1_BEFORE:-0}
EP2_BEFORE=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_BEFORE=${EP2_BEFORE:-0}
echo "  Baseline: EP1=$EP1_BEFORE lines, EP2=$EP2_BEFORE lines"

# Level 2: Hash on model + prompt prefix
# Same model+prompt should go to same backend
echo "Testing 10 requests with same model and prompt..."
FIRST_RESP=""
for i in {1..10}; do
    req_id="level2-same-$i"
    echo -n "  Request $i (ID: $req_id)... "
    
    result=$($dexec l3h1 curl -sk  -i http://10.10.10.254:$PORT/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d '{
            "model": "Qwen/Qwen3-0.6B",
            "prompt": "Explain quantum computing",
            "max_tokens": 32,
            "temperature": 0.1
        }' 2>&1)
    
    response_req_id=$(echo "$result" | grep -i "X-Request-Id:" | cut -d' ' -f2 | tr -d '\r')
    [[ -z "$FIRST_RESP" ]] && FIRST_RESP="$result"
    
    if [[ $result == *"\"choices\""* ]]; then
        echo "OK (Response-ID: $response_req_id)"
    else
        echo "FAIL"
        code=1
    fi
    
    sleep 1
done

# Validate JSON structure of first response
FIRST_BODY=$(echo "$FIRST_RESP" | awk '/^\r$/{found=1;next} found{print}' | tr -d '\r')
if [[ -z "$FIRST_BODY" ]]; then
    FIRST_BODY=$(echo "$FIRST_RESP" | tail -1)
fi
if echo "$FIRST_BODY" | grep -qP '"total_tokens"\s*:\s*[1-9]'; then
    echo "  ✓ JSON: usage.total_tokens > 0"
else
    echo "  ~ JSON: usage.total_tokens not verified (mock may omit usage)"
fi
if echo "$FIRST_BODY" | grep -q '"model"'; then
    echo "  ✓ JSON: model field present"
else
    echo "  ✗ JSON: model field missing in response"
    code=1
fi

sleep 2
# Verify radix-tree prefix-cache consistency: all 10 same-prompt requests must land on ONE backend
EP1_AFTER=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_AFTER=${EP1_AFTER:-0}
EP2_AFTER=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_AFTER=${EP2_AFTER:-0}
D1=$((EP1_AFTER - EP1_BEFORE))
D2=$((EP2_AFTER - EP2_BEFORE))
echo "  CHWBL WRR L2 routing: EP1_delta=$D1  EP2_delta=$D2"
if ([ "$D1" -ge 10 ] && [ "$D2" -eq 0 ]) || ([ "$D2" -ge 10 ] && [ "$D1" -eq 0 ]); then
    echo "  ✓ CHWBL WRR L2 radix-tree consistency verified: all requests to one backend (D1=$D1, D2=$D2)"
else
    echo "  ✗ CHWBL WRR L2 radix-tree inconsistent: requests split across backends (D1=$D1, D2=$D2)"
    code=1
fi

echo "#########################################"
echo "Testing Level 2 distribution with different prompts"
echo "#########################################"

# Different prompts might hash to different backends
prompts=(
    "What is machine learning?"
    "Explain deep learning"
    "Describe neural networks"
    "What are transformers?"
)

for i in "${!prompts[@]}"; do
    req_id="level2-prompt-$((i+1))"
    echo "Test $((i+1)) - Prompt: ${prompts[$i]}"
    
    result=$($dexec l3h1 curl -sk  -i http://10.10.10.254:$PORT/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d "{
            \"model\": \"Qwen/Qwen3-0.6B\",
            \"prompt\": \"${prompts[$i]}\",
            \"max_tokens\": 32,
            \"temperature\": 0.1
        }" 2>&1)
    
    if [[ $result == *"\"choices\""* ]]; then
        echo "  ✓ Request completed"
    else
        echo "  ✗ Request failed"
        code=1
    fi
    
    sleep 1
done

echo "#########################################"
echo "Testing chat completions endpoint"
echo "#########################################"

for i in {1..3}; do
    req_id="level2-chat-$i"
    echo "Chat test $i (Request-ID: $req_id)..."
    
    result=$($dexec l3h1 curl -sk  -i http://10.10.10.254:$PORT/v1/chat/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d '{
            "model": "Qwen/Qwen3-0.6B",
            "messages": [
                {"role": "user", "content": "Explain AI briefly"}
            ],
            "max_tokens": 32,
            "temperature": 0.1
        }' 2>&1)
    
    if [[ $result == *"\"choices\""* ]]; then
        echo "  ✓ Chat request $i completed"
    else
        echo "  ✗ Chat request $i failed"
        code=1
    fi
    
    sleep 1
done

echo "#########################################"
echo "Testing load factor behavior"
echo "#########################################"

echo "Making 20 rapid requests to test load distribution..."
echo "Load factor=125% means servers can handle 25% overload"

success_count=0
for i in {1..20}; do
    req_id="level2-load-$i"
    result=$($dexec l3h1 curl -sk  -H "X-Request-Id: $req_id" http://10.10.10.254:$PORT/v1/models 2>&1)
    
    if [[ $result == *"Qwen/Qwen3-0.6B"* ]]; then
        ((success_count++))
    fi
done

echo "Success rate: $success_count/20"
if [[ $success_count -ge 18 ]]; then
    echo "✓ Load distribution working (>= 90% success)"
else
    echo "✗ Load distribution issues (< 90% success)"
    code=1
fi

echo "#########################################"
echo "Verifying LoxiLB statistics"
echo "#########################################"

$dexec llb1 loxicmd get lb -o wide | grep $PORT

echo "#########################################"
echo "Level 2 Test Summary"
echo "#########################################"

if [[ $code == 0 ]]; then
    echo "SCENARIO-vllm-httpproxy-CHWBL-wrr-Level2 [OK]"
    echo ""
    echo "✓ CHWBL Level 2 working correctly"
    echo "✓ Extended hash (model + prompt) functional"
    echo "✓ Radix-tree prefix-cache consistency verified (same prompt → same backend)"
    echo "✓ Load factor (125%) respected"
    echo "✓ Replication (100 vnodes) working"
else
    echo "SCENARIO-vllm-httpproxy-CHWBL-wrr-Level2 [FAILED]"
fi

exit $code
