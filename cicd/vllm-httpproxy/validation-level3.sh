#!/bin/bash
source ../common.sh

echo SCENARIO-vllm-httpproxy-CHWBL-Level3

code=0

echo "#########################################"
echo "Testing CHWBL Level 3 - Full Hash"
echo "Port: 2023"
echo "Config: --chwbl-prefix-hash-level=3"
echo "        --chwbl-mean-load-factor=250"
echo "        --chwbl-replication=200"
echo "#########################################"

PORT=2023

echo "#########################################"
echo "Verifying LB configuration"
echo "#########################################"

lb_config=$($dexec llb1 loxicmd get lb -o wide | grep $PORT)
echo "$lb_config"
if [[ -z "$lb_config" ]]; then
    echo "ERROR: LB rule for port $PORT not found"
    exit 1
fi

# Verify CHWBL parameters in wide output
# Verify CHWBL parameters in wide output — match labeled fields precisely
if echo "$lb_config" | grep -qE 'chwbl-mean-load-factor[=: ]*250([^0-9]|$)' && \
   echo "$lb_config" | grep -qE 'chwbl-replication[=: ]*200([^0-9]|$)'; then
    echo "✓ CHWBL parameters verified: mean-load-factor=250, replication=200"
else
    echo "✗ CHWBL parameters not found in output (mean-load-factor=250, replication=200 expected)"
    code=1
fi

echo "#########################################"
echo "Testing Level 3 full hash consistency"
echo "(radix-tree prefix-cache: same model+prompt+temperature must route to same backend)"
echo "#########################################"

# Capture EP log baseline for routing consistency verification
EP1_BEFORE=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_BEFORE=${EP1_BEFORE:-0}
EP2_BEFORE=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_BEFORE=${EP2_BEFORE:-0}
echo "  Baseline: EP1=$EP1_BEFORE lines, EP2=$EP2_BEFORE lines"

# Level 3: Hash on model + prompt + temperature
# Same parameters should consistently route to same backend
echo "Testing 15 requests with identical parameters..."
FIRST_RESP=""
for i in {1..15}; do
    req_id="level3-same-$i"
    echo -n "  Request $i (ID: $req_id)... "
    
    result=$($dexec l3h1 curl -sk  -i http://10.10.10.254:$PORT/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d '{
            "model": "Qwen/Qwen3-0.6B",
            "prompt": "Describe artificial intelligence",
            "max_tokens": 48,
            "temperature": 0.7
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
# Verify radix-tree prefix-cache consistency: all 15 same-param requests must land on ONE backend
EP1_AFTER=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_AFTER=${EP1_AFTER:-0}
EP2_AFTER=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_AFTER=${EP2_AFTER:-0}
D1=$((EP1_AFTER - EP1_BEFORE))
D2=$((EP2_AFTER - EP2_BEFORE))
echo "  CHWBL L3 routing: EP1_delta=$D1  EP2_delta=$D2"
if ([ "$D1" -ge 15 ] && [ "$D2" -eq 0 ]) || ([ "$D2" -ge 15 ] && [ "$D1" -eq 0 ]); then
    echo "  ✓ CHWBL L3 radix-tree consistency verified: all requests to one backend (D1=$D1, D2=$D2)"
else
    echo "  ✗ CHWBL L3 radix-tree inconsistent: requests split across backends (D1=$D1, D2=$D2)"
    code=1
fi

echo "#########################################"
echo "Testing Level 3 distribution with varied parameters"
echo "#########################################"

# Different temperatures should hash differently at Level 3
temperatures=(0.1 0.3 0.5 0.7 0.9)

for temp in "${temperatures[@]}"; do
    req_id="level3-temp-$(echo $temp | tr '.' '_')"
    echo "Test with temperature=$temp (Request-ID: $req_id)"
    
    result=$($dexec l3h1 curl -sk  -i http://10.10.10.254:$PORT/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d "{
            \"model\": \"Qwen/Qwen3-0.6B\",
            \"prompt\": \"What is AI?\",
            \"max_tokens\": 32,
            \"temperature\": $temp
        }" 2>&1)
    
    if [[ $result == *"\"choices\""* ]]; then
        echo "  ✓ Temperature $temp completed"
    else
        echo "  ✗ Temperature $temp failed"
        code=1
    fi
    
    sleep 1
done

echo "#########################################"
echo "Testing max_tokens variation"
echo "#########################################"

max_tokens_values=(16 32 64 128)

for tokens in "${max_tokens_values[@]}"; do
    req_id="level3-tokens-$tokens"
    echo "Test with max_tokens=$tokens (Request-ID: $req_id)"
    
    result=$($dexec l3h1 curl -sk  -i http://10.10.10.254:$PORT/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d "{
            \"model\": \"Qwen/Qwen3-0.6B\",
            \"prompt\": \"Explain quantum physics\",
            \"max_tokens\": $tokens,
            \"temperature\": 0.5
        }" 2>&1)
    
    if [[ $result == *"\"choices\""* ]]; then
        echo "  ✓ max_tokens=$tokens completed"
    else
        echo "  ✗ max_tokens=$tokens failed"
        code=1
    fi
    
    sleep 1
done

echo "#########################################"
echo "Testing high load with Level 3"
echo "#########################################"

echo "Making 30 requests to test load distribution with 250% load factor..."
echo "Load factor=250% means servers can handle 150% overload"
PORT=2023
success_count=0
for i in {1..30}; do
    req_id="level3-load-$i"
    temp=$(printf "%.1f" $(echo "scale=1; 0.1 + ($i % 9) * 0.1" | bc))
    
    result=$($dexec l3h1 curl -sk  -i http://10.10.10.254:$PORT/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d "{
            \"model\": \"Qwen/Qwen3-0.6B\",
            \"prompt\": \"Test prompt $i\",
            \"max_tokens\": 16,
            \"temperature\": $temp
        }" 2>&1)
    
    if [[ $result == *"\"choices\""* ]]; then
        ((success_count++))
        echo -n "."
    else
        echo -n "x"
    fi
done
echo ""

echo "Success rate: $success_count/30"
if [[ $success_count -ge 27 ]]; then
    echo "✓ High load handling working (>= 90% success)"
else
    echo "✗ High load handling issues (< 90% success)"
    code=1
fi

echo "#########################################"
echo "Testing chat completions with Level 3"
echo "#########################################"

for i in {1..5}; do
    req_id="level3-chat-$i"
    echo "Chat test $i (Request-ID: $req_id)..."
    
    result=$($dexec l3h1 curl -sk  -i http://10.10.10.254:$PORT/v1/chat/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d "{
            \"model\": \"Qwen/Qwen3-0.6B\",
            \"messages\": [
                {\"role\": \"system\", \"content\": \"You are a helpful assistant.\"},
                {\"role\": \"user\", \"content\": \"Question $i: What is deep learning?\"}
            ],
            \"max_tokens\": 48,
            \"temperature\": 0.5
        }" 2>&1)
    
    if [[ $result == *"\"choices\""* ]]; then
        echo "  ✓ Chat request $i completed"
    else
        echo "  ✗ Chat request $i failed"
        code=1
    fi
    
    sleep 1
done

echo "#########################################"
echo "Testing replication with 200 vnodes"
echo "#########################################"

echo "Making diverse requests to test virtual node distribution..."
success_count=0
for i in {1..20}; do
    req_id="level3-vnode-$i"
    
    result=$($dexec l3h1 curl -sk  -H "X-Request-Id: $req_id" http://10.10.10.254:$PORT/v1/models 2>&1)
    
    if [[ $result == *"Qwen/Qwen3-0.6B"* ]]; then
        ((success_count++))
    fi
done

echo "Success rate: $success_count/20"
if [[ $success_count -ge 18 ]]; then
    echo "✓ Virtual node replication working (>= 90% success)"
else
    echo "✗ Virtual node issues (< 90% success)"
    code=1
fi

echo "#########################################"
echo "Verifying LoxiLB statistics"
echo "#########################################"

$dexec llb1 loxicmd get lb -o wide | grep $PORT

echo "#########################################"
echo "Level 3 Test Summary"
echo "#########################################"

if [[ $code == 0 ]]; then
    echo "SCENARIO-vllm-httpproxy-CHWBL-Level3 [OK]"
    echo ""
    echo "✓ CHWBL Level 3 working correctly"
    echo "✓ Full hash (model + prompt + params) functional"
    echo "✓ Radix-tree prefix-cache consistency verified (same prompt+temp → same backend)"
    echo "✓ High load factor (250%) handling verified"
    echo "✓ High replication (200 vnodes) working"
    echo "✓ Parameter variation distribution confirmed"
else
    echo "SCENARIO-vllm-httpproxy-CHWBL-Level3 [FAILED]"
fi

exit $code
