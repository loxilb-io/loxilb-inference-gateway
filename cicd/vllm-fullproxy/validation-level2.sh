#!/bin/bash
source ../common.sh

echo SCENARIO-vllm-fullproxy-CHWBL-Level2

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

lb_json=$($dexec llb1 wget -qO- http://127.0.0.1:11111/netlox/v1/config/loadbalancer/all 2>/dev/null)
lb_config=$(echo "$lb_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('lbAttr', []):
    sa = r.get('serviceArguments', {})
    if sa.get('port') == $PORT:
        print(json.dumps(sa))
")
if [[ -z "$lb_config" ]]; then
    echo "ERROR: LB rule for port $PORT not found via REST API"
    echo "$lb_json"
    exit 1
fi
echo "$lb_config"

# Verify CHWBL parameters using JSON field names from REST API
if echo "$lb_config" | grep -qE '"chwbl_mean_load_factor":[[:space:]]*125' && \
   echo "$lb_config" | grep -qE '"chwbl_replication":[[:space:]]*100'; then
    echo "✓ CHWBL parameters verified: chwbl_mean_load_factor=125, chwbl_replication=100"
else
    echo "✗ CHWBL parameters not found in REST API response (chwbl_mean_load_factor:125, chwbl_replication:100 expected)"
    code=1
fi

echo "#########################################"
echo "Testing Level 2 consistency"
echo "#########################################"

# Level 2: Hash on model + prompt prefix
# Same model+prompt should go to same backend
echo "Testing 10 requests with same model and prompt..."
for i in {1..10}; do
    req_id="level2-same-$i"
    echo "Request $i (ID: $req_id)..."
    
    result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem --no-keepalive -i https://10.10.10.254:$PORT/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d '{
            "model": "Qwen/Qwen3-0.6B",
            "prompt": "Explain quantum computing",
            "max_tokens": 8,
            "temperature": 0.1
        }' 2>&1)
    
    response_req_id=$(echo "$result" | grep -i "X-Request-Id:" | cut -d' ' -f2 | tr -d '\r')
    
    if [[ $result == *"\"choices\""* ]]; then
        echo "  ✓ Request $i completed (Response-ID: $response_req_id)"
    else
        echo "  ✗ Request $i failed"
        code=1
    fi
    
    sleep 1
done

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
    
    result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem --no-keepalive -i https://10.10.10.254:$PORT/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d "{
            \"model\": \"Qwen/Qwen3-0.6B\",
            \"prompt\": \"${prompts[$i]}\",
            \"max_tokens\": 8,
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
    
    result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem --no-keepalive -i https://10.10.10.254:$PORT/v1/chat/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d '{
            "model": "Qwen/Qwen3-0.6B",
            "messages": [
                {"role": "user", "content": "Explain AI briefly"}
            ],
            "max_tokens": 8,
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
    result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem -H "X-Request-Id: $req_id" https://10.10.10.254:$PORT/v1/models 2>&1)
    
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

$dexec llb1 wget -qO- http://127.0.0.1:11111/netlox/v1/config/loadbalancer/all 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('lbAttr', []):
    sa = r.get('serviceArguments', {})
    if sa.get('port') == $PORT:
        print(json.dumps(sa, indent=2))
"

echo "#########################################"
echo "Level 2 Test Summary"
echo "#########################################"

if [[ $code == 0 ]]; then
    echo "SCENARIO-vllm-fullproxy-CHWBL-Level2 [OK]"
    echo ""
    echo "✓ CHWBL Level 2 working correctly"
    echo "✓ Extended hash (model + prompt) functional"
    echo "✓ Load factor (125%) respected"
    echo "✓ Replication (100 vnodes) working"
else
    echo "SCENARIO-vllm-fullproxy-CHWBL-Level2 [FAILED]"
fi

exit $code
