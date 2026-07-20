#!/bin/bash
source ../common.sh

echo SCENARIO-vllm-fullproxy-CHWBL-Level1

code=0

echo "#########################################"
echo "Testing CHWBL Level 1 - Basic Prefix Hash"
echo "Port: 2021"
echo "Config: --chwbl-prefix-hash-level=1"
echo "#########################################"

PORT=2021

echo "#########################################"
echo "Verifying LB configuration"
echo "#########################################"

lb_json=$($dexec llb1 wget -qO- http://127.0.0.1:11111/netlox/v1/config/loadbalancer/all 2>/dev/null)
echo "$lb_json" | grep -o "\"port\":$PORT" > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
    echo "ERROR: LB rule for port $PORT not found via REST API"
    echo "$lb_json"
    exit 1
fi
echo "$lb_json" | grep -o "\"port\":$PORT.*\"sel\":8" || echo "$lb_json" | python3 -c "import sys,json; rules=[r for r in json.load(sys.stdin).get('lbAttr',[]) if r.get('serviceArguments',{}).get('port')==$PORT]; print(json.dumps(rules[0].get('serviceArguments',{}))) if rules else print('not found')"

echo "#########################################"
echo "Testing CHWBL Level 1 consistency"
echo "(same model+prompt must route to same backend)"
echo "#########################################"

# Warmup: send 1 request with exact same model+prompt to initialize CHWBL routing
# and ensure vLLM EP is ready for the first real request (avoids cold-start failure)
echo "  Sending warmup request (same model+prompt) to initialize routing..."
$dexec l3h1 curl -sk --cacert /tmp/minica.pem --no-keepalive -i https://10.10.10.254:$PORT/v1/completions \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: warmup-L1-same" \
    -d '{"model":"Qwen/Qwen3-0.6B","prompt":"CHWBL L1 consistency probe","max_tokens":4,"temperature":0.0}' > /dev/null 2>&1
sleep 3
echo "  Warmup done. Capturing baselines..."

# Capture EP log baselines AFTER warmup — count only POST /v1/completions to exclude health probes
EP1_BEFORE=$($dexec l3ep1 grep -c 'POST /v1/completions' /tmp/vllm-server1.log 2>/dev/null)
EP1_BEFORE=${EP1_BEFORE:-0}
EP2_BEFORE=$($dexec l3ep2 grep -c 'POST /v1/completions' /tmp/vllm-server2.log 2>/dev/null)
EP2_BEFORE=${EP2_BEFORE:-0}
echo "  Baseline (completions only): EP1=$EP1_BEFORE, EP2=$EP2_BEFORE"

OK_COUNT=0
for i in {1..8}; do
    req_id="level1-same-$i"
    echo -n "  Request $i (ID: $req_id)... "
    result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem --no-keepalive -i https://10.10.10.254:$PORT/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d '{"model":"Qwen/Qwen3-0.6B","prompt":"CHWBL L1 consistency probe","max_tokens":8,"temperature":0.0}' 2>&1)
    if echo "$result" | grep -q '"choices"'; then
        echo "OK"
        OK_COUNT=$((OK_COUNT + 1))
    else
        echo "FAIL (response: $(echo "$result" | grep -oE 'HTTP/[0-9.]+ [0-9]+' | head -1))"
        code=1
    fi
    sleep 1
done
[ "$OK_COUNT" -eq 8 ] || code=1
echo "  Functional: $OK_COUNT/8 requests succeeded"

sleep 2
# Count only POST /v1/completions to exclude health probes from delta calculation
EP1_AFTER=$($dexec l3ep1 grep -c 'POST /v1/completions' /tmp/vllm-server1.log 2>/dev/null)
EP1_AFTER=${EP1_AFTER:-0}
EP2_AFTER=$($dexec l3ep2 grep -c 'POST /v1/completions' /tmp/vllm-server2.log 2>/dev/null)
EP2_AFTER=${EP2_AFTER:-0}
D1=$((EP1_AFTER - EP1_BEFORE))
D2=$((EP2_AFTER - EP2_BEFORE))
echo "  CHWBL routing: EP1_delta=$D1  EP2_delta=$D2"
# Level 1 hashes on model name: same model = same backend always
if ([ "$D1" -ge 8 ] && [ "$D2" -eq 0 ]) || ([ "$D2" -ge 8 ] && [ "$D1" -eq 0 ]); then
    echo "  ✓ CHWBL L1 consistent: all requests to one backend (D1=$D1, D2=$D2)"
else
    echo "  ✗ CHWBL L1 inconsistent: requests split across backends (D1=$D1, D2=$D2)"
    code=1
fi

echo "#########################################"
echo "Testing load endpoint distribution"
echo "(/v1/models has no model key: falls back to round-robin)"
echo "#########################################"

EP1_B2=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_B2=${EP1_B2:-0}
EP2_B2=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_B2=${EP2_B2:-0}
for i in {1..6}; do
    $dexec l3h1 curl -sk --cacert /tmp/minica.pem \
        -H "X-Request-Id: level1-dist-$i" \
        https://10.10.10.254:$PORT/v1/models > /dev/null 2>&1
    sleep 0.5
done
sleep 2
D1B=$(($(  $dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}') - EP1_B2))
D2B=$(($(  $dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}') - EP2_B2))
echo "  Distribution EP1_delta=$D1B  EP2_delta=$D2B"
if [ "$((D1B + D2B))" -gt 0 ]; then
    echo "  ✓ Traffic flowing (EP1_delta=$D1B, EP2_delta=$D2B)"
else
    echo "  ✗ No traffic observed on any backend"
    code=1
fi

echo "#########################################"
echo "Testing /v1/models endpoint"
echo "#########################################"

for i in {1..5}; do
    req_id="level1-models-$i"
    result=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem -H "X-Request-Id: $req_id" https://10.10.10.254:$PORT/v1/models 2>&1)
    
    if [[ $result == *"Qwen/Qwen3-0.6B"* ]]; then
        echo "  ✓ Models request $i OK"
    else
        echo "  ✗ Models request $i failed"
        code=1
    fi
    sleep 1
done

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
echo "Level 1 Test Summary"
echo "#########################################"

if [[ $code == 0 ]]; then
    echo "SCENARIO-vllm-fullproxy-CHWBL-Level1 [OK]"
    echo ""
    echo "✓ CHWBL Level 1 working correctly"
    echo "✓ Basic prefix hash (model name only) functional"
    echo "✓ Request consistency verified"
else
    echo "SCENARIO-vllm-fullproxy-CHWBL-Level1 [FAILED]"
fi

exit $code
