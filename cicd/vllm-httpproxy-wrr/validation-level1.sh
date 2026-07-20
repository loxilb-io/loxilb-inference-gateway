#!/bin/bash
source ../common.sh

echo SCENARIO-vllm-httpproxy-CHWBL-wrr-Level1

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

$dexec llb1 loxicmd get lb -o wide | grep $PORT
if [[ $? -ne 0 ]]; then
    echo "ERROR: LB rule for port $PORT not found"
    exit 1
fi

echo "#########################################"
echo "Testing CHWBL WRR Level 1 consistency"
echo "(same model+prompt must route to same backend)"
echo "#########################################"

EP1_BEFORE=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_BEFORE=${EP1_BEFORE:-0}
EP2_BEFORE=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_BEFORE=${EP2_BEFORE:-0}
echo "  Baseline: EP1=$EP1_BEFORE lines, EP2=$EP2_BEFORE lines"

OK_COUNT=0
for i in {1..8}; do
    req_id="level1-same-$i"
    echo -n "  Request $i (ID: $req_id)... "
    result=$($dexec l3h1 curl -sk -i http://10.10.10.254:$PORT/v1/completions \
        -H "Content-Type: application/json" \
        -H "X-Request-Id: $req_id" \
        -d '{"model":"Qwen/Qwen3-0.6B","prompt":"CHWBL WRR L1 consistency probe","max_tokens":8,"temperature":0.0}' 2>&1)
    if echo "$result" | grep -q '"choices"'; then
        echo "OK"
        OK_COUNT=$((OK_COUNT + 1))
    else
        echo "FAIL"
        code=1
    fi
    sleep 1
done
[ "$OK_COUNT" -eq 8 ] || code=1
echo "  Functional: $OK_COUNT/8 requests succeeded"

sleep 2
EP1_AFTER=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_AFTER=${EP1_AFTER:-0}
EP2_AFTER=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_AFTER=${EP2_AFTER:-0}
D1=$((EP1_AFTER - EP1_BEFORE))
D2=$((EP2_AFTER - EP2_BEFORE))
echo "  CHWBL WRR routing: EP1_delta=$D1  EP2_delta=$D2"
if ([ "$D1" -ge 8 ] && [ "$D2" -eq 0 ]) || ([ "$D2" -ge 8 ] && [ "$D1" -eq 0 ]); then
    echo "  ✓ CHWBL WRR L1 consistent: all requests to one backend (D1=$D1, D2=$D2)"
else
    echo "  ✗ CHWBL WRR L1 inconsistent: requests split (D1=$D1, D2=$D2)"
    code=1
fi

echo "#########################################"
echo "Testing WRR weight distribution (8:2 ratio)"
echo "EP1 should handle ~80%, EP2 ~20% of traffic"
echo "#########################################"

EP1_B2=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_B2=${EP1_B2:-0}
EP2_B2=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_B2=${EP2_B2:-0}
# Use /v1/models (no model key → WRR distributes across both EPs)
for i in {1..50}; do
    $dexec l3h1 curl -sk \
        -H "X-Request-Id: wrr-dist-$i" \
        http://10.10.10.254:$PORT/v1/models > /dev/null 2>&1
    sleep 0.2
done
sleep 2
D1B=$(($(  $dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}') - EP1_B2))
D2B=$(($(  $dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}') - EP2_B2))
TOTAL=$((D1B + D2B))
echo "  WRR distribution: EP1=$D1B EP2=$D2B Total=$TOTAL"
if [ "$TOTAL" -gt 0 ] && [ "$D2B" -ge 2 ]; then
    RATIO=$((D1B * 100 / TOTAL))
    echo "  EP1 handled ${RATIO}% of traffic (expected ~80% for weight 8:2)"
    # Allow ±25% tolerance on expected 80% ratio
    if [ "$RATIO" -ge 55 ] && [ "$RATIO" -le 95 ]; then
        echo "  ✓ WRR weight distribution within tolerance (${RATIO}% for EP1)"
    else
        echo "  ✗ WRR weight distribution out of tolerance (${RATIO}% for EP1, expected 55-95%)"
        code=1
    fi
elif [ "$TOTAL" -gt 0 ] && [ "$D2B" -eq 0 ]; then
    echo "  ✗ WRR failed: EP2 received zero traffic (EP1=$D1B, EP2=$D2B)"
    code=1
else
    echo "  ✗ No traffic observed on any backend"
    code=1
fi

echo "#########################################"
echo "Testing /v1/models endpoint"
echo "#########################################"

for i in {1..5}; do
    req_id="level1-models-$i"
    result=$($dexec l3h1 curl -sk  -H "X-Request-Id: $req_id" http://10.10.10.254:$PORT/v1/models 2>&1)
    
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

$dexec llb1 loxicmd get lb -o wide | grep $PORT

echo "#########################################"
echo "Level 1 Test Summary"
echo "#########################################"

if [[ $code == 0 ]]; then
    echo "SCENARIO-vllm-httpproxy-CHWBL-wrr-Level1 [OK]"
    echo ""
    echo "✓ CHWBL Level 1 working correctly"
    echo "✓ Basic prefix hash (model name only) functional"
    echo "✓ Request consistency verified"
else
    echo "SCENARIO-vllm-httpproxy-CHWBL-wrr-Level1 [FAILED]"
fi

exit $code
