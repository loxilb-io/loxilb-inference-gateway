#!/bin/bash
source ../common.sh

echo "#########################################"
echo "CHWBL Comprehensive Validation Suite"
echo "Testing all 3 levels sequentially"
echo "#########################################"

total_code=0
failover_code=0
errorhandling_code=0
concurrency_code=0
resilience_code=0
probe_code=0

echo ""
echo "========================================="
echo "LEVEL 1: Basic Prefix Hash"
echo "========================================="
./validation-level1.sh
level1_code=$?
if [[ $level1_code -ne 0 ]]; then
    total_code=1
    echo "✗ Level 1 FAILED"
else
    echo "✓ Level 1 PASSED"
fi
echo ""
sleep 90

echo "========================================="
echo "LEVEL 2: Extended Hash with Load Factor"
echo "========================================="
./validation-level2.sh
level2_code=$?
if [[ $level2_code -ne 0 ]]; then
    total_code=1
    echo "✗ Level 2 FAILED"
else
    echo "✓ Level 2 PASSED"
fi
echo ""
sleep 60

echo "========================================="
echo "LEVEL 3: Full Hash with High Replication"
echo "========================================="
./validation-level3.sh
level3_code=$?
if [[ $level3_code -ne 0 ]]; then
    total_code=1
    echo "✗ Level 3 FAILED"
else
    echo "✓ Level 3 PASSED"
fi
echo ""
sleep 60

echo "========================================="
echo "FAILOVER: EP Down/Recovery + CHWBL Re-stick"
echo "========================================="
./validation-failover.sh
failover_code=$?
if [[ $failover_code -ne 0 ]]; then
    total_code=1
    echo "✗ Failover FAILED"
else
    echo "✓ Failover PASSED"
fi
echo ""
sleep 30

echo "========================================="
echo "PROBE TIMING: probeTimeout + probeRetries"
echo "========================================="
./validation-probe.sh
probe_code=$?
if [[ $probe_code -ne 0 ]]; then
    total_code=1
    echo "✗ Probe Timing FAILED"
else
    echo "✓ Probe Timing PASSED"
fi
echo ""
sleep 30

echo "========================================="
echo "ERROR HANDLING: Invalid Inputs + Protocol"
echo "========================================="
./validation-errorhandling.sh
errorhandling_code=$?
if [[ $errorhandling_code -ne 0 ]]; then
    total_code=1
    echo "✗ Error Handling FAILED"
else
    echo "✓ Error Handling PASSED"
fi
echo ""
sleep 30

echo "========================================="
echo "CONCURRENCY: Parallel Load + SSE Streams"
echo "========================================="
./validation-concurrency.sh
concurrency_code=$?
if [[ $concurrency_code -ne 0 ]]; then
    total_code=1
    echo "✗ Concurrency FAILED"
else
    echo "✓ Concurrency PASSED"
fi
echo ""
sleep 30

echo "========================================="
echo "RESILIENCE: Edge Cases + Headers"
echo "========================================="
./validation-resilience.sh
resilience_code=$?
if [[ $resilience_code -ne 0 ]]; then
    total_code=1
    echo "✗ Resilience FAILED"
else
    echo "✓ Resilience PASSED"
fi
echo ""

echo "#########################################"
echo "Final Summary - All Levels"
echo "#########################################"

echo ""
echo "Test Results:"
echo "  Level 1 (Port 2021): $([ $level1_code -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
echo "  Level 2 (Port 2022): $([ $level2_code -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
echo "  Level 3 (Port 2023): $([ $level3_code -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
echo "  Failover:            $([ $failover_code -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
echo "  Probe Timing:        $([ $probe_code -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
echo "  Error Handling:      $([ $errorhandling_code -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
echo "  Concurrency:         $([ $concurrency_code -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
echo "  Resilience:          $([ $resilience_code -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
echo ""

if [[ $total_code -eq 0 ]]; then
    echo "========================================="
    echo "ALL TESTS PASSED ✓"
    echo "========================================="
    echo ""
    echo "CHWBL Validation Complete:"
    echo "  ✓ Level 1: Basic prefix hash working"
    echo "  ✓ Level 2: Load factor (125%) verified"
    echo "  ✓ Level 3: High load factor (250%) + replication (200) confirmed"
    echo "  ✓ Request consistency maintained across all levels"
    echo "  ✓ Load distribution balanced"
    echo ""
    echo "Production GA Validation Complete:"
    echo "  ✓ Failover: EP health detection + traffic reroute + CHWBL re-stick"
    echo "  ✓ Probe Timing: probeTimeout=10s × probeRetries=1 detection verified"
    echo "  ✓ Error Handling: invalid inputs + TLS enforcement + method rejection"
    echo "  ✓ Concurrency: CHWBL pin correctness + SSE streams + rapid-fire requests"
    echo "  ✓ Resilience: large tokens + Unicode + SSE [DONE] + Content-Type + headers"
else
    echo "========================================="
    echo "SOME TESTS FAILED ✗"
    echo "========================================="
    echo ""
    echo "Check individual test outputs above for details"
fi

echo ""
echo "#########################################"
echo "Complete LoxiLB Statistics"
echo "#########################################"
$dexec llb1 wget -qO- http://127.0.0.1:11111/netlox/v1/config/loadbalancer/all 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('lbAttr', []):
    sa = r.get('serviceArguments', {})
    eps = r.get('endpoints', [])
    print(f\"  port={sa.get('port')} sel={sa.get('sel')} mode={sa.get('mode')} chwbl_lvl={sa.get('chwbl_prefix_hash_level','-')} chwbl_lf={sa.get('chwbl_mean_load_factor','-')} chwbl_repl={sa.get('chwbl_replication','-')}\")
    for ep in eps:
        print(f\"    -> {ep.get('endpointIP')}:{ep.get('targetPort')} w={ep.get('weight')}\")
"

exit $total_code
