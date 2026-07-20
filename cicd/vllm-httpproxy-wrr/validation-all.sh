#!/bin/bash
source ../common.sh

echo "#########################################"
echo "CHWBL-WRR over HTTPProxy Comprehensive Validation Suite"
echo "Testing all 3 levels sequentially"
echo "#########################################"

total_code=0

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
sleep 5

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
sleep 5

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

echo "#########################################"
echo "Final Summary - All Levels"
echo "#########################################"

echo ""
echo "Test Results:"
echo "  Level 1 (Port 2021): $([ $level1_code -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
echo "  Level 2 (Port 2022): $([ $level2_code -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
echo "  Level 3 (Port 2023): $([ $level3_code -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
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
$dexec llb1 loxicmd get lb -o wide

exit $total_code
