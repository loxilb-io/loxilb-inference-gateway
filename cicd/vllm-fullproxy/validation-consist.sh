#!/bin/bash
# cicd/vllm-fullproxy/validation-consist.sh — CHWBL cross-level consistency validation
# Verifies that the same (model, prompt, temperature) is routed to the same backend
# across all 3 CHWBL prefix-hash levels (ports 2021/2022/2023).
source ../common.sh
exec < /dev/null

echo SCENARIO-vllm-fullproxy-CHWBL-consistency

code=0

check() {
  local desc="$1"
  local result="$2"
  if [ "$result" = "0" ]; then
    echo "  PASS: $desc"
  else
    echo "  FAIL: $desc"
    code=1
  fi
}

echo "#########################################"
echo "C1: CHWBL LEVEL-1 DETERMINISM (model name)"
echo "#########################################"

EP1_B=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_B=${EP1_B:-0}
EP2_B=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_B=${EP2_B:-0}

OK=0
for i in {1..6}; do
  R=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem \
    https://10.10.10.254:2021/v1/completions \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: consist-l1-$i" \
    -d '{"model":"Qwen/Qwen3-0.6B","prompt":"CHWBL L1 determinism","max_tokens":8,"temperature":0.0}' 2>&1)
  echo "$R" | grep -q '"choices"' && OK=$((OK+1))
  sleep 1
done
check "C1a: 6/6 level-1 requests succeeded ($OK/6)" $([ "$OK" -eq 6 ] && echo 0 || echo 1)

sleep 2
D1=$(($(  $dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}') - EP1_B))
D2=$(($(  $dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}') - EP2_B))
if ([ "$D1" -ge 6 ] && [ "$D2" -eq 0 ]) || ([ "$D2" -ge 6 ] && [ "$D1" -eq 0 ]); then
  check "C1b: L1 deterministic — same model always to same backend (D1=$D1, D2=$D2)" 0
else
  check "C1b: L1 non-deterministic — requests split (D1=$D1, D2=$D2)" 1
fi

echo "#########################################"
echo "C2: CHWBL LEVEL-2 DETERMINISM (model + prompt prefix)"
echo "#########################################"

EP1_B=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_B=${EP1_B:-0}
EP2_B=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_B=${EP2_B:-0}

OK=0
for i in {1..6}; do
  R=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem \
    https://10.10.10.254:2022/v1/completions \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: consist-l2-$i" \
    -d '{"model":"Qwen/Qwen3-0.6B","prompt":"CHWBL L2 determinism check","max_tokens":8,"temperature":0.0}' 2>&1)
  echo "$R" | grep -q '"choices"' && OK=$((OK+1))
  sleep 1
done
check "C2a: 6/6 level-2 requests succeeded ($OK/6)" $([ "$OK" -eq 6 ] && echo 0 || echo 1)

sleep 2
D1=$(($(  $dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}') - EP1_B))
D2=$(($(  $dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}') - EP2_B))
if ([ "$D1" -ge 6 ] && [ "$D2" -eq 0 ]) || ([ "$D2" -ge 6 ] && [ "$D1" -eq 0 ]); then
  check "C2b: L2 deterministic — same model+prompt always to same backend (D1=$D1, D2=$D2)" 0
else
  check "C2b: L2 non-deterministic — requests split (D1=$D1, D2=$D2)" 1
fi

echo "#########################################"
echo "C3: CHWBL LEVEL-3 DETERMINISM (model + prompt + temperature)"
echo "#########################################"

EP1_B=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_B=${EP1_B:-0}
EP2_B=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_B=${EP2_B:-0}

OK=0
for i in {1..6}; do
  R=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem \
    https://10.10.10.254:2023/v1/completions \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: consist-l3-$i" \
    -d '{"model":"Qwen/Qwen3-0.6B","prompt":"CHWBL L3 full hash probe","max_tokens":8,"temperature":0.7}' 2>&1)
  echo "$R" | grep -q '"choices"' && OK=$((OK+1))
  sleep 1
done
check "C3a: 6/6 level-3 requests succeeded ($OK/6)" $([ "$OK" -eq 6 ] && echo 0 || echo 1)

sleep 2
D1=$(($(  $dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}') - EP1_B))
D2=$(($(  $dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}') - EP2_B))
if ([ "$D1" -ge 6 ] && [ "$D2" -eq 0 ]) || ([ "$D2" -ge 6 ] && [ "$D1" -eq 0 ]); then
  check "C3b: L3 deterministic — same model+prompt+temp always to same backend (D1=$D1, D2=$D2)" 0
else
  check "C3b: L3 non-deterministic — requests split (D1=$D1, D2=$D2)" 1
fi

echo "#########################################"
echo "C4: DIFFERENT PROMPTS DISTRIBUTE ACROSS LEVELS"
echo "    (distinct prompts may route to different backends)"
echo "#########################################"

EP1_B=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_B=${EP1_B:-0}
EP2_B=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_B=${EP2_B:-0}

DIFF_PROMPTS=("Alpha question here" "Beta different content" "Gamma alternate topic" "Delta varied subject" "Epsilon unique entry")
OK=0
for i in "${!DIFF_PROMPTS[@]}"; do
  R=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem \
    https://10.10.10.254:2022/v1/completions \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: consist-dist-$((i+1))" \
    -d "{\"model\":\"Qwen/Qwen3-0.6B\",\"prompt\":\"${DIFF_PROMPTS[$i]}\",\"max_tokens\":8,\"temperature\":0.0}" 2>&1)
  echo "$R" | grep -q '"choices"' && OK=$((OK+1))
  sleep 1
done
check "C4a: 5/5 distribution requests succeeded ($OK/5)" $([ "$OK" -eq 5 ] && echo 0 || echo 1)

sleep 2
D1=$(($(  $dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}') - EP1_B))
D2=$(($(  $dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}') - EP2_B))
echo "  Distribution: EP1_delta=$D1  EP2_delta=$D2"
if [ "$((D1+D2))" -gt 0 ]; then
  check "C4b: traffic was processed on at least one backend" 0
else
  check "C4b: traffic was processed on at least one backend" 1
fi

echo "#########################################"
echo "C5: X-REQUEST-ID ACROSS ALL 3 LEVELS"
echo "#########################################"

for p in 2021 2022 2023; do
  T_ID=$($dexec l3h1 curl -sk --cacert /tmp/minica.pem -i \
    https://10.10.10.254:$p/v1/completions \
    -H "Content-Type: application/json" \
    -d '{"model":"Qwen/Qwen3-0.6B","prompt":"id check","max_tokens":4}' 2>&1 | \
    grep -i 'X-Request-Id:' | head -1 | sed 's/.*X-Request-Id: *//i' | tr -d '\r\n ')
  if echo "$T_ID" | grep -qE '^[0-9a-f]{32}$'; then
    check "C5: auto-inject on port $p (got 32-char hex ID)" 0
  else
    check "C5: auto-inject on port $p (got '$T_ID')" 1
  fi
  sleep 1
done

echo "#########################################"
echo "Test Summary"
echo "#########################################"

if [[ $code == 0 ]]; then
  echo "SCENARIO-vllm-fullproxy-CHWBL-consistency [OK]"
else
  echo "SCENARIO-vllm-fullproxy-CHWBL-consistency [FAILED]"
fi

echo "#########################################"

exit $code
