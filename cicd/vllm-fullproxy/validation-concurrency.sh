#!/bin/bash
source ../common.sh

VIP="10.10.10.254"
PORT=2020
CHWBL_L1_PORT=2021
CHWBL_L2_PORT=2022
CACERT="/tmp/minica.pem"
MODEL="Qwen/Qwen3-0.6B"
BASEURL="https://${VIP}:${PORT}"
CHWBL_L1_URL="https://${VIP}:${CHWBL_L1_PORT}"
CHWBL_L2_URL="https://${VIP}:${CHWBL_L2_PORT}"

echo "#########################################"
echo "vLLM Fullproxy Concurrency Validation"
echo "#########################################"

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


# Clean up any leftover temp files
rm -f /tmp/cicd-p1-*.txt /tmp/cicd-p2-*.txt /tmp/cicd-p3-*.txt /tmp/cicd-p4-*.txt

# ─── P1: 20 parallel same-prompt to CHWBL L1 ────────────────────────────────
echo ""
echo "=== P1: 20 Parallel Same-Prompt -> CHWBL L1 (port ${CHWBL_L1_PORT}) ==="

EP1_P1_BEFORE=$($dexec l3ep1 grep -c 'POST /v1/completions' /tmp/vllm-server1.log 2>/dev/null || echo 0); EP1_P1_BEFORE=${EP1_P1_BEFORE:-0}
EP2_P1_BEFORE=$($dexec l3ep2 grep -c 'POST /v1/completions' /tmp/vllm-server2.log 2>/dev/null || echo 0); EP2_P1_BEFORE=${EP2_P1_BEFORE:-0}

for i in $(seq 1 20); do
    $dexec l3h1 curl -sk --cacert "${CACERT}" \
        "${CHWBL_L1_URL}/v1/completions" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"${MODEL}\",\"prompt\":\"concurrent probe same\",\"max_tokens\":3}" \
        > /tmp/cicd-p1-${i}.txt 2>&1 &
done
wait

SUCCESS_P1=$(grep -l '"choices"' /tmp/cicd-p1-*.txt 2>/dev/null | wc -l)
check "P1a: >=18/20 same-prompt concurrent requests succeed" $([ "$SUCCESS_P1" -ge 18 ] && echo 0 || echo 1)

EP1_P1_AFTER=$($dexec l3ep1 grep -c 'POST /v1/completions' /tmp/vllm-server1.log 2>/dev/null || echo 0); EP1_P1_AFTER=${EP1_P1_AFTER:-0}
EP2_P1_AFTER=$($dexec l3ep2 grep -c 'POST /v1/completions' /tmp/vllm-server2.log 2>/dev/null || echo 0); EP2_P1_AFTER=${EP2_P1_AFTER:-0}
D1_P1=$(( EP1_P1_AFTER - EP1_P1_BEFORE ))
D2_P1=$(( EP2_P1_AFTER - EP2_P1_BEFORE ))

# CHWBL pins all same-prompt requests to one backend (one delta must be 0)
check "P1b: CHWBL L1 pins all 20 requests to ONE backend (other delta == 0)" $([ "$D1_P1" -eq 0 ] || [ "$D2_P1" -eq 0 ] && echo 0 || echo 1)

# ─── P2: 20 parallel different-prompt to CHWBL L2 ───────────────────────────
echo ""
echo "=== P2: 20 Parallel Different-Prompt -> CHWBL L2 (port ${CHWBL_L2_PORT}) ==="

EP1_P2_BEFORE=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_P2_BEFORE=${EP1_P2_BEFORE:-0}
EP2_P2_BEFORE=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_P2_BEFORE=${EP2_P2_BEFORE:-0}

for i in $(seq 1 20); do
    $dexec l3h1 curl -sk --cacert "${CACERT}" \
        "${CHWBL_L2_URL}/v1/completions" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"${MODEL}\",\"prompt\":\"probe-concurrent-${i}\",\"max_tokens\":3}" \
        > /tmp/cicd-p2-${i}.txt 2>&1 &
done
wait

SUCCESS_P2=$(grep -l '"choices"' /tmp/cicd-p2-*.txt 2>/dev/null | wc -l)
check "P2a: >=18/20 different-prompt concurrent requests succeed" $([ "$SUCCESS_P2" -ge 18 ] && echo 0 || echo 1)

EP1_P2_AFTER=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_P2_AFTER=${EP1_P2_AFTER:-0}
EP2_P2_AFTER=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_P2_AFTER=${EP2_P2_AFTER:-0}
D1_P2=$(( EP1_P2_AFTER - EP1_P2_BEFORE ))
D2_P2=$(( EP2_P2_AFTER - EP2_P2_BEFORE ))

check "P2b: total EP traffic >= 18 across both backends (no silent drops)" $([ $(( D1_P2 + D2_P2 )) -ge 18 ] && echo 0 || echo 1)

# ─── P3: 5 parallel SSE streams ──────────────────────────────────────────────
echo ""
echo "=== P3: 5 Parallel SSE Streams -> port ${PORT} ==="

for i in $(seq 1 5); do
    $dexec l3h1 curl -sk --cacert "${CACERT}" \
        "${BASEURL}/v1/completions" \
        -H "Content-Type: application/json" \
        -H "Accept: text/event-stream" \
        -d "{\"model\":\"${MODEL}\",\"prompt\":\"stream test ${i}\",\"max_tokens\":8,\"stream\":true}" \
        > /tmp/cicd-p3-${i}.txt 2>&1 &
done
wait

SSE_P3=$(grep -l 'data:' /tmp/cicd-p3-*.txt 2>/dev/null | wc -l)
check "P3a: >=4/5 parallel SSE streams contain data: events" $([ "$SSE_P3" -ge 4 ] && echo 0 || echo 1)

# ─── P4: 20 rapid-fire sequential requests ───────────────────────────────────
echo ""
echo "=== P4: 20 Rapid-Fire Sequential Requests -> port ${PORT} ==="

SUCCESS_P4=0
for i in $(seq 1 20); do
    BODY=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
        "${BASEURL}/v1/completions" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"${MODEL}\",\"prompt\":\"rapid ${i}\",\"max_tokens\":2}" 2>/dev/null)
    echo "$BODY" | grep -q '"choices"' && SUCCESS_P4=$(( SUCCESS_P4 + 1 ))
    # Save output for P4b HTML check
    echo "$BODY" > /tmp/cicd-p4-${i}.txt
done

check "P4a: >=19/20 rapid-fire sequential requests succeed" $([ "$SUCCESS_P4" -ge 19 ] && echo 0 || echo 1)

HTML_COUNT=$(grep -rl '<html>' /tmp/cicd-p1-*.txt /tmp/cicd-p2-*.txt /tmp/cicd-p4-*.txt 2>/dev/null | wc -l)
check "P4b: no HTML error pages in any request output" $([ "$HTML_COUNT" -eq 0 ] && echo 0 || echo 1)

exit $code
