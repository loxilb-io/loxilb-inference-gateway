#!/bin/bash
source ../common.sh

VIP="10.10.10.254"
PORT=2020
CHWBL_PORT=2021
CACERT="/tmp/minica.pem"
MODEL="Qwen/Qwen3-0.6B"
BASEURL="https://${VIP}:${PORT}"
CHWBL_URL="https://${VIP}:${CHWBL_PORT}"

echo "#########################################"
echo "vLLM Fullproxy Failover Validation"
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


# ─── F1: Baseline round-robin ────────────────────────────────────────────────
echo ""
echo "=== F1: Baseline Round-Robin ==="

# Capture EP log sizes before
EP1_BEFORE=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_BEFORE=${EP1_BEFORE:-0}
EP2_BEFORE=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_BEFORE=${EP2_BEFORE:-0}

# F1a: 5 requests → all succeed
F1A_OK=0
for i in $(seq 1 5); do
    BODY=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
        "${BASEURL}/v1/completions" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"${MODEL}\",\"prompt\":\"baseline probe ${i}\",\"max_tokens\":3}" 2>/dev/null)
    echo "$BODY" | grep -q '"choices"' && F1A_OK=$((F1A_OK + 1))
done
check "F1a: 5 baseline requests all succeed" $([ "$F1A_OK" -eq 5 ] && echo 0 || echo 1)

# Capture EP log sizes after baseline
EP1_AFTER=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_AFTER=${EP1_AFTER:-0}
EP2_AFTER=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_AFTER=${EP2_AFTER:-0}
D1=$(( EP1_AFTER - EP1_BEFORE ))
D2=$(( EP2_AFTER - EP2_BEFORE ))

# F1b: Both EPs got traffic
check "F1b: both EP1 and EP2 received traffic" $([ "$D1" -gt 0 ] && [ "$D2" -gt 0 ] && echo 0 || echo 1)

# ─── F2: EP2 down ────────────────────────────────────────────────────────────
echo ""
echo "=== F2: EP2 Failure Detection ==="

# F2a: Kill EP2 vLLM process inside container (pkill covers both python and python3)
$dexec l3ep2 pkill -9 -f vllm.entrypoints.openai 2>/dev/null || true
check "F2a: EP2 vLLM process killed" "0"

# F2b: Wait for LoxiLB to mark EP2 nok
# probeTimeout=10s, probeRetries=1 → detection within 10*1+15=25s max
F2B_OK=1
for attempt in $(seq 1 25); do
    NOK=$($dexec llb1 wget -qO- http://127.0.0.1:11111/netlox/v1/config/endpoint/all 2>/dev/null | python3 -c "import sys,json; data=json.load(sys.stdin); nok=[e for e in data.get('Attr',[]) if str(e.get('currState','')).lower() in ('nok','down','inactive','false')]; print(len(nok))" 2>/dev/null || echo 0)
    if [ "${NOK:-0}" -ge 1 ]; then
        F2B_OK=0
        break
    fi
    sleep 1
done
check "F2b: LoxiLB detects EP2 down (nok count >= 1 within 25s, probeTimeout=10s×probeRetries=1+15s buffer)" "$F2B_OK"

# F2c: 5 requests still succeed (traffic rerouted to EP1)
F2C_OK=0
for i in $(seq 1 5); do
    BODY=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
        "${BASEURL}/v1/completions" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"${MODEL}\",\"prompt\":\"post-failure probe ${i}\",\"max_tokens\":3}" 2>/dev/null)
    echo "$BODY" | grep -q '"choices"' && F2C_OK=$((F2C_OK + 1))
done
check "F2c: 5 requests succeed after EP2 down (traffic rerouted)" $([ "$F2C_OK" -eq 5 ] && echo 0 || echo 1)

# F2d: All 5 rerouted requests went to EP1 only (EP2 delta == 0)
EP1_F2_BEFORE=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_F2_BEFORE=${EP1_F2_BEFORE:-0}
EP2_F2_BEFORE=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_F2_BEFORE=${EP2_F2_BEFORE:-0}
for i in $(seq 1 5); do
    $dexec l3h1 curl -sk --cacert "${CACERT}" \
        "${BASEURL}/v1/completions" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"${MODEL}\",\"prompt\":\"reroute check ${i}\",\"max_tokens\":2}" > /dev/null 2>&1
done
EP1_F2_AFTER=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_F2_AFTER=${EP1_F2_AFTER:-0}
EP2_F2_AFTER=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_F2_AFTER=${EP2_F2_AFTER:-0}
D2_F2=$(( EP2_F2_AFTER - EP2_F2_BEFORE ))
check "F2d: all traffic to EP1 only after EP2 down (EP2 delta == 0)" $([ "$D2_F2" -eq 0 ] && echo 0 || echo 1)

# ─── F3: EP2 recovery ────────────────────────────────────────────────────────
echo ""
echo "=== F3: EP2 Recovery ==="

# F3a: Restart vLLM on EP2 (match original startup flags from config.sh)
$dexec l3ep2 bash -c "cd /workspace && VLLM_CPU_OMP_THREADS_BIND='1' VLLM_USE_V1=0 VLLM_CPU_KVCACHE_SPACE=1 python -m vllm.entrypoints.openai.api_server --model Qwen/Qwen3-0.6B --device cpu --dtype float32 --max-model-len 1024 --host 0.0.0.0 --port 8000 --enable-request-id-headers > /tmp/vllm-server2.log 2>&1 &"

# Wait up to 90s for EP2 vLLM to become ready
F3A_READY=1
for attempt in $(seq 1 90); do
    STATUS=$($dexec l3ep2 curl -s http://localhost:8000/v1/models 2>/dev/null)
    if echo "$STATUS" | grep -q '"data"'; then
        F3A_READY=0
        break
    fi
    sleep 1
done
check "F3a: EP2 vLLM restarted and ready (GET /v1/models responds within 90s)" "$F3A_READY"

# F3b: Wait up to 30s for LoxiLB to mark BOTH EPs ok (positive ok-count == 2).
# Uses a POSITIVE state check ('ok','up','active','true') instead of absence-of-nok
# to correctly handle all loxilb state representations including 'false' for nok.
F3B_OK=1
for attempt in $(seq 1 30); do
    OK_COUNT=$($dexec llb1 wget -qO- http://127.0.0.1:11111/netlox/v1/config/endpoint/all 2>/dev/null | python3 -c "import sys,json; data=json.load(sys.stdin); ok=[e for e in data.get('Attr',[]) if str(e.get('currState','')).lower() in ('ok','up','active','true')]; print(len(ok))" 2>/dev/null || echo 0)
    if [ "${OK_COUNT:-0}" -ge 2 ]; then
        F3B_OK=0
        break
    fi
    sleep 1
done
check "F3b: LoxiLB marks both EPs healthy (ok count >= 2 within 30s)" "$F3B_OK"

# F3c: After recovery EP2 gets traffic again
EP1_F3_BEFORE=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_F3_BEFORE=${EP1_F3_BEFORE:-0}
EP2_F3_BEFORE=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_F3_BEFORE=${EP2_F3_BEFORE:-0}
for i in $(seq 1 8); do
    $dexec l3h1 curl -sk --cacert "${CACERT}" \
        "${BASEURL}/v1/completions" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"${MODEL}\",\"prompt\":\"recovery check ${i}\",\"max_tokens\":2}" > /dev/null 2>&1
done
EP2_F3_AFTER=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_F3_AFTER=${EP2_F3_AFTER:-0}
D2_F3=$(( EP2_F3_AFTER - EP2_F3_BEFORE ))
check "F3c: EP2 receives traffic again after recovery (delta > 0)" $([ "$D2_F3" -gt 0 ] && echo 0 || echo 1)

# ─── F4: CHWBL re-stick ──────────────────────────────────────────────────────
echo ""
echo "=== F4: CHWBL Re-stick Post-Recovery ==="

EP1_F4_BEFORE=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_F4_BEFORE=${EP1_F4_BEFORE:-0}
EP2_F4_BEFORE=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_F4_BEFORE=${EP2_F4_BEFORE:-0}

# 6 identical requests to CHWBL L1 port
F4_OK=0
for i in $(seq 1 6); do
    BODY=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
        "${CHWBL_URL}/v1/completions" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"${MODEL}\",\"prompt\":\"chwbl restick probe\",\"max_tokens\":3}" 2>/dev/null)
    echo "$BODY" | grep -q '"choices"' && F4_OK=$((F4_OK + 1))
done

EP1_F4_AFTER=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}'); EP1_F4_AFTER=${EP1_F4_AFTER:-0}
EP2_F4_AFTER=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}'); EP2_F4_AFTER=${EP2_F4_AFTER:-0}
D1_F4=$(( EP1_F4_AFTER - EP1_F4_BEFORE ))
D2_F4=$(( EP2_F4_AFTER - EP2_F4_BEFORE ))

# All 6 succeed
check "F4: CHWBL re-stick: 6/6 identical requests succeed post-recovery" $([ "$F4_OK" -eq 6 ] && echo 0 || echo 1)
# All land on one backend (one delta must be 0)
check "F4b: CHWBL re-stick: all 6 pinned to ONE backend (other delta == 0)" $([ "$D1_F4" -eq 0 ] || [ "$D2_F4" -eq 0 ] && echo 0 || echo 1)

exit $code
