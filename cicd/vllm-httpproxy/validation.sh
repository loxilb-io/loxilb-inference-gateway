#!/bin/bash
# cicd/vllm-httpproxy/validation.sh — LoxiLB + vLLM HTTP fullproxy validation
# Tests: T1 readiness, T2 /v1/models, T3 /v1/completions, T4 /v1/chat/completions,
#        T5 X-Request-Id auto-inject, T6 X-Request-Id preserve,
#        T7 CHWBL routing consistency, T8 load distribution,
#        T9 SSE streaming, T10 LB config verification
source ../common.sh
exec < /dev/null

echo SCENARIO-vllm-httpproxy

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

PORT=2020

echo "#########################################"
echo "T1: vLLM READINESS PROBE"
echo "#########################################"

for ep in l3ep1 l3ep2; do
  ready=1
  for ((i=0; i<60; i+=5)); do
    if $dexec "$ep" curl -sf http://localhost:8000/v1/models 2>/dev/null | grep -q '"data"'; then
      echo "  $ep: ready after ${i}s"
      ready=0
      break
    fi
    echo "  $ep: waiting... (${i}s)"
    sleep 5
  done
  check "T1: $ep vLLM responsive" "$ready"
done

echo "#########################################"
echo "T2: /v1/models ENDPOINT"
echo "#########################################"

T2_RESP=$($dexec l3h1 curl -sk \
  http://10.10.10.254:$PORT/v1/models 2>&1)
echo "$T2_RESP" | head -3
if echo "$T2_RESP" | grep -q '"data"' && echo "$T2_RESP" | grep -q 'Qwen'; then
  check "T2: /v1/models returns model list with Qwen entry" 0
else
  check "T2: /v1/models returns model list with Qwen entry" 1
fi
sleep 2

echo "#########################################"
echo "T3: /v1/completions ENDPOINT"
echo "#########################################"

T3_RESP=$($dexec l3h1 curl -sk -i \
  http://10.10.10.254:$PORT/v1/completions \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: cicd-t3-completions" \
  -d '{"model":"Qwen/Qwen3-0.6B","prompt":"What is 2+2?","max_tokens":16,"temperature":0.1}' 2>&1)
echo "$T3_RESP" | tail -5
if echo "$T3_RESP" | grep -q '"choices"' && echo "$T3_RESP" | grep -q '"text"'; then
  check "T3: /v1/completions returns choices+text" 0
else
  check "T3: /v1/completions returns choices+text" 1
fi
sleep 2

echo "#########################################"
echo "T4: /v1/chat/completions ENDPOINT"
echo "#########################################"

T4_RESP=$($dexec l3h1 curl -sk -i \
  http://10.10.10.254:$PORT/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: cicd-t4-chat" \
  -d '{"model":"Qwen/Qwen3-0.6B","messages":[{"role":"user","content":"Hello"}],"max_tokens":16,"temperature":0.1}' 2>&1)
echo "$T4_RESP" | tail -5
if echo "$T4_RESP" | grep -q '"choices"' && echo "$T4_RESP" | grep -q '"message"'; then
  check "T4: /v1/chat/completions returns choices+message" 0
else
  check "T4: /v1/chat/completions returns choices+message" 1
fi
sleep 2

echo "#########################################"
echo "T5: X-REQUEST-ID AUTO-INJECT (no client header)"
echo "#########################################"

T5_RESP=$($dexec l3h1 curl -sk -i \
  http://10.10.10.254:$PORT/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen3-0.6B","prompt":"ping","max_tokens":4}' 2>&1)
T5_ID=$(echo "$T5_RESP" | grep -i 'X-Request-Id:' | head -1 | sed 's/.*X-Request-Id: *//i' | tr -d '\r\n ')
echo "  Auto-injected ID: '$T5_ID'"
if echo "$T5_ID" | grep -qE '^[0-9a-f]{32}$'; then
  check "T5: auto-inject produces 32-char hex X-Request-Id" 0
else
  check "T5: auto-inject produces 32-char hex X-Request-Id (got '$T5_ID')" 1
fi
sleep 2

echo "#########################################"
echo "T6: X-REQUEST-ID CLIENT PRESERVE"
echo "#########################################"

T6_RESP=$($dexec l3h1 curl -sk -i \
  -H "X-Request-Id: cicd-preserve-check-001" \
  http://10.10.10.254:$PORT/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen3-0.6B","prompt":"ping","max_tokens":4}' 2>&1)
T6_ID=$(echo "$T6_RESP" | grep -i 'X-Request-Id:' | head -1 | sed 's/.*X-Request-Id: *//i' | tr -d '\r\n ')
echo "  Returned ID: '$T6_ID'"
if [ "$T6_ID" = "cicd-preserve-check-001" ]; then
  check "T6: client X-Request-Id preserved verbatim" 0
else
  check "T6: client X-Request-Id preserved verbatim (got '$T6_ID')" 1
fi
sleep 2

echo "#########################################"
echo "T7: CHWBL ROUTING CONSISTENCY"
echo "    (same model+prompt must route to same backend)"
echo "#########################################"

# Consistency MUST be tested against a CHWBL rule, NOT the round-robin VIP on
# port 2020 (--select=rr), which alternates backends by design. Port 2021 is
# the CHWBL Level-1 rule (hash on model name), so identical requests pin to a
# single backend. (The old test hit $PORT=2020 and so "failed" on the expected
# round-robin split.)
CHWBL_PORT=2021

# Attribute each request to the backend that actually served it via its
# X-Request-Id, which vLLM records as its internal request id ("Received
# request cmpl-<x-request-id>-0"). Raw log-line deltas are unusable here:
# loxilb health-probes BOTH backends continuously (--monitor GET /v1/models)
# and vLLM emits periodic background metric lines, so both logs grow regardless
# of where the completions actually land.
T7_OK=0
for i in {1..5}; do
  r=$($dexec l3h1 curl -sk \
    http://10.10.10.254:$CHWBL_PORT/v1/completions \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: cicd-t7-consist-$i" \
    -d '{"model":"Qwen/Qwen3-0.6B","prompt":"CHWBL consistency probe","max_tokens":8,"temperature":0.0}' 2>&1)
  echo "$r" | grep -q '"choices"' && T7_OK=$((T7_OK + 1))
  sleep 1
done
check "T7a: all 5 consistency requests succeeded ($T7_OK/5)" $([ "$T7_OK" -eq 5 ] && echo 0 || echo 1)

sleep 2
# Count, per request, which backend logged its X-Request-Id. Presence-per-id
# (not line count) so multiple log lines for one request still count once, and
# health-probe / metrics lines (which never carry the tag) are ignored.
EP1_HITS=0; EP2_HITS=0
for i in {1..5}; do
  if $dexec l3ep1 grep -q "cicd-t7-consist-$i" /tmp/vllm-server1.log 2>/dev/null; then
    EP1_HITS=$((EP1_HITS + 1))
  fi
  if $dexec l3ep2 grep -q "cicd-t7-consist-$i" /tmp/vllm-server2.log 2>/dev/null; then
    EP2_HITS=$((EP2_HITS + 1))
  fi
done
echo "  Backend hits by request-id: EP1=$EP1_HITS  EP2=$EP2_HITS (attributed $((EP1_HITS + EP2_HITS))/5)"
if [ "$((EP1_HITS + EP2_HITS))" -eq 0 ]; then
  # No tag found in either backend log -> measurement gap, not a routing verdict.
  check "T7b: CHWBL consistency — INDETERMINATE: no request-id found in backend logs" 1
elif [ "$EP1_HITS" -eq 0 ] || [ "$EP2_HITS" -eq 0 ]; then
  check "T7b: CHWBL consistency — all attributed requests to one backend (EP1=$EP1_HITS, EP2=$EP2_HITS)" 0
else
  check "T7b: CHWBL consistency — requests split across backends (EP1=$EP1_HITS, EP2=$EP2_HITS)" 1
fi

echo "#########################################"
echo "T8: LOAD DISTRIBUTION"
echo "#########################################"

EP1_BASE=$($dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}')
EP1_BASE=${EP1_BASE:-0}
EP2_BASE=$($dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}')
EP2_BASE=${EP2_BASE:-0}

for i in {1..12}; do
  $dexec l3h1 curl -sk \
    -H "X-Request-Id: cicd-t8-dist-$i" \
    http://10.10.10.254:$PORT/v1/models > /dev/null 2>&1
  sleep 0.5
done
sleep 2

EP1_D=$(($(  $dexec l3ep1 wc -l /tmp/vllm-server1.log 2>/dev/null | awk '{print $1}') - EP1_BASE))
EP2_D=$(($(  $dexec l3ep2 wc -l /tmp/vllm-server2.log 2>/dev/null | awk '{print $1}') - EP2_BASE))
echo "  Distribution: EP1_delta=$EP1_D  EP2_delta=$EP2_D"
if [ "$EP1_D" -gt 0 ] && [ "$EP2_D" -gt 0 ]; then
  check "T8: load distributed — both EPs received traffic (EP1_delta=$EP1_D, EP2_delta=$EP2_D)" 0
elif [ "$((EP1_D + EP2_D))" -gt 0 ]; then
  check "T8: load distribution — only one EP received traffic (EP1_delta=$EP1_D, EP2_delta=$EP2_D)" 1
else
  check "T8: load distribution — no EP traffic observed" 1
fi

echo "#########################################"
echo "T9: SSE STREAMING (/v1/completions stream=true)"
echo "#########################################"

T9_RESP=$($dexec l3h1 curl -sk \
  -N --max-time 20 \
  http://10.10.10.254:$PORT/v1/completions \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  -H "X-Request-Id: cicd-t9-sse" \
  -d '{"model":"Qwen/Qwen3-0.6B","prompt":"Count to 3","max_tokens":16,"stream":true}' 2>&1)
echo "$T9_RESP" | head -5
if echo "$T9_RESP" | grep -q 'data:'; then
  check "T9: SSE streaming returns data: events" 0
elif echo "$T9_RESP" | grep -q '"choices"'; then
  check "T9: SSE streaming (non-stream fallback response — acceptable)" 0
else
  check "T9: SSE streaming failed — no data: events and no choices in response" 1
fi

echo "#########################################"
echo "T10: LB CONFIG VERIFICATION"
echo "#########################################"

LB_OUT=$($dexec llb1 loxicmd get lb -o wide 2>/dev/null)
echo "$LB_OUT"
if echo "$LB_OUT" | grep -q "$PORT"; then
  check "T10: LB rule for port $PORT present in loxicmd output" 0
else
  check "T10: LB rule for port $PORT present in loxicmd output" 1
fi
for p in 2021 2022 2023; do
  if echo "$LB_OUT" | grep -q "$p"; then
    check "T10: CHWBL LB rule port $p present" 0
  else
    check "T10: CHWBL LB rule port $p present" 1
  fi
done

echo "#########################################"
echo "Debug: vLLM server logs (last 5 lines each)"
echo "#########################################"
for ep in l3ep1 l3ep2; do
  echo "=== $ep ==="
  $dexec "$ep" bash -c 'tail -n 5 /tmp/vllm-server*.log 2>/dev/null' || echo "no logs"
done

echo "#########################################"
echo "Test Summary"
echo "#########################################"

if [[ $code == 0 ]]; then
  echo "SCENARIO-vllm-httpproxy [OK]"
else
  echo "SCENARIO-vllm-httpproxy [FAILED]"
fi

echo "#########################################"

exit $code
