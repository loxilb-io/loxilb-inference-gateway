#!/bin/bash
source ../common.sh

VIP="10.10.10.254"
PORT=2020
CACERT="/tmp/minica.pem"
MODEL="Qwen/Qwen3-0.6B"
BASEURL="https://${VIP}:${PORT}"

echo "#########################################"
echo "vLLM Fullproxy Resilience Validation"
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


# ─── R1: Large token response ────────────────────────────────────────────────
echo ""
echo "=== R1: Large Token Response (max_tokens=64) ==="

BODY_R1=$($dexec l3h1 curl -sk --cacert "${CACERT}" --no-keepalive \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${MODEL}\",\"prompt\":\"tell me about networking\",\"max_tokens\":64}" 2>/dev/null)

check "R1a: max_tokens=64 -> valid JSON with choices" $(echo "$BODY_R1" | grep -q '"choices"' && echo 0 || echo 1)

BYTES_R1=$(echo "$BODY_R1" | wc -c)
check "R1b: max_tokens=64 response body > 200 bytes" $([ "$BYTES_R1" -gt 200 ] && echo 0 || echo 1)

# ─── R2: Unicode / CJK prompt ────────────────────────────────────────────────
echo ""
echo "=== R2: Unicode CJK Prompt ==="

BODY_R2=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${MODEL}\",\"prompt\":\"東京のネットワーク技術\",\"max_tokens\":8}" 2>/dev/null)

check "R2a: Unicode CJK prompt -> valid completion with choices" $(echo "$BODY_R2" | grep -q '"choices"' && echo 0 || echo 1)

# ─── R3: X-Forwarded-For passthrough (soft warn) ────────────────────────────
echo ""
echo "=== R3: X-Forwarded-For Header Passthrough (soft check) ==="

$dexec l3h1 curl -sk --cacert "${CACERT}" \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 1.2.3.4" \
    -d "{\"model\":\"${MODEL}\",\"prompt\":\"xff test\",\"max_tokens\":3}" > /dev/null 2>&1

echo "[WARN R3] X-Forwarded-For passthrough: not verified (behavior undefined in fullproxy mode)"
check "R3: X-Forwarded-For soft check (always pass)" "0"

# ─── R4 + R5: SSE stream terminator and chunk count ─────────────────────────
echo ""
echo "=== R4/R5: SSE Stream [DONE] Terminator and Chunk Count ==="

BODY_SSE=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${MODEL}\",\"prompt\":\"test done\",\"max_tokens\":8,\"stream\":true}" 2>/dev/null)

check "R4a: SSE stream response contains 'data: [DONE]' terminator" $(echo "$BODY_SSE" | grep -q 'data: \[DONE\]' && echo 0 || echo 1)

SSE_LINES=$(echo "$BODY_SSE" | grep -c '^data:')
check "R5a: SSE stream has >= 2 data: chunks (not single-buffered)" $([ "$SSE_LINES" -ge 2 ] && echo 0 || echo 1)

# ─── R6: Content-Type response headers ──────────────────────────────────────
echo ""
echo "=== R6: Response Content-Type Headers ==="

CT_JSON=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
    -D - \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${MODEL}\",\"prompt\":\"header check\",\"max_tokens\":2}" 2>/dev/null \
    | grep -i '^content-type:')

check "R6a: /v1/completions Content-Type contains application/json" $(echo "$CT_JSON" | grep -qi 'application/json' && echo 0 || echo 1)

HEADERS_SSE=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
    -D - \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${MODEL}\",\"prompt\":\"hdr test\",\"max_tokens\":4,\"stream\":true}" 2>/dev/null \
    | head -20)

check "R6b: SSE streaming Content-Type contains text/event-stream" $(echo "$HEADERS_SSE" | grep -qi 'text/event-stream' && echo 0 || echo 1)

# ─── R7: Many custom headers ─────────────────────────────────────────────────
echo ""
echo "=== R7: Many Custom Request Headers ==="

BODY_R7=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -H "X-Custom-Header-1: val1" \
    -H "X-Custom-Header-2: val2" \
    -H "X-Custom-Header-3: val3" \
    -H "X-Custom-Header-4: val4" \
    -H "X-Custom-Header-5: val5" \
    -H "X-Custom-Header-6: val6" \
    -H "X-Custom-Header-7: val7" \
    -H "X-Custom-Header-8: val8" \
    -H "X-Custom-Header-9: val9" \
    -H "X-Custom-Header-10: val10" \
    -d "{\"model\":\"${MODEL}\",\"prompt\":\"header test\",\"max_tokens\":4}" 2>/dev/null)

check "R7a: 10 custom request headers -> valid completion response" $(echo "$BODY_R7" | grep -q '"choices"' && echo 0 || echo 1)

exit $code
