#!/bin/bash
source ../common.sh

VIP="10.10.10.254"
PORT=2020
CACERT="/tmp/minica.pem"
MODEL="Qwen/Qwen3-0.6B"
BASEURL="https://${VIP}:${PORT}"

echo "#########################################"
echo "vLLM Fullproxy Error Handling Validation"
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


# ─── E1: Invalid model name ──────────────────────────────────────────────────
echo ""
echo "=== E1: Invalid Model Name ==="

HTTP_CODE=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
    -o /dev/null -w "%{http_code}" \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"invalid-model-xyz","prompt":"test","max_tokens":3}' 2>/dev/null)

check "E1a: invalid model name -> 4xx (not 200)" $([ "$HTTP_CODE" != "200" ] && [ -n "$HTTP_CODE" ] && echo 0 || echo 1)

BODY_E1=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"invalid-model-xyz","prompt":"test","max_tokens":3}' 2>/dev/null)

check "E1b: invalid model -> response body contains error key" $(echo "$BODY_E1" | grep -q '"error"' && echo 0 || echo 1)

# ─── E2: Malformed JSON ──────────────────────────────────────────────────────
echo ""
echo "=== E2: Malformed JSON Body ==="

HTTP_CODE_E2=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
    -o /dev/null -w "%{http_code}" \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -d 'not-json-at-all' 2>/dev/null)

BODY_E2=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -d 'not-json-at-all' 2>/dev/null)

check "E2a: malformed JSON -> 4xx, no choices in body" $([ "$HTTP_CODE_E2" != "200" ] && ! echo "$BODY_E2" | grep -q '"choices"' && echo 0 || echo 1)

# ─── E3: Missing Content-Type ────────────────────────────────────────────────
echo ""
echo "=== E3: Missing Content-Type ==="

BODY_E3=$($dexec l3h1 curl -sk --cacert "${CACERT}" \
    --max-time 15 \
    "${BASEURL}/v1/completions" \
    --data-raw "{\"model\":\"${MODEL}\",\"prompt\":\"test\",\"max_tokens\":1}" 2>/dev/null)

check "E3a: missing Content-Type -> response exists within 15s (no hang)" $([ -n "$BODY_E3" ] && echo 0 || echo 1)

# ─── E4: Wrong HTTP methods ──────────────────────────────────────────────────
echo ""
echo "=== E4: Wrong HTTP Methods ==="

HTTP_PUT=$($dexec l3h1 curl -sk -X PUT --cacert "${CACERT}" \
    -o /dev/null -w "%{http_code}" \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${MODEL}\",\"prompt\":\"test\",\"max_tokens\":1}" 2>/dev/null)

check "E4a: PUT /v1/completions -> non-200/201 (method not allowed)" $([ "$HTTP_PUT" != "200" ] && [ "$HTTP_PUT" != "201" ] && [ -n "$HTTP_PUT" ] && echo 0 || echo 1)

HTTP_GET=$($dexec l3h1 curl -sk -X GET --cacert "${CACERT}" \
    -o /dev/null -w "%{http_code}" \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" 2>/dev/null)

check "E4b: GET /v1/completions -> non-200/201 (method not allowed)" $([ "$HTTP_GET" != "200" ] && [ "$HTTP_GET" != "201" ] && [ -n "$HTTP_GET" ] && echo 0 || echo 1)

# ─── E5: max_tokens=0 ────────────────────────────────────────────────────────
echo ""
echo "=== E5: Edge-Case Parameters ==="

$dexec l3h1 curl -sk --cacert "${CACERT}" \
    --max-time 15 \
    "${BASEURL}/v1/completions" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${MODEL}\",\"prompt\":\"test\",\"max_tokens\":0}" > /dev/null 2>&1
E5_EXIT=$?

# curl exit 28 = timeout → FAIL (proxy hung); exit 0 or other = no hang
check "E5a: max_tokens=0 -> no hang (curl exits within 15s, not timeout)" $([ "$E5_EXIT" -ne 28 ] && echo 0 || echo 1)

# ─── E6: Wrong CA cert ───────────────────────────────────────────────────────
echo ""
echo "=== E6: TLS Certificate Validation ==="

$dexec l3h1 curl -s --cacert /dev/null \
    "https://${VIP}:${PORT}/v1/models" > /dev/null 2>&1
E6_EXIT=$?

check "E6a: wrong CA cert -> SSL error (curl exits non-zero)" $([ "$E6_EXIT" -ne 0 ] && echo 0 || echo 1)

# ─── E7: Plain HTTP to HTTPS port ────────────────────────────────────────────
echo ""
echo "=== E7: Protocol Enforcement ==="

HTTP_CODE_E7=$($dexec l3h1 curl -sk --max-time 5 \
    -o /dev/null -w "%{http_code}" \
    "http://${VIP}:${PORT}/v1/models" 2>/dev/null || echo "000")

check "E7a: plain HTTP to HTTPS port -> rejected (not 200)" $([ "$HTTP_CODE_E7" != "200" ] && echo 0 || echo 1)

exit $code
