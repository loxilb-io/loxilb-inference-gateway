#!/bin/bash
# validate_cli.sh — End-to-end REST API validation for AI Gateway commands.
# Replaces the former loxicmd-based CLI tests with direct REST API calls so that
# CI is not blocked by loxicmd binary availability or version skew.
#
# Runs AFTER existing T1-T8 REST tests in validation.sh.
# Sources ../common.sh for $hexec helper.

source ../common.sh

LOXILB_API="${LOXILB_API:-http://localhost:11111/netlox/v1}"

echo ""
echo "========================================="
echo " REST API Validation (AI Gateway)"
echo "========================================="

check_cli() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == *"$want"* ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAIL] — expected '$want', got: $got"
    exit 1
  fi
}

# ── Authenticate ──────────────────────────────────────────────────────────────
echo ""
echo "Setup: Authenticating with REST API"
CLI_TOKEN=$($hexec llb1 curl -s -X POST \
  "$LOXILB_API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [[ -z "$CLI_TOKEN" ]]; then
  echo "  FATAL: CLI auth failed"
  exit 1
fi
echo "  token obtained [OK]"
AUTH_HDR="Authorization: Bearer $CLI_TOKEN"

# ── T-CLI-1: Create API key ──────────────────────────────────────────────────
TENANT_ID="cli-test-$(date +%s)"
echo ""
echo "T-CLI-1: Create API key via POST /config/ai/apikey (tenant=$TENANT_ID)"
resp=$($hexec llb1 curl -s -w "\n%{http_code}" -X POST \
  "$LOXILB_API/config/ai/apikey" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HDR" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"name\":\"rest-test-key\",\"allowed_models\":[],\"rate_limit_rps\":10,\"burst_size\":20,\"tokens_per_min\":5000,\"enabled\":true}")
body=$(echo "$resp" | head -n1)
http_code=$(echo "$resp" | tail -n1)
echo "  HTTP $http_code | body: $body"
if [[ "$http_code" != "201" ]]; then
  echo "  T-CLI-1 expected 201 got $http_code [FAIL]"; exit 1
fi
KEY_ID=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('key_id',''))" 2>/dev/null)
RAW_KEY=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
if [[ -z "$KEY_ID" ]] || [[ -z "$RAW_KEY" ]]; then
  echo "  T-CLI-1 missing key_id or raw_key [FAIL]"; exit 1
fi
echo "  KEY_ID=$KEY_ID RAW_KEY=${RAW_KEY:0:10}... [OK]"

# ── T-CLI-2: List API keys by tenant ─────────────────────────────────────────
echo ""
echo "T-CLI-2: List API keys via GET /config/ai/apikey?tenant_id=$TENANT_ID"
list_resp=$($hexec llb1 curl -s -H "$AUTH_HDR" \
  "$LOXILB_API/config/ai/apikey?tenant_id=$TENANT_ID")
check_cli "T-CLI-2 list contains key_id" "$KEY_ID" "$list_resp"
check_cli "T-CLI-2 list contains tenant_id" "$TENANT_ID" "$list_resp"

# ── T-CLI-3: Get API key by ID ───────────────────────────────────────────────
echo ""
echo "T-CLI-3: Get API key by ID via GET /config/ai/apikey/$KEY_ID"
get_resp=$($hexec llb1 curl -s -w "\n%{http_code}" \
  -H "$AUTH_HDR" "$LOXILB_API/config/ai/apikey/$KEY_ID")
get_body=$(echo "$get_resp" | head -n1)
get_code=$(echo "$get_resp" | tail -n1)
if [[ "$get_code" != "200" ]]; then
  echo "  T-CLI-3 expected 200 got $get_code [FAIL]"; exit 1
fi
check_cli "T-CLI-3 rate_limit_rps=10" "10" "$get_body"
check_cli "T-CLI-3 tokens_per_min=5000" "5000" "$get_body"
# Verify key_hash NOT leaked
if python3 -c "import sys,json; d=json.load(sys.stdin); exit(1 if 'key_hash' in d else 0)" <<< "$get_body" 2>/dev/null; then
  echo "  T-CLI-3 key_hash absent (not leaked) [OK]"
else
  echo "  T-CLI-3 key_hash LEAKED in GET response [FAIL]"; exit 1
fi

# ── T-CLI-4: Create tenant rate limit ────────────────────────────────────────
echo ""
echo "T-CLI-4: Set tenant rate limit via POST /config/ai/tenant/ratelimit"
rl_code=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$LOXILB_API/config/ai/tenant/ratelimit" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HDR" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"rps\":200,\"tokens_per_min\":100000}")
if [[ "$rl_code" != "200" && "$rl_code" != "201" && "$rl_code" != "204" ]]; then
  echo "  T-CLI-4 expected 2xx got $rl_code [FAIL]"; exit 1
fi
echo "  T-CLI-4 rate limit set ($rl_code) [OK]"

# ── T-CLI-5: Get tenant rate limit ───────────────────────────────────────────
echo ""
echo "T-CLI-5: Get tenant rate limit via GET /config/ai/tenant/ratelimit/$TENANT_ID"
rl_resp=$($hexec llb1 curl -s -H "$AUTH_HDR" \
  "$LOXILB_API/config/ai/tenant/ratelimit/$TENANT_ID")
check_cli "T-CLI-5 rps=200" "200" "$rl_resp"
check_cli "T-CLI-5 tokens_per_min=100000" "100000" "$rl_resp"

# ── T-CLI-6: Delete API key ──────────────────────────────────────────────────
echo ""
echo "T-CLI-6: Delete API key via DELETE /config/ai/apikey/$KEY_ID"
del_code=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  -H "$AUTH_HDR" "$LOXILB_API/config/ai/apikey/$KEY_ID")
if [[ "$del_code" != "200" && "$del_code" != "204" ]]; then
  echo "  T-CLI-6 expected 200/204 got $del_code [FAIL]"; exit 1
fi
echo "  T-CLI-6 deleted ($del_code) [OK]"

# ── T-CLI-7: Get deleted key → 404 ───────────────────────────────────────────
echo ""
echo "T-CLI-7: Get deleted API key $KEY_ID → expect 404"
gone_code=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" \
  -H "$AUTH_HDR" "$LOXILB_API/config/ai/apikey/$KEY_ID")
if [[ "$gone_code" == "404" ]]; then
  echo "  T-CLI-7 deleted key returns 404 [OK]"
else
  echo "  T-CLI-7 expected 404 got $gone_code [FAIL]"; exit 1
fi

# ── T-CLI-8: Create without tenant_id → 400/422 ──────────────────────────────
echo ""
echo "T-CLI-8: Create API key with empty tenant_id → expect 400 or 422"
bad_code=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$LOXILB_API/config/ai/apikey" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HDR" \
  -d '{"tenant_id":"","name":"empty-tenant-test","enabled":true}')
if [[ "$bad_code" == "400" || "$bad_code" == "422" ]]; then
  echo "  T-CLI-8 empty tenant_id rejected ($bad_code) [OK]"
else
  echo "  T-CLI-8 expected 400/422 got $bad_code [FAIL]"; exit 1
fi

echo ""
echo "=== REST API Validation: All T-CLI tests passed ==="
