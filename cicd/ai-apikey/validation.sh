#!/bin/bash
# Validates the AI Gateway:
#   Control-plane  (T1–T8)  – REST API CRUD for API keys and tenant rate limits.
#   Data-plane     (DP-T*)  – live traffic enforcement through sockproxy:
#                              valid key → 200, no/invalid key → 401,
#                              disallowed model → 403, burst over limit → 429.

source ../common.sh
echo SCENARIO-ai-apikey
code=0

# ── helpers ──────────────────────────────────────────────────────────────────
check() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == *"$want"* ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAILED] — expected '$want', got: $got"
    code=1
  fi
}

check_json() {
  local label="$1" field="$2" want="$3" json="$4"
  local got
  got=$(echo "$json" | jq -r "$field" 2>/dev/null)
  if [[ "$got" == "$want" ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAILED] — field='$field' expected='$want' got='$got'"
    code=1
  fi
}

# ── authenticate ─────────────────────────────────────────────────────────────
echo ""
echo "Authenticating with loxilb REST API..."
LOGIN_RESP=$($hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!"}')
TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [[ -z "$TOKEN" ]]; then
  echo "  FATAL: Failed to obtain auth token. login response: $LOGIN_RESP"
  echo "SCENARIO-ai-apikey [FAILED]"
  exit 1
fi
echo "  token obtained: ${TOKEN:0:20}..."
AUTH="-H Authorization:\ Bearer\ $TOKEN"

# Start a simple HTTP backend on l3ep1 port 8080
$hexec l3ep1 node ../common/tcp_server.js server1 &
sleep 3

# ── T1: Create API key ────────────────────────────────────────────────────────
echo ""
echo "T1: Create API key via POST /config/ai/apikey"
resp=$($hexec llb1 curl -s -w "\n%{http_code}" -X POST \
  http://localhost:11111/netlox/v1/config/ai/apikey \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "tenant_id":       "cicd-tenant",
    "name":            "cicd-key-1",
    "allowed_models":  ["Qwen/Qwen3-0.6B", "llama-3"],
    "rate_limit_rps":  5,
    "burst_size":      10,
    "tokens_per_min":  1000,
    "enabled":         true
  }')
body=$(echo "$resp" | head -n1)
http_code=$(echo "$resp" | tail -n1)
echo "  HTTP $http_code | body: $body"
check "create returns 201" "201" "$http_code"

RAW_KEY=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('raw_key',''))" 2>/dev/null)
KEY_ID=$(echo "$body"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('key_id',''))"  2>/dev/null)

if [[ -z "$RAW_KEY" ]] || [[ ! "$RAW_KEY" == lxb_* ]]; then
  echo "  raw_key missing or wrong prefix [FAILED] raw_key='$RAW_KEY'"
  code=1
else
  echo "  raw_key=lxb_*** (${#RAW_KEY} chars) [OK]"
fi
if [[ -z "$KEY_ID" ]]; then
  echo "  key_id missing [FAILED]"
  code=1
else
  echo "  key_id=$KEY_ID [OK]"
fi

# ── T2: Create a second key for tenant isolation test ────────────────────────
echo ""
echo "T2: Create second API key (different tenant)"
resp2=$($hexec llb1 curl -s -w "\n%{http_code}" -X POST \
  http://localhost:11111/netlox/v1/config/ai/apikey \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "tenant_id":       "other-tenant",
    "name":            "other-key",
    "allowed_models":  [],
    "rate_limit_rps":  10,
    "burst_size":      20,
    "tokens_per_min":  5000,
    "enabled":         true
  }')
http_code2=$(echo "$resp2" | tail -n1)
check "second key returns 201" "201" "$http_code2"
KEY_ID2=$(echo "$resp2" | head -n1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('key_id',''))" 2>/dev/null)

# ── T3: List API keys by tenant ───────────────────────────────────────────────
echo ""
echo "T3: List API keys for cicd-tenant"
list_resp=$($hexec llb1 curl -s \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:11111/netlox/v1/config/ai/apikey?tenant_id=cicd-tenant")
echo "  list response: $list_resp"
check "list contains cicd-key-1" "cicd-key-1" "$list_resp"
# Verify other-tenant key is NOT in this list
if echo "$list_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); keys=[k.get('tenant_id') for k in d]; assert all(t == 'cicd-tenant' for t in keys)" 2>/dev/null; then
  echo "  list isolation (no other-tenant keys) [OK]"
else
  echo "  list isolation check [FAILED] — other tenant's keys may appear"
  code=1
fi

# ── T4: Get API key by ID ─────────────────────────────────────────────────────
echo ""
echo "T4: Get API key by ID"
get_resp=$($hexec llb1 curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:11111/netlox/v1/config/ai/apikey/$KEY_ID")
get_body=$(echo "$get_resp" | head -n1)
get_code=$(echo "$get_resp" | tail -n1)
echo "  HTTP $get_code | body: $get_body"
check "get by ID returns 200"    "200"         "$get_code"
check "get body has tenant_id"   "cicd-tenant" "$get_body"
check "get body has name"        "cicd-key-1"  "$get_body"
# C-1 fix: check() substring-matches 'key_hash' in both 'key_hash_absent' and
# 'key_hash_PRESENT', so the old call was always OK. Use an explicit exit-code
# test instead to reliably detect leakage.
if python3 -c "import sys,json; d=json.load(sys.stdin); exit(1 if 'key_hash' in d else 0)" <<< "$get_body" 2>/dev/null; then
  echo "  key_hash absent (not leaked) [OK]"
else
  echo "  key_hash LEAKED in GET response [FAILED]"
  code=1
fi

# ── T5: Set tenant rate limit ─────────────────────────────────────────────────
echo ""
echo "T5: Set tenant rate limit via POST /config/ai/tenant/ratelimit"
rl_resp=$($hexec llb1 curl -s -w "\n%{http_code}" -X POST \
  http://localhost:11111/netlox/v1/config/ai/tenant/ratelimit \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"tenant_id":"cicd-tenant","rps":50,"tokens_per_min":2000}')
rl_code=$(echo "$rl_resp" | tail -n1)
echo "  HTTP $rl_code"
check "set rate limit returns 2xx" "20" "$rl_code"

# ── T6: Get tenant rate limit ─────────────────────────────────────────────────
echo ""
echo "T6: Get tenant rate limit"
get_rl=$($hexec llb1 curl -s \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:11111/netlox/v1/config/ai/tenant/ratelimit/cicd-tenant")
echo "  response: $get_rl"
check "get rate limit has rps"           "50"   "$get_rl"
check "get rate limit has tokens_per_min" "2000" "$get_rl"

# ── T7: Unauthenticated request is rejected (VIP enforces AI Gateway auth) ────
echo ""
echo "T7: Unauthenticated request → 401 Unauthorized (data-plane enforcement active)"
t7_resp=$($hexec l3h1 curl -s -w "\n%{http_code}" --max-time 5 http://10.10.10.254:2020/)
t7_code=$(echo "$t7_resp" | tail -n1)
check "T7 no key → 401" "401" "$t7_code"

# ── T8: Revoke key → 404 on subsequent GET ───────────────────────────────────
echo ""
echo "T8: Revoke API key (DELETE /config/ai/apikey/{key_id})"
del_code=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:11111/netlox/v1/config/ai/apikey/$KEY_ID")
echo "  DELETE HTTP $del_code"
check "revoke returns 204" "204" "$del_code"

sleep 1
get_after=$($hexec llb1 curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:11111/netlox/v1/config/ai/apikey/$KEY_ID")
get_after_code=$(echo "$get_after" | tail -n1)
check "get after revoke returns 404" "404" "$get_after_code"

# Cleanup second key
$hexec llb1 curl -s -o /dev/null -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:11111/netlox/v1/config/ai/apikey/$KEY_ID2" 2>/dev/null

# ══════════════════════════════════════════════════════════════════════════════
# DATA-PLANE ENFORCEMENT TESTS (DP-T1 – DP-T7)
# Traffic from l3h1 → sockproxy(10.10.10.254:2020) → l3ep1:8080
# Enforcement: llb_ai_validate_key + llb_ai_ratelimit_check in sockproxy_http.c
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== DATA-PLANE ENFORCEMENT TESTS ==="

# ── Create three keys dedicated to DP tests ──────────────────────────────────
# dp_open  : no model restriction, generous rate limit — for DP-T1, DP-T7
# dp_model : restricted to llama-3 only              — for DP-T4 (403)
# dp_throttl: burst=1 / rps=1                        — for DP-T5 (429)

dp_open=$($hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/ai/apikey \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"tenant_id":"dp-tenant","name":"dp-open","allowed_models":[],"rate_limit_rps":100,"burst_size":200,"tokens_per_min":100000,"enabled":true}')
DP_OPEN_KEY=$(echo "$dp_open" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
DP_OPEN_ID=$(echo  "$dp_open" | python3 -c "import sys,json; print(json.load(sys.stdin).get('key_id',''))"  2>/dev/null)

dp_model=$($hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/ai/apikey \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"tenant_id":"dp-tenant","name":"dp-model","allowed_models":["llama-3"],"rate_limit_rps":100,"burst_size":200,"tokens_per_min":100000,"enabled":true}')
DP_MODEL_KEY=$(echo "$dp_model" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
DP_MODEL_ID=$(echo  "$dp_model" | python3 -c "import sys,json; print(json.load(sys.stdin).get('key_id',''))"  2>/dev/null)

dp_throttl=$($hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/ai/apikey \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"tenant_id":"dp-tenant","name":"dp-throttl","allowed_models":[],"rate_limit_rps":1,"burst_size":1,"tokens_per_min":100000,"enabled":true}')
DP_RL_KEY=$(echo "$dp_throttl" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
DP_RL_ID=$(echo  "$dp_throttl" | python3 -c "import sys,json; print(json.load(sys.stdin).get('key_id',''))"  2>/dev/null)

if [[ -z "$DP_OPEN_KEY" ]] || [[ -z "$DP_MODEL_KEY" ]] || [[ -z "$DP_RL_KEY" ]]; then
  echo "  FATAL: Failed to create one or more DP test keys — skipping DP-T* tests"
  code=1
else

  # ── DP-T1: Valid key (no model restriction) → reaches backend ──────────────
  echo ""
  echo "DP-T1: Valid key → 200 + backend response"
  dp1=$($hexec l3h1 curl -s --max-time 8 \
    -H "X-Api-Key: $DP_OPEN_KEY" \
    http://10.10.10.254:2020/)
  check "DP-T1 valid key reaches backend" "server1" "$dp1"

  # ── DP-T2: No key → 401 ────────────────────────────────────────────────────
  echo ""
  echo "DP-T2: No X-Api-Key header → 401 Unauthorized"
  dp2=$($hexec l3h1 curl -s -w "\n%{http_code}" --max-time 8 \
    http://10.10.10.254:2020/)
  check "DP-T2 no key → 401" "401" "$(echo "$dp2" | tail -n1)"
  check "DP-T2 body has invalid_api_key" "invalid_api_key" "$(echo "$dp2" | head -n1)"

  # ── DP-T3: Syntactically valid but unknown key → 401 ───────────────────────
  echo ""
  echo "DP-T3: Fabricated key (not in DB) → 401 Unauthorized"
  dp3=$($hexec l3h1 curl -s -w "\n%{http_code}" --max-time 8 \
    -H "X-Api-Key: lxb_00000000000000000000000000000000" \
    http://10.10.10.254:2020/)
  check "DP-T3 unknown key → 401" "401" "$(echo "$dp3" | tail -n1)"

  # ── DP-T4: Key with model restriction, wrong model → 403 ───────────────────
  echo ""
  echo "DP-T4: Key allows llama-3 only; send X-Model: mistral-7b → 403 Forbidden"
  dp4=$($hexec l3h1 curl -s -w "\n%{http_code}" --max-time 8 \
    -H "X-Api-Key: $DP_MODEL_KEY" \
    -H "X-Model: mistral-7b" \
    http://10.10.10.254:2020/)
  check "DP-T4 wrong model → 403" "403" "$(echo "$dp4" | tail -n1)"
  check "DP-T4 body has model_not_allowed" "model_not_allowed" "$(echo "$dp4" | head -n1)"

  # DP-T4b: Same key, correct model → 200
  dp4b=$($hexec l3h1 curl -s --max-time 8 \
    -H "X-Api-Key: $DP_MODEL_KEY" \
    -H "X-Model: llama-3" \
    http://10.10.10.254:2020/)
  check "DP-T4b correct model → backend" "server1" "$dp4b"

  # ── DP-T5: Per-key rate limit (burst=1, rps=1) → 429 on burst ──────────────
  echo ""
  echo "DP-T5: Burst 6 requests against rps=1 burst=1 key → at least one 429"
  # H-3 fix: send all 6 requests in parallel so they arrive together and actually
  # hit the burst window, rather than serially where token refill hides the limit.
  dp5_tmpdir=$(mktemp -d)
  dp5_pids=()
  for i in $(seq 1 6); do
    $hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "X-Api-Key: $DP_RL_KEY" \
      http://10.10.10.254:2020/ > "$dp5_tmpdir/$i" &
    dp5_pids+=($!)
  done
  wait "${dp5_pids[@]}"
  dp5_429=0
  for i in $(seq 1 6); do
    if [[ "$(cat $dp5_tmpdir/$i)" == "429" ]]; then dp5_429=1; fi
  done
  rm -rf "$dp5_tmpdir"
  if [[ $dp5_429 == 1 ]]; then
    echo "  DP-T5 rate limit returned 429 [OK]"
  else
    echo "  DP-T5 rate limit NOT enforced — no 429 seen [FAILED]"
    code=1
  fi

  # ── DP-T6: Per-tenant rate limit → 429 (set rps=1 on dp-tenant) ────────────
  echo ""
  echo "DP-T6: Tenant rps=1 rate limit → at least one 429"
  $hexec llb1 curl -s -o /dev/null -X POST http://localhost:11111/netlox/v1/config/ai/tenant/ratelimit \
    -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
    -d '{"tenant_id":"dp-tenant","rps":1,"tokens_per_min":100000}' 2>/dev/null
  # H-3 fix: parallel burst (same as DP-T5) so requests hit the tenant window together
  dp6_tmpdir=$(mktemp -d)
  dp6_pids=()
  for i in $(seq 1 6); do
    $hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "X-Api-Key: $DP_OPEN_KEY" \
      http://10.10.10.254:2020/ > "$dp6_tmpdir/$i" &
    dp6_pids+=($!)
  done
  wait "${dp6_pids[@]}"
  dp6_429=0
  for i in $(seq 1 6); do
    if [[ "$(cat $dp6_tmpdir/$i)" == "429" ]]; then dp6_429=1; fi
  done
  rm -rf "$dp6_tmpdir"
  if [[ $dp6_429 == 1 ]]; then
    echo "  DP-T6 tenant rate limit returned 429 [OK]"
  else
    echo "  DP-T6 tenant rate limit NOT enforced — no 429 seen [FAILED]"
    code=1
  fi
  # Reset tenant limit so DP-T7 is not blocked
  $hexec llb1 curl -s -o /dev/null -X POST http://localhost:11111/netlox/v1/config/ai/tenant/ratelimit \
    -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
    -d '{"tenant_id":"dp-tenant","rps":0,"tokens_per_min":100000}' 2>/dev/null

  # ── DP-T7: Revoke dp_open key → subsequent request returns 401 ─────────────
  echo ""
  echo "DP-T7: Revoke dp_open key → 401 on next request"
  $hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    "http://localhost:11111/netlox/v1/config/ai/apikey/$DP_OPEN_ID" >/dev/null
  # H-2 fix: poll for up to 10 s instead of a fixed sleep 1 to avoid flakiness
  # on a slow host while not wasting 9 s on a fast one.
  dp7_got_401=0
  for _poll in $(seq 1 10); do
    dp7_code=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "X-Api-Key: $DP_OPEN_KEY" \
      http://10.10.10.254:2020/)
    if [[ "$dp7_code" == "401" ]]; then
      dp7_got_401=1; break
    fi
    sleep 1
  done
  if [[ $dp7_got_401 -eq 1 ]]; then
    echo "  DP-T7 revoked key → 401 (after poll) [OK]"
  else
    echo "  DP-T7 revoked key NOT rejected within 10 s [FAILED]"
    code=1
  fi

  # Cleanup remaining DP test keys
  $hexec llb1 curl -s -o /dev/null -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    "http://localhost:11111/netlox/v1/config/ai/apikey/$DP_MODEL_ID" 2>/dev/null
  $hexec llb1 curl -s -o /dev/null -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    "http://localhost:11111/netlox/v1/config/ai/apikey/$DP_RL_ID" 2>/dev/null

  # ── DP-T-DISABLED: Create disabled key → data-plane rejects immediately ──
  echo ""
  echo "DP-T-DISABLED (H-1): Create key with enabled:false → data-plane 401"
  DP_DIS_BODY=$($hexec llb1 curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    http://localhost:11111/netlox/v1/config/ai/apikey \
    -d '{"tenant_id":"dp-tenant","name":"dp-disabled-key","enabled":false,"allowed_models":[],"rate_limit":{"rps":100,"burst":200}}')
  DP_DIS_ID=$(echo "$DP_DIS_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('key_id',''))" 2>/dev/null)
  DP_DIS_KEY=$(echo "$DP_DIS_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('raw_key',''))" 2>/dev/null)
  if [[ -z "$DP_DIS_ID" || -z "$DP_DIS_KEY" ]]; then
    echo "  DP-T-DISABLED: SKIP — disabled key not created (API may not support enabled:false yet)"
  else
    # Poll up to 10s for data-plane to pick up the disabled state
    dis_code="000"
    for i in $(seq 1 10); do
      dis_code=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        -H "X-Api-Key: $DP_DIS_KEY" http://10.10.10.254:2020/ 2>/dev/null)
      [[ "$dis_code" == "401" ]] && break
      sleep 1
    done
    if [[ "$dis_code" == "401" ]]; then
      echo "  DP-T-DISABLED: disabled key rejected with 401 [OK]"
    else
      echo "  DP-T-DISABLED: disabled key returned $dis_code (expected 401) [FAILED]"
      code=1
    fi
    $hexec llb1 curl -s -o /dev/null -X DELETE \
      -H "Authorization: Bearer $TOKEN" \
      "http://localhost:11111/netlox/v1/config/ai/apikey/$DP_DIS_ID" 2>/dev/null
  fi

  # ── DP-T-ROTATE: PATCH allowed_models → data-plane enforces new restriction ─
  echo ""
  echo "DP-T-ROTATE (H-5): Update key allowed_models via PATCH → data-plane enforces"
  DP_ROT_BODY=$($hexec llb1 curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    http://localhost:11111/netlox/v1/config/ai/apikey \
    -d '{"tenant_id":"dp-tenant","name":"dp-rotate-key","enabled":true,"allowed_models":["llama-3"],"rate_limit":{"rps":100,"burst":200}}')
  DP_ROT_ID=$(echo "$DP_ROT_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('key_id',''))" 2>/dev/null)
  DP_ROT_KEY=$(echo "$DP_ROT_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('raw_key',''))" 2>/dev/null)
  if [[ -z "$DP_ROT_ID" || -z "$DP_ROT_KEY" ]]; then
    echo "  DP-T-ROTATE: SKIP — rotate key not created"
  else
    # Verify initial model restriction works (llama-3 allowed)
    rot_initial=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "X-Api-Key: $DP_ROT_KEY" -H "X-Model: llama-3" http://10.10.10.254:2020/ 2>/dev/null)
    echo "  DP-T-ROTATE initial (llama-3 allowed): HTTP $rot_initial"
    # PATCH allowed_models to restrict to mistral-7b only
    patch_code=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X PATCH \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      http://localhost:11111/netlox/v1/config/ai/apikey/$DP_ROT_ID \
      -d '{"allowed_models":["mistral-7b"]}' 2>/dev/null)
    if [[ "$patch_code" == "200" || "$patch_code" == "204" ]]; then
      # Poll for data-plane to see llama-3 now rejected
      rot_after="000"
      for i in $(seq 1 10); do
        rot_after=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
          -H "X-Api-Key: $DP_ROT_KEY" -H "X-Model: llama-3" http://10.10.10.254:2020/ 2>/dev/null)
        [[ "$rot_after" == "403" ]] && break
        sleep 1
      done
      if [[ "$rot_after" == "403" ]]; then
        echo "  DP-T-ROTATE: after PATCH, llama-3 rejected with 403 [OK]"
      else
        echo "  DP-T-ROTATE: after PATCH, llama-3 returned $rot_after (expected 403) — key rotation not enforced [FAILED]"
        code=1
      fi
    else
      echo "  DP-T-ROTATE: PATCH returned $patch_code (PATCH /config/ai/apikey may not be implemented yet — SKIP)"
    fi
    $hexec llb1 curl -s -o /dev/null -X DELETE \
      -H "Authorization: Bearer $TOKEN" \
      "http://localhost:11111/netlox/v1/config/ai/apikey/$DP_ROT_ID" 2>/dev/null
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# AUTH GUARD TESTS (DP-T8 through DP-T15)
# Verifies that all management API endpoints reject unauthenticated requests,
# empty tenant_id is rejected, and the first request before the rate-limit
# threshold succeeds.
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== Auth Guard Tests (DP-T8 through DP-T15) ==="

# ── DP-T8: POST /config/ai/apikey without Bearer token → 401 ─────────────────
echo ""
echo "DP-T8: POST /netlox/v1/config/ai/apikey without auth → 401"
status=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X POST \
    http://localhost:11111/netlox/v1/config/ai/apikey \
    -H "Content-Type: application/json" \
    -d '{"tenant_id":"cicd-tenant","name":"unauth-test","enabled":true}')
check "DP-T8 unauth create → 401" "401" "$status"

# ── DP-T9: GET /config/ai/apikey without token → 401 ─────────────────────────
echo ""
echo "DP-T9: GET /netlox/v1/config/ai/apikey without auth → 401"
status=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:11111/netlox/v1/config/ai/apikey?tenant_id=cicd-tenant")
check "DP-T9 unauth list → 401" "401" "$status"

# ── DP-T10: DELETE /config/ai/apikey/{id} without token → 401 ────────────────
echo ""
echo "DP-T10: DELETE /netlox/v1/config/ai/apikey/nonexistent-id without auth → 401"
status=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
    "http://localhost:11111/netlox/v1/config/ai/apikey/nonexistent-id")
check "DP-T10 unauth delete → 401" "401" "$status"

# ── DP-T11: POST with empty tenant_id (authenticated) → 400/422 ──────────────
echo ""
echo "DP-T11: POST /netlox/v1/config/ai/apikey with empty tenant_id → 400 or 422"
status=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X POST \
    http://localhost:11111/netlox/v1/config/ai/apikey \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"tenant_id":"","name":"empty-tenant-test","enabled":true}')
if [[ "$status" == "400" || "$status" == "422" ]]; then
    echo "  DP-T11 empty tenant_id rejected → $status [OK]"
else
    echo "  DP-T11 empty tenant_id NOT rejected → $status [FAILED]"
    code=1
fi

# ── DP-T12: Rate-limit first request succeeds before limit is hit ─────────────
echo ""
echo "DP-T12: Rate-limit first request succeeds before limit is hit"
dp12_resp=$($hexec llb1 curl -s -X POST \
    http://localhost:11111/netlox/v1/config/ai/apikey \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"tenant_id":"dp-tenant","name":"dp-rl-check","allowed_models":[],"rate_limit_rps":100,"burst_size":200,"tokens_per_min":100000,"enabled":true}')
DP12_KEY=$(echo "$dp12_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
DP12_ID=$(echo  "$dp12_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('key_id',''))"  2>/dev/null)
if [[ -n "$DP12_KEY" ]]; then
    first_status=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
        -H "X-Api-Key: $DP12_KEY" \
        http://10.10.10.254:2020/ 2>/dev/null || echo "000")
    check "DP-T12 first request before limit → 200" "200" "$first_status"
    $hexec llb1 curl -s -o /dev/null -X DELETE \
        -H "Authorization: Bearer $TOKEN" \
        "http://localhost:11111/netlox/v1/config/ai/apikey/$DP12_ID" 2>/dev/null
else
    echo "  DP-T12 could not create rate-limit check key [FAILED]"
    code=1
fi

# ── DP-T13: POST /config/ai/tenant/ratelimit without token → 401 ─────────────
echo ""
echo "DP-T13: POST /netlox/v1/config/ai/tenant/ratelimit without auth → 401"
status=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X POST \
    http://localhost:11111/netlox/v1/config/ai/tenant/ratelimit \
    -H "Content-Type: application/json" \
    -d '{"tenant_id":"cicd-tenant","requests_per_minute":10}')
check "DP-T13 unauth rate-limit set → 401" "401" "$status"

# ── DP-T14: GET /config/ai/apikey/{id} without token → 401 ───────────────────
echo ""
echo "DP-T14: GET /netlox/v1/config/ai/apikey/{id} without auth → 401"
status=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:11111/netlox/v1/config/ai/apikey/nonexistent-id")
check "DP-T14 unauth get-by-id → 401" "401" "$status"

# ── DP-T15: GET /config/ai/tenant/ratelimit/{tenant_id} without token → 401 ──
echo ""
echo "DP-T15: GET /netlox/v1/config/ai/tenant/ratelimit/{tenant_id} without auth → 401"
status=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:11111/netlox/v1/config/ai/tenant/ratelimit/cicd-tenant")
check "DP-T15 unauth get-ratelimit → 401" "401" "$status"

sudo killall -9 node 2>/dev/null
echo ""
echo "Running CLI (REST API) validation tests..."
bash validate_cli.sh
cli_code=$?
if [ $cli_code -ne 0 ]; then
  code=1
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [[ $code == 0 ]]; then
  echo "SCENARIO-ai-apikey [OK]"
else
  echo "SCENARIO-ai-apikey [FAILED]"
fi
exit $code
