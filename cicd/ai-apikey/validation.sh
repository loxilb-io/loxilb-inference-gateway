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
      # This used to print "may not be implemented yet — SKIP" and return
      # without touching $code, so the one outcome the case exists to detect
      # — PATCH not working — was the one outcome it reported as success.
      # PATCH /config/ai/apikey/{key_id} is a raw-middleware route
      # (ConfigPatchAIApikey, wired in configure_loxilb_rest_api.go); it is
      # specified in api/swagger-extras.yml, not swagger.yml, which is why it
      # reads as absent if you only look at the generated spec. It exists, so
      # a non-2xx here is a regression, not an unimplemented feature.
      echo "  DP-T-ROTATE: PATCH returned $patch_code (expected 200/204) [FAILED]"
      code=1
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

# ══════════════════════════════════════════════════════════════════════════════
# QOS MANAGEMENT API (QOS-API-*)
#
# The ladder's management surface: per-user rows, the defaults rows they fall
# through to, and the API key's own rate fields. Before this block, ai-apikey
# reached 6 of the 13 route/verb pairs on this surface — the whole of
# /config/ai/user/ratelimit and /config/ai/ratelimit/defaults was untested.
#
# Statuses asserted here were read out of the handlers and the spec, not
# assumed, because two different layers answer and they answer differently:
#
#   * A typed cmn.ValidationError becomes HTTP 400 with a `fields` array
#     naming the refused field (ResultErrorResponseError).
#   * go-swagger's request binding runs FIRST and answers 422 — for a missing
#     `required` property, and for a value outside an `enum`. So "invalid
#     scope" is 422, not the 400 a reader of the handler alone would predict:
#     the handler's own `default:` branch is unreachable over HTTP.
#
# Successful writes on this surface return 204, not 200.
# ══════════════════════════════════════════════════════════════════════════════

QOS_T="qos-tenant"
QOS_U="qos-user"
QOS_SEEN=""

# Record every QOS-API case that actually asserts, so the Z block below can
# compare what ran against what was declared.
qos_note() {
  local id="${1%% *}"
  case "$id" in QOS-API-*) ;; *) return ;; esac
  case " $QOS_SEEN " in *" $id "*) ;; *) QOS_SEEN="$QOS_SEEN $id" ;; esac
}
qcheck()      { qos_note "$1"; check "$@"; }
qcheck_json() { qos_note "$1"; check_json "$@"; }

# api <METHOD> <path> [json] — prints the body, sets QOS_CODE to the status.
# An empty status is never a gateway answer; it means curl never completed, so
# it is reported as a failure of the measurement rather than scored as one.
QOS_CODE=""
api() {
  local m=$1 p=$2 b=${3:-} out
  if [[ -n "$b" ]]; then
    out=$($hexec llb1 curl -s -w "\n%{http_code}" -X "$m" \
      -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
      "http://localhost:11111/netlox/v1$p" -d "$b" 2>/dev/null)
  else
    out=$($hexec llb1 curl -s -w "\n%{http_code}" -X "$m" \
      -H "Authorization: Bearer $TOKEN" \
      "http://localhost:11111/netlox/v1$p" 2>/dev/null)
  fi
  QOS_CODE=$(printf '%s' "$out" | tail -n1)
  if [[ -z "$QOS_CODE" ]]; then
    echo "  FATAL: $m $p produced no HTTP status — the request never completed"
    code=1
    QOS_CODE="000"
  fi
  printf '%s' "$out" | sed '$d'
}

# api_noauth <METHOD> <path> — status only, no Authorization header.
api_noauth() {
  local m=$1 p=$2
  $hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X "$m" \
    "http://localhost:11111/netlox/v1$p" 2>/dev/null
}

# ── QOS-API-001: POST / GET / list one user's limits ─────────────────────────
echo ""
echo "QOS-API-001: POST user limits, read back by identity and in the tenant list"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$QOS_U\",\"rps\":7,\"burst_size\":14,\"tokens_per_min\":900}" >/dev/null
qcheck "QOS-API-001 POST user limits → 204" "204" "$QOS_CODE"

got=$(api GET "/config/ai/user/ratelimit/$QOS_T/$QOS_U")
qcheck      "QOS-API-001 GET user limits → 200" "200" "$QOS_CODE"
qcheck_json "QOS-API-001 rps read back"            ".rps"            "7"      "$got"
qcheck_json "QOS-API-001 burst_size read back"     ".burst_size"     "14"     "$got"
qcheck_json "QOS-API-001 tokens_per_min read back" ".tokens_per_min" "900"    "$got"
qcheck_json "QOS-API-001 identity read back"       ".user_id"        "$QOS_U" "$got"

lst=$(api GET "/config/ai/user/ratelimit/$QOS_T")
qcheck      "QOS-API-001 list → 200" "200" "$QOS_CODE"
qcheck_json "QOS-API-001 list contains the user" \
  "[.[] | select(.user_id==\"$QOS_U\")] | length" "1" "$lst"

# ── QOS-API-002: model_limits replace as a set ───────────────────────────────
#
# The user surface replaces model_limits wholesale (SetUserRateLimit), which is
# NOT how the tenant surface behaves: there, omitted model_limits preserve the
# existing rows. Asserting the removal is the only way that difference stays
# true — a partial-upsert regression would leave mistral-7b behind and every
# "is llama-3 present" check would still pass.
echo ""
echo "QOS-API-002: POST replacing the user's model_limits — removed rows must be gone"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$QOS_U\",\"rps\":7,\"tokens_per_min\":900,\
\"model_limits\":[{\"model\":\"llama-3\",\"tokens_per_min\":100},{\"model\":\"mistral-7b\",\"tokens_per_min\":200}]}" >/dev/null
qcheck "QOS-API-002 POST two model rows → 204" "204" "$QOS_CODE"

api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$QOS_U\",\"rps\":7,\"tokens_per_min\":900,\
\"model_limits\":[{\"model\":\"llama-3\",\"tokens_per_min\":150}]}" >/dev/null
qcheck "QOS-API-002 POST replacing with one row → 204" "204" "$QOS_CODE"

got=$(api GET "/config/ai/user/ratelimit/$QOS_T/$QOS_U")
qcheck_json "QOS-API-002 surviving row updated" \
  "[.model_limits[] | select(.model==\"llama-3\")] | .[0].tokens_per_min" "150" "$got"
qcheck_json "QOS-API-002 removed row is absent" \
  "[.model_limits[] | select(.model==\"mistral-7b\")] | length" "0" "$got"
qcheck_json "QOS-API-002 exactly one model row remains" \
  ".model_limits | length" "1" "$got"

# ── QOS-API-003: DELETE the user's limits ────────────────────────────────────
echo ""
echo "QOS-API-003: DELETE user limits → 204, and the row is gone"
api DELETE "/config/ai/user/ratelimit/$QOS_T/$QOS_U" >/dev/null
qcheck "QOS-API-003 DELETE → 204" "204" "$QOS_CODE"
api GET "/config/ai/user/ratelimit/$QOS_T/$QOS_U" >/dev/null
qcheck "QOS-API-003 GET after DELETE → 404" "404" "$QOS_CODE"

# ── QOS-API-004: global defaults ─────────────────────────────────────────────
echo ""
echo "QOS-API-004: POST/GET scope 'global' defaults"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"global","default_user_rps":3,"default_user_tpm":300,"default_tenant_rps":30,"default_tenant_tpm":3000}' >/dev/null
qcheck "QOS-API-004 POST global defaults → 204" "204" "$QOS_CODE"

got=$(api GET /config/ai/ratelimit/defaults/global)
qcheck      "QOS-API-004 GET global → 200" "200" "$QOS_CODE"
qcheck_json "QOS-API-004 default_user_rps"   ".default_user_rps"   "3"    "$got"
qcheck_json "QOS-API-004 default_user_tpm"   ".default_user_tpm"   "300"  "$got"
qcheck_json "QOS-API-004 default_tenant_rps" ".default_tenant_rps" "30"   "$got"
qcheck_json "QOS-API-004 default_tenant_tpm" ".default_tenant_tpm" "3000" "$got"

# ── QOS-API-005: rule-scoped defaults select by rule_ident ───────────────────
echo ""
echo "QOS-API-005: scope 'rule' defaults are selected by rule_ident, not shared with 'global'"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"rule","rule_ident":"qos-svc-a","default_user_rps":11,"default_user_tpm":1100}' >/dev/null
qcheck "QOS-API-005 POST rule defaults (svc-a) → 204" "204" "$QOS_CODE"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"rule","rule_ident":"qos-svc-b","default_user_rps":22,"default_user_tpm":2200}' >/dev/null
qcheck "QOS-API-005 POST rule defaults (svc-b) → 204" "204" "$QOS_CODE"

got=$(api GET "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-a")
qcheck      "QOS-API-005 GET svc-a → 200" "200" "$QOS_CODE"
qcheck_json "QOS-API-005 svc-a keeps its own value" ".default_user_rps" "11" "$got"
got=$(api GET "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-b")
qcheck_json "QOS-API-005 svc-b keeps its own value" ".default_user_rps" "22" "$got"
# The global row must not have been overwritten by either rule write.
got=$(api GET /config/ai/ratelimit/defaults/global)
qcheck_json "QOS-API-005 global row untouched by rule writes" ".default_user_rps" "3" "$got"

# ── QOS-API-006: DELETE defaults by scope ────────────────────────────────────
echo ""
echo "QOS-API-006: DELETE defaults by scope removes only the addressed row"
api DELETE "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-a" >/dev/null
qcheck "QOS-API-006 DELETE rule/svc-a → 204" "204" "$QOS_CODE"
api GET "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-a" >/dev/null
qcheck "QOS-API-006 GET deleted rule row → 404" "404" "$QOS_CODE"
# The sibling and the global row must survive: a delete that takes neighbours
# with it looks identical to a correct delete if you only check the target.
got=$(api GET "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-b")
qcheck      "QOS-API-006 sibling rule row survives → 200" "200" "$QOS_CODE"
qcheck_json "QOS-API-006 sibling value intact" ".default_user_rps" "22" "$got"
api GET /config/ai/ratelimit/defaults/global >/dev/null
qcheck "QOS-API-006 global row survives → 200" "200" "$QOS_CODE"

# ── QOS-API-007: an entry that constrains nothing is refused ─────────────────
#
# SetUserRateLimit computes "does this row decide anything" from RPS and
# TokensPerMin ONLY — burst_size is deliberately not part of it. A burst-only
# row is therefore refused exactly like an all-zero one, which is the kind of
# rule that silently stops being true; assert it directly.
echo ""
echo "QOS-API-007: all-zero and burst-only entries are refused"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"zero-user\",\"rps\":0,\"burst_size\":0,\"tokens_per_min\":0}" >/dev/null
qcheck "QOS-API-007 all-zero user entry → 400" "400" "$QOS_CODE"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"burst-only\",\"rps\":0,\"burst_size\":50,\"tokens_per_min\":0}" >/dev/null
qcheck "QOS-API-007 burst-only user entry → 400 (burst alone decides nothing)" "400" "$QOS_CODE"
api GET "/config/ai/user/ratelimit/$QOS_T/burst-only" >/dev/null
qcheck "QOS-API-007 refused entry created no row → 404" "404" "$QOS_CODE"
api POST /config/ai/ratelimit/defaults '{"scope":"rule","rule_ident":"qos-zero"}' >/dev/null
qcheck "QOS-API-007 all-zero defaults entry → 400" "400" "$QOS_CODE"

# ── QOS-API-008: negative values are refused, and change nothing ─────────────
echo ""
echo "QOS-API-008: negative values are refused and leave existing state alone"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"neg-user\",\"rps\":-1,\"tokens_per_min\":10}" >/dev/null
qcheck "QOS-API-008 negative rps → 400" "400" "$QOS_CODE"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"global","default_user_rps":-5,"default_user_tpm":10}' >/dev/null
qcheck "QOS-API-008 negative default → 400" "400" "$QOS_CODE"
got=$(api GET /config/ai/ratelimit/defaults/global)
qcheck_json "QOS-API-008 rejected write left the global row unchanged" \
  ".default_user_rps" "3" "$got"

# ── QOS-API-009: scope/rule_ident coherence ──────────────────────────────────
#
# 422 not 400 for the enum: `scope` is `enum: [global, rule]` in the spec, both
# as a body property and as a path parameter, so go-swagger refuses it during
# binding and the handler's own "invalid scope" branch never runs. Asserting
# 400 here would be asserting a line of code that is unreachable over HTTP.
echo ""
echo "QOS-API-009: invalid scope is refused at binding (422); scope/rule_ident mismatch at 400"
api POST /config/ai/ratelimit/defaults '{"scope":"bogus","default_user_rps":1}' >/dev/null
qcheck "QOS-API-009 invalid scope in body → 422 (enum, refused by binding)" "422" "$QOS_CODE"
api GET /config/ai/ratelimit/defaults/bogus >/dev/null
qcheck "QOS-API-009 invalid scope in path → 422" "422" "$QOS_CODE"
api POST /config/ai/ratelimit/defaults '{"scope":"rule","default_user_rps":1}' >/dev/null
qcheck "QOS-API-009 scope 'rule' without rule_ident → 400" "400" "$QOS_CODE"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"global","rule_ident":"nope","default_user_rps":1}' >/dev/null
qcheck "QOS-API-009 scope 'global' with a rule_ident → 400" "400" "$QOS_CODE"

# ── QOS-API-010: the API key's own rate fields, at create and over PATCH ─────
#
# PATCH /config/ai/apikey/{key_id} is a raw-middleware route registered in
# configure_loxilb_rest_api.go and specified in api/swagger-extras.yml — it is
# absent from swagger.yml by design, which is why it reads as missing if the
# generated spec is the only thing consulted.
echo ""
echo "QOS-API-010: key rate fields set at create, then changed by PATCH"
kb=$(api POST /config/ai/apikey \
  "{\"tenant_id\":\"$QOS_T\",\"name\":\"qos-key\",\"enabled\":true,\
\"allowed_models\":[\"llama-3\"],\"rate_limit_rps\":5,\"burst_size\":10,\"tokens_per_min\":500}")
qcheck "QOS-API-010 create key → 2xx" "20" "$QOS_CODE"
QOS_KEY_ID=$(echo "$kb" | jq -r '.key_id // empty' 2>/dev/null)
QOS_RAW_KEY=$(echo "$kb" | jq -r '.raw_key // empty' 2>/dev/null)

if [[ -z "$QOS_KEY_ID" ]]; then
  echo "  QOS-API-010 [FAILED] — key creation returned no key_id; PATCH cases cannot run"
  code=1
else
  got=$(api GET "/config/ai/apikey/$QOS_KEY_ID")
  qcheck_json "QOS-API-010 create-time rate_limit_rps"  ".rate_limit_rps"  "5"   "$got"
  qcheck_json "QOS-API-010 create-time burst_size"      ".burst_size"      "10"  "$got"
  qcheck_json "QOS-API-010 create-time tokens_per_min"  ".tokens_per_min"  "500" "$got"

  api PATCH "/config/ai/apikey/$QOS_KEY_ID" \
    '{"rate_limit_rps":9,"burst_size":18,"tokens_per_min":1500}' >/dev/null
  qcheck "QOS-API-010 PATCH the three rate fields → 2xx" "20" "$QOS_CODE"
  got=$(api GET "/config/ai/apikey/$QOS_KEY_ID")
  qcheck_json "QOS-API-010 patched rate_limit_rps" ".rate_limit_rps" "9"    "$got"
  qcheck_json "QOS-API-010 patched burst_size"     ".burst_size"     "18"   "$got"
  qcheck_json "QOS-API-010 patched tokens_per_min" ".tokens_per_min" "1500" "$got"

  # ── QOS-API-010b: absent means untouched, explicit 0 means "no limit" ──────
  #
  # The handler takes the three rate fields as *int: nil (absent from the JSON)
  # leaves the stored value alone, 0 is a real value meaning no limit. Those
  # two are indistinguishable in a body that simply omits the field, so both
  # halves have to be asserted or the distinction can rot unnoticed.
  echo ""
  echo "QOS-API-010b: an omitted PATCH field is untouched; an explicit 0 is stored"
  api PATCH "/config/ai/apikey/$QOS_KEY_ID" '{"rate_limit_rps":4}' >/dev/null
  qcheck "QOS-API-010b PATCH one field → 2xx" "20" "$QOS_CODE"
  got=$(api GET "/config/ai/apikey/$QOS_KEY_ID")
  qcheck_json "QOS-API-010b named field changed"      ".rate_limit_rps" "4"    "$got"
  qcheck_json "QOS-API-010b omitted burst_size kept"  ".burst_size"     "18"   "$got"
  qcheck_json "QOS-API-010b omitted tokens_per_min kept" ".tokens_per_min" "1500" "$got"

  api PATCH "/config/ai/apikey/$QOS_KEY_ID" '{"tokens_per_min":0}' >/dev/null
  qcheck "QOS-API-010b PATCH explicit zero → 2xx" "20" "$QOS_CODE"
  got=$(api GET "/config/ai/apikey/$QOS_KEY_ID")
  qcheck_json "QOS-API-010b explicit 0 stored as no-limit" ".tokens_per_min" "0" "$got"
  qcheck_json "QOS-API-010b explicit 0 did not disturb rps" ".rate_limit_rps" "4" "$got"

  # ── QOS-API-010c: the raw arm's own error contract ────────────────────────
  #
  # This route bypasses generated request binding, so its refusals are written
  # by hand and do not inherit the generated arms' envelope: writeKeyStoreFailure
  # emits SimpleError {"error": ...}, not RawError's code/message/result/fields.
  # A unit test pins the 503 case (TestExtrasApikeyPatchUnavailableIsSimpleError);
  # these pin what a client actually receives for 404 and 401.
  echo ""
  echo "QOS-API-010c: PATCH on the raw arm — unknown key, no auth, error envelope"
  body=$(api PATCH "/config/ai/apikey/no-such-key-id" '{"rate_limit_rps":1}')
  qcheck "QOS-API-010c PATCH unknown key_id → 404" "404" "$QOS_CODE"
  qcheck_json "QOS-API-010c error envelope is SimpleError {\"error\":...}" \
    "if has(\"error\") then \"yes\" else \"no\" end" "yes" "$body"
  st=$(api_noauth PATCH "/config/ai/apikey/$QOS_KEY_ID")
  qcheck "QOS-API-010c PATCH without auth → 401" "401" "$st"

  # ── QOS-API-011: PATCH activates without recreating the credential ─────────
  #
  # The point of the PATCH gap fix: changing a limit used to mean recycling the
  # key, which invalidates a credential clients are still holding. So the thing
  # to assert is that the SAME raw key still works after the change.
  #
  # Scope note: this asserts the stored limit changed and the credential
  # survived. Whether the data plane then *enforces* the new rate is Phase 3's
  # QoS runtime ladder, and belongs in a scenario that can drive sustained
  # traffic; asserting a 429 here would be timing-dependent and would fail for
  # reasons unrelated to the API under test.
  echo ""
  echo "QOS-API-011: after PATCH the same credential still authenticates"
  api PATCH "/config/ai/apikey/$QOS_KEY_ID" '{"rate_limit_rps":6}' >/dev/null
  qcheck "QOS-API-011 PATCH → 2xx" "20" "$QOS_CODE"
  got=$(api GET "/config/ai/apikey/$QOS_KEY_ID")
  qcheck_json "QOS-API-011 new limit is stored" ".rate_limit_rps" "6" "$got"
  qcheck_json "QOS-API-011 key was not recreated (key_id stable)" \
    ".key_id" "$QOS_KEY_ID" "$got"
  if [[ -n "$QOS_RAW_KEY" ]]; then
    st=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "X-Api-Key: $QOS_RAW_KEY" -H "X-Model: llama-3" http://10.10.10.254:2020/ 2>/dev/null)
    qcheck "QOS-API-011 the original raw key still authenticates → 200" "200" "$st"
  else
    echo "  QOS-API-011 [FAILED] — no raw_key returned at create; cannot prove the credential survived"
    code=1
    qos_note "QOS-API-011"
  fi

  api DELETE "/config/ai/apikey/$QOS_KEY_ID" >/dev/null
fi

# ── QOS-API-012: every new endpoint rejects an unauthenticated caller ────────
echo ""
echo "QOS-API-012: unauthenticated callers are rejected on every endpoint added here"
for spec in \
  "POST|/config/ai/user/ratelimit" \
  "GET|/config/ai/user/ratelimit/$QOS_T" \
  "GET|/config/ai/user/ratelimit/$QOS_T/$QOS_U" \
  "DELETE|/config/ai/user/ratelimit/$QOS_T/$QOS_U" \
  "POST|/config/ai/ratelimit/defaults" \
  "GET|/config/ai/ratelimit/defaults/global" \
  "DELETE|/config/ai/ratelimit/defaults/global" ; do
  m=${spec%%|*}; p=${spec#*|}
  st=$(api_noauth "$m" "$p")
  qcheck "QOS-API-012 unauth $m $p → 401" "401" "$st"
done

# ── QOS-API-013: absent rows answer 404, not an empty success ───────────────
echo ""
echo "QOS-API-013: a row that does not exist is 404"
api GET "/config/ai/user/ratelimit/$QOS_T/definitely-absent" >/dev/null
qcheck "QOS-API-013 absent user row → 404" "404" "$QOS_CODE"
api GET "/config/ai/ratelimit/defaults/rule?rule_ident=definitely-absent" >/dev/null
qcheck "QOS-API-013 absent defaults row → 404" "404" "$QOS_CODE"
# A tenant with no rows must list empty rather than 404 — the list and the
# single-item GET answer differently and both answers are deliberate.
lst=$(api GET "/config/ai/user/ratelimit/tenant-with-no-rows")
qcheck      "QOS-API-013 list for an unknown tenant → 200" "200" "$QOS_CODE"
qcheck_json "QOS-API-013 list for an unknown tenant is empty" "length" "0" "$lst"

# ── QOS-API-014 / 015: identities that would alias a bucket key ─────────────
#
# ValidateQoSIdentity refuses "|" (the composite bucket-key delimiter) and the
# sync-wire scope prefixes, because either would let one identity's bucket
# round-trip into another scope's. Reserved prefixes are
# k: u: t: tm: uq: um: kq: v: ver: (pkg/ratelimit.ReservedIdentityScopePrefixes).
echo ""
echo "QOS-API-014: an identity containing the bucket-key delimiter is refused"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"bad|user\",\"rps\":1}" >/dev/null
qcheck "QOS-API-014 user_id containing '|' → 400" "400" "$QOS_CODE"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"bad|tenant\",\"user_id\":\"$QOS_U\",\"rps\":1}" >/dev/null
qcheck "QOS-API-014 tenant_id containing '|' → 400" "400" "$QOS_CODE"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$QOS_U\",\"rps\":1,\
\"model_limits\":[{\"model\":\"bad|model\",\"tokens_per_min\":10}]}" >/dev/null
qcheck "QOS-API-014 model name containing '|' → 400" "400" "$QOS_CODE"
api GET "/config/ai/user/ratelimit/$QOS_T/bad|user" >/dev/null
qcheck "QOS-API-014 refused identity created no row → 404" "404" "$QOS_CODE"

echo ""
echo "QOS-API-015: an identity beginning with a reserved sync-wire prefix is refused"
for pfx in "uq:" "um:" "kq:" "t:" "ver:"; do
  api POST /config/ai/user/ratelimit \
    "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"${pfx}victim\",\"rps\":1}" >/dev/null
  qcheck "QOS-API-015 user_id starting '$pfx' → 400" "400" "$QOS_CODE"
done
api POST /config/ai/ratelimit/defaults \
  '{"scope":"rule","rule_ident":"v:svc","default_user_rps":1}' >/dev/null
qcheck "QOS-API-015 rule_ident starting 'v:' → 400" "400" "$QOS_CODE"

# ── QOS-API-016: tenant burst_pct and user burst_size are different fields ──
#
# The tenant scope expresses burst as a PERCENT of tokens_per_min (burst_pct,
# 0 = server default, positive values clamped 1-1000); the user scope uses an
# ABSOLUTE request-bucket capacity (burst_size). They are not spellings of one
# another, and a refactor that unified them would still pass any test that only
# ever read one scope back.
echo ""
echo "QOS-API-016: tenant burst_pct and user burst_size do not contaminate each other"
api POST /config/ai/tenant/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"rps\":40,\"tokens_per_min\":4000,\"burst_pct\":150}" >/dev/null
qcheck "QOS-API-016 POST tenant limits with burst_pct → 2xx" "20" "$QOS_CODE"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$QOS_U\",\"rps\":7,\"burst_size\":14,\"tokens_per_min\":900}" >/dev/null
qcheck "QOS-API-016 POST user limits with burst_size → 204" "204" "$QOS_CODE"

tg=$(api GET "/config/ai/tenant/ratelimit/$QOS_T")
qcheck_json "QOS-API-016 tenant reports burst_pct"    ".burst_pct" "150" "$tg"
qcheck_json "QOS-API-016 tenant carries no burst_size" \
  "if has(\"burst_size\") then \"present\" else \"absent\" end" "absent" "$tg"
ug=$(api GET "/config/ai/user/ratelimit/$QOS_T/$QOS_U")
qcheck_json "QOS-API-016 user reports burst_size"     ".burst_size" "14" "$ug"
qcheck_json "QOS-API-016 user carries no burst_pct" \
  "if has(\"burst_pct\") then \"present\" else \"absent\" end" "absent" "$ug"

# ── clean up the rows this block created ────────────────────────────────────
api DELETE "/config/ai/user/ratelimit/$QOS_T/$QOS_U"               >/dev/null 2>&1
api DELETE "/config/ai/ratelimit/defaults/global"                  >/dev/null 2>&1
api DELETE "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-b" >/dev/null 2>&1

# ── QOS-API-Z1/Z2: the block ran what it claims to run ──────────────────────
#
# A deleted, renamed or short-circuited case stops being tested silently: the
# pass count just gets smaller and the run still says OK. Comparing the case
# IDs that actually asserted against the declared set is what makes coverage
# unable to shrink without turning the run red.
echo ""
echo "QOS-API-Z: declared-vs-executed inventory"
QOS_EXPECTED="QOS-API-001 QOS-API-002 QOS-API-003 QOS-API-004 QOS-API-005 \
QOS-API-006 QOS-API-007 QOS-API-008 QOS-API-009 QOS-API-010 QOS-API-010b \
QOS-API-010c QOS-API-011 QOS-API-012 QOS-API-013 QOS-API-014 QOS-API-015 \
QOS-API-016"
qos_missing=""
for want in $QOS_EXPECTED; do
  case " $QOS_SEEN " in *" $want "*) ;; *) qos_missing="$qos_missing $want" ;; esac
done
qos_extra=""
for got in $QOS_SEEN; do
  case " $QOS_EXPECTED " in *" $got "*) ;; *) qos_extra="$qos_extra $got" ;; esac
done
if [[ -n "$qos_missing" ]]; then
  echo "  QOS-API-Z1 declared cases did not run:$qos_missing [FAILED]"
  code=1
else
  echo "  QOS-API-Z1 every declared case ran [OK]"
fi
if [[ -n "$qos_extra" ]]; then
  # A new case is good news, but it has to be declared or the inventory stops
  # being the thing that notices a deletion.
  echo "  QOS-API-Z2 cases ran that are not declared:$qos_extra — add them to QOS_EXPECTED [FAILED]"
  code=1
else
  echo "  QOS-API-Z2 no undeclared cases ran [OK]"
fi

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
