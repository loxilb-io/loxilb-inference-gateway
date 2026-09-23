#!/bin/bash
# Validates the AI Gateway:
#   Control-plane  (T1–T8)  – REST API CRUD for API keys and tenant rate limits.
#   Data-plane     (DP-T*)  – live traffic enforcement through sockproxy:
#                              valid key → 200, no/invalid key → 401,
#                              disallowed model → 403, burst over limit → 429.

source ../common.sh
echo SCENARIO-ai-apikey
code=0

# ── preflight: the JSON extractor must exist BEFORE anything is scored ───────
#
# check_json() and the key extraction below shell out to `jq` on the HOST, not
# inside llb1: `hexec` is `ip netns exec`, which swaps the network namespace
# and keeps the host filesystem, so a jq installed into the container is never
# on this PATH. An absent jq writes nothing to stdout and every assertion then
# reads got='' — exactly what a gateway omitting the field would produce.
# A missing extractor is a lost measurement, so it is refused here, before a
# single assertion is allowed to score.
require_host_tools jq || { echo "SCENARIO-ai-apikey [FAILED]"; exit 1; }
JQ_ERR=$(mktemp)
trap 'rm -f "$JQ_ERR"' EXIT

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

# check_json <label> <field> <want> <json>
#
# Three different things used to arrive here as got='': the gateway omitted the
# field, the body was empty, and the extractor never ran. Only the first is a
# product answer; the other two are failures of the measurement and now say so
# in their own words, so a broken bed can never be read as a broken gateway.
check_json() {
  local label="$1" field="$2" want="$3" json="$4"
  local got rc
  if [[ -z "$json" ]]; then
    echo "  $label [FAILED] — LOST MEASUREMENT: the response body was empty,"
    echo "      so field='$field' was never read (expected='$want')"
    code=1
    return
  fi
  got=$(printf '%s' "$json" | jq -r "$field" 2>"$JQ_ERR")
  rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "  $label [FAILED] — LOST MEASUREMENT: the extractor failed (jq exit $rc),"
    echo "      field='$field' expected='$want'"
    echo "      jq said: $(tr '\n' ' ' < "$JQ_ERR")"
    echo "      body was: $json"
    code=1
    return
  fi
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
track_helper
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

# ── metric helpers ───────────────────────────────────────────────────────────
#
# This scenario drives every precondition the AI key-authorization and quota
# families need -- a disallowed model, a per-key rps ceiling, a per-tenant rps
# ceiling, a tenant token quota and per-model token quotas -- and scored none of
# them. A REST read-back proves the row reached the DATABASE; the gauges below
# are collected from the LIVE rate-limiter store and the counters are written at
# the point of denial, so they cover the half a read-back cannot reach.

# metric_sum <family> [label-substr] [label-substr] -> the summed value of every
# series in the family carrying ALL the given label fragments, or "unreadable".
#
# Fragments are matched independently, so an assert does not depend on the order
# the exposition format happens to serialise a label set in.
#
# "unreadable" is NOT zero. An absent family legitimately reads 0 -- but so does
# a scrape that never completed, and a delta taken across one silently reports
# "nothing happened". Every arm below refuses to score on it.
metric_sum() {
  local fam="$1"; shift
  local body
  body=$($hexec llb1 curl -s --max-time 8 \
    -H "Authorization: Bearer $TOKEN" \
    http://localhost:11111/netlox/v1/metrics 2>/dev/null)
  case "$body" in
    *loxilb_*) ;;
    *) echo "unreadable"; return ;;
  esac
  printf '%s\n' "$body" | awk -v fam="$fam" -v a="${1:-}" -v b="${2:-}" '
    $0 ~ "^" fam "([{ ]|$)" {
      if (a != "" && index($0, a) == 0) next
      if (b != "" && index($0, b) == 0) next
      v = $NF; if (v + 0 == v) { s += v }
    }
    END { printf "%.0f", s + 0 }'
}

# metric_label_set <family> <label-name> -> the sorted, comma-joined set of that
# label's values across the family, or "unreadable".
#
# A per-label oracle needs the SET, not a count: a family that grew a child for
# a model nobody configured reads exactly like one that lost a child, if all you
# compare is how many there are.
metric_label_set() {
  local body
  body=$($hexec llb1 curl -s --max-time 8 \
    -H "Authorization: Bearer $TOKEN" \
    http://localhost:11111/netlox/v1/metrics 2>/dev/null)
  case "$body" in
    *loxilb_*) ;;
    *) echo "unreadable"; return ;;
  esac
  printf '%s\n' "$body" | awk -v fam="$1" -v key="$2" '
    $0 ~ "^" fam "{" {
      if (match($0, key "=\"[^\"]*\"")) {
        v = substr($0, RSTART + length(key) + 2, RLENGTH - length(key) - 3)
        print v
      }
    }' | sort -u | paste -sd, -
}

# wait_metric <family> <label-substr> <want> <secs> -> the last value read.
#
# The limiter store is refreshed from the key store, so a gauge is not
# guaranteed to carry a just-POSTed value on the very next scrape. Poll the
# MECHANISM rather than sleeping a guessed interval, and hand back what was
# actually seen so the assert reports the real number on a timeout.
wait_metric() {
  local fam="$1" lab="$2" want="$3" secs="${4:-20}" got=""
  local i
  for i in $(seq 1 "$secs"); do
    got=$(metric_sum "$fam" "$lab")
    [[ "$got" == "$want" ]] && { echo "$got"; return; }
    sleep 1
  done
  echo "$got"
}

# check_delta <label> <want> <before> <after>
check_delta() {
  local label="$1" want="$2" before="$3" after="$4"
  if [[ "$before" == "unreadable" || "$after" == "unreadable" ]]; then
    echo "  $label [FAILED] — LOST MEASUREMENT: a /metrics scrape did not complete"
    echo "      (before='$before' after='$after'), so the delta was never taken"
    code=1
    return
  fi
  local got=$(( after - before ))
  if [[ "$got" -eq "$want" ]]; then
    echo "  $label [OK] (delta=$got)"
  else
    echo "  $label [FAILED] — expected delta $want, got $got (before=$before after=$after)"
    code=1
  fi
}

# burst_429 <tmpdir> <n> -> how many of the n parallel responses were 429, or
# "lost:<k>" when k of them carry no status at all.
#
# An empty file is a curl that never completed, not a request the gateway
# allowed. Counting it as "not 429" turns a bed that failed to spawn into a
# product that failed to throttle -- and the count is used below as the exact
# oracle for the metric delta, so a dropped response would show up as the
# COUNTER being wrong. Refuse the measurement instead of guessing at it.
burst_429() {
  local dir="$1" n="$2" i c got=0 lost=0
  for i in $(seq 1 "$n"); do
    c=$(cat "$dir/$i" 2>/dev/null)
    case "$c" in
      429)            got=$((got + 1)) ;;
      [1-5][0-9][0-9]) ;;
      *)              lost=$((lost + 1)) ;;
    esac
  done
  if [[ $lost -gt 0 ]]; then echo "lost:$lost"; else echo "$got"; fi
}

# check_metric <label> <want> <got> -- exact equality, "unreadable"-aware.
check_metric() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == "unreadable" ]]; then
    echo "  $label [FAILED] — LOST MEASUREMENT: the /metrics scrape did not complete"
    code=1
  elif [[ "$got" == "$want" ]]; then
    echo "  $label [OK] ($got)"
  else
    echo "  $label [FAILED] — expected '$want', got '$got'"
    code=1
  fi
}

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

# ── NOTE: the tenant/per-model token-quota gauges are NOT coverable here ─────
#
# loxilb_ai_token_quota_limit_tokens and its model-scoped siblings are produced
# by a collector walking the LIVE rate-limiter store at scrape time, and an
# entry only appears in that store when a charge SETTLES against the bucket --
# not when the limit is configured, and not when a request is merely admitted.
# This scenario's backend is a plain HTTP echo, so no response ever carries a
# usage object and no tokens are ever charged. Measured on the bed: after a
# full run, with dp-tenant carrying tokens_per_min=100000 and all the DP
# traffic behind it, the entire token_quota family set is three series and
# contains no limit gauge at all.
#
# Asserting them here would have produced a check that reads 0 forever and a
# "utilization is 0" that passes because the family is ABSENT -- the vacuous
# shape this suite exists to catch. They belong in a scenario whose backend
# returns token usage; cicd/ai-jwtauth already carries the VIP-scoped pair.

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

  # ── DP-T1c: the cold-start latch fires once per PROCESS, not per request ───
  #
  # loxilb_ai_token_quota_cold_open_total records that this node began serving
  # token-quota traffic with no warm peer state. It is an eager scalar, so it
  # exists at 0 from boot and a 0 here means the writer never ran -- unlike a
  # lazy vector, where absence and never-fired are the same reading.
  #
  # The gateway under test has no sync peers, so the fail-open arm is the only
  # reachable one and the count after the first request through the limiter is
  # exactly 1. The value is re-read at the end of the data-plane block: the
  # contract is "at most once per process start", and a latch that re-armed per
  # request would climb with the burst traffic while still passing a >= 1
  # check. The flat re-read is what makes this an assertion about the latch
  # rather than about the first request.
  cold0=$(metric_sum loxilb_ai_token_quota_cold_open_total)
  check_metric "DP-T1c cold-start fail-open latched exactly once" "1" "$cold0"

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
  # Baselines for the 403 counter. The family has two writers -- the API-key
  # validator and its JWT sibling -- but this scenario configures no bearer
  # arm at all, so the only reachable writer here is the key one. The llama-3
  # child is carried alongside as the flat control: DP-T4b drives the SAME key
  # with the model it does allow, and a writer that charged on the allowed path
  # too would move it.
  mna_bad0=$(metric_sum loxilb_ai_model_not_allowed_total 'model="mistral-7b"' 'tenant="dp-tenant"')
  mna_ok0=$(metric_sum  loxilb_ai_model_not_allowed_total 'model="llama-3"'    'tenant="dp-tenant"')
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

  # One denied request, one allowed request, same key: exactly one charge, on
  # the denied model's child only.
  mna_bad1=$(metric_sum loxilb_ai_model_not_allowed_total 'model="mistral-7b"' 'tenant="dp-tenant"')
  mna_ok1=$(metric_sum  loxilb_ai_model_not_allowed_total 'model="llama-3"'    'tenant="dp-tenant"')
  check_delta "DP-T4m mistral-7b charged exactly once" 1 "$mna_bad0" "$mna_bad1"
  check_delta "DP-T4m llama-3 flat across the allowed request" 0 "$mna_ok0" "$mna_ok1"

  # ── DP-T5: Per-key rate limit (burst=1, rps=1) → 429 on burst ──────────────
  echo ""
  echo "DP-T5: Burst 6 requests against rps=1 burst=1 key → at least one 429"
  # H-3 fix: send all 6 requests in parallel so they arrive together and actually
  # hit the burst window, rather than serially where token refill hides the limit.
  # Baseline both reasons. A per-key denial and a per-tenant denial land on the
  # SAME family and differ only in `reason`, so each arm asserts its own child
  # AND the other one flat -- otherwise a writer charging the wrong reason
  # reads exactly like the right one.
  rlh_key0=$(metric_sum    loxilb_ai_rate_limit_hits_total 'tenant="dp-tenant"' 'reason="rate_limit_exceeded"')
  rlh_tenant0=$(metric_sum loxilb_ai_rate_limit_hits_total 'tenant="dp-tenant"' 'reason="tenant_quota_exceeded"')
  dp5_tmpdir=$(mktemp -d)
  dp5_pids=()
  for i in $(seq 1 6); do
    $hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "X-Api-Key: $DP_RL_KEY" \
      http://10.10.10.254:2020/ > "$dp5_tmpdir/$i" &
    dp5_pids+=($!)
  done
  wait "${dp5_pids[@]}"
  dp5_429=$(burst_429 "$dp5_tmpdir" 6)
  rm -rf "$dp5_tmpdir"
  case "$dp5_429" in
    lost:*)
      echo "  DP-T5 [FAILED] — LOST MEASUREMENT: ${dp5_429#lost:} of 6 responses carried no status"
      code=1 ;;
    0)
      echo "  DP-T5 rate limit NOT enforced — no 429 seen [FAILED]"
      code=1 ;;
    *)
      echo "  DP-T5 rate limit returned ${dp5_429} x 429 [OK]" ;;
  esac

  # The counter against the wire, not against a guess. The burst size is
  # deliberately not asserted -- how many of six parallel requests fall inside
  # one token window is timing -- but whatever the wire reported, the family
  # must have charged exactly that many, under the key reason.
  #
  # The tenant child stays flat for a structural reason worth stating: the
  # per-key stage runs BEFORE the per-tenant stage and returns on denial, so a
  # request the key rejected never reaches the tenant bucket, and dp-tenant has
  # no limit of its own yet.
  rlh_key1=$(metric_sum    loxilb_ai_rate_limit_hits_total 'tenant="dp-tenant"' 'reason="rate_limit_exceeded"')
  rlh_tenant1=$(metric_sum loxilb_ai_rate_limit_hits_total 'tenant="dp-tenant"' 'reason="tenant_quota_exceeded"')
  case "$dp5_429" in
    lost:*|0)
      echo "  DP-T5m rate_limit_exceeded delta NOT SCORED — the drive above did not measure" ;;
    *)
      check_delta "DP-T5m rate_limit_exceeded charged once per observed 429" "$dp5_429" "$rlh_key0" "$rlh_key1"
      check_delta "DP-T5m tenant_quota_exceeded flat (key stage denies first)" 0 "$rlh_tenant0" "$rlh_tenant1" ;;
  esac

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
  dp6_429=$(burst_429 "$dp6_tmpdir" 6)
  rm -rf "$dp6_tmpdir"
  case "$dp6_429" in
    lost:*)
      echo "  DP-T6 [FAILED] — LOST MEASUREMENT: ${dp6_429#lost:} of 6 responses carried no status"
      code=1 ;;
    0)
      echo "  DP-T6 tenant rate limit NOT enforced — no 429 seen [FAILED]"
      code=1 ;;
    *)
      echo "  DP-T6 tenant rate limit returned ${dp6_429} x 429 [OK]" ;;
  esac

  # The mirror of DP-T5m, and the half that makes the pair an oracle rather
  # than two similar checks: the two arms differ in ONE field -- which limit is
  # set to 1 -- and each expects the OTHER reason to stay put. dp-open carries
  # rps=100/burst=200, so the key stage admits all six and every denial here is
  # the tenant bucket's.
  rlh_key2=$(metric_sum    loxilb_ai_rate_limit_hits_total 'tenant="dp-tenant"' 'reason="rate_limit_exceeded"')
  rlh_tenant2=$(metric_sum loxilb_ai_rate_limit_hits_total 'tenant="dp-tenant"' 'reason="tenant_quota_exceeded"')
  case "$dp6_429" in
    lost:*|0)
      echo "  DP-T6m tenant_quota_exceeded delta NOT SCORED — the drive above did not measure" ;;
    *)
      check_delta "DP-T6m tenant_quota_exceeded charged once per observed 429" "$dp6_429" "$rlh_tenant1" "$rlh_tenant2"
      check_delta "DP-T6m rate_limit_exceeded flat (key admits all six)" 0 "$rlh_key1" "$rlh_key2" ;;
  esac
  # Reset tenant limit so DP-T7 is not blocked
  $hexec llb1 curl -s -o /dev/null -X POST http://localhost:11111/netlox/v1/config/ai/tenant/ratelimit \
    -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
    -d '{"tenant_id":"dp-tenant","rps":0,"tokens_per_min":100000}' 2>/dev/null

  # ── DP-T6k: the gate runs on EVERY request of a reused client connection ──
  #
  # A client that opens one connection and keeps it open is checked on each
  # request, not only the first. curl reuses the connection across --next
  # segments and %{num_connects} reports whether a segment opened a new one,
  # so the shape "200 on a new connection, 200 reused, 401 reused" proves the
  # gate re-ran on the reused connection rather than the client reconnecting.
  echo ""
  echo "DP-T6k: bad key on the SECOND request of a reused connection → 401"
  dp6k=$($hexec l3h1 curl -s -o /dev/null --max-time 8 -w "%{http_code}/%{num_connects}\n" \
      -H "X-Api-Key: $DP_OPEN_KEY" http://10.10.10.254:2020/ \
    --next -s -o /dev/null --max-time 8 -w "%{http_code}/%{num_connects}\n" \
      -H "X-Api-Key: $DP_OPEN_KEY" http://10.10.10.254:2020/ \
    --next -s -o /dev/null --max-time 8 -w "%{http_code}/%{num_connects}\n" \
      -H "X-Api-Key: lxb_0000000000000000000000000000000000000000" http://10.10.10.254:2020/)
  check "DP-T6k first request opens the connection → 200"   "200/1" "$(echo "$dp6k" | sed -n 1p)"
  check "DP-T6k second request reuses the connection → 200" "200/0" "$(echo "$dp6k" | sed -n 2p)"
  check "DP-T6k bad key on the reused connection → 401"     "401/0" "$(echo "$dp6k" | sed -n 3p)"

  # ── DP-T6l: the gate re-run does not cost a backend connection per request ─
  #
  # The gate used to re-run only because the request boundary released the
  # backend leg, so a kept-alive client cost one backend connect per request
  # (TIME-WAIT toward the backend grew with the request rate). Four admitted
  # requests on one client connection must ride one backend leg: the
  # gateway-side TIME-WAIT count toward the backend port may grow by the one
  # close that ends the connection, never by one per request.
  echo ""
  echo "DP-T6l: four requests on one client connection ride one backend leg"
  tw0=$($hexec llb1 ss -Htan state time-wait '( dport = :8080 )' | wc -l)
  dp6l=$($hexec l3h1 curl -s -o /dev/null --max-time 8 -w "%{http_code}/%{num_connects}\n" \
      -H "X-Api-Key: $DP_OPEN_KEY" http://10.10.10.254:2020/ \
    --next -s -o /dev/null --max-time 8 -w "%{http_code}/%{num_connects}\n" \
      -H "X-Api-Key: $DP_OPEN_KEY" http://10.10.10.254:2020/ \
    --next -s -o /dev/null --max-time 8 -w "%{http_code}/%{num_connects}\n" \
      -H "X-Api-Key: $DP_OPEN_KEY" http://10.10.10.254:2020/ \
    --next -s -o /dev/null --max-time 8 -w "%{http_code}/%{num_connects}\n" \
      -H "X-Api-Key: $DP_OPEN_KEY" http://10.10.10.254:2020/)
  sleep 1
  tw1=$($hexec llb1 ss -Htan state time-wait '( dport = :8080 )' | wc -l)
  check "DP-T6l all four requests admitted on one connection" "200/1
200/0
200/0
200/0" "$dp6l"
  if [[ $((tw1 - tw0)) -le 1 ]]; then
    echo "  DP-T6l backend TIME-WAIT grew by $((tw1 - tw0)) for four requests (≤ 1) [OK]"
  else
    echo "  DP-T6l backend TIME-WAIT grew by $((tw1 - tw0)) for four requests — one backend connect per request [FAILED]"
    code=1
  fi

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

  # ── DP-T7c: the cold-start latch did not re-arm ────────────────────────────
  # Same scalar, read after every DP request above -- two burst arms of six
  # plus the model, revoke and poll traffic. Still 1.
  cold1=$(metric_sum loxilb_ai_token_quota_cold_open_total)
  check_delta "DP-T7c cold-start latch flat across all data-plane traffic" 0 "$cold0" "$cold1"

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

# api <METHOD> <path> [json] — drives one request and publishes its result in
# QOS_BODY / QOS_CODE. It deliberately does NOT print the body.
#
# 🚨 It used to print the body so call sites could write `got=$(api GET ...)`.
# That put every call in a command-substitution SUBSHELL, so the QOS_CODE
# assignment never reached the caller and the next status assertion scored the
# PREVIOUS request's status. Eight assertions were reading a stale value on the
# first live run. Publishing the body through a global keeps the status and the
# body that produced it in the same shell, so they cannot drift apart.
#
# An empty status is never a gateway answer; it means curl never completed, so
# it is reported as a failure of the measurement rather than scored as one.
QOS_CODE=""
QOS_BODY=""
QOS_CODE_FRESH=0
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
  QOS_BODY=$(printf '%s' "$out" | sed '$d')
  QOS_CODE_FRESH=1
  if [[ -z "$QOS_CODE" ]]; then
    echo "  FATAL: $m $p produced no HTTP status — the request never completed"
    code=1
    QOS_CODE="000"
  fi
}

# qcheck_code <label> <want> — assert the status of the request just made.
#
# The freshness flag is the harness's own red twin for the staleness defect
# above: a status may be scored exactly once, by the assertion that follows its
# request. A second assertion with no request in between is not a pass and not
# a fail of the product — it is a broken test, and says so.
qcheck_code() {
  local label="$1" want="$2"
  if [[ "$QOS_CODE_FRESH" != "1" ]]; then
    qos_note "$label"
    echo "  $label [FAILED] — stale status: no request was made since the last status assertion"
    code=1
    return
  fi
  QOS_CODE_FRESH=0
  qcheck "$label" "$want" "$QOS_CODE"
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
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$QOS_U\",\"rps\":7,\"burst_size\":14,\"tokens_per_min\":900}"
qcheck_code "QOS-API-001 POST user limits → 204" "204"

api GET "/config/ai/user/ratelimit/$QOS_T/$QOS_U"
got=$QOS_BODY
qcheck_code "QOS-API-001 GET user limits → 200" "200"
qcheck_json "QOS-API-001 rps read back"            ".rps"            "7"      "$got"
qcheck_json "QOS-API-001 burst_size read back"     ".burst_size"     "14"     "$got"
qcheck_json "QOS-API-001 tokens_per_min read back" ".tokens_per_min" "900"    "$got"
qcheck_json "QOS-API-001 identity read back"       ".user_id"        "$QOS_U" "$got"

api GET "/config/ai/user/ratelimit/$QOS_T"
lst=$QOS_BODY
qcheck_code "QOS-API-001 list → 200" "200"
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
\"model_limits\":[{\"model\":\"llama-3\",\"tokens_per_min\":100},{\"model\":\"mistral-7b\",\"tokens_per_min\":200}]}"
qcheck_code "QOS-API-002 POST two model rows → 204" "204"

api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$QOS_U\",\"rps\":7,\"tokens_per_min\":900,\
\"model_limits\":[{\"model\":\"llama-3\",\"tokens_per_min\":150}]}"
qcheck_code "QOS-API-002 POST replacing with one row → 204" "204"

api GET "/config/ai/user/ratelimit/$QOS_T/$QOS_U"
got=$QOS_BODY
qcheck_json "QOS-API-002 surviving row updated" \
  "[.model_limits[] | select(.model==\"llama-3\")] | .[0].tokens_per_min" "150" "$got"
qcheck_json "QOS-API-002 removed row is absent" \
  "[.model_limits[] | select(.model==\"mistral-7b\")] | length" "0" "$got"
qcheck_json "QOS-API-002 exactly one model row remains" \
  ".model_limits | length" "1" "$got"

# ── QOS-API-003: DELETE the user's limits ────────────────────────────────────
echo ""
echo "QOS-API-003: DELETE user limits → 204, and the row is gone"
api DELETE "/config/ai/user/ratelimit/$QOS_T/$QOS_U"
qcheck_code "QOS-API-003 DELETE → 204" "204"
api GET "/config/ai/user/ratelimit/$QOS_T/$QOS_U"
qcheck_code "QOS-API-003 GET after DELETE → 404" "404"

# ── QOS-API-004: global defaults ─────────────────────────────────────────────
echo ""
echo "QOS-API-004: POST/GET scope 'global' defaults"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"global","default_user_rps":3,"default_user_tpm":300,"default_tenant_rps":30,"default_tenant_tpm":3000}'
qcheck_code "QOS-API-004 POST global defaults → 204" "204"

api GET /config/ai/ratelimit/defaults/global
got=$QOS_BODY
qcheck_code "QOS-API-004 GET global → 200" "200"
qcheck_json "QOS-API-004 default_user_rps"   ".default_user_rps"   "3"    "$got"
qcheck_json "QOS-API-004 default_user_tpm"   ".default_user_tpm"   "300"  "$got"
qcheck_json "QOS-API-004 default_tenant_rps" ".default_tenant_rps" "30"   "$got"
qcheck_json "QOS-API-004 default_tenant_tpm" ".default_tenant_tpm" "3000" "$got"

# ── QOS-API-005: rule-scoped defaults select by rule_ident ───────────────────
echo ""
echo "QOS-API-005: scope 'rule' defaults are selected by rule_ident, not shared with 'global'"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"rule","rule_ident":"qos-svc-a","default_user_rps":11,"default_user_tpm":1100}'
qcheck_code "QOS-API-005 POST rule defaults (svc-a) → 204" "204"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"rule","rule_ident":"qos-svc-b","default_user_rps":22,"default_user_tpm":2200}'
qcheck_code "QOS-API-005 POST rule defaults (svc-b) → 204" "204"

api GET "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-a"
got=$QOS_BODY
qcheck_code "QOS-API-005 GET svc-a → 200" "200"
qcheck_json "QOS-API-005 svc-a keeps its own value" ".default_user_rps" "11" "$got"
api GET "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-b"
got=$QOS_BODY
qcheck_json "QOS-API-005 svc-b keeps its own value" ".default_user_rps" "22" "$got"
# The global row must not have been overwritten by either rule write.
api GET /config/ai/ratelimit/defaults/global
got=$QOS_BODY
qcheck_json "QOS-API-005 global row untouched by rule writes" ".default_user_rps" "3" "$got"

# ── QOS-API-006: DELETE defaults by scope ────────────────────────────────────
echo ""
echo "QOS-API-006: DELETE defaults by scope removes only the addressed row"
api DELETE "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-a"
qcheck_code "QOS-API-006 DELETE rule/svc-a → 204" "204"
api GET "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-a"
qcheck_code "QOS-API-006 GET deleted rule row → 404" "404"
# The sibling and the global row must survive: a delete that takes neighbours
# with it looks identical to a correct delete if you only check the target.
api GET "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-b"
got=$QOS_BODY
qcheck_code "QOS-API-006 sibling rule row survives → 200" "200"
qcheck_json "QOS-API-006 sibling value intact" ".default_user_rps" "22" "$got"
api GET /config/ai/ratelimit/defaults/global
qcheck_code "QOS-API-006 global row survives → 200" "200"

# ── QOS-API-007: an entry that constrains nothing is refused ─────────────────
#
# SetUserRateLimit computes "does this row decide anything" from RPS and
# TokensPerMin ONLY — burst_size is deliberately not part of it. A burst-only
# row is therefore refused exactly like an all-zero one, which is the kind of
# rule that silently stops being true; assert it directly.
echo ""
echo "QOS-API-007: all-zero and burst-only entries are refused"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"zero-user\",\"rps\":0,\"burst_size\":0,\"tokens_per_min\":0}"
qcheck_code "QOS-API-007 all-zero user entry → 400" "400"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"burst-only\",\"rps\":0,\"burst_size\":50,\"tokens_per_min\":0}"
qcheck_code "QOS-API-007 burst-only user entry → 400 (burst alone decides nothing)" "400"
api GET "/config/ai/user/ratelimit/$QOS_T/burst-only"
qcheck_code "QOS-API-007 refused entry created no row → 404" "404"
api POST /config/ai/ratelimit/defaults '{"scope":"rule","rule_ident":"qos-zero"}'
qcheck_code "QOS-API-007 all-zero defaults entry → 400" "400"

# ── QOS-API-008: negative values are refused, and change nothing ─────────────
echo ""
echo "QOS-API-008: negative values are refused and leave existing state alone"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"neg-user\",\"rps\":-1,\"tokens_per_min\":10}"
qcheck_code "QOS-API-008 negative rps → 400" "400"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"global","default_user_rps":-5,"default_user_tpm":10}'
qcheck_code "QOS-API-008 negative default → 400" "400"
api GET /config/ai/ratelimit/defaults/global
got=$QOS_BODY
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
api POST /config/ai/ratelimit/defaults '{"scope":"bogus","default_user_rps":1}'
qcheck_code "QOS-API-009 invalid scope in body → 422 (enum, refused by binding)" "422"
api GET /config/ai/ratelimit/defaults/bogus
qcheck_code "QOS-API-009 invalid scope in path → 422" "422"
api POST /config/ai/ratelimit/defaults '{"scope":"rule","default_user_rps":1}'
qcheck_code "QOS-API-009 scope 'rule' without rule_ident → 400" "400"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"global","rule_ident":"nope","default_user_rps":1}'
qcheck_code "QOS-API-009 scope 'global' with a rule_ident → 400" "400"

# ── QOS-API-010: the API key's own rate fields, at create and over PATCH ─────
#
# PATCH /config/ai/apikey/{key_id} is a raw-middleware route registered in
# configure_loxilb_rest_api.go and specified in api/swagger-extras.yml — it is
# absent from swagger.yml by design, which is why it reads as missing if the
# generated spec is the only thing consulted.
echo ""
echo "QOS-API-010: key rate fields set at create, then changed by PATCH"
api POST /config/ai/apikey \
  "{\"tenant_id\":\"$QOS_T\",\"name\":\"qos-key\",\"enabled\":true,\
\"allowed_models\":[\"llama-3\"],\"rate_limit_rps\":5,\"burst_size\":10,\"tokens_per_min\":500}"
kb=$QOS_BODY
qcheck_code "QOS-API-010 create key → 2xx" "20"
QOS_KEY_ID=$(echo "$kb" | jq -r '.key_id // empty' 2>/dev/null)
QOS_RAW_KEY=$(echo "$kb" | jq -r '.raw_key // empty' 2>/dev/null)

if [[ -z "$QOS_KEY_ID" ]]; then
  echo "  QOS-API-010 [FAILED] — key creation returned no key_id; PATCH cases cannot run"
  code=1
else
  api GET "/config/ai/apikey/$QOS_KEY_ID"
  got=$QOS_BODY
  qcheck_json "QOS-API-010 create-time rate_limit_rps"  ".rate_limit_rps"  "5"   "$got"
  qcheck_json "QOS-API-010 create-time burst_size"      ".burst_size"      "10"  "$got"
  qcheck_json "QOS-API-010 create-time tokens_per_min"  ".tokens_per_min"  "500" "$got"

  api PATCH "/config/ai/apikey/$QOS_KEY_ID" \
    '{"rate_limit_rps":9,"burst_size":18,"tokens_per_min":1500}'
  qcheck_code "QOS-API-010 PATCH the three rate fields → 2xx" "20"
  api GET "/config/ai/apikey/$QOS_KEY_ID"
  got=$QOS_BODY
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
  api PATCH "/config/ai/apikey/$QOS_KEY_ID" '{"rate_limit_rps":4}'
  qcheck_code "QOS-API-010b PATCH one field → 2xx" "20"
  api GET "/config/ai/apikey/$QOS_KEY_ID"
  got=$QOS_BODY
  qcheck_json "QOS-API-010b named field changed"      ".rate_limit_rps" "4"    "$got"
  qcheck_json "QOS-API-010b omitted burst_size kept"  ".burst_size"     "18"   "$got"
  qcheck_json "QOS-API-010b omitted tokens_per_min kept" ".tokens_per_min" "1500" "$got"

  # ApiKeySummary serialises the three rate fields with `omitempty`, so a
  # stored 0 leaves the wire, not a `"tokens_per_min": 0`. Measured, not
  # predicted: the first run read `null` here. `// 0` reads the wire the way
  # the schema defines it — and because the field held 1500 immediately
  # before, this still proves the write LANDED rather than being skipped.
  api PATCH "/config/ai/apikey/$QOS_KEY_ID" '{"tokens_per_min":0}'
  qcheck_code "QOS-API-010b PATCH explicit zero → 2xx" "20"
  api GET "/config/ai/apikey/$QOS_KEY_ID"
  got=$QOS_BODY
  qcheck_json "QOS-API-010b explicit 0 stored as no-limit" "(.tokens_per_min // 0)" "0" "$got"
  qcheck_json "QOS-API-010b explicit 0 replaced the previous 1500" \
    "if (.tokens_per_min // 0) == 1500 then \"unchanged\" else \"changed\" end" "changed" "$got"
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
  api PATCH "/config/ai/apikey/no-such-key-id" '{"rate_limit_rps":1}'
  body=$QOS_BODY
  qcheck_code "QOS-API-010c PATCH unknown key_id → 404" "404"
  qcheck_json "QOS-API-010c error envelope is SimpleError {\"error\":...}" \
    "if has(\"error\") then \"yes\" else \"no\" end" "yes" "$body"
  st=$(api_noauth PATCH "/config/ai/apikey/$QOS_KEY_ID")
  qcheck "QOS-API-010c PATCH without auth → 401" "401" "$st"

  # ── QOS-API-010e: a PATCH that names no known field is refused ────────────
  #
  # The raw arm used to fall through every branch and answer 204 when the body
  # carried no field it recognises. Two lies in one status code, both measured
  # live before this case was written:
  #
  #   PATCH /config/ai/apikey/definitely-no-such-key {}                 → 204
  #   PATCH /config/ai/apikey/definitely-no-such-key {"not_a_field":1}  → 204
  #   GET   /config/ai/apikey/definitely-no-such-key                    → 404
  #
  # A misspelled field name ("ratelimit_rps") was therefore reported as a
  # successful update that never happened, and 204 on PATCH asserts the
  # resource exists — so a provisioning loop of "patch, create on 404" would
  # never create. The control below keeps the honest 404 honest: naming a real
  # field on a missing key must still be 404, not swept into the new 400.
  echo ""
  echo "QOS-API-010e: a PATCH naming no known field is refused, on a real key and a missing one"
  api PATCH "/config/ai/apikey/$QOS_KEY_ID" '{}'
  qcheck_code "QOS-API-010e empty PATCH body on a real key → 400" "400"
  api PATCH "/config/ai/apikey/$QOS_KEY_ID" '{"ratelimit_rps":123}'
  got=$QOS_BODY
  qcheck_code "QOS-API-010e misspelled field is refused, not silently ignored → 400" "400"
  qcheck_json "QOS-API-010e and the refusal says what is missing" \
    "if (.error // \"\") | test(\"no patchable field\") then \"explained\" else \"opaque\" end" \
    "explained" "$got"
  # It really was a no-op: the misspelling must not have reached rate_limit_rps.
  api GET "/config/ai/apikey/$QOS_KEY_ID"
  got=$QOS_BODY
  qcheck_json "QOS-API-010e the refused PATCH changed nothing" ".rate_limit_rps" "4" "$got"

  api PATCH "/config/ai/apikey/no-such-key-at-all" '{}'
  qcheck_code "QOS-API-010e empty PATCH on a MISSING key → 400, never a 204 that implies it exists" "400"
  api PATCH "/config/ai/apikey/no-such-key-at-all" '{"rate_limit_rps":1}'
  qcheck_code "QOS-API-010e control: a real field on a missing key is still 404" "404"

  # ── QOS-API-011: PATCH activates without recreating the credential ─────────
  #
  # The point of the PATCH gap fix: changing a limit used to mean recycling the
  # key, which invalidates a credential clients are still holding. So the thing
  # to assert is that the SAME raw key still works after the change.
  #
  # Scope note: this asserts the stored limit changed and the credential
  # survived. Whether the data plane then *enforces* the new rate belongs to
  # the QoS runtime ladder, in a scenario that can drive sustained traffic;
  # asserting a 429 here would be timing-dependent and would fail for reasons
  # unrelated to the API under test.
  echo ""
  echo "QOS-API-011: after PATCH the same credential still authenticates"
  api PATCH "/config/ai/apikey/$QOS_KEY_ID" '{"rate_limit_rps":6}'
  qcheck_code "QOS-API-011 PATCH → 2xx" "20"
  api GET "/config/ai/apikey/$QOS_KEY_ID"
  got=$QOS_BODY
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

  api DELETE "/config/ai/apikey/$QOS_KEY_ID"
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

# ── QOS-API-012b: an AUTHENTICATED caller without the authority is 403 ───────
#
# 012 above only covers the missing credential. A present credential that may
# not do this is a different decision with a different status, and it is the
# one that actually separates authentication from authorization: if role
# enforcement regressed to "any valid token wins", every 401 assertion above
# would still pass.
#
# viewer is GET-only by pkg/authz's closed set (AuthorizeRole: RoleViewer
# returns nil for GET and for POST /auth/logout, ErrPermissionDenied for
# everything else), so the same endpoint list must answer 403 to a viewer and
# 401 to nobody at all.
echo ""
echo "QOS-API-012b: an authenticated viewer is refused the writes, and allowed the reads"
QOS_VGUARD="qos-viewer-guarded"

$hexec llb1 curl -s -o /dev/null -X POST http://localhost:11111/netlox/v1/auth/users \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"username":"qos-viewer","password":"Viewer123!","role":"viewer"}' 2>/dev/null
VIEWER_TOKEN=$($hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"qos-viewer","password":"Viewer123!"}' 2>/dev/null \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)

# No token means the viewer account was never created, and every 403 below
# would then be a 401 scored against the wrong mechanism. Fail the measurement
# rather than the product.
if [[ -z "$VIEWER_TOKEN" ]]; then
  qos_note "QOS-API-012b"
  echo "  QOS-API-012b [FAILED] — no viewer token: the account was not created, so the 403 legs cannot be scored"
  code=1
else
  # The positive control, and it has to come first: a viewer that cannot read
  # either is a principal denied everything, which would make every 403 below
  # true for a reason that has nothing to do with the method.
  st=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X GET \
    -H "Authorization: Bearer $VIEWER_TOKEN" \
    "http://localhost:11111/netlox/v1/config/ai/user/ratelimit/$QOS_T" 2>/dev/null)
  qcheck "QOS-API-012b viewer GET tenant list → 200" "200" "$st"

  # The block owns the row the viewer tries to delete. QOS-API-003 already
  # removed $QOS_T/$QOS_U, so borrowing it would make "the row survived" fail
  # for a reason that has nothing to do with authorization.
  api POST /config/ai/user/ratelimit \
    "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$QOS_VGUARD\",\"rps\":3,\"tokens_per_min\":300}"
  qcheck_code "QOS-API-012b fixture row created as admin → 204" "204"

  for spec in \
    "POST|/config/ai/user/ratelimit|{\"tenant_id\":\"$QOS_T\",\"user_id\":\"viewer-must-not-write\",\"rps\":1}" \
    "DELETE|/config/ai/user/ratelimit/$QOS_T/$QOS_VGUARD|" \
    "POST|/config/ai/ratelimit/defaults|{\"rule_ident\":\"viewer-must-not-write\",\"rps\":1}" \
    "DELETE|/config/ai/ratelimit/defaults/global|" ; do
    m=${spec%%|*}; rest=${spec#*|}; p=${rest%%|*}; b=${rest#*|}
    if [[ -n "$b" ]]; then
      st=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X "$m" \
        -H "Content-Type: application/json" -H "Authorization: Bearer $VIEWER_TOKEN" \
        "http://localhost:11111/netlox/v1$p" -d "$b" 2>/dev/null)
    else
      st=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X "$m" \
        -H "Authorization: Bearer $VIEWER_TOKEN" \
        "http://localhost:11111/netlox/v1$p" 2>/dev/null)
    fi
    qcheck "QOS-API-012b viewer $m $p → 403" "403" "$st"
  done

  # The refusals must have been refusals. A status is what the gateway SAID;
  # these two reads are what it DID, and a 403 that wrote anyway is the worst
  # of both readings.
  api GET "/config/ai/user/ratelimit/$QOS_T/$QOS_VGUARD"
  qcheck_code "QOS-API-012b the row the viewer was refused to delete survived → 200" "200"
  api GET "/config/ai/user/ratelimit/$QOS_T/viewer-must-not-write"
  qcheck_code "QOS-API-012b the row the viewer was refused to create never appeared → 404" "404"

  api DELETE "/config/ai/user/ratelimit/$QOS_T/$QOS_VGUARD"
fi

# ── QOS-API-013: absent rows answer 404, not an empty success ───────────────
echo ""
echo "QOS-API-013: a row that does not exist is 404"
api GET "/config/ai/user/ratelimit/$QOS_T/definitely-absent"
qcheck_code "QOS-API-013 absent user row → 404" "404"
api GET "/config/ai/ratelimit/defaults/rule?rule_ident=definitely-absent"
qcheck_code "QOS-API-013 absent defaults row → 404" "404"
# A tenant with no rows must list empty rather than 404 — the list and the
# single-item GET answer differently and both answers are deliberate.
api GET "/config/ai/user/ratelimit/tenant-with-no-rows"
lst=$QOS_BODY
qcheck_code "QOS-API-013 list for an unknown tenant → 200" "200"
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
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"bad|user\",\"rps\":1}"
qcheck_code "QOS-API-014 user_id containing '|' → 400" "400"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"bad|tenant\",\"user_id\":\"$QOS_U\",\"rps\":1}"
qcheck_code "QOS-API-014 tenant_id containing '|' → 400" "400"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$QOS_U\",\"rps\":1,\
\"model_limits\":[{\"model\":\"bad|model\",\"tokens_per_min\":10}]}"
qcheck_code "QOS-API-014 model name containing '|' → 400" "400"
api GET "/config/ai/user/ratelimit/$QOS_T/bad|user"
qcheck_code "QOS-API-014 refused identity created no row → 404" "404"

echo ""
echo "QOS-API-015: an identity beginning with a reserved sync-wire prefix is refused"
for pfx in "uq:" "um:" "kq:" "t:" "ver:"; do
  api POST /config/ai/user/ratelimit \
    "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"${pfx}victim\",\"rps\":1}"
  qcheck_code "QOS-API-015 user_id starting '$pfx' → 400" "400"
done
api POST /config/ai/ratelimit/defaults \
  '{"scope":"rule","rule_ident":"v:svc","default_user_rps":1}'
qcheck_code "QOS-API-015 rule_ident starting 'v:' → 400" "400"

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
  "{\"tenant_id\":\"$QOS_T\",\"rps\":40,\"tokens_per_min\":4000,\"burst_pct\":150}"
qcheck_code "QOS-API-016 POST tenant limits with burst_pct → 2xx" "20"
api POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$QOS_U\",\"rps\":7,\"burst_size\":14,\"tokens_per_min\":900}"
qcheck_code "QOS-API-016 POST user limits with burst_size → 204" "204"

api GET "/config/ai/tenant/ratelimit/$QOS_T"
tg=$QOS_BODY
qcheck_json "QOS-API-016 tenant reports burst_pct"    ".burst_pct" "150" "$tg"
qcheck_json "QOS-API-016 tenant carries no burst_size" \
  "if has(\"burst_size\") then \"present\" else \"absent\" end" "absent" "$tg"
api GET "/config/ai/user/ratelimit/$QOS_T/$QOS_U"
ug=$QOS_BODY
qcheck_json "QOS-API-016 user reports burst_size"     ".burst_size" "14" "$ug"
qcheck_json "QOS-API-016 user carries no burst_pct" \
  "if has(\"burst_pct\") then \"present\" else \"absent\" end" "absent" "$ug"

# ── QOS-API-017: rule_ident coherence across the three verbs ────────────────
#
# The spec for GET and DELETE /config/ai/ratelimit/defaults/{scope} says the
# rule_ident query parameter "is ignored for scope 'global'", and POST enforces
# the same coherence from the other side by refusing a global body that carries
# one (QOS-API-009). GET and DELETE passed it straight to the store, which keys
# rows on (scope, rule_ident) — so a stray rule_ident on a global request
# addressed a row that cannot exist: GET answered 404 while the global row sat
# there, and DELETE answered 404 having removed nothing.
#
# That is not cosmetic. A client keeping one query template for both scopes
# reads "no global defaults configured" for a tenant that has them, and a
# reconciler that does GET → 404 → POST recreates a row it never saw.
#
# The second half guards the fix from over-reaching: dropping rule_ident must
# happen for 'global' ONLY. If scope 'rule' ever stopped keying on it, every
# service would share one defaults row, which is the far worse bug.
echo ""
echo "QOS-API-017: rule_ident is ignored for scope 'global' and still selects for scope 'rule'"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"global","default_user_rps":3,"default_user_tpm":300,"default_tenant_rps":30,"default_tenant_tpm":3000}'
qcheck_code "QOS-API-017 re-seed the global row → 204" "204"

api GET "/config/ai/ratelimit/defaults/global?rule_ident=stray"
got=$QOS_BODY
qcheck_code "QOS-API-017 GET global with a stray rule_ident → 200 (ignored, not 404)" "200"
qcheck_json "QOS-API-017 it is the global row that came back" ".scope" "global" "$got"
qcheck_json "QOS-API-017 with the global row's values" ".default_user_rps" "3" "$got"

api GET "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-b"
got=$QOS_BODY
qcheck_code "QOS-API-017 scope 'rule' still selects by rule_ident → 200" "200"
qcheck_json "QOS-API-017 and returns that service's own value" ".default_user_rps" "22" "$got"
api GET "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-never"
qcheck_code "QOS-API-017 an unknown rule_ident is still 404" "404"

api DELETE "/config/ai/ratelimit/defaults/global?rule_ident=stray"
qcheck_code "QOS-API-017 DELETE global with a stray rule_ident → 204 (ignored, not 404)" "204"
api GET /config/ai/ratelimit/defaults/global
qcheck_code "QOS-API-017 and the global row really is gone → 404" "404"

# ── QOS-API-018: a 404 names the resource that was asked for ────────────────
#
# Every "no such row" in the key store used to be the single ErrKeyNotFound
# sentinel, whose message is "API key not found" — so asking for an absent
# rate-limit row was answered with the wrong resource's name, and the REST
# layer decided 404-vs-500 by looking for the substring "not found" in it.
# Both halves matter: the wording misleads an operator, and a status code that
# depends on phrasing turns any store error containing those two words into
# "this row does not exist", the one answer that invites a caller to create it.
echo ""
echo "QOS-API-018: not-found bodies name the resource, not the API key"
api GET "/config/ai/user/ratelimit/$QOS_T/definitely-absent"
got=$QOS_BODY
qcheck_code "QOS-API-018 absent user row → 404" "404"
qcheck_json "QOS-API-018 the user 404 does not claim an API key is missing" \
  "if (.result // \"\") | test(\"API key\") then \"wrong-resource\" else \"ok\" end" "ok" "$got"
qcheck_json "QOS-API-018 it names the user rate-limit row" \
  "if (.result // \"\") | test(\"user rate-limit row\") then \"named\" else \"unnamed\" end" "named" "$got"

api GET "/config/ai/ratelimit/defaults/rule?rule_ident=definitely-absent"
got=$QOS_BODY
qcheck_code "QOS-API-018 absent defaults row → 404" "404"
qcheck_json "QOS-API-018 the defaults 404 does not claim an API key is missing" \
  "if (.result // \"\") | test(\"API key\") then \"wrong-resource\" else \"ok\" end" "ok" "$got"
qcheck_json "QOS-API-018 it names the defaults row" \
  "if (.result // \"\") | test(\"rate-limit defaults row\") then \"named\" else \"unnamed\" end" "named" "$got"

# The API key's own 404 must keep saying "API key" — the fix splits the
# sentinels, it does not rename the one that was already right.
api GET "/config/ai/apikey/no-such-key-at-all"
got=$QOS_BODY
qcheck_code "QOS-API-018 absent API key → 404" "404"
qcheck_json "QOS-API-018 and that one still names the API key" \
  "if (.result // .error // \"\") | test(\"API key\") then \"named\" else \"unnamed\" end" "named" "$got"

# ── QOS-API-019: vip_shared_* round-trip, and POST replaces the whole row ───
#
# vip_shared_rps / vip_shared_tpm arm the opt-in per-service shared bucket for
# keyless traffic. They are settable and returned on this surface and were
# never asserted, so a serialisation or column mix-up here would be invisible.
#
# The second half pins the write semantic: POST REPLACES the row, it does not
# merge. Combined with "a zero field falls through to unlimited", a client that
# posts one field to change it silently removes every other bound on the row —
# a fail-open config change. The spec text does not say which it is, so assert
# what it does: a silent flip to merge semantics would otherwise pass unseen.
echo ""
echo "QOS-API-019: vip_shared_* round-trip, and a partial POST replaces the row"
api POST /config/ai/ratelimit/defaults \
  '{"scope":"global","default_user_rps":3,"vip_shared_rps":9,"vip_shared_tpm":900}'
qcheck_code "QOS-API-019 POST defaults with vip_shared_* → 204" "204"
api GET /config/ai/ratelimit/defaults/global
got=$QOS_BODY
qcheck_json "QOS-API-019 vip_shared_rps round-trips" ".vip_shared_rps" "9"   "$got"
qcheck_json "QOS-API-019 vip_shared_tpm round-trips" ".vip_shared_tpm" "900" "$got"
qcheck_json "QOS-API-019 and did not land in the user fields" ".default_user_rps" "3" "$got"

api POST /config/ai/ratelimit/defaults '{"scope":"global","default_user_rps":5}'
qcheck_code "QOS-API-019 POST one field → 204" "204"
api GET /config/ai/ratelimit/defaults/global
got=$QOS_BODY
qcheck_json "QOS-API-019 the named field changed" ".default_user_rps" "5" "$got"
qcheck_json "QOS-API-019 an omitted vip_shared_rps was ZEROED, not preserved" \
  "(.vip_shared_rps // 0)" "0" "$got"
qcheck_json "QOS-API-019 an omitted vip_shared_tpm was ZEROED, not preserved" \
  "(.vip_shared_tpm // 0)" "0" "$got"

# ── clean up the rows this block created ────────────────────────────────────
api DELETE "/config/ai/user/ratelimit/$QOS_T/$QOS_U"
api DELETE "/config/ai/ratelimit/defaults/global"
api DELETE "/config/ai/ratelimit/defaults/rule?rule_ident=qos-svc-b"

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
QOS-API-010c QOS-API-010e QOS-API-011 QOS-API-012 QOS-API-012b QOS-API-013 QOS-API-014 QOS-API-015 \
QOS-API-016 QOS-API-017 QOS-API-018 QOS-API-019"
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

stop_helpers
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
