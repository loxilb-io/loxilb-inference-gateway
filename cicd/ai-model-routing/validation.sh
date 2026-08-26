#!/bin/bash
# Validates AI model-name based routing.
# Model routing is wired via find_endpoint_lpm in sockproxy.c.
# X-Model header OR JSON body "model" field triggers per-model pool selection.

source ../common.sh
echo SCENARIO-ai-model-routing
code=0

check() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == *"$want"* ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAILED] — expected '$want', got: '$got'"
    code=1
  fi
}

# ── Start mock backends ───────────────────────────────────────────────────────
$hexec l3ep1 node ../common/tcp_server.js server-llama   &
$hexec l3ep2 node ../common/tcp_server.js server-mistral &
$hexec l3ep3 node ../common/tcp_server.js server-wild    &
sleep 4

# ── T1: X-Model header → llama-70b pool ─────────────────────────────────────
echo ""
echo "T1: X-Model header routes to llama-70b pool"
r=$($hexec l3h1 curl -s --max-time 8 \
  -H "X-Model: llama-70b" \
  http://10.10.10.254:2020/)
check "llama pool via X-Model" "server-llama" "$r"

# ── T2: JSON body model field → mistral-7b pool ─────────────────────────────
echo ""
echo "T2: JSON body 'model' field routes to mistral-7b pool"
r=$($hexec l3h1 curl -s --max-time 8 -X POST \
  -H "Content-Type: application/json" \
  -d '{"model":"mistral-7b","messages":[{"role":"user","content":"hi"}]}' \
  http://10.10.10.254:2021/)
check "mistral pool via JSON body" "server-mistral" "$r"

# ── T3: No model → wildcard pool ────────────────────────────────────────────
echo ""
echo "T3: No model header/body → wildcard pool"
r=$($hexec l3h1 curl -s --max-time 8 http://10.10.10.254:2022/)
check "wildcard pool, no model" "server-wild" "$r"

# ── T4: Unknown model → 503 + model_unavailable body ────────────────────────
echo ""
echo "T4: Unknown model on port with no wildcard → 503 + model_unavailable"
r=$($hexec l3h1 curl -s --max-time 8 -w "\n%{http_code}" \
  -H "X-Model: unknown-xyz" \
  http://10.10.10.254:2020/)
body=$(echo "$r" | sed '$d')
http_code=$(echo "$r" | tail -n1)
check "unknown model returns 503" "503" "$http_code"
check "body contains model_unavailable" "model_unavailable" "$body"

# ── T5: X-Model overrides JSON body model ────────────────────────────────────
echo ""
echo "T5: X-Model header overrides JSON body model field"
r=$($hexec l3h1 curl -s --max-time 8 -X POST \
  -H "Content-Type: application/json" \
  -H "X-Model: llama-70b" \
  -d '{"model":"mistral-7b","messages":[{"role":"user","content":"hi"}]}' \
  http://10.10.10.254:2020/)
check "X-Model overrides JSON body" "server-llama" "$r"

# ── T6: Concurrent requests reach separate backends ──────────────────────────
echo ""
echo "T6: Concurrent requests reach separate backends"
$hexec l3h1 curl -s --max-time 8 -H "X-Model: llama-70b" \
  http://10.10.10.254:2020/ > /tmp/t6_llama 2>/dev/null &
pid1=$!
$hexec l3h1 curl -s --max-time 8 -H "X-Model: mistral-7b" \
  http://10.10.10.254:2021/ > /tmp/t6_mistral 2>/dev/null &
pid2=$!
$hexec l3h1 curl -s --max-time 8 \
  http://10.10.10.254:2022/ > /tmp/t6_wild 2>/dev/null &
pid3=$!
wait $pid1 $pid2 $pid3
r_llama=$(cat /tmp/t6_llama 2>/dev/null)
r_mistral=$(cat /tmp/t6_mistral 2>/dev/null)
r_wild=$(cat /tmp/t6_wild 2>/dev/null)
check "concurrent llama"   "server-llama"   "$r_llama"
check "concurrent mistral" "server-mistral" "$r_mistral"
check "concurrent wild"    "server-wild"    "$r_wild"
rm -f /tmp/t6_llama /tmp/t6_mistral /tmp/t6_wild

# ── T7: Empty X-Model + no JSON model → wildcard pool ───────────────────────
echo ""
echo "T7: Empty X-Model + no JSON model → wildcard pool"
r=$($hexec l3h1 curl -s --max-time 8 \
  -H "X-Model: " \
  http://10.10.10.254:2022/)
check "empty X-Model falls to wildcard" "server-wild" "$r"

# ── T8: Delete llama-70b rule → 503 or connection refused ─────────────────
echo ""
echo "T8: Delete llama-70b rule → subsequent request fails (503 or conn refused)"
$hexec l3h1 curl -s -X DELETE \
  "http://10.10.10.254:11111/netlox/v1/config/loadbalancer/hosturl/10.10.10.254/externalipaddress/10.10.10.254/port/2020/protocol/tcp?path_prefix=/&path_match_mode=prefix&model_name=llama-70b" \
  >/dev/null 2>&1
sleep 2
r=$($hexec l3h1 curl -s --max-time 8 -w "\n%{http_code}" \
  -H "X-Model: llama-70b" \
  http://10.10.10.254:2020/)
http_code=$(echo "$r" | tail -n1)
# After deleting the last rule on a port, the proxy returns 503 (no matching
# rule) or 404. curl 000 (connection refused / no response) is treated as a
# test failure — it indicates the VIP socket closed before returning a clean
# HTTP response, which is unexpected.
if [[ "$http_code" == "503" ]] || [[ "$http_code" == "404" ]]; then
  echo "  post-delete returns $http_code [OK]"
else
  echo "  post-delete returns $http_code [FAILED] — expected 503 or 404"
  code=1
fi

# Restore the port 2020 llama-70b rule that this test just deleted. The later
# GET-roundtrip check (validate_cli.sh API-T1a) asserts config.sh's port 2020
# rule still exists with model_name=llama-70b, so we must put it back — same
# pattern as the mTLS suite's delete-then-restore API tests.
$hexec l3h1 curl -s -o /dev/null -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":     "10.10.10.254",
      "port":            2020,
      "protocol":       "tcp",
      "sel":             0,
      "mode":            4,
      "host":           "10.10.10.254",
      "path_prefix":    "/",
      "path_match_mode": "prefix",
      "model_name":     "llama-70b",
      "inactiveTimeOut": 30
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}
    ]
  }'
sleep 1

# ── T9: model_name with '/' → clean error (not 500) ─────────────────────────
echo ""
echo "T9: model_name with '/' routes cleanly — no internal error (not 500)"
res9=$($hexec l3h1 curl -s --max-time 8 -o /dev/null -w "%{http_code}" -X POST \
  http://10.10.10.254:2021/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Model: llama/3.1" \
  -d '{"model":"llama/3.1","messages":[{"role":"user","content":"hi"}]}')
# Port 2021 has model_name=mistral-7b; llama/3.1 matches no rule → 503.
# Accept 200 (routed), 404 (no rule match), or 503 (routing miss).
# Reject 500 (internal server error = routing key corruption from slash char).
if [[ "$res9" == "200" || "$res9" == "404" || "$res9" == "503" ]]; then
  echo "  T9: slash-in-model-name → $res9 (no internal error) [OK]"
else
  echo "  T9: slash-in-model-name → $res9 (UNEXPECTED — possible key corruption) [FAILED]"
  code=1
fi

# ── T10: model name wrong case → routing miss (case-sensitive) ───────────────
echo ""
echo "T10: model name wrong case (MISTRAL-7B) → routing miss (case-sensitive)"
res10=$($hexec l3h1 curl -s --max-time 8 -o /dev/null -w "%{http_code}" -X POST \
  http://10.10.10.254:2021/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Model: MISTRAL-7B" \
  -d '{"model":"MISTRAL-7B","messages":[{"role":"user","content":"hi"}]}')
# Port 2021 rule uses model_name=mistral-7b (lowercase).
# loxilb routing is definitively case-sensitive (design decision).
# A wrong-case header MUST miss — accept anything except 200 as correct.
if [[ "$res10" != "200" ]]; then
  echo "  T10: wrong-case model rejected → $res10 [OK]"
else
  echo "  T10: wrong-case model ACCEPTED → $res10 [FAILED — routing must be case-sensitive]"
  code=1
fi

# ── T11: Combined auth+routing — SKIP (no --userservice in this scenario) ──
echo ""
echo "T11: Combined auth+routing test"
echo "  T11: [SKIP] This scenario does not start loxilb with --userservice."
echo "  T11: Combined auth+routing (key restricted to model X, request X-Model: Y → 403)"
echo "  T11: is covered by the ai-apikey scenario where --userservice is active."

# ── T12: delete by full L7 key — model_name selects the rule ─────────────────
# The rule key includes model_name, so a delete has to name it; a delete that
# omits it matches only the model-less rule on the same VIP:port. Both rules
# point at server-llama so the survivor can be shown to still serve.
echo ""
echo "T12: L7-keyed rule delete (two rules on one VIP:port, port 2040)"
API=http://10.10.10.254:11111/netlox/v1
check_eq() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAILED] — expected '$want', got '$got'"
    code=1
  fi
}
mk_l7() { # <model_name or empty> -> http code
  $hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X POST "$API/config/loadbalancer" \
    -H "Content-Type: application/json" -d '{
      "serviceArguments": {
        "externalIP": "10.10.10.254", "port": 2040, "protocol": "tcp", "sel": 0, "mode": 4,
        "host": "10.10.10.254", "path_prefix": "/", "path_match_mode": "prefix",
        "model_name": "'"$1"'", "inactiveTimeOut": 30
      },
      "endpoints": [{"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}]
    }'
}
del_l7() { # <query string> -> http code
  $hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
    "$API/config/loadbalancer/hosturl/10.10.10.254/externalipaddress/10.10.10.254/port/2040/protocol/tcp?$1"
}
models_2040() { # sorted model names of the rules on port 2040; "-" = no model
  $hexec l3h1 curl -s "$API/config/loadbalancer/all" | python3 -c '
import sys, json
d = json.load(sys.stdin)
print(",".join(sorted((r["serviceArguments"].get("model_name") or "-")
      for r in d.get("lbAttr", []) if int(r["serviceArguments"].get("port", -1)) == 2040)))'
}
check_eq "T12a create model-keyed rule (qwen-test)" "200" "$(mk_l7 qwen-test)"
check_eq "T12a create model-less rule on the same VIP:port" "200" "$(mk_l7 '')"
sleep 1
check_eq "T12a both rules present" "-,qwen-test" "$(models_2040)"
check_eq "T12b delete without model_name" "200" "$(del_l7 'path_prefix=%2F&path_match_mode=prefix')"
check_eq "T12b only the model-less rule was removed" "qwen-test" "$(models_2040)"
r=$($hexec l3h1 curl -s --max-time 8 -H "X-Model: qwen-test" http://10.10.10.254:2040/)
check "T12b surviving model-keyed rule still serves" "server-llama" "$r"
check_eq "T12c delete naming a model no rule carries -> 404" "404" "$(del_l7 'path_prefix=%2F&path_match_mode=prefix&model_name=no-such-model')"
check_eq "T12c rule untouched by that delete" "qwen-test" "$(models_2040)"
check_eq "T12d delete naming the model" "200" "$(del_l7 'path_prefix=%2F&path_match_mode=prefix&model_name=qwen-test')"
check_eq "T12d no rule left on port 2040" "" "$(models_2040)"

# ── Cleanup ──────────────────────────────────────────────────────────────────
sudo killall -9 node 2>/dev/null

# ── CLI (REST API) Validation (T-CLI-1 through T-CLI-7) ──────────────────────
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
  echo "SCENARIO-ai-model-routing [OK]"
else
  echo "SCENARIO-ai-model-routing [FAILED]"
fi
exit $code
