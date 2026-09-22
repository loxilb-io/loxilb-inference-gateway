#!/bin/bash
#
# sockmap-fullproxy / validation_apikey_response.sh
#
# Validates the DIRECTIONAL eligibility split for api_key_auth services.
#
# The gate used to refuse acceleration on any service that declares api_key_auth,
# in every direction. But that declaration only owns REQUEST bytes: the credential
# is validated and X-Api-Key is stripped before dispatch, and nothing in it rewrites
# a response byte. So the refusal now follows the direction actually asked for:
#
#   sockMapMode = both | request   -> 400, naming the request direction
#   sockMapMode = response         -> accepted, with a warning that accelerated
#                                     responses are no longer recorded
#
# That is worth having because an inference response dwarfs the request that asked
# for it, so the response direction is where the copy avoidance actually pays.
#
# The scenario earns the allowance rather than assuming it. Step 5 is the one that
# matters: ONE keep-alive connection whose first request carries a valid key and
# whose later requests carry none. If the request direction were accelerated, those
# later requests would skip admission and come back 200 -- the connection's first
# request would have bought the rest a pass. They must all be 401.
#
# Self-contained: it creates its own rules and key and removes them, so it runs
# standalone once config.sh has brought the testbed up.
#
#   VIP 10.10.10.254:2042  api_key_auth=required, sockMapMode=response  (subject)
#   VIP 10.10.10.254:2043  api_key_auth=required, sockMapMode=off       (control)
#   backends 9092 / 9093, request_path_server.js -- it echoes every header the
#   backend saw, which is what makes the X-Api-Key strip observable from a client.
#
# Requires: loxilb started with --sockmapsupport, on a kernel carrying the
# sk_psock_backlog fix (see docs/sockmap-acceleration.md).

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-apikey-response"
VIP=10.10.10.254
ACCEL_PORT=2042
CTRL_PORT=2043
EP_ACCEL=9092
EP_CTRL=9093
EP_IP=31.31.31.1
EP_NS=l3ep1        # the namespace 31.31.31.1 lives in
CLIENT_NS=l3h1     # the namespace traffic is driven from
LLB=llb1
KA_REQS=6

echo "$SCENARIO"

API="http://localhost:11111/netlox/v1/config"

# POSTs a rule and echoes "<http_code>|<body>", so a step can assert on both the
# status and the message. Kept local rather than pushed into sockmap_common.sh
# because it is the only caller that needs api_key_auth and sse_mode knobs.
post_rule() {   # <port> <ep_port> <sockMapMode> <api_key_auth|""> <sse:true|false>
  local port=$1 ep_port=$2 mode=$3 akey=$4 sse=$5
  local akey_field=""
  [[ -n "$akey" ]] && akey_field="\"api_key_auth\": \"$akey\","
  local body
  body=$(cat <<EOF
{
  "serviceArguments": {
    "externalIP": "$VIP",
    "port": $port,
    "protocol": "tcp",
    "mode": 4,
    "sel": 0,
    "name": "apikey-resp-$port",
    $akey_field
    "sse_mode": $sse,
    "sockMapMode": "$mode"
  },
  "endpoints": [ {"endpointIP":"$EP_IP","targetPort":$ep_port,"weight":1} ]
}
EOF
)
  local resp
  resp=$(_sm_dexec "$LLB" curl -sS -w '\n%{http_code}' -X POST \
           -H 'Content-Type: application/json' -d "$body" "$API/loadbalancer")
  echo "$resp" >> "$SOCKMAP_ARTIFACTS_DIR/api_responses.log"
  local code=${resp##*$'\n'}
  local payload=${resp%$'\n'*}
  echo "${code}|$(echo "$payload" | tr '\n' ' ')"
}

sockmap_wait_api_ready "$LLB" || { echo "FATAL: API never became ready"; exit 1; }

echo "  -- Step 0: backends"

# request_path_server.js rather than tcp_server.js: it answers with every header the
# backend saw, which is the only way a client can tell whether the X-Api-Key strip
# survived on the requests AFTER the first one.
$hexec $EP_NS node ./request_path_server.js resp-accel "$EP_ACCEL" >/dev/null 2>&1 &
$hexec $EP_NS node ./request_path_server.js resp-ctrl  "$EP_CTRL"  >/dev/null 2>&1 &
for _ in $(seq 20); do
  a=$($hexec $CLIENT_NS curl -s --max-time 2 -o /dev/null -w '%{http_code}' "http://$EP_IP:$EP_ACCEL/" 2>/dev/null)
  b=$($hexec $CLIENT_NS curl -s --max-time 2 -o /dev/null -w '%{http_code}' "http://$EP_IP:$EP_CTRL/" 2>/dev/null)
  [[ "$a" == "200" && "$b" == "200" ]] && break
  sleep 1
done
if [[ "$a" != "200" || "$b" != "200" ]]; then
  echo "FATAL: backends did not come up ($EP_ACCEL=$a $EP_CTRL=$b)"
  sockmap_kill_tcp_servers
  exit 1
fi

echo "  -- Step 1: the gate refuses the request direction and names it"

for mode in both request; do
  out=$(post_rule "$ACCEL_PORT" "$EP_ACCEL" "$mode" required false)
  code=${out%%|*}; msg=${out#*|}
  if [[ "$code" == "400" ]] && echo "$msg" | grep -q "request direction"; then
    sockmap_result "gate: api_key_auth + $mode refused" "OK" "400, request direction"
  else
    sockmap_result "gate: api_key_auth + $mode refused" "FAILED" "HTTP $code: $msg"
  fi
done

# The allowance is api_key_auth's alone: pair it with a declaration that DOES own
# response bytes and the response direction must go back to being refused.
out=$(post_rule "$ACCEL_PORT" "$EP_ACCEL" response required true)
code=${out%%|*}
if [[ "$code" == "400" ]]; then
  sockmap_result "gate: api_key_auth + sse_mode + response refused" "OK" "400"
else
  sockmap_result "gate: api_key_auth + sse_mode + response refused" "FAILED" "HTTP $code"
fi

echo "  -- Step 2: the response direction is accepted"

out=$(post_rule "$ACCEL_PORT" "$EP_ACCEL" response required false)
code=${out%%|*}
if [[ "$code" =~ ^20 ]]; then
  sockmap_result "gate: api_key_auth + response accepted" "OK" "HTTP $code"
else
  sockmap_result "gate: api_key_auth + response accepted" "FAILED" "HTTP $code: ${out#*|}"
  echo "FATAL: the subject rule was not created, nothing below can run"
  exit 1
fi

out=$(post_rule "$CTRL_PORT" "$EP_CTRL" off required false)
[[ "${out%%|*}" =~ ^20 ]] || { echo "FATAL: control rule not created: $out"; exit 1; }

# Accepting it must say what it costs, rather than letting response accounting stop
# moving and leaving an operator to discover that from a flat graph.
if $dexec $LLB grep -q "accelerated responses are NOT recorded" /var/log/loxilb.log 2>/dev/null; then
  sockmap_result "accounting trade is logged" "OK"
else
  sockmap_result "accounting trade is logged" "FAILED" "no warning in loxilb.log"
fi

echo "  -- Step 3: the accelerated rule is in the portset, the control rule is not"

sockmap_portset_wait "$LLB" "$VIP" "$ACCEL_PORT" 10
if sockmap_portset_has "$LLB" "$VIP" "$ACCEL_PORT"; then
  sockmap_result "portset holds the response-accelerated rule" "OK"
else
  sockmap_result "portset holds the response-accelerated rule" "FAILED" "$VIP:$ACCEL_PORT absent"
fi
if sockmap_portset_has "$LLB" "$VIP" "$CTRL_PORT"; then
  sockmap_result "portset excludes the off rule" "FAILED" "$VIP:$CTRL_PORT present"
else
  sockmap_result "portset excludes the off rule" "OK"
fi

echo "  -- Step 4: a valid key is admitted, and the backend never sees it"

KEY_RESP=$($dexec $LLB curl -sS -X POST "$API/ai/apikey" \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"sockmap-tenant","name":"sockmap-resp-key"}')
RAW_KEY=$(echo "$KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
[[ -n "$RAW_KEY" ]] || { echo "FATAL: API key creation failed: $KEY_RESP"; exit 1; }

REQ_BEFORE=$(sockmap_redirect_req_count "$LLB")
RESP_BEFORE=$(sockmap_redirect_resp_count "$LLB")
DROP_BEFORE=$(sockmap_redirect_drop_count "$LLB")
MISS_BEFORE=$(sockmap_peer_miss_count "$LLB")

specs=(); for ((i = 0; i < KA_REQS; i++)); do specs+=("key:$RAW_KEY"); done
happy=$($hexec $CLIENT_NS python3 ./apikey_ka_client.py "$VIP" "$ACCEL_PORT" "${specs[@]}")
echo "$happy" > "$SOCKMAP_ARTIFACTS_DIR/apikey_happy_path.jsonl"

n_200=$(echo "$happy" | grep -c '"status": 200')
if [[ "$n_200" == "$KA_REQS" ]]; then
  sockmap_result "valid key: all $KA_REQS requests admitted" "OK"
else
  sockmap_result "valid key: all $KA_REQS requests admitted" "FAILED" "$n_200/$KA_REQS were 200"
fi

# The strip is the other half of what the credential declaration owns. It happens on
# the request path, which is still relayed, so it must hold for every request of the
# connection -- not just the first.
if echo "$happy" | grep -q '"backend_saw_key": true'; then
  sockmap_result "X-Api-Key stripped on every request" "FAILED" "a backend echo contained the key"
else
  sockmap_result "X-Api-Key stripped on every request" "OK"
fi

if echo "$happy" | grep -q '"reused": true'; then
  sockmap_result "the $KA_REQS requests shared one connection" "OK"
else
  sockmap_result "the $KA_REQS requests shared one connection" "FAILED" "client reconnected, result is meaningless"
fi

echo "  -- Step 5: request 1's credential does NOT buy the connection a pass"

# The attack the response-only allowance has to survive, and the one an "authenticate
# once then offload" design would fail: valid key first, nothing afterwards.
specs=("key:$RAW_KEY"); for ((i = 1; i < KA_REQS; i++)); do specs+=("none"); done
tofu=$($hexec $CLIENT_NS python3 ./apikey_ka_client.py "$VIP" "$ACCEL_PORT" "${specs[@]}")
echo "$tofu" > "$SOCKMAP_ARTIFACTS_DIR/apikey_tofu.jsonl"

first=$(echo "$tofu" | head -1 | python3 -c "import sys,json; print(json.loads(sys.stdin.readline())['status'])" 2>/dev/null)
later_200=$(echo "$tofu" | grep '"i": [1-9]' | grep -c '"status": 200')
later_401=$(echo "$tofu" | grep '"i": [1-9]' | grep -c '"status": 401')

if [[ "$first" == "200" ]]; then
  sockmap_result "keyed first request admitted" "OK"
else
  sockmap_result "keyed first request admitted" "FAILED" "status $first"
fi
if [[ "$later_200" == "0" && "$later_401" == "$((KA_REQS - 1))" ]]; then
  sockmap_result "later unkeyed requests all refused" "OK" "$later_401 x 401"
else
  sockmap_result "later unkeyed requests all refused" "FAILED" \
    "$later_200 admitted without a credential -- the request direction skipped admission"
fi

echo "  -- Step 6: only the response direction was redirected"

REQ_DELTA=$(( $(sockmap_redirect_req_count "$LLB") - REQ_BEFORE ))
RESP_DELTA=$(( $(sockmap_redirect_resp_count "$LLB") - RESP_BEFORE ))
MISS_DELTA=$(( $(sockmap_peer_miss_count "$LLB") - MISS_BEFORE ))

if [[ "$RESP_DELTA" -gt 0 ]]; then
  sockmap_result "response direction accelerated" "OK" "+$RESP_DELTA"
else
  sockmap_result "response direction accelerated" "FAILED" "no response redirect"
fi
if [[ "$REQ_DELTA" -eq 0 ]]; then
  sockmap_result "request direction never accelerated" "OK"
else
  sockmap_result "request direction never accelerated" "FAILED" \
    "+$REQ_DELTA -- requests bypassed the relay that enforces the credential"
fi
if [[ "$MISS_DELTA" -eq 0 ]]; then
  sockmap_result "no peer_miss" "OK"
else
  sockmap_result "no peer_miss" "FAILED" "+$MISS_DELTA"
fi
sockmap_assert_no_redirect_drop "$LLB" "$DROP_BEFORE"

echo "  -- Step 7: cleanup"

sockmap_delete_lb_via_api "$LLB" "$VIP" "$ACCEL_PORT"
sockmap_delete_lb_via_api "$LLB" "$VIP" "$CTRL_PORT"
sockmap_kill_tcp_servers

if [[ "$SOCKMAP_FAIL_COUNT" -eq 0 ]]; then
  echo "$SCENARIO [OK]"
  exit 0
fi
echo "$SCENARIO [FAILED] ($SOCKMAP_FAIL_COUNT)"
exit 1
