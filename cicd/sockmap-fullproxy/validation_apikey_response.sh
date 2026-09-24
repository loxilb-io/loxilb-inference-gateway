#!/bin/bash
#
# sockmap-fullproxy / validation_apikey_response.sh
#
# The DIRECTIONAL eligibility split for api_key_auth services, end to end.
#
# A declared api_key_auth owns the REQUEST direction: the credential is validated
# and X-Api-Key is stripped before dispatch, on every request of a keep-alive
# connection. It rewrites no response byte. So the control plane refuses both and
# request naming the request direction, and accepts response with a warning that
# accelerated responses are not recorded. The data plane pairs the connection the
# same way: only the backend socket is handed to the kernel, so responses are
# redirected to the client while every request keeps arriving in userspace for
# admission. That is where the acceleration pays: an inference response dwarfs
# the request that asked for it.
#
#   sockMapMode = both | request   -> 400, naming the request direction
#   sockMapMode = response         -> accepted; responses redirected, requests relayed
#
# The suite earns the allowance rather than assuming it. Step 5 is the one that
# matters: ONE keep-alive connection whose first request carries a valid key and
# whose later requests carry none. If the request direction were accelerated,
# those later requests would skip admission and come back 200. Step 6 is the
# other half: the response counter of the subject must MOVE, or the accepted
# mode is a readback with nothing behind it.
#
# Self-contained: it creates its own rules and key and removes them, so it runs
# standalone once config.sh has brought the testbed up.
#
#   VIP 10.10.10.254:2042  api_key_auth=required, sockMapMode=response  (subject)
#   VIP 10.10.10.254:2043  api_key_auth=required, sockMapMode=off       (control)
#   backends 9092 / 9093, request_path_server.js -- it echoes every header the
#   backend saw, which is what makes the X-Api-Key strip observable from a client.
#
# Requires: loxilb started with --sockmapsupport AND the testbed's API-key store
# (SOCKMAP_AI_KEY_STORE=1 ./config.sh). Without the store the key of Step 4 cannot
# be created, and the suite refuses to start rather than run three steps and
# stop. The subject's responses ARE accelerated, so the kernel requirement in
# docs/sockmap-acceleration.md applies; the echoes here are a few hundred bytes.

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
CTRL_REQS=3

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
  body=$(cat <<JSON
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
JSON
)
  local resp
  resp=$(_sm_dexec "$LLB" curl -sS -w '\n%{http_code}' -X POST \
           -H 'Content-Type: application/json' -d "$body" "$API/loadbalancer")
  echo "$resp" >> "$SOCKMAP_ARTIFACTS_DIR/api_responses.log"
  local code=${resp##*$'\n'}
  local payload=${resp%$'\n'*}
  echo "${code}|$(echo "$payload" | tr '\n' ' ')"
}

# The sockMapMode the readback reports for a rule ("off" when the field is
# omitted, "" when the rule is absent). Read through python: a shell pattern
# cannot tell one rule's field from its neighbour's.
rule_mode() {   # <port>
  _sm_dexec "$LLB" curl -s "$API/loadbalancer/all" | python3 -c '
import json, sys
port = int(sys.argv[1])
try:
    rules = json.load(sys.stdin).get("lbAttr", [])
except ValueError:
    rules = []
for r in rules:
    sa = r.get("serviceArguments", {})
    if sa.get("externalIP") == "10.10.10.254" and sa.get("port") == port and sa.get("protocol") == "tcp":
        print(sa.get("sockMapMode") or "off")
        break
' "$1" 2>/dev/null
}

# One field of the client summary line.
ka_field() {    # <jsonl> <field>
  printf '%s\n' "$1" | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        d = json.loads(line)
    except ValueError:
        continue
    if d.get("summary"):
        print(d.get(sys.argv[1], ""))
' "$2" 2>/dev/null
}

# Requests of a run whose status is <code>; with a third argument, only those
# with i >= that index.
ka_count_status() {   # <jsonl> <code> [<from_i>]
  printf '%s\n' "$1" | python3 -c '
import json, sys
code = int(sys.argv[1]); start = int(sys.argv[2]) if len(sys.argv) > 2 else 0
n = 0
for line in sys.stdin:
    try:
        d = json.loads(line)
    except ValueError:
        continue
    if d.get("summary") or d.get("i", -1) < start:
        continue
    if d.get("status") == code:
        n += 1
print(n)
' "$2" "${3:-0}" 2>/dev/null
}

# Requests of a run that were 200 AND whose backend echo was parsed and did NOT
# contain the key. A null (unparsable echo) does not count: the strip is proven
# per echo, never assumed from silence.
ka_count_stripped() {   # <jsonl>
  printf '%s\n' "$1" | python3 -c '
import json, sys
n = 0
for line in sys.stdin:
    try:
        d = json.loads(line)
    except ValueError:
        continue
    if d.get("summary"):
        continue
    if d.get("status") == 200 and d.get("backend_saw_key") is False:
        n += 1
print(n)
' 2>/dev/null
}

sockmap_wait_api_ready "$LLB" || { echo "FATAL: API never became ready"; exit 1; }

# The store is a precondition of the whole suite, not of Step 4 alone: the gate
# steps before it are only half the contract, and a run that stops at the key
# would leave them reading as a pass. So the store is probed at the door and its
# absence is FATAL, named after the knob that supplies it. No RESULT line is
# printed on this path, so a workflow step goes red.
store_probe=$(_sm_dexec "$LLB" curl -s -o /dev/null -w '%{http_code}' \
                "$API/ai/apikey?tenant_id=sockmap-probe" | tail -c 3)
if [[ "$store_probe" != "200" ]]; then
  echo "FATAL: no usable API-key store behind $LLB (GET $API/ai/apikey answered HTTP ${store_probe:-none})."
  echo "       This suite creates a key. Bring the testbed up with: SOCKMAP_AI_KEY_STORE=1 ./config.sh"
  exit 1
fi

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
  if [[ "$code" == "400" ]] && echo "$msg" | grep -q "refused for the request direction"; then
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

# Nothing above may have created a rule.
if [[ -z "$(rule_mode "$ACCEL_PORT")" ]]; then
  sockmap_result "a refused POST created no rule" "OK"
else
  sockmap_result "a refused POST created no rule" "FAILED" "rule $VIP:$ACCEL_PORT exists with mode $(rule_mode "$ACCEL_PORT")"
fi

echo "  -- Step 2: the response direction is accepted"

out=$(post_rule "$ACCEL_PORT" "$EP_ACCEL" response required false)
code=${out%%|*}
if [[ "$code" =~ ^20 ]]; then
  sockmap_result "gate: api_key_auth + response accepted" "OK" "HTTP $code"
else
  sockmap_result "gate: api_key_auth + response accepted" "FAILED" "HTTP $code: ${out#*|}"
  echo "FATAL: the subject rule was not created, nothing below can run"
  sockmap_kill_tcp_servers
  exit 1
fi

out=$(post_rule "$CTRL_PORT" "$EP_CTRL" off required false)
[[ "${out%%|*}" =~ ^20 ]] || { echo "FATAL: control rule not created: $out"; sockmap_kill_tcp_servers; exit 1; }

got_mode=$(rule_mode "$ACCEL_PORT")
if [[ "$got_mode" == "response" ]]; then
  sockmap_result "readback: the subject rule holds response" "OK"
else
  sockmap_result "readback: the subject rule holds response" "FAILED" "sockMapMode=$got_mode"
fi

# Accepting it must say what it costs, rather than letting response accounting stop
# moving and leaving an operator to discover that from a flat graph. The log is
# read through the helper that knows where the daemon writes it; a presence
# check against a file that does not exist can only ever fail, but the same
# mistake in an absence check passes for nothing, so the source is asserted
# non-empty first and the line count travels with the verdict.
gw_log=$(sockmap_gateway_log "$LLB")
gw_log_lines=$(printf '%s\n' "$gw_log" | grep -c .)
if [[ "$gw_log_lines" -eq 0 ]]; then
  sockmap_result "accounting trade is logged" "FAILED" "gateway log unreadable: 0 lines from docker logs + /var/log/loxilb*.log"
elif printf '%s\n' "$gw_log" | grep -q "accelerated responses are NOT recorded"; then
  sockmap_result "accounting trade is logged" "OK" "$gw_log_lines log lines read"
else
  sockmap_result "accounting trade is logged" "FAILED" "no acceptance warning in $gw_log_lines log lines"
fi

echo "  -- Step 3: the accelerated rule is in the portset, the control rule is not"

sockmap_portset_wait "$LLB" "$SOCKMAP_VIP_NAME" "$ACCEL_PORT" present 20 "$VIP"
if sockmap_portset_has "$LLB" "$SOCKMAP_VIP_NAME" "$ACCEL_PORT" "$VIP"; then
  sockmap_result "portset holds the response-accelerated rule" "OK"
else
  sockmap_result "portset holds the response-accelerated rule" "FAILED" "$VIP:$ACCEL_PORT absent"
fi
if sockmap_portset_has "$LLB" "$SOCKMAP_VIP_NAME" "$CTRL_PORT" "$VIP"; then
  sockmap_result "portset excludes the off rule" "FAILED" "$VIP:$CTRL_PORT present"
else
  sockmap_result "portset excludes the off rule" "OK"
fi

echo "  -- Step 4: a valid key is admitted on every request, and the backend never sees it"

KEY_RESP=$($dexec $LLB curl -sS -w '\n%{http_code}' -X POST "$API/ai/apikey" \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"sockmap-tenant","name":"sockmap-resp-key"}')
KEY_CODE=${KEY_RESP##*$'\n'}
RAW_KEY=$(printf '%s' "${KEY_RESP%$'\n'*}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
if [[ "$KEY_CODE" != "201" || -z "$RAW_KEY" ]]; then
  echo "FATAL: API key creation failed (HTTP $KEY_CODE): ${KEY_RESP%$'\n'*}"
  sockmap_kill_tcp_servers
  exit 1
fi

REQ_BEFORE=$(sockmap_redirect_req_count "$LLB")
RESP_BEFORE=$(sockmap_redirect_resp_count "$LLB")
DROP_BEFORE=$(sockmap_redirect_drop_count "$LLB")
MISS_BEFORE=$(sockmap_peer_miss_count "$LLB")

specs=(); for ((i = 0; i < KA_REQS; i++)); do specs+=("key:$RAW_KEY"); done
happy=$($hexec $CLIENT_NS python3 ./apikey_ka_client.py "$VIP" "$ACCEL_PORT" "${specs[@]}")
echo "$happy" > "$SOCKMAP_ARTIFACTS_DIR/apikey_happy_path.jsonl"

h_done=$(ka_field "$happy" completed)
h_200=$(ka_count_status "$happy" 200)
h_conns=$(ka_field "$happy" connections)
h_stripped=$(ka_count_stripped "$happy")

if [[ "$h_done" == "$KA_REQS" && "$h_200" == "$KA_REQS" ]]; then
  sockmap_result "valid key: all $KA_REQS requests answered 200" "OK"
else
  sockmap_result "valid key: all $KA_REQS requests answered 200" "FAILED" "completed=${h_done:-?} 200s=${h_200:-?}"
fi

# Keep-alive is intact with the response direction in the kernel: one connection
# carried them all. A reconnect here would mean a redirected response ended the
# connection, and the strip and admission results below would be meaningless.
if [[ "$h_conns" == "1" ]]; then
  sockmap_result "the $KA_REQS admitted requests shared one connection" "OK"
else
  sockmap_result "the $KA_REQS admitted requests shared one connection" "FAILED" "connections=${h_conns:-?}"
fi

# The strip is the other half of what the credential declaration owns. It happens
# on the request path, which is still relayed, so it must hold for every request
# of the connection -- not just the first. Proven per echo: every 200 must carry a
# parsed echo that lacks the key; an echo that could not be parsed proves nothing.
if [[ "$h_stripped" == "$KA_REQS" ]]; then
  sockmap_result "X-Api-Key stripped on every request (parsed per echo)" "OK" "$h_stripped/$KA_REQS"
else
  sockmap_result "X-Api-Key stripped on every request (parsed per echo)" "FAILED" "$h_stripped/$KA_REQS echoes proved the strip"
fi

echo "  -- Step 5: request 1's credential does NOT buy the connection a pass"

# The attack the response-only allowance has to survive, and the one an
# "authenticate once then offload" design would fail: valid key first, nothing
# afterwards. Every later request must be refused on its own; a refusal is
# answered by the gateway with Connection: close, so each later denial costs the
# client a reconnect, and the count of those is asserted rather than hidden.
specs=("key:$RAW_KEY"); for ((i = 1; i < KA_REQS; i++)); do specs+=("none"); done
tofu=$($hexec $CLIENT_NS python3 ./apikey_ka_client.py "$VIP" "$ACCEL_PORT" "${specs[@]}")
echo "$tofu" > "$SOCKMAP_ARTIFACTS_DIR/apikey_tofu.jsonl"

t_done=$(ka_field "$tofu" completed)
t_first=$(printf '%s\n' "$tofu" | head -1 | python3 -c "import sys,json; print(json.loads(sys.stdin.readline()).get('status'))" 2>/dev/null)
t_later_200=$(ka_count_status "$tofu" 200 1)
t_later_401=$(ka_count_status "$tofu" 401 1)
t_closed=$(ka_field "$tofu" closed_by_server)
t_conns=$(ka_field "$tofu" connections)

if [[ "$t_done" == "$KA_REQS" ]]; then
  sockmap_result "every request of the mixed run drew a response" "OK"
else
  sockmap_result "every request of the mixed run drew a response" "FAILED" "completed=${t_done:-?}/$KA_REQS"
fi
if [[ "$t_first" == "200" ]]; then
  sockmap_result "keyed first request admitted" "OK"
else
  sockmap_result "keyed first request admitted" "FAILED" "status $t_first"
fi
if [[ "$t_later_200" == "0" && "$t_later_401" == "$((KA_REQS - 1))" ]]; then
  sockmap_result "later unkeyed requests all refused" "OK" "$t_later_401 x 401"
else
  sockmap_result "later unkeyed requests all refused" "FAILED" \
    "$t_later_200 admitted without a credential -- the request direction skipped admission"
fi
# A denial ends the connection and the next request opens a new one. The first
# denial rides the connection the admitted request left open, so N-1 denials
# are N-1 closes over N-1 connections: one fewer connection than requests, and
# not one per request. The lazy client reports that count as it is.
if [[ "$t_closed" == "$((KA_REQS - 1))" && "$t_conns" == "$((KA_REQS - 1))" ]]; then
  sockmap_result "each denial closed the connection, each next request reconnected" "OK" "closed=$t_closed connections=$t_conns"
else
  sockmap_result "each denial closed the connection, each next request reconnected" "FAILED" "closed=${t_closed:-?} connections=${t_conns:-?}"
fi

echo "  -- Step 6: only the response direction was redirected"

REQ_DELTA=$(( $(sockmap_redirect_req_count "$LLB") - REQ_BEFORE ))
RESP_DELTA=$(( $(sockmap_redirect_resp_count "$LLB") - RESP_BEFORE ))
MISS_DELTA=$(( $(sockmap_peer_miss_count "$LLB") - MISS_BEFORE ))

# The accepted mode has to be more than a readback: the subject's responses went
# through the kernel, so this counter moved.
if [[ "$RESP_DELTA" -gt 0 ]]; then
  sockmap_result "response direction accelerated" "OK" "+$RESP_DELTA"
else
  sockmap_result "response direction accelerated" "FAILED" "no response redirect -- the mode was accepted and nothing was paired"
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
sockmap_assert_no_redirect_drop "$LLB" "$DROP_BEFORE" "no redirect was refused"

# The control rule holds the same credential with acceleration off: its traffic
# must move neither counter, so the deltas above belong to the subject alone.
CREQ_BEFORE=$(sockmap_redirect_req_count "$LLB")
CRESP_BEFORE=$(sockmap_redirect_resp_count "$LLB")
ctrl_ok=0
for ((i = 0; i < CTRL_REQS; i++)); do
  c=$($hexec $CLIENT_NS curl -s --max-time 5 -o /dev/null -w '%{http_code}' -H "X-Api-Key: $RAW_KEY" "http://$VIP:$CTRL_PORT/echo" 2>/dev/null)
  [[ "$c" == "200" ]] && ctrl_ok=$((ctrl_ok + 1))
done
sleep 1
CREQ_DELTA=$(( $(sockmap_redirect_req_count "$LLB") - CREQ_BEFORE ))
CRESP_DELTA=$(( $(sockmap_redirect_resp_count "$LLB") - CRESP_BEFORE ))
if [[ "$ctrl_ok" == "$CTRL_REQS" ]]; then
  sockmap_result "control (off): all $CTRL_REQS keyed requests answered 200" "OK"
else
  sockmap_result "control (off): all $CTRL_REQS keyed requests answered 200" "FAILED" "$ctrl_ok/$CTRL_REQS"
fi
if [[ "$CREQ_DELTA" -eq 0 && "$CRESP_DELTA" -eq 0 ]]; then
  sockmap_result "control (off): nothing redirected in either direction" "OK"
else
  sockmap_result "control (off): nothing redirected in either direction" "FAILED" "req +$CREQ_DELTA resp +$CRESP_DELTA"
fi

echo "  -- Step 7: cleanup"

sockmap_delete_lb_via_api "$LLB" "$VIP" "$ACCEL_PORT"
sockmap_delete_lb_via_api "$LLB" "$VIP" "$CTRL_PORT"
sockmap_kill_tcp_servers

sockmap_finalize "$SCENARIO"
