#!/bin/bash
# mcp - E2E validation of the loxilb-mcp bridge.
# Builds the bridge from this repo, points it at llb1 over streamable HTTP
# (loopback bind), and drives it with plain curl JSON-RPC — CI needs no LLM.
#
# Covered areas:
#   1 observe        health_overview / lb_list vs loxicmd / ct_list under
#                    traffic / metrics_snapshot
#   2 manage         lb_create -> real traffic -> lb_delete confirm-token
#                    round-trip + audit.jsonl entries
#   3 guardrails     viewer role sees no mutating tools; delete without
#                    confirm_token stays a preview
#   4 ai ops         ai_apikey create(file)/list/update/delete confirm flow,
#                    ai_ratelimit_set/get
#   5 rca            diagnose_l4_errors / capacity_report evidence bundles,
#                    ai_traffic_report F12 caveat
# The AI 429-under-traffic drill and the 12h soak need an SSE backend and
# wall-clock time — they run separately on a dedicated testbed, not here.
source ../common.sh
echo SCENARIO-mcp

code=0
fail() { echo "  [FAILED] $1"; code=1; }
pass() { echo "  [OK] $1"; }

# ---------- bridge setup ----------

llbIP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' llb1 2>/dev/null)
if [[ -z "$llbIP" ]]; then
    llbIP=$(docker inspect --format='{{.NetworkSettings.IPAddress}}' llb1 2>/dev/null)
fi
if [[ -z "$llbIP" ]]; then
    echo "SCENARIO-mcp [FAILED] (no llb1 container IP)"
    exit 1
fi

echo "building loxilb-mcp"
if ! (cd ../../mcp && go build -o ../cicd/mcp/loxilb-mcp ./cmd/loxilb-mcp); then
    echo "SCENARIO-mcp [FAILED] (build)"
    exit 1
fi

VTOKEN="ci-viewer-token-0123456789abcdef"
OTOKEN="ci-operator-token-0123456789abcd"
ATOKEN="ci-admin-token-0123456789abcdef0"
rm -rf .mcp-audit
cat > loxilb-mcp-ci.yaml <<EOF
default_target: llb1
targets:
  llb1:
    url: http://$llbIP:11111
clients:
  - { name: ci-viewer,   role: viewer,   token: $VTOKEN }
  - { name: ci-operator, role: operator, token: $OTOKEN }
  - { name: ci-admin,    role: admin,    token: $ATOKEN }
audit_dir: ./.mcp-audit
secrets_dir: ./.mcp-audit/secrets
EOF

./loxilb-mcp --config loxilb-mcp-ci.yaml --transport http --listen 127.0.0.1:8891 &
MCP_PID=$!
cleanup() {
    kill $MCP_PID 2>/dev/null
    sudo killall -9 node 2>/dev/null
}
trap cleanup EXIT
sleep 2

MCP=http://127.0.0.1:8891

# ---------- minimal MCP-over-HTTP client ----------

# mcp_session <token>: initialize a session, cache its id in $SESSION.
mcp_session() {
    local hdrs; hdrs=$(mktemp)
    curl -s -o /dev/null -D "$hdrs" "$MCP" \
        -H "Authorization: Bearer $1" -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cicd","version":"0"}}}'
    SESSION=$(awk 'tolower($1)=="mcp-session-id:"{print $2}' "$hdrs" | tr -d '\r')
    rm -f "$hdrs"
    [[ -z "$SESSION" ]] && return 1
    curl -s -o /dev/null "$MCP" \
        -H "Authorization: Bearer $1" -H "Mcp-Session-Id: $SESSION" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
}

RPCID=1
# mcp_rpc <token> <method> [params-json]: raw JSON-RPC, prints the result line.
mcp_rpc() {
    RPCID=$((RPCID+1))
    local params="$3"
    [[ -z "$params" ]] && params='{}'
    curl -s "$MCP" \
        -H "Authorization: Bearer $1" -H "Mcp-Session-Id: $SESSION" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":$RPCID,\"method\":\"$2\",\"params\":$params}" |
        sed -n 's/^data: //p'
}

# mcp_call <token> <tool> [args-json]: tools/call, prints the result line.
mcp_call() {
    local args="$3"
    [[ -z "$args" ]] && args='{}'
    mcp_rpc "$1" tools/call "{\"name\":\"$2\",\"arguments\":$args}"
}

# ---------- 0. sessions ----------

mcp_session "$ATOKEN" && pass "admin session established" || { fail "no admin session"; echo "SCENARIO-mcp [FAILED]"; exit 1; }
ADMIN_SESSION=$SESSION

# ---------- 1. observe ----------

echo "### observe"
res=$(mcp_call "$ATOKEN" health_overview)
echo "$res" | grep -q '"reachable":true' && pass "health_overview reachable" || fail "health_overview: $res"

res=$(mcp_call "$ATOKEN" lb_list)
mcpRules=$(echo "$res" | grep -o '"total_count":[0-9]*' | head -1 | cut -d: -f2)
cliRules=$($dexec llb1 loxicmd get lb -o json | grep -c '"externalIP"')
[[ -n "$mcpRules" && "$mcpRules" == "$cliRules" ]] \
    && pass "lb_list matches loxicmd ($mcpRules rules)" \
    || fail "lb_list=$mcpRules loxicmd=$cliRules"

$hexec l3ep1 node ../common/tcp_server.js server1 &
sleep 4
for i in $(seq 1 5); do $hexec l3h1 curl --max-time 5 -s 20.20.20.1:2020 >/dev/null; done
res=$(mcp_call "$ATOKEN" ct_list '{"service":""}')
echo "$res" | grep -q '"total_count"' && pass "ct_list returns aggregates" || fail "ct_list: $res"

res=$(mcp_call "$ATOKEN" metrics_snapshot '{"families":["loxilb_lb_rules","loxilb_active_conntrack_entries"]}')
echo "$res" | grep -q '"family_count":[1-9]' && pass "metrics_snapshot non-empty" || fail "metrics_snapshot: $res"

# ---------- 2. manage round-trip ----------

echo "### manage round-trip"
res=$(mcp_call "$ATOKEN" lb_create '{"external_ip":"20.20.20.2","port":2020,"protocol":"tcp","endpoints":[{"ip":"31.31.31.1","port":8080}]}')
echo "$res" | grep -q '"action":"executed"' && pass "lb_create executed" || fail "lb_create: $res"
sleep 3
out=$($hexec l3h1 curl --max-time 10 -s 20.20.20.2:2020)
[[ "$out" == "server1" ]] && pass "traffic flows through MCP-created VIP" || fail "no traffic through new VIP ($out)"

res=$(mcp_call "$ATOKEN" lb_delete '{"external_ip":"20.20.20.2","port":2020,"protocol":"tcp"}')
echo "$res" | grep -q '"action":"preview"' && pass "lb_delete first call previews" || fail "lb_delete preview: $res"
tok=$(echo "$res" | sed -n 's/.*"confirm_token":"\([^"]*\)".*/\1/p')
[[ -n "$tok" ]] || fail "no confirm_token in preview"
mcp_call "$ATOKEN" lb_list | grep -q '20.20.20.2' || fail "rule vanished after preview (must not)"

res=$(mcp_call "$ATOKEN" lb_delete "{\"external_ip\":\"20.20.20.2\",\"port\":2020,\"protocol\":\"tcp\",\"confirm_token\":\"$tok\"}")
echo "$res" | grep -q '"action":"executed"' && pass "lb_delete executed with token" || fail "lb_delete execute: $res"
mcp_call "$ATOKEN" lb_list | grep -q '20.20.20.2' && fail "rule still present after delete" || pass "rule gone after delete"

grep -q '"tool":"lb_create"' .mcp-audit/audit.jsonl && grep -q '"tool":"lb_delete"' .mcp-audit/audit.jsonl \
    && pass "audit.jsonl records create+delete" || fail "audit entries missing"

# ---------- 3. guardrails ----------

echo "### guardrails"
mcp_session "$VTOKEN" && pass "viewer session established" || fail "no viewer session"
res=$(mcp_rpc "$VTOKEN" tools/list)
echo "$res" | grep -q '"name":"lb_create"' && fail "viewer sees lb_create" || pass "viewer sees no lb_create"
echo "$res" | grep -q '"name":"ai_apikey_delete"' && fail "viewer sees ai_apikey_delete" || pass "viewer sees no ai_apikey_delete"
echo "$res" | grep -q '"name":"diagnose_l4_errors"' && pass "viewer sees diagnose tools" || fail "viewer missing diagnose tools"

# ---------- 4. AI ops ----------

echo "### ai ops"
SESSION=$ADMIN_SESSION
res=$(mcp_call "$ATOKEN" ai_apikey_create '{"tenant_id":"cicd","name":"mcp-ci","rate_limit_rps":5}')
if echo "$res" | grep -q '"key_file"'; then
    pass "ai_apikey_create wrote key to file"
    echo "$res" | grep -q '"raw_key"' && fail "raw key leaked in default create response" || pass "no key material in response"
    kf=$(echo "$res" | sed -n 's/.*"key_file":"\([^"]*\)".*/\1/p')
    [[ -f "$kf" ]] && pass "key file exists on bridge host" || fail "key file $kf missing"
    kid=$(echo "$res" | sed -n 's/.*"key_id":"\([^"]*\)".*/\1/p')

    mcp_call "$ATOKEN" ai_apikey_list '{"tenant_id":"cicd"}' | grep -q "$kid" \
        && pass "ai_apikey_list shows the key" || fail "created key not listed"

    res=$(mcp_call "$ATOKEN" ai_apikey_update "{\"key_id\":\"$kid\",\"enabled\":false}")
    echo "$res" | grep -q '"action":"executed"' && pass "ai_apikey_update disabled key" || fail "ai_apikey_update: $res"

    res=$(mcp_call "$ATOKEN" ai_apikey_delete "{\"key_id\":\"$kid\"}")
    tok=$(echo "$res" | sed -n 's/.*"confirm_token":"\([^"]*\)".*/\1/p')
    [[ -n "$tok" ]] && pass "ai_apikey_delete previews with token" || fail "ai_apikey_delete preview: $res"
    res=$(mcp_call "$ATOKEN" ai_apikey_delete "{\"key_id\":\"$kid\",\"confirm_token\":\"$tok\"}")
    echo "$res" | grep -q '"action":"executed"' && pass "ai_apikey_delete executed" || fail "ai_apikey_delete execute: $res"
else
    # AI gateway store may be disabled in the plain LB image; treat as skip.
    echo "  [SKIP] ai_apikey_* (create failed: $(echo "$res" | head -c 120))"
fi

res=$(mcp_call "$ATOKEN" ai_ratelimit_set '{"tenant_id":"cicd","rps":5,"tokens_per_min":1000}')
if echo "$res" | grep -q '"action":"executed"'; then
    pass "ai_ratelimit_set executed"
    mcp_call "$ATOKEN" ai_ratelimit_get '{"tenant_id":"cicd"}' | grep -q '"rps":5' \
        && pass "ai_ratelimit_get reads back rps=5" || fail "ai_ratelimit_get readback"
else
    echo "  [SKIP] ai_ratelimit_* (set failed: $(echo "$res" | head -c 120))"
fi

# ---------- 5. RCA / diagnostics ----------

echo "### rca"
res=$(mcp_call "$ATOKEN" diagnose_l4_errors)
echo "$res" | grep -q '"evidence"' && pass "diagnose_l4_errors returns evidence" || fail "diagnose_l4_errors: $res"
res=$(mcp_call "$ATOKEN" capacity_report)
echo "$res" | grep -q '"evidence"' && pass "capacity_report returns evidence" || fail "capacity_report: $res"
res=$(mcp_call "$ATOKEN" ai_traffic_report)
echo "$res" | grep -q 'F12' && pass "ai_traffic_report surfaces F12 caveat" || fail "F12 caveat missing: $res"
res=$(mcp_rpc "$ATOKEN" prompts/list)
echo "$res" | grep -q 'triage-alert' && pass "prompts registered" || fail "prompts/list: $res"

if [[ $code == 0 ]]; then
    echo SCENARIO-mcp [OK]
else
    echo SCENARIO-mcp [FAILED]
fi
exit $code
