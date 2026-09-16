#!/bin/bash
#
# sockmap-fullproxy / validation.sh
#
# Validation scenario:
#   1. the sockmap BPF assets exist at boot time
#   2. R1 (sockmap on, vip 2020) is registered in vip_portset
#   3. R2 (sockmap off, vip 2021) is not registered in vip_portset
#   4. HTTP traffic through R1: responses are correct, load is distributed, and
#      sock_proxy_map entries increase
#   5. HTTP traffic through R2: responses are correct and sock_proxy_map does not grow
#   6. docker logs contain no sockmap failure messages
#   7. after deleting R1, port 2020 is removed from vip_portset
#   8. a service whose data plane touches request bytes refuses a sockMapMode
#      other than off: sse_mode, pd_disagg_mode, and ANY api_key_auth declaration
#      including an explicit "disabled" (R-1..R-8), while an omitted api_key_auth
#      stays accelerable (R-16)
#   9. an L7 policy and a sockMapMode are mutually exclusive in both attach
#      orders (R-10..R-13)

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy"
TOTAL_REQ=8
server1_pid=""
server2_pid=""

cleanup_backend_servers() {
  sockmap_kill_tcp_servers
  if [[ -n "$server1_pid" ]]; then
    wait "$server1_pid" 2>/dev/null || true
  fi
  if [[ -n "$server2_pid" ]]; then
    wait "$server2_pid" 2>/dev/null || true
  fi
}

trap cleanup_backend_servers EXIT

echo "================ $SCENARIO ================"

# ---------- Step 1: boot-time assets ----------
sockmap_section 1 "Daemon boot assets"

if sockmap_assert_bpf_assets llb1; then
  sockmap_result "sockops prog + 6 sockmap maps attached" "OK"
else
  sockmap_result "sockops prog + 6 sockmap maps attached" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (bootstrap)"
  exit 1
fi

# ---------- Step 2/3: portset registration ----------
sockmap_section 2 "Per-rule portset state"

if sockmap_portset_has llb1 "$SOCKMAP_VIP_NAME" 2020; then
  sockmap_result "R1 vip 2020 in sockmap_vip_portset"   "OK"
else
  sockmap_result "R1 vip 2020 in sockmap_vip_portset"   "FAILED"
fi

if sockmap_portset_has llb1 "$SOCKMAP_VIP_NAME" 2021; then
  sockmap_result "R2 vip 2021 NOT in sockmap_vip_portset" "FAILED" "leaked into portset"
else
  sockmap_result "R2 vip 2021 NOT in sockmap_vip_portset" "OK"
fi

if sockmap_portset_has llb1 "$SOCKMAP_EP_NAME" 8080; then
  sockmap_result "R1 endpoint port 8080 in sockmap_ep_portset" "OK"
else
  sockmap_result "R1 endpoint port 8080 in sockmap_ep_portset" "FAILED"
fi

# ---------- Step 4 prep: start backend servers ----------
sockmap_section 3 "Start backend HTTP servers"

$hexec l3ep1 node ../common/tcp_server.js server1 &
server1_pid=$!
$hexec l3ep2 node ../common/tcp_server.js server2 &
server2_pid=$!

# Wait for the servers to be ready, checked directly on 8080
sleep 3
ready=0
for i in $(seq 1 15); do
  r1=$($hexec l3h1 curl --max-time 3 -s http://31.31.31.1:8080/ 2>/dev/null || true)
  r2=$($hexec l3h1 curl --max-time 3 -s http://32.32.32.1:8080/ 2>/dev/null || true)
  if [[ "$r1" == "server1" && "$r2" == "server2" ]]; then
    ready=1
    break
  fi
  sleep 1
done

if [[ $ready -eq 1 ]]; then
  sockmap_result "backend server1/server2 ready" "OK"
else
  sockmap_result "backend server1/server2 ready" "FAILED" "r1='$r1' r2='$r2'"
  echo "RESULT: $SCENARIO [FAILED] (backend not ready)"
  exit 1
fi

# ---------- helper: run traffic & observe sockhash/peer_map ----------
# $1 vip:port URL
# $2 expected output file prefix (artifacts)
# Returns: number of distinct backends hit (1 or 2), whether all responses were OK
# (0=ok), and the peak sockhash/peer_map entry counts observed
run_traffic_and_observe() {
  local url=$1
  local prefix=$2

  local hits_s1=0 hits_s2=0 unexpected=0
  local max_sockhash=0 cur_sockhash
  local max_peer_map=0 cur_peer_map

  local out="$SOCKMAP_ARTIFACTS_DIR/${prefix}_responses.txt"
  : > "$out"

  for i in $(seq 1 $TOTAL_REQ); do
    res=$($hexec l3h1 curl --max-time 5 -s "$url" 2>/dev/null || echo "ERR")
    echo "$res" >> "$out"
    case "$res" in
      server1) hits_s1=$((hits_s1 + 1)) ;;
      server2) hits_s2=$((hits_s2 + 1)) ;;
      *)       unexpected=$((unexpected + 1)) ;;
    esac
    # capture the sockhash count right after each request
    cur_sockhash=$(sockmap_sockhash_count llb1)
    if (( cur_sockhash > max_sockhash )); then
      max_sockhash=$cur_sockhash
    fi

    cur_peer_map=$(sockmap_peer_map_count llb1)
    if (( cur_peer_map > max_peer_map )); then
      max_peer_map=$cur_peer_map
    fi
  done

  echo "$hits_s1 $hits_s2 $unexpected $max_sockhash $max_peer_map"
}

# With a short curl request the socket and peer pair may already be gone by the time
# the response ends, so a snapshot can read 0. For R1 a live sample is therefore also
# taken while a keep-alive connection is briefly held open.
observe_live_map_peaks() {
  local vip=$1
  local port=$2

  local max_sockhash=0 cur_sockhash
  local max_peer_map=0 cur_peer_map
  local hold_pid

  $hexec l3h1 bash -c "exec 3<>/dev/tcp/${vip}/${port}; printf 'GET / HTTP/1.1\r\nHost: ${vip}\r\nConnection: keep-alive\r\n\r\n' >&3; sleep 3; exec 3<&-; exec 3>&-" &
  hold_pid=$!

  for i in $(seq 1 15); do
    cur_sockhash=$(sockmap_sockhash_count llb1)
    if (( cur_sockhash > max_sockhash )); then
      max_sockhash=$cur_sockhash
    fi

    cur_peer_map=$(sockmap_peer_map_count llb1)
    if (( cur_peer_map > max_peer_map )); then
      max_peer_map=$cur_peer_map
    fi
    sleep 0.2
  done

  wait "$hold_pid" 2>/dev/null || true
  echo "$max_sockhash $max_peer_map"
}

# ---------- Step 4: traffic on R1 (sockmap on) ----------
sockmap_section 4 "Traffic on R1 (sockmap=on) — http://10.10.10.254:2020"

# The redirect counter is monotonic, so single curl requests accumulate into it and no
# live sampling is needed.
r1_redir_before=$(sockmap_redirect_count llb1)

read r1_hs1 r1_hs2 r1_unexp r1_sockhash r1_peer_map < <(run_traffic_and_observe \
  "http://10.10.10.254:2020/" "r1")

r1_redir_after=$(sockmap_redirect_count llb1)
r1_redir_delta=$(( r1_redir_after - r1_redir_before ))

if (( r1_sockhash == 0 || r1_peer_map == 0 )); then
  read r1_live_sockhash r1_live_peer_map < <(observe_live_map_peaks 10.10.10.254 2020)
  if (( r1_live_sockhash > r1_sockhash )); then
    r1_sockhash=$r1_live_sockhash
  fi
  if (( r1_live_peer_map > r1_peer_map )); then
    r1_peer_map=$r1_live_peer_map
  fi
fi

dist_detail="server1=$r1_hs1 server2=$r1_hs2 unexpected=$r1_unexp"
if (( r1_unexp == 0 && r1_hs1 + r1_hs2 == TOTAL_REQ )); then
  sockmap_result "R1 all HTTP responses OK"           "OK"     "$dist_detail"
else
  sockmap_result "R1 all HTTP responses OK"           "FAILED" "$dist_detail"
fi

if (( r1_hs1 > 0 && r1_hs2 > 0 )); then
  sockmap_result "R1 traffic distributed to both backends" "OK"
else
  sockmap_result "R1 traffic distributed to both backends" "FAILED" "$dist_detail"
fi

# A rising redirect counter in the sk_skb verdict is the direct signal that sockmap
# engaged (the counter is monotonic).
if (( r1_redir_delta >= 1 )); then
  sockmap_result "R1 sk_skb redirect counter increased (>=1)" "OK" "delta=$r1_redir_delta"
else
  sockmap_result "R1 sk_skb redirect counter increased (>=1)" "FAILED" "delta=$r1_redir_delta; sockmap not engaging"
fi

# The sock_proxy_map (SOCKHASH) and peer_map peaks are secondary indicators: they are
# transient and exist only while a connection is alive.
if (( r1_sockhash > 0 )); then
  sockmap_result "R1 sock_proxy_map entries observed (>=1)" "OK" "peak=$r1_sockhash"
else
  sockmap_result "R1 sock_proxy_map entries observed (>=1)" "FAILED" "peak=$r1_sockhash; sockmap may not be engaging"
fi

if (( r1_peer_map > 0 )); then
  sockmap_result "R1 peer_map entries observed (>=1)" "OK" "peak=$r1_peer_map"
else
  sockmap_result "R1 peer_map entries observed (>=1)" "FAILED" "peak=$r1_peer_map; pairing may not be engaging"
fi

# ---------- Step 5: traffic on R2 (sockmap off, control) ----------
sockmap_section 5 "Traffic on R2 (sockmap=off, control) — http://10.10.10.254:2021"

# brief pause to minimize any lingering effect of the R1 connections
sleep 3

r2_redir_before=$(sockmap_redirect_count llb1)

read r2_hs1 r2_hs2 r2_unexp r2_sockhash r2_peer_map < <(run_traffic_and_observe \
  "http://10.10.10.254:2021/" "r2")

r2_redir_after=$(sockmap_redirect_count llb1)
r2_redir_delta=$(( r2_redir_after - r2_redir_before ))

dist_detail="server1=$r2_hs1 server2=$r2_hs2 unexpected=$r2_unexp"
if (( r2_unexp == 0 && r2_hs1 + r2_hs2 == TOTAL_REQ )); then
  sockmap_result "R2 all HTTP responses OK"           "OK"     "$dist_detail"
else
  sockmap_result "R2 all HTTP responses OK"           "FAILED" "$dist_detail"
fi

if (( r2_hs1 > 0 && r2_hs2 > 0 )); then
  sockmap_result "R2 traffic distributed to both backends" "OK"
else
  sockmap_result "R2 traffic distributed to both backends" "FAILED" "$dist_detail"
fi

# R2 has sockmap_en=false, so it must never enter sock_proxy_map.
if (( r2_sockhash == 0 )); then
  sockmap_result "R2 sock_proxy_map entries == 0 (expected)" "OK"
else
  sockmap_result "R2 sock_proxy_map entries == 0 (expected)" "FAILED" "peak=$r2_sockhash"
fi

if (( r2_peer_map == 0 )); then
  sockmap_result "R2 peer_map entries == 0 (expected)" "OK"
else
  sockmap_result "R2 peer_map entries == 0 (expected)" "FAILED" "peak=$r2_peer_map"
fi

# R2 has sockmap off, so the verdict redirect counter must never increase (control).
if (( r2_redir_delta == 0 )); then
  sockmap_result "R2 sk_skb redirect counter unchanged (==0)" "OK"
else
  sockmap_result "R2 sk_skb redirect counter unchanged (==0)" "FAILED" "delta=$r2_redir_delta"
fi

# ---------- Step 6: log scan ----------
sockmap_section 6 "loxilb log scan for sockmap failures"

fail_cnt=$(sockmap_log_failure_count llb1)
if (( fail_cnt == 0 )); then
  sockmap_result "no sockmap failure messages in docker logs" "OK"
else
  sockmap_result "no sockmap failure messages in docker logs" "FAILED" "$fail_cnt occurrences"
  sudo docker logs llb1 2>&1 \
    | grep -E "Sockmap: Registration failed!|Sockmap: peer_map|sockmap: " \
    | tail -20 \
    > "$SOCKMAP_ARTIFACTS_DIR/sockmap_failures.log"
fi

# ---------- Step 7: R1 delete -> portset cleanup ----------
sockmap_section 7 "Delete R1 and check portset cleanup"

if sockmap_delete_lb_via_api llb1 10.10.10.254 2020; then
  sleep 2
  if sockmap_portset_has llb1 "$SOCKMAP_VIP_NAME" 2020; then
    sockmap_result "vip 2020 removed from sockmap_vip_portset" "FAILED" "still present"
  else
    sockmap_result "vip 2020 removed from sockmap_vip_portset" "OK"
  fi
else
  sockmap_result "vip 2020 removed from sockmap_vip_portset" "FAILED" "delete API failed"
fi

# R2 (sockmap_en=false) should not have added a refcount to the endpoint portset, so
# after deleting R1 no port 8080 should remain in the ep portset.
if sockmap_portset_has llb1 "$SOCKMAP_EP_NAME" 8080; then
  sockmap_result "ep port 8080 removed from sockmap_ep_portset" "FAILED" "still present (refcount leak?)"
else
  sockmap_result "ep port 8080 removed from sockmap_ep_portset" "OK"
fi

# ---------- Step 8: AI gateway services refuse a sockMapMode ----------
# An AI gateway service (sse_mode, pd_disagg_mode or api_key_auth) re-runs admission
# at every keep-alive request and records requests from their responses. With a
# direction accelerated, later requests on a connection reach the backend without
# the API key or rate-limit check, and responses are not recorded, so any mode other
# than off is refused with 400. The replace case covers api_key_auth being preserved
# when a replace omits it.
sockmap_section 8 "AI gateway services refuse a sockMapMode"

AIGW_PORT=2060
AIGW_EP_PORT=8260

# $1 extra serviceArguments JSON fields, $2 sockMapMode; prints "<http code> <body>"
aigw_post() {
  local body="{\"serviceArguments\":{\"externalIP\":\"10.10.10.254\",\"port\":$AIGW_PORT,\"protocol\":\"tcp\",\"mode\":4,\"name\":\"aigw-reject\",\"sockMapMode\":\"$2\"$1},\"endpoints\":[{\"endpointIP\":\"31.31.31.1\",\"targetPort\":$AIGW_EP_PORT,\"weight\":1}]}"
  _sm_dexec llb1 curl -sS -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' \
    -d "$body" "http://localhost:11111/netlox/v1/config/loadbalancer" \
    | awk 'NR==1{b=$0} END{print $0" "b}'
}

# $1 label, $2 extra fields, $3 sockMapMode
aigw_expect_refused() {
  local out
  out=$(aigw_post "$2" "$3")
  # The needle is "sockmap", not "AI gateway": PR-A widens the refusal beyond
  # ai_gw services and rewords the message.
  if [[ "$out" == 400\ * && "$out" == *"sockmap"* ]]; then
    sockmap_result "$1 refused" "OK"
  else
    sockmap_result "$1 refused" "FAILED" "$out"
    sockmap_delete_lb_via_api llb1 10.10.10.254 "$AIGW_PORT" >/dev/null 2>&1 || true
  fi
}

# pd_disagg_mode is covered by the unit tests: a P/D rule also needs prefill and
# decode endpoints, and that check answers before this one.
aigw_expect_refused "R-1 sse_mode + request"           ',"sse_mode":true'            request
aigw_expect_refused "R-2 sse_mode + response"          ',"sse_mode":true'            response
aigw_expect_refused "R-3 api_key_auth=required + both" ',"api_key_auth":"required"' both

out=$(aigw_post ',"api_key_auth":"required"' off)
if [[ "$out" == 200\ * ]]; then
  sockmap_result "api_key_auth=required + off accepted" "OK"
  aigw_expect_refused "R-3 replace omitting api_key_auth + request" '' request
  sockmap_delete_lb_via_api llb1 10.10.10.254 "$AIGW_PORT" >/dev/null 2>&1 || true
else
  sockmap_result "api_key_auth=required + off accepted" "FAILED" "$out"
fi

# R-6..R-8 (issue 1, PR-A). ANY non-empty api_key_auth declaration gives the data
# plane a non-zero apikey_auth wire value, and it then strips X-Api-Key from
# EVERY request — an explicit "disabled" included, because that value claims the
# header's namespace for the gateway without enforcing a credential. An
# accelerated request direction skips that strip from the second keep-alive
# request on, so the tenant credential reaches the backend. The ai_gw check
# resolves "disabled" to "not an AI gateway" and lets the combination through,
# which is the defect. "jwt" and "apikey-or-jwt" belong to the unit tests: those
# modes also require a configured JWT profile, and that check answers first.
sockmap_xfail_register "R-6" "explicit api_key_auth=disabled is not refused yet (issue 1, PR-A)"
sockmap_xfail_register "R-7" "explicit api_key_auth=disabled is not refused yet (issue 1, PR-A)"
sockmap_xfail_register "R-8" "explicit api_key_auth=disabled is not refused yet (issue 1, PR-A)"
aigw_expect_refused "R-6 api_key_auth=disabled + request"  ',"api_key_auth":"disabled"' request
aigw_expect_refused "R-7 api_key_auth=disabled + response" ',"api_key_auth":"disabled"' response
aigw_expect_refused "R-8 api_key_auth=disabled + both"     ',"api_key_auth":"disabled"' both

# R-16: the mirror image of R-6..R-8, guarding against over-refusal. An OMITTED
# api_key_auth declares nothing, the data plane touches no header, and the rule
# must stay accelerable. The rule is deleted first on purpose: a POST against an
# existing rule is a replace, and a replace that omits api_key_auth PRESERVES it,
# so a leftover rule from the cases above would make this refuse for the right
# reason at the wrong moment.
sockmap_delete_lb_via_api llb1 10.10.10.254 "$AIGW_PORT" >/dev/null 2>&1 || true
out=$(aigw_post '' both)
if [[ "$out" == 200\ * ]]; then
  sockmap_result "R-16 api_key_auth omitted + both accepted" "OK"
else
  sockmap_result "R-16 api_key_auth omitted + both accepted" "FAILED" "$out"
fi
sockmap_delete_lb_via_api llb1 10.10.10.254 "$AIGW_PORT" >/dev/null 2>&1 || true

# ---------- Step 9: an L7 policy and acceleration are mutually exclusive ----------
# A rule with an L7 policy rewrites request headers on EVERY request
# (l7_inject_req_headers_h1: X-Forwarded-For always overwritten, X-Forwarded-Port
# and -Proto, and the insertHeaders SET/ADD/REMOVE operations) and can inject a
# Set-Cookie on every response. An accelerated direction moves those bytes in the
# kernel instead, so from the second keep-alive request the policy is not applied:
# a client-supplied X-Forwarded-For rides through unmodified and a REMOVE stops
# removing. Neither side of the pairing is checked today, and the policy can be
# attached AFTER the rule is created, so the refusal has to live in both places
# (issue 1, PR-A).
sockmap_section 9 "An L7 policy and a sockMapMode are mutually exclusive"

L7_PORT=2062
L7_EP_PORT=8261
L7_LB_ID="sockmap-l7-lb"
L7_POL_ID="sockmap-l7-pol"

sockmap_xfail_register "R-10" "a rule carrying an L7 policy still accepts a sockMapMode (issue 1, PR-A)"
sockmap_xfail_register "R-11" "an L7 policy still attaches to an accelerated rule (issue 1, PR-A)"

# $1 sockMapMode; prints "<http code> <body>"
l7_lb_post() {
  local body="{\"serviceArguments\":{\"id\":\"$L7_LB_ID\",\"externalIP\":\"10.10.10.254\",\"port\":$L7_PORT,\"protocol\":\"tcp\",\"mode\":4,\"name\":\"sockmap-l7\",\"sockMapMode\":\"$1\"},\"endpoints\":[{\"endpointIP\":\"31.31.31.1\",\"targetPort\":$L7_EP_PORT,\"weight\":1}]}"
  _sm_dexec llb1 curl -sS -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' \
    -d "$body" "http://localhost:11111/netlox/v1/config/loadbalancer" \
    | awk 'NR==1{b=$0} END{print $0" "b}'
}

# Attaches a policy that rewrites request headers, which is the processing an
# accelerated request direction would skip. Prints "<http code> <body>".
l7_pol_post() {
  local body="{\"id\":\"$L7_POL_ID\",\"name\":\"sockmap-l7-headers\",\"lbId\":\"$L7_LB_ID\",\"rules\":[{\"position\":1,\"matchSets\":[{\"conditions\":[{\"field\":\"PATH\",\"op\":\"STARTS_WITH\",\"value\":\"/\"}]}],\"action\":{\"kind\":\"REJECT\",\"reject\":{\"statusCode\":451}},\"insertHeaders\":[{\"op\":\"REMOVE\",\"name\":\"X-Internal\",\"value\":\"\"}]}]}"
  _sm_dexec llb1 curl -sS -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' \
    -d "$body" "http://localhost:11111/netlox/v1/config/l7policy" \
    | awk 'NR==1{b=$0} END{print $0" "b}'
}

l7_pol_delete() {
  _sm_dexec llb1 curl -sS -o /dev/null -X DELETE \
    "http://localhost:11111/netlox/v1/config/l7policy/id/$L7_POL_ID" >/dev/null 2>&1 || true
}

l7_ok() { [[ "$1" == 20*\ * ]]; }

l7_pol_delete
sockmap_delete_lb_via_api llb1 10.10.10.254 "$L7_PORT" >/dev/null 2>&1 || true

# R-11: the rule is accelerated first, then the policy is attached.
out=$(l7_lb_post both)
if l7_ok "$out"; then
  resp=$(l7_pol_post)
  if [[ "$resp" == 400\ * ]]; then
    sockmap_result "R-11 policy refused on an accelerated rule" "OK"
  else
    sockmap_result "R-11 policy refused on an accelerated rule" "FAILED" "$resp"
  fi
  # The attach may have been accepted; start the next case from a clean state.
  l7_pol_delete
else
  sockmap_result "R-11 policy refused on an accelerated rule" "FAILED" "LB create: $out"
fi

# R-12: with the rule back on off, the same attach must succeed. This is the
# positive control that keeps the refusal from becoming a blanket ban.
out=$(l7_lb_post off)
if l7_ok "$out"; then
  resp=$(l7_pol_post)
  if l7_ok "$resp"; then
    sockmap_result "R-12 policy attaches to an off rule" "OK"
  else
    sockmap_result "R-12 policy attaches to an off rule" "FAILED" "$resp"
  fi
else
  sockmap_result "R-12 policy attaches to an off rule" "FAILED" "LB replace: $out"
fi

# R-10: the other order — the policy is attached, then a mode is requested.
resp=$(l7_lb_post both)
if [[ "$resp" == 400\ * ]]; then
  sockmap_result "R-10 sockMapMode refused on a policy rule" "OK"
else
  sockmap_result "R-10 sockMapMode refused on a policy rule" "FAILED" "$resp"
  l7_lb_post off >/dev/null    # it was accepted; undo before R-13
fi

# R-13: once the policy is gone the rule may be accelerated again.
l7_pol_delete
resp=$(l7_lb_post both)
if l7_ok "$resp"; then
  sockmap_result "R-13 sockMapMode accepted after the policy is deleted" "OK"
else
  sockmap_result "R-13 sockMapMode accepted after the policy is deleted" "FAILED" "$resp"
fi
sockmap_delete_lb_via_api llb1 10.10.10.254 "$L7_PORT" >/dev/null 2>&1 || true

# ---------- finalize ----------
sockmap_finalize "$SCENARIO"
