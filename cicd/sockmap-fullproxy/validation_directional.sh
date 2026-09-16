#!/bin/bash
#
# sockmap-fullproxy / validation_directional.sh
#
# Validates directional sockmap offloading (sockMapMode = request / response).
#
# A self-contained scenario: it creates its own rules (vip 2040 req-only, vip 2041
# resp-only) and deletes them when done, so it can be run standalone once config.sh has
# brought the testbed up.
#
# Backend ports (dedicated, isolated from 8080):
#   req-only -> backend 9090, resp-only -> backend 9091.
#   This test validates directional separation, so the two rules get separate backend
#   ports; they are also dedicated ports rather than 8080 so they cannot collide with
#   the default config.sh rules (2020/2021 -> backend 8080). That way the "port removed"
#   check in Step 7 stays accurate even while the default rules are up.
#   (tcp_server.js listens on an arbitrary port given as a numeric third argument -
#   9090/9091 here.)
#
#   Background: this test once used req->8080, which collided with the backend port of
#   config.sh's 2020 rule (->8080), and "8080 still present after deleting both rules"
#   was misread as an ep_portset refcount leak. Measurement on 2026-06-12 established
#   that the refcount was correct and the leftover was a confound: the config.sh rule
#   legitimately held 8080 (see status.md Known Issue). Dedicated ports (9090/9091)
#   remove the confound entirely.
#
# Engine behaviour under test:
#   - peer_map is installed in setup_proxy_path right after userspace parses the first
#     request of a connection. So the first request always goes through userspace, and
#     kernel redirect becomes possible from the response that immediately follows.
#   - Therefore:
#       * response-only: even a single request gives REDIRECT_RESP > 0, REDIRECT_REQ == 0
#       * request-only:  only the 2nd and later requests of a keep-alive connection give
#         REDIRECT_REQ > 0, with REDIRECT_RESP == 0
#   - The directional counters (REDIRECT_REQ/RESP) are global PERCPU values, so each
#     measurement window drives traffic to one VIP only and is judged by the delta.
#   - Only the sockets that receive the accelerated direction are in sock_verdict_map,
#     and only once their pair is installed: the backend socket when the pair is
#     installed, the client socket after the first request has been handed to the
#     backend. The other direction never runs the verdict, and no socket runs it
#     without a peer, so PEER_MISS + INELIGIBLE must not grow at all.
#  9. two rules over ONE endpoint address and port, one both and one off: they
#     share the endpoint portset entry, and nothing else — the off rule's traffic
#     moves no redirect counter (invariant I4).

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-directional"
REQ_VIP=10.10.10.254
REQ_PORT=2040       # request-only VIP
RESP_PORT=2041      # response-only VIP
EP_PORT_REQ=9090    # request-only backend port (dedicated, isolated from 8080)
EP_PORT_RESP=9091   # response-only backend port (dedicated, separate)
# Requests per connection; must be >= 2 so the request direction engages on the 2nd.
KA_REQS=6
# Number of connections (curl invocations).
KA_CONNS=4

srv_pids=()

cleanup() {
  sockmap_delete_lb_via_api llb1 "$REQ_VIP" "$REQ_PORT"  >/dev/null 2>&1 || true
  sockmap_delete_lb_via_api llb1 "$REQ_VIP" "$RESP_PORT" >/dev/null 2>&1 || true
  sockmap_kill_tcp_servers
  local p
  for p in "${srv_pids[@]}"; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

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

# ---------- Step 2: backend servers (two ports) ----------
sockmap_section 2 "Start backend HTTP servers (ports $EP_PORT_REQ, $EP_PORT_RESP)"
# tcp_server.js listens on an arbitrary port given as a numeric third argument; 9090
# and 9091 are dedicated, isolated from config.sh's 8080.
$hexec l3ep1 node ../common/tcp_server.js server1 "$EP_PORT_REQ" &     # 9090
srv_pids+=($!)
$hexec l3ep2 node ../common/tcp_server.js server2 "$EP_PORT_REQ" &     # 9090
srv_pids+=($!)
$hexec l3ep1 node ../common/tcp_server.js server1 "$EP_PORT_RESP" &    # 9091
srv_pids+=($!)
$hexec l3ep2 node ../common/tcp_server.js server2 "$EP_PORT_RESP" &    # 9091
srv_pids+=($!)

sleep 3
ready=0
for i in $(seq 1 15); do
  a1=$($hexec l3h1 curl --max-time 3 -s http://31.31.31.1:$EP_PORT_REQ/  2>/dev/null || true)
  a2=$($hexec l3h1 curl --max-time 3 -s http://32.32.32.1:$EP_PORT_REQ/  2>/dev/null || true)
  b1=$($hexec l3h1 curl --max-time 3 -s http://31.31.31.1:$EP_PORT_RESP/ 2>/dev/null || true)
  b2=$($hexec l3h1 curl --max-time 3 -s http://32.32.32.1:$EP_PORT_RESP/ 2>/dev/null || true)
  if [[ "$a1" == "server1" && "$a2" == "server2" && "$b1" == "server1" && "$b2" == "server2" ]]; then
    ready=1; break
  fi
  sleep 1
done
if [[ $ready -eq 1 ]]; then
  sockmap_result "backends ready on both ports" "OK"
else
  sockmap_result "backends ready on both ports" "FAILED" "$EP_PORT_REQ:[$a1,$a2] $EP_PORT_RESP:[$b1,$b2]"
  echo "RESULT: $SCENARIO [FAILED] (backend not ready)"
  exit 1
fi

# ---------- Step 3: directional rules ----------
sockmap_section 3 "Create directional rules (request-only / response-only)"

if sockmap_create_lb_via_api llb1 "$REQ_VIP" "$REQ_PORT" "$EP_PORT_REQ" \
      "31.31.31.1,32.32.32.1" "request" "sockmap-req-only"; then
  sockmap_result "req-only rule (vip $REQ_PORT -> $EP_PORT_REQ, mode=request) created" "OK"
else
  sockmap_result "req-only rule created" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (rule create)"
  exit 1
fi

if sockmap_create_lb_via_api llb1 "$REQ_VIP" "$RESP_PORT" "$EP_PORT_RESP" \
      "31.31.31.1,32.32.32.1" "response" "sockmap-resp-only"; then
  sockmap_result "resp-only rule (vip $RESP_PORT -> $EP_PORT_RESP, mode=response) created" "OK"
else
  sockmap_result "resp-only rule created" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (rule create)"
  exit 1
fi

# Both rules are enabled, so both vips and each ep port are registered in the portsets.
# The dp work is asynchronous, hence the polling.
if sockmap_portset_wait llb1 "$SOCKMAP_VIP_NAME" "$REQ_PORT"  present \
   && sockmap_portset_wait llb1 "$SOCKMAP_VIP_NAME" "$RESP_PORT" present; then
  sockmap_result "both vip ports in sockmap_vip_portset" "OK"
else
  sockmap_result "both vip ports in sockmap_vip_portset" "FAILED"
fi
if sockmap_portset_wait llb1 "$SOCKMAP_EP_NAME" "$EP_PORT_REQ" present \
   && sockmap_portset_wait llb1 "$SOCKMAP_EP_NAME" "$EP_PORT_RESP" present; then
  sockmap_result "both endpoint ports in sockmap_ep_portset" "OK"
else
  sockmap_result "both endpoint ports in sockmap_ep_portset" "FAILED"
fi

# Direction split: which side's sockets get the verdict.
#   request-only : VIP verdict_refs=1, endpoints verdict_refs=0
#   response-only: VIP verdict_refs=0, endpoints verdict_refs=1
vr_req_vip=$(sockmap_portset_verdict_refs llb1 "$SOCKMAP_VIP_NAME" "$REQ_VIP" "$REQ_PORT")
vr_resp_vip=$(sockmap_portset_verdict_refs llb1 "$SOCKMAP_VIP_NAME" "$REQ_VIP" "$RESP_PORT")
vr_req_ep=$(sockmap_portset_verdict_refs llb1 "$SOCKMAP_EP_NAME" 31.31.31.1 "$EP_PORT_REQ")
vr_resp_ep=$(sockmap_portset_verdict_refs llb1 "$SOCKMAP_EP_NAME" 31.31.31.1 "$EP_PORT_RESP")
vr_detail="req vip=$vr_req_vip ep=$vr_req_ep, resp vip=$vr_resp_vip ep=$vr_resp_ep"
if [[ "$vr_req_vip" == "1" && "$vr_req_ep" == "0" && "$vr_resp_vip" == "0" && "$vr_resp_ep" == "1" ]]; then
  sockmap_result "verdict_refs follow the accelerated direction" "OK" "$vr_detail"
else
  sockmap_result "verdict_refs follow the accelerated direction" "FAILED" "$vr_detail"
fi

# keep-alive traffic: one curl invocation sends KA_REQS URLs to the same host in
# sequence, reusing a single connection.
# Output: "<ok_count> <bad_count> <total>"
run_keepalive_traffic() {
  local url=$1
  local prefix=$2
  local urls=()
  local i
  for ((i=0; i<KA_REQS; i++)); do urls+=("$url"); done

  local ok=0 bad=0 total=0
  local out="$SOCKMAP_ARTIFACTS_DIR/${prefix}_responses.txt"
  : > "$out"
  for ((i=0; i<KA_CONNS; i++)); do
    res=$($hexec l3h1 curl --max-time 8 -s "${urls[@]}" 2>/dev/null || echo "ERR")
    echo "$res" >> "$out"
    local n1 n2
    n1=$(grep -o "server1" <<<"$res" | wc -l)
    n2=$(grep -o "server2" <<<"$res" | wc -l)
    ok=$(( ok + n1 + n2 ))
    total=$(( total + KA_REQS ))
  done
  bad=$(( total - ok ))
  echo "$ok $bad $total"
}

# ---------- Step 4: response-only ----------
sockmap_section 4 "response-only traffic (vip $RESP_PORT) — expect RESP>0, REQ==0"
sleep 2

resp_req_before=$(sockmap_redirect_req_count llb1)
resp_resp_before=$(sockmap_redirect_resp_count llb1)
resp_miss_before=$(( $(sockmap_peer_miss_count llb1) + $(sockmap_ineligible_count llb1) ))

read ro_ok ro_bad ro_total < <(run_keepalive_traffic "http://$REQ_VIP:$RESP_PORT/" "resp_only")

resp_req_after=$(sockmap_redirect_req_count llb1)
resp_resp_after=$(sockmap_redirect_resp_count llb1)
resp_req_delta=$(( resp_req_after - resp_req_before ))
resp_resp_delta=$(( resp_resp_after - resp_resp_before ))
resp_miss_delta=$(( $(sockmap_peer_miss_count llb1) + $(sockmap_ineligible_count llb1) - resp_miss_before ))

if (( ro_bad == 0 && ro_ok == ro_total )); then
  sockmap_result "resp-only all responses intact (no hijack)" "OK" "ok=$ro_ok/$ro_total"
else
  sockmap_result "resp-only all responses intact (no hijack)" "FAILED" "ok=$ro_ok/$ro_total bad=$ro_bad"
fi
if (( resp_resp_delta > 0 )); then
  sockmap_result "resp-only REDIRECT_RESP increased (>0)" "OK" "delta=$resp_resp_delta"
else
  sockmap_result "resp-only REDIRECT_RESP increased (>0)" "FAILED" "delta=$resp_resp_delta; response not offloaded"
fi
if (( resp_req_delta == 0 )); then
  sockmap_result "resp-only REDIRECT_REQ unchanged (==0)" "OK"
else
  sockmap_result "resp-only REDIRECT_REQ unchanged (==0)" "FAILED" "delta=$resp_req_delta; request leaked to kernel"
fi
# Client sockets are not in sock_verdict_map, and the backend sockets that are always
# have a peer, so nothing is passed up by the verdict.
if (( resp_miss_delta == 0 )); then
  sockmap_result "resp-only verdict passes nothing (miss+inelig==0)" "OK"
else
  sockmap_result "resp-only verdict passes nothing (miss+inelig==0)" "FAILED" "delta=$resp_miss_delta; a socket ran the verdict without a peer"
fi

# ---------- Step 5: request-only ----------
sockmap_section 5 "request-only traffic (vip $REQ_PORT) — expect REQ>0, RESP==0"
sleep 3   # let the response-only connections drain, so the global counters stay clean

req_req_before=$(sockmap_redirect_req_count llb1)
req_resp_before=$(sockmap_redirect_resp_count llb1)
req_miss_before=$(( $(sockmap_peer_miss_count llb1) + $(sockmap_ineligible_count llb1) ))

read rq_ok rq_bad rq_total < <(run_keepalive_traffic "http://$REQ_VIP:$REQ_PORT/" "req_only")

req_req_after=$(sockmap_redirect_req_count llb1)
req_resp_after=$(sockmap_redirect_resp_count llb1)
req_req_delta=$(( req_req_after - req_req_before ))
req_resp_delta=$(( req_resp_after - req_resp_before ))
req_miss_delta=$(( $(sockmap_peer_miss_count llb1) + $(sockmap_ineligible_count llb1) - req_miss_before ))

if (( rq_bad == 0 && rq_ok == rq_total )); then
  sockmap_result "req-only all responses intact" "OK" "ok=$rq_ok/$rq_total"
else
  sockmap_result "req-only all responses intact" "FAILED" "ok=$rq_ok/$rq_total bad=$rq_bad"
fi
# The request direction only engages on the 2nd and later requests of a connection;
# the first goes through userspace for pairing setup.
if (( req_req_delta > 0 )); then
  sockmap_result "req-only REDIRECT_REQ increased (>0)" "OK" "delta=$req_req_delta"
else
  sockmap_result "req-only REDIRECT_REQ increased (>0)" "FAILED" "delta=$req_req_delta; request not offloaded (need keep-alive 2nd+ req)"
fi
if (( req_resp_delta == 0 )); then
  sockmap_result "req-only REDIRECT_RESP unchanged (==0)" "OK"
else
  sockmap_result "req-only REDIRECT_RESP unchanged (==0)" "FAILED" "delta=$req_resp_delta; response leaked to kernel"
fi
# Backend sockets are not in sock_verdict_map, and a client socket is added only after
# its first request went through userspace, so nothing is passed up by the verdict.
if (( req_miss_delta == 0 )); then
  sockmap_result "req-only verdict passes nothing (miss+inelig==0)" "OK"
else
  sockmap_result "req-only verdict passes nothing (miss+inelig==0)" "FAILED" "delta=$req_miss_delta; a socket ran the verdict without a peer"
fi

# ---------- Step 6: log scan ----------
sockmap_section 6 "loxilb log scan for sockmap failures"
fail_cnt=$(sockmap_log_failure_count llb1)
if (( fail_cnt == 0 )); then
  sockmap_result "no sockmap failure messages in docker logs" "OK"
else
  sockmap_result "no sockmap failure messages in docker logs" "FAILED" "$fail_cnt occurrences"
fi

# ---------- Step 7: delete -> portset cleanup ----------
sockmap_section 7 "Delete directional rules and check portset cleanup"
sockmap_delete_lb_via_api llb1 "$REQ_VIP" "$REQ_PORT"  >/dev/null 2>&1 || true
sockmap_delete_lb_via_api llb1 "$REQ_VIP" "$RESP_PORT" >/dev/null 2>&1 || true

if sockmap_portset_wait llb1 "$SOCKMAP_VIP_NAME" "$REQ_PORT"  absent \
   && sockmap_portset_wait llb1 "$SOCKMAP_VIP_NAME" "$RESP_PORT" absent; then
  sockmap_result "vip ports removed from sockmap_vip_portset" "OK"
else
  sockmap_result "vip ports removed from sockmap_vip_portset" "FAILED" "still present"
fi
# The dedicated ports (9090/9091) do not collide with config.sh's 8080, so each ep port
# must drop to refcount 0 and be removed when its own rule is deleted - accurately,
# whether or not the default config.sh rules are present.
if sockmap_portset_wait llb1 "$SOCKMAP_EP_NAME" "$EP_PORT_REQ"  absent \
   && sockmap_portset_wait llb1 "$SOCKMAP_EP_NAME" "$EP_PORT_RESP" absent; then
  sockmap_result "both ep ports removed from sockmap_ep_portset" "OK"
else
  sockmap_result "both ep ports removed from sockmap_ep_portset" "FAILED" \
    "$EP_PORT_REQ=$(sockmap_portset_has llb1 "$SOCKMAP_EP_NAME" "$EP_PORT_REQ" && echo y || echo n) $EP_PORT_RESP=$(sockmap_portset_has llb1 "$SOCKMAP_EP_NAME" "$EP_PORT_RESP" && echo y || echo n)"
fi

# ---------- Step 8: re-create on the same VIP:port with another mode ----------
# Deleting the last rule on a VIP:port keeps the proxy listener, so a new rule there
# lands on the surviving listener. It must be paired by its own mode, not the one the
# deleted rule had: vip $REQ_PORT was request-only above and is response-only now.
sockmap_section 8 "Re-create vip $REQ_PORT as response-only (was request-only)"
if sockmap_create_lb_via_api llb1 "$REQ_VIP" "$REQ_PORT" "$EP_PORT_REQ" \
      "31.31.31.1,32.32.32.1" "response" "sockmap-recreated"; then
  sockmap_portset_wait llb1 "$SOCKMAP_EP_NAME" "$EP_PORT_REQ" present >/dev/null
  sleep 2
  rc_req_before=$(sockmap_redirect_req_count llb1)
  rc_resp_before=$(sockmap_redirect_resp_count llb1)
  read rc_ok rc_bad rc_total < <(run_keepalive_traffic "http://$REQ_VIP:$REQ_PORT/" "recreated")
  rc_req_delta=$(( $(sockmap_redirect_req_count llb1) - rc_req_before ))
  rc_resp_delta=$(( $(sockmap_redirect_resp_count llb1) - rc_resp_before ))
  if (( rc_bad == 0 && rc_ok == rc_total )); then
    sockmap_result "re-created rule responses intact" "OK" "ok=$rc_ok/$rc_total"
  else
    sockmap_result "re-created rule responses intact" "FAILED" "ok=$rc_ok/$rc_total bad=$rc_bad"
  fi
  if (( rc_resp_delta > 0 && rc_req_delta == 0 )); then
    sockmap_result "re-created rule follows its own mode" "OK" "resp=$rc_resp_delta req=$rc_req_delta"
  else
    sockmap_result "re-created rule follows its own mode" "FAILED" \
      "resp=$rc_resp_delta req=$rc_req_delta; paired by the deleted rule's mode"
  fi
  sockmap_delete_lb_via_api llb1 "$REQ_VIP" "$REQ_PORT" >/dev/null 2>&1 || true
else
  sockmap_result "re-create vip $REQ_PORT as response-only" "FAILED" "API"
fi

# ---------- Step 9: two rules on one endpoint, one accelerated and one not ----------
# The isolation invariant. Two rules pointing at the SAME endpoint address and
# port share that portset entry, because a backend
# connection carries nothing that says which rule opened it, and both rules' sockets
# are registered as possible redirect targets. That sharing must stop there: whether
# a connection runs the verdict is decided by the rule that handled it, so the off
# rule's traffic must move no redirect counter at all.
sockmap_section 9 "One endpoint shared by an accelerated and an off rule"
SHARED_ACC_PORT=2044
SHARED_OFF_PORT=2045
sockmap_delete_lb_via_api llb1 "$REQ_VIP" "$SHARED_ACC_PORT" >/dev/null 2>&1 || true
sockmap_delete_lb_via_api llb1 "$REQ_VIP" "$SHARED_OFF_PORT" >/dev/null 2>&1 || true

if sockmap_create_lb_via_api llb1 "$REQ_VIP" "$SHARED_ACC_PORT" "$EP_PORT_RESP" \
      "31.31.31.1,32.32.32.1" "both" "sockmap-shared-accel" \
   && sockmap_create_lb_via_api llb1 "$REQ_VIP" "$SHARED_OFF_PORT" "$EP_PORT_RESP" \
      "31.31.31.1,32.32.32.1" "off" "sockmap-shared-off"; then
  sleep 2

  sh_req_before=$(sockmap_redirect_req_count llb1)
  sh_resp_before=$(sockmap_redirect_resp_count llb1)
  read sh_ok sh_bad sh_total < <(run_keepalive_traffic "http://$REQ_VIP:$SHARED_OFF_PORT/" "shared_off")
  sh_req_delta=$(( $(sockmap_redirect_req_count llb1) - sh_req_before ))
  sh_resp_delta=$(( $(sockmap_redirect_resp_count llb1) - sh_resp_before ))
  if (( sh_bad == 0 && sh_ok == sh_total )); then
    sockmap_result "off rule on a shared endpoint serves" "OK" "ok=$sh_ok/$sh_total"
  else
    sockmap_result "off rule on a shared endpoint serves" "FAILED" "ok=$sh_ok/$sh_total"
  fi
  if (( sh_req_delta == 0 && sh_resp_delta == 0 )); then
    sockmap_result "off rule runs no verdict on a shared endpoint" "OK"
  else
    sockmap_result "off rule runs no verdict on a shared endpoint" "FAILED" \
      "req=+$sh_req_delta resp=+$sh_resp_delta; the other rule's mode leaked"
  fi

  sh_req_before=$(sockmap_redirect_req_count llb1)
  sh_resp_before=$(sockmap_redirect_resp_count llb1)
  read sh_ok sh_bad sh_total < <(run_keepalive_traffic "http://$REQ_VIP:$SHARED_ACC_PORT/" "shared_accel")
  sh_req_delta=$(( $(sockmap_redirect_req_count llb1) - sh_req_before ))
  sh_resp_delta=$(( $(sockmap_redirect_resp_count llb1) - sh_resp_before ))
  if (( sh_bad == 0 && sh_ok == sh_total && sh_req_delta > 0 && sh_resp_delta > 0 )); then
    sockmap_result "accelerated rule on the same endpoint redirects" "OK" \
      "req=+$sh_req_delta resp=+$sh_resp_delta"
  else
    sockmap_result "accelerated rule on the same endpoint redirects" "FAILED" \
      "ok=$sh_ok/$sh_total req=+$sh_req_delta resp=+$sh_resp_delta"
  fi

  sockmap_delete_lb_via_api llb1 "$REQ_VIP" "$SHARED_ACC_PORT" >/dev/null 2>&1 || true
  sockmap_delete_lb_via_api llb1 "$REQ_VIP" "$SHARED_OFF_PORT" >/dev/null 2>&1 || true
else
  sockmap_result "shared-endpoint rules created" "FAILED" "API"
fi

# ---------- finalize ----------
echo
if (( SOCKMAP_FAIL_COUNT == 0 )); then
  echo "RESULT: $SCENARIO [OK]"
  exit 0
else
  echo "RESULT: $SCENARIO [FAILED] ($SOCKMAP_FAIL_COUNT check(s) failed)"
  echo "Artifacts: $SOCKMAP_ARTIFACTS_DIR/"
  exit 1
fi
