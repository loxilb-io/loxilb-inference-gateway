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
  sockmap_result "sockops prog + 5 sockmap maps attached" "OK"
else
  sockmap_result "sockops prog + 5 sockmap maps attached" "FAILED"
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
