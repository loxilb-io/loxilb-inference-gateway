#!/bin/bash
#
# sockmap-fullproxy / validation_concurrent.sh  (stage D: concurrent connections)
#
# Purpose:
#   Demonstrates that the old partial-key limitation described in
#   port-encoding-and-peer-pairing.md section 2.2 - where the PASSIVE key
#   {0,0,0,vip_port} was identical for every client, so BPF_NOEXIST allowed only one
#   accelerated connection per VIP - is resolved by the full 4-tuple design.
#   Verifies that N concurrent connections are all redirected and that everything is
#   cleaned up without leaking afterwards.
#
# Prerequisite: config.sh must already have created R1 (2020, sockmap on) and
#       R2 (2021, off). Unlike validation.sh this script does not delete the rules, so
#       it can be run standalone and repeatedly. (In a full suite, run it before
#       validation.sh, which deletes R1.)
#
# Checks:
#   D1  concurrent responses are correct and distributed across both backends
#   D2  sock_proxy_map / peer_map hold >= N entries at once (ideally ~2N)
#   D3  the REDIRECT_OK delta scales with connection count (>= N, not pinned at 1)
#   D4  no increase in registration failure logs
#   D5  both maps drain to 0 after the connections close (no churn or leak)
#   D6  control arm R2 (off): REDIRECT delta == 0, peer_map == 0

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-concurrent"
N=20            # concurrent connections
REQS=2          # requests per connection (2 exercises the frontend->backend direction too)
server1_pid=""
server2_pid=""

cleanup() {
  sockmap_kill_tcp_servers
  if [[ -n "$server1_pid" ]]; then wait "$server1_pid" 2>/dev/null || true; fi
  if [[ -n "$server2_pid" ]]; then wait "$server2_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

echo "================ $SCENARIO ================"

# ---------- [1] boot assets ----------
sockmap_section 1 "Daemon boot assets"
if sockmap_assert_bpf_assets llb1; then
  sockmap_result "sockops prog + 5 sockmap maps attached" "OK"
else
  sockmap_result "sockops prog + 5 sockmap maps attached" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (bootstrap)"
  exit 1
fi

# ---------- [2] backend servers ----------
sockmap_section 2 "Start backend HTTP servers"
$hexec l3ep1 node ../common/tcp_server.js server1 &
server1_pid=$!
$hexec l3ep2 node ../common/tcp_server.js server2 &
server2_pid=$!

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

# ---------- helpers ----------
# Starts N concurrent /dev/tcp keep-alive holds. Each connection sends REQS GETs,
# captures the responses to an outfile, and then holds the connection open for a few
# seconds to give the sampling a window.
# The bash -c body is single-quoted and vip/port are passed safely as positional
# arguments ($1/$2).
HOLD_PIDS=()
launch_conc_holds() {
  local vip=$1 port=$2 prefix=$3 i outfile
  HOLD_PIDS=()
  for i in $(seq 1 "$N"); do
    outfile="$SOCKMAP_ARTIFACTS_DIR/conc_${prefix}_${i}.txt"
    $hexec l3h1 bash -c '
      vip="$1"; port="$2"
      exec 3<>/dev/tcp/${vip}/${port} || exit 7
      printf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n" "$vip" >&3
      sleep 0.4
      printf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n" "$vip" >&3
      cat <&3 &
      cp=$!
      sleep 3.5
      kill "$cp" 2>/dev/null
      exec 3<&-
      exec 3>&-
    ' _ "$vip" "$port" > "$outfile" 2>/dev/null &
    HOLD_PIDS+=("$!")
  done
}

# Measures the peak sock_proxy_map/peer_map entry counts while the holds are alive.
PEAK_SOCKHASH=0
PEAK_PEER=0
sample_peaks_until_done() {
  PEAK_SOCKHASH=0
  PEAK_PEER=0
  local iter=0 alive p cur
  while :; do
    alive=0
    for p in "${HOLD_PIDS[@]}"; do
      if kill -0 "$p" 2>/dev/null; then alive=1; break; fi
    done
    cur=$(sockmap_sockhash_count llb1)
    (( cur > PEAK_SOCKHASH )) && PEAK_SOCKHASH=$cur
    cur=$(sockmap_peer_map_count llb1)
    (( cur > PEAK_PEER )) && PEAK_PEER=$cur
    iter=$((iter + 1))
    (( alive == 0 )) && break
    (( iter > 100 )) && break
    sleep 0.15
  done
}

# Aggregates backend distribution from the N response files captured under the prefix.
HITS_S1=0; HITS_S2=0; UNEXP=0
aggregate_hits() {
  local prefix=$1 i f
  HITS_S1=0; HITS_S2=0; UNEXP=0
  for i in $(seq 1 "$N"); do
    f="$SOCKMAP_ARTIFACTS_DIR/conc_${prefix}_${i}.txt"
    if grep -q "server1" "$f" 2>/dev/null; then
      HITS_S1=$((HITS_S1 + 1))
    elif grep -q "server2" "$f" 2>/dev/null; then
      HITS_S2=$((HITS_S2 + 1))
    else
      UNEXP=$((UNEXP + 1))
    fi
  done
}

wait_holds() {
  local p
  for p in "${HOLD_PIDS[@]}"; do
    wait "$p" 2>/dev/null || true
  done
}

# ---------- [3] R1 concurrent (sockmap on) ----------
sockmap_section 3 "Concurrent load on R1 (sockmap=on) — N=$N held conns, $REQS req each"

log_fail_before=$(sockmap_log_failure_count llb1)
r1_redir_before=$(sockmap_redirect_count llb1)

launch_conc_holds 10.10.10.254 2020 r1
sample_peaks_until_done
wait_holds

r1_redir_after=$(sockmap_redirect_count llb1)
r1_redir_delta=$(( r1_redir_after - r1_redir_before ))
aggregate_hits r1
dist="server1=$HITS_S1 server2=$HITS_S2 unexpected=$UNEXP"

if (( UNEXP == 0 && HITS_S1 + HITS_S2 == N )); then
  sockmap_result "D1 all $N concurrent responses OK" "OK" "$dist"
else
  sockmap_result "D1 all $N concurrent responses OK" "FAILED" "$dist"
fi

if (( HITS_S1 > 0 && HITS_S2 > 0 )); then
  sockmap_result "D1 distributed to both backends" "OK" "$dist"
else
  sockmap_result "D1 distributed to both backends" "FAILED" "$dist"
fi

# The point: with the old partial-key design the sockhash peak was pinned at ~2, one
# connection. With the full 4-tuple design N connections coexist, so the peak is >= N
# and ideally ~2N.
if (( PEAK_SOCKHASH >= N && PEAK_PEER >= N )); then
  sockmap_result "D2 maps hold >= $N concurrent entries" "OK" \
    "sockhash peak=$PEAK_SOCKHASH peer_map peak=$PEAK_PEER (ideal ~$((2 * N)))"
else
  sockmap_result "D2 maps hold >= $N concurrent entries" "FAILED" \
    "sockhash peak=$PEAK_SOCKHASH peer_map peak=$PEAK_PEER"
fi

# The point: redirects scale with connection count. Pinned at 1 means acceleration is
# stuck on a single connection.
if (( r1_redir_delta >= N )); then
  sockmap_result "D3 redirect counter scales (>= $N)" "OK" "delta=$r1_redir_delta"
else
  sockmap_result "D3 redirect counter scales (>= $N)" "FAILED" \
    "delta=$r1_redir_delta; expected >= $N (acceleration may be stuck on one connection)"
fi

# ---------- [4] drain after R1 ----------
sockmap_section 4 "Map drain after R1 connections close"
sleep 3
drain_sockhash=$(sockmap_sockhash_count llb1)
drain_peer=$(sockmap_peer_map_count llb1)
if (( drain_sockhash == 0 && drain_peer == 0 )); then
  sockmap_result "D5 sock_proxy_map & peer_map drained to 0" "OK"
else
  sockmap_result "D5 sock_proxy_map & peer_map drained to 0" "FAILED" \
    "sockhash=$drain_sockhash peer_map=$drain_peer"
fi

# ---------- [5] R2 concurrent control (sockmap off) ----------
sockmap_section 5 "Concurrent load on R2 (sockmap=off, control) — N=$N held conns"

r2_redir_before=$(sockmap_redirect_count llb1)

launch_conc_holds 10.10.10.254 2021 r2
sample_peaks_until_done
wait_holds

r2_redir_after=$(sockmap_redirect_count llb1)
r2_redir_delta=$(( r2_redir_after - r2_redir_before ))
aggregate_hits r2
r2_dist="server1=$HITS_S1 server2=$HITS_S2 unexpected=$UNEXP"

# D6a: an off service must never be redirected, since it has no peer_map pairing.
if (( r2_redir_delta == 0 )); then
  sockmap_result "D6a R2 redirect counter unchanged (==0)" "OK"
else
  sockmap_result "D6a R2 redirect counter unchanged (==0)" "FAILED" "delta=$r2_redir_delta"
fi

# D6b: an off service must never enter peer_map.
if (( PEAK_PEER == 0 )); then
  sockmap_result "D6b R2 peer_map stays empty (==0)" "OK"
else
  sockmap_result "D6b R2 peer_map stays empty (==0)" "FAILED" "peer_map peak=$PEAK_PEER"
fi

# Extra: R2 is still a normal fullproxy, so its responses and distribution must be fine.
if (( UNEXP == 0 && HITS_S1 > 0 && HITS_S2 > 0 )); then
  sockmap_result "R2 responses OK + distributed" "OK" "$r2_dist"
else
  sockmap_result "R2 responses OK + distributed" "FAILED" "$r2_dist"
fi

# Informational: ep_portset(8080) is registered by R1 and shared globally, so R2's
# backend socket can transiently appear in the sockhash - the verdict then takes
# SK_PASS on a peer_map miss. That is not acceleration, so it is reported as an
# observation rather than a pass/fail check.
printf "    %-48s : %s\n" "R2 sock_proxy_map peak (info, shared 8080)" "$PEAK_SOCKHASH"

# brief cleanup so R2 connections do not leak into the log scan window
sleep 2

# ---------- [6] log scan ----------
sockmap_section 6 "loxilb log scan for sockmap failures (delta over this run)"
log_fail_after=$(sockmap_log_failure_count llb1)
log_fail_delta=$(( log_fail_after - log_fail_before ))
if (( log_fail_delta == 0 )); then
  sockmap_result "D4 no new sockmap failure messages" "OK"
else
  sockmap_result "D4 no new sockmap failure messages" "FAILED" "$log_fail_delta new occurrences"
  sudo docker logs llb1 2>&1 \
    | grep -E "Sockmap: Registration failed!|Sockmap: peer_map|sockmap: " \
    | tail -20 \
    > "$SOCKMAP_ARTIFACTS_DIR/sockmap_concurrent_failures.log"
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
