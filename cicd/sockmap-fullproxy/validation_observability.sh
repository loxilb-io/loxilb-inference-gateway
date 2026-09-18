#!/bin/bash
#
# sockmap-fullproxy / validation_observability.sh
#
# What an operator can see of accelerated traffic. Acceleration moves bytes out of
# userspace, so everything userspace used to count about them has to be counted
# somewhere else, or it silently disappears:
#
#   1. boot assets
#   2. backend: request_path_server.js
#   3. O-3  the rule's endpoint counter reports the same bytes as on `off`, for
#           one fixed volume of traffic (request, response and both arms). The
#           counter is the bytes the proxy delivered to clients; an accelerated
#           response direction delivers them in the kernel
#      O-1  no redirect was refused during normal traffic (REDIRECT_DROP == 0)
#   4. O-5  a connection closed by the sockmapreset action is still counted
#      O-4  (information only) what the counter shows while an accelerated
#           connection is open: kernel bytes are folded in when it ends
#   5. O-2  a redirect whose target is missing is counted as REDIRECT_DROP and
#           not as a redirect. The target is removed with bpftool: a fault
#           injection, the stream it is applied to stalls
#      O-6  debug/psock-drops.bt attributes that drop to sk_psock_verdict_apply
#           and to the backend socket (BLOCKED without bpftrace on the host)
#   6. PEER_MISS stays zero and no sockmap failure is logged
#
# Step 5 runs last among the traffic steps because it deliberately breaks one
# connection; O-1 is closed before it.

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-observability"
VIP=10.10.10.254
EP=31.31.31.1
EP_PORT=9092
CLIENT=./request_path_client.py
PORT_OFF=2100
PORT_REQ=2101
PORT_RESP=2102
PORT_BOTH=2103
PORT_RESET=2104      # both, the sockmapreset target of O-5
PORT_FAULT=2105      # both, the fault-injection target of O-2
ALL_PORTS="$PORT_OFF $PORT_REQ $PORT_RESP $PORT_BOTH $PORT_RESET $PORT_FAULT"
BT_OUT="$SOCKMAP_ARTIFACTS_DIR/psock-drops.txt"
HOLD_OUT="$SOCKMAP_ARTIFACTS_DIR/observability-hold.txt"
KA_OUT="$SOCKMAP_ARTIFACTS_DIR/observability-keepalive.txt"

cleanup() {
  for p in $ALL_PORTS; do
    sockmap_delete_lb_via_api llb1 "$VIP" "$p" >/dev/null 2>&1 || true
  done
  sockmap_kill_tcp_servers
  sudo pkill -f 'bpftrace .*psock-drops.bt' >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Runs the fixed traffic volume once on a port and prints the counter delta, or
# "FAIL <client output>".
volume_delta() {
  local port=$1 before after out
  before=$(sockmap_ep_counter_bytes llb1 "$VIP" "$port")
  out=$($hexec l3h1 python3 "$CLIENT" volume "$VIP" "$port" 2>&1)
  if [[ $out != OK* ]]; then
    echo "FAIL $out"
    return
  fi
  # An accelerated connection's close is deferred by up to ~75ms (half-close
  # handling); the fold happens at teardown.
  sleep 1
  after=$(sockmap_ep_counter_bytes llb1 "$VIP" "$port")
  echo $(( after - before ))
}

echo "================ $SCENARIO ================"

# ---------- Step 1: boot assets ----------
sockmap_section 1 "Daemon boot assets"
if sockmap_assert_bpf_assets llb1; then
  sockmap_result "sockops prog + sockmap maps attached" "OK"
else
  sockmap_result "sockops prog + sockmap maps attached" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (bootstrap)"
  exit 1
fi

PEER_MISS_START=$(sockmap_peer_miss_count llb1)
DROP_START=$(sockmap_redirect_drop_count llb1)

# ---------- Step 2: backend and rules ----------
sockmap_section 2 "Backend and rules"
$hexec l3ep1 node ./request_path_server.js e1 "$EP_PORT" >/dev/null 2>&1 &
ready=0
for i in $(seq 1 20); do
  code=$($hexec l3h1 curl -s --max-time 2 -o /dev/null -w '%{http_code}' \
           "http://$EP:$EP_PORT/" 2>/dev/null)
  if [[ "$code" == "200" ]]; then
    ready=1
    break
  fi
  sleep 1
done
if (( ! ready )); then
  sockmap_result "backend ready" "FAILED" "http=$code"
  echo "RESULT: $SCENARIO [FAILED] (backend)"
  exit 1
fi

created=1
for spec in "$PORT_OFF off" "$PORT_REQ request" "$PORT_RESP response" "$PORT_BOTH both" \
            "$PORT_RESET both" "$PORT_FAULT both"; do
  set -- $spec
  sockmap_create_lb_via_api llb1 "$VIP" "$1" "$EP_PORT" "$EP" "$2" "obs-$1" >/dev/null || created=0
done
if (( created )); then
  sockmap_result "backend ready, six rules created" "OK"
else
  sockmap_result "backend ready, six rules created" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (rules)"
  exit 1
fi
sleep 2

# ---------- Step 3: the counter against `off` ----------
sockmap_section 3 "Endpoint counter bytes, accelerated arms against off"
off_delta=$(volume_delta "$PORT_OFF")
if [[ $off_delta =~ ^[0-9]+$ ]] && (( off_delta > 0 )); then
  sockmap_result "O-3 off: the reference arm counted the traffic" "OK" "$off_delta bytes"
else
  sockmap_result "O-3 off: the reference arm counted the traffic" "FAILED" "$off_delta"
fi

for spec in "$PORT_REQ request" "$PORT_RESP response" "$PORT_BOTH both"; do
  set -- $spec
  label="O-3 $2: endpoint counter bytes equal to off"
  d=$(volume_delta "$1")
  if [[ ! $d =~ ^[0-9]+$ ]]; then
    sockmap_result "$label" "FAILED" "traffic: $d"
  elif [[ $off_delta =~ ^[0-9]+$ ]] && (( d == off_delta )); then
    sockmap_result "$label" "OK" "$d bytes"
  else
    sockmap_result "$label" "FAILED" "$d bytes, off counted $off_delta"
  fi
done

sockmap_assert_no_redirect_drop llb1 "$DROP_START" "O-1 no redirect refused during normal traffic"

# ---------- Step 4: a connection closed by the reset action ----------
sockmap_section 4 "A connection closed by sockmapreset is counted"
before=$(sockmap_ep_counter_bytes llb1 "$VIP" "$PORT_RESET")
: > "$HOLD_OUT"
$hexec l3h1 python3 "$CLIENT" volume "$VIP" "$PORT_RESET" 15 > "$HOLD_OUT" 2>&1 &
hold_pid=$!
for i in $(seq 1 40); do
  grep -q '^DONE' "$HOLD_OUT" && break
  sleep 0.25
done
if ! grep -q '^DONE' "$HOLD_OUT"; then
  sockmap_result "O-5 both: the traffic ran before the reset" "FAILED" "$(head -1 "$HOLD_OUT")"
else
  open_delta=$(( $(sockmap_ep_counter_bytes llb1 "$VIP" "$PORT_RESET") - before ))
  echo "    (O-4 information: while the connection is open the counter shows" \
       "$open_delta of the $off_delta bytes; the rest is folded in when it ends)"
  reply=$(sockmap_reset_accel_via_api llb1 "$VIP" "$PORT_RESET")
  dropped=$(grep -oE '"droppedConnections":[[:space:]]*[0-9]+' <<< "$reply" | grep -oE '[0-9]+$')
  if [[ -z "$dropped" || "$dropped" == 0 ]]; then
    sockmap_result_blocked "O-5 both: a reset connection is counted" \
      "the reset closed nothing ($reply)"
  else
    sleep 1
    d=$(( $(sockmap_ep_counter_bytes llb1 "$VIP" "$PORT_RESET") - before ))
    if [[ $off_delta =~ ^[0-9]+$ ]] && (( d == off_delta )); then
      sockmap_result "O-5 both: a reset connection is counted" "OK" "$d bytes"
    else
      sockmap_result "O-5 both: a reset connection is counted" "FAILED" \
        "$d bytes, off counted $off_delta"
    fi
  fi
fi
kill "$hold_pid" >/dev/null 2>&1
wait "$hold_pid" 2>/dev/null

# ---------- Step 5: a refused redirect ----------
sockmap_section 5 "A redirect with no target (fault injection)"
bt_pid=""
if command -v bpftrace >/dev/null 2>&1; then
  sudo timeout 30 bpftrace debug/psock-drops.bt > "$BT_OUT" 2>&1 &
  bt_pid=$!
  for i in $(seq 1 40); do
    grep -q '^tracing' "$BT_OUT" 2>/dev/null && break
    sleep 0.25
  done
fi

drop0=$(sockmap_redirect_drop_count llb1)
: > "$KA_OUT"
$hexec l3h1 python3 "$CLIENT" keepalive "$VIP" "$PORT_FAULT" 5 1000 > "$KA_OUT" 2>&1 &
ka_pid=$!
sleep 1.5
removed=$(sockmap_proxy_map_drop_clients llb1 "$VIP" "$PORT_FAULT")
resp0=$(sockmap_redirect_resp_count llb1)
wait "$ka_pid" 2>/dev/null
resp1=$(sockmap_redirect_resp_count llb1)
drop1=$(sockmap_redirect_drop_count llb1)

if [[ "$removed" == 0 ]]; then
  sockmap_result_blocked "O-2 a refused redirect is counted as REDIRECT_DROP" \
    "no client socket of port $PORT_FAULT was in sock_proxy_map"
  sockmap_result_blocked "O-2 a refused redirect is not counted as a redirect" \
    "no fault was injected"
else
  if (( drop1 - drop0 > 0 )); then
    sockmap_result "O-2 a refused redirect is counted as REDIRECT_DROP" "OK" "+$(( drop1 - drop0 ))"
  else
    sockmap_result "O-2 a refused redirect is counted as REDIRECT_DROP" "FAILED" \
      "REDIRECT_DROP +0 ($(head -1 "$KA_OUT"))"
  fi
  if (( resp1 - resp0 == 0 )); then
    sockmap_result "O-2 a refused redirect is not counted as a redirect" "OK"
  else
    sockmap_result "O-2 a refused redirect is not counted as a redirect" "FAILED" \
      "REDIRECT_RESP +$(( resp1 - resp0 )) after the target was removed"
  fi
fi

if [[ -z "$bt_pid" ]]; then
  sockmap_result_blocked "O-6 psock-drops.bt attributes the drop" "bpftrace is not installed"
elif [[ "$removed" == 0 ]]; then
  sudo pkill -INT -f 'bpftrace .*psock-drops.bt' >/dev/null 2>&1
  sockmap_result_blocked "O-6 psock-drops.bt attributes the drop" "no fault was injected"
else
  sudo pkill -INT -f 'bpftrace .*psock-drops.bt' >/dev/null 2>&1
  wait "$bt_pid" 2>/dev/null
  if grep -qE "^@by_socket\[sk_psock_verdict_apply, [0-9]+, $EP_PORT\]" "$BT_OUT"; then
    sockmap_result "O-6 psock-drops.bt attributes the drop" "OK" \
      "$(grep -E '^@drops\[sk_psock_verdict_apply' "$BT_OUT" | head -1)"
  else
    sockmap_result "O-6 psock-drops.bt attributes the drop" "FAILED" \
      "no sk_psock_verdict_apply drop on a backend socket (see $BT_OUT)"
  fi
fi

# ---------- Step 6: invariant counters ----------
sockmap_section 6 "Verdict passes and failure logs"
sockmap_assert_no_pass llb1 "$PEER_MISS_START" "no socket ran the verdict without a peer"
fail_cnt=$(sockmap_log_failure_count llb1)
if (( fail_cnt == 0 )); then
  sockmap_result "no sockmap failure messages in the daemon logs" "OK"
else
  sockmap_result "no sockmap failure messages in the daemon logs" "FAILED" "$fail_cnt occurrences"
fi

sockmap_finalize "$SCENARIO"
