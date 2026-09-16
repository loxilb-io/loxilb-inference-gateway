#!/bin/bash
#
# sockmap-fullproxy / validation_control.sh
#
# The invariant under test: the operator can stop acceleration
# deterministically. A configuration change applies to new
# connections, and an explicit admin action drops the accelerated connections of
# one rule — only those, and without a drop window, since it only closes.
#
# None of this exists yet. The action is PR-B, so every case here is registered
# as a known defect and reports XFAIL until it lands; each will report XPASS, and
# fail the suite, once it works, which is the signal to drop the registration.
#
#   1. boot assets
#   2. backends: request_path_server.js (HTTP/1.1) and h2c_server.js
#   3. C-1  the action drops a rule's accelerated connections and reports how many
#      C-2  a connection of the same rule that was never accelerated survives
#      C-3  another rule's accelerated connections survive
#      C-4  sock_verdict_map and peer_map return to their baseline size
#
# The cases split two ways while the action is missing. C-1, C-5, C-6 and the two
# that invoke the action assert the missing behaviour directly, so they are known
# defects and report XFAIL. The rest only mean something once something is actually
# being dropped — "the other rule survived" is vacuously true when nothing is
# dropped — so they report BLOCKED rather than a pass that claims a fix.
#   4. C-5  reducing the mode (both -> off) drops the accelerated connections
#      C-6  deleting the rule drops them
#   5. C-7  a rule with no accelerated connection answers 200 with 0 dropped
#      C-8  an unknown rule answers 404
#   6. C-10 the action under 50 concurrent connections leaves no crash or leak
#      C-9  PEER_MISS stays zero and no sockmap failure is logged
#
# C-5 and C-6 are the semantics decision D-C: today a mode change and a delete
# apply to new connections only, which validation_request_path.sh step 5 asserts.
# When PR-B lands, that step's expectations move here.

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-control"
VIP=10.10.10.254
EP=31.31.31.1
H1_EP_PORT=9092
H2C_EP_PORT=9093
CLIENT=./request_path_client.py
PORT_A=2090      # accelerated, the teardown target
PORT_B=2091      # accelerated, must be untouched
PORT_C=2092      # accelerated rule serving h2c, so nothing is ever accelerated
ALL_PORTS="$PORT_A $PORT_B $PORT_C"

XFAIL_PRB="the admin teardown action does not exist yet (issue 2, PR-B)"
BLOCKED_PRB="needs a working teardown action to mean anything (issue 2, PR-B)"
# Only the cases that DIRECTLY assert the missing behaviour are known defects.
# Everything downstream of the action — "the other rule survived", "the maps came
# back", "an unknown rule 404s" — would pass VACUOUSLY while nothing is dropped, so
# those are reported BLOCKED instead: an xfail there reports XPASS and claims a fix
# that has not happened.
for c in C-1 C-5 C-6 C-7-action C-10-action; do
  sockmap_xfail_register "$c" "$XFAIL_PRB"
done

# Is the route implemented at all? Probed on a port that carries no rule: an
# unimplemented route answers 404 with go-swagger's "path ... was not found",
# while the real handler answers 404 about the RULE. That distinction is also
# case C-8, so it is asserted from this same probe.
ACTION_PROBE=""
action_available() { [[ -n "$ACTION_PROBE" && "$ACTION_PROBE" != *"was not found"* ]]; }

cleanup() {
  for p in $ALL_PORTS; do
    sockmap_delete_lb_via_api llb1 "$VIP" "$p" >/dev/null 2>&1 || true
  done
  sockmap_kill_tcp_servers
}
trap cleanup EXIT

# Prints "<http code> <body>" for the teardown action.
reset_accel() { sockmap_reset_accel_via_api llb1 "$VIP" "$1"; }

# Prints the number the action reported as dropped, or nothing.
dropped_count() {
  grep -oE '"droppedConnections":[[:space:]]*[0-9]+' <<< "$1" \
    | grep -oE '[0-9]+$' | head -1
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
VERDICT_BASE=$(sockmap_verdict_sockhash_count llb1)
PEER_BASE=$(sockmap_peer_map_count llb1)

# ---------- Step 2: backends ----------
sockmap_section 2 "Backends"
$hexec l3ep1 node ./request_path_server.js e1 "$H1_EP_PORT" >/dev/null 2>&1 &
$hexec l3ep1 node ./h2c_server.js e1 "$H2C_EP_PORT" >/dev/null 2>&1 &

ready=0
for i in $(seq 1 20); do
  a=$($hexec l3h1 curl -s --max-time 2 -o /dev/null -w '%{http_code}' \
        "http://$EP:$H1_EP_PORT/" 2>/dev/null)
  b=$($hexec l3h1 curl -s --http2-prior-knowledge --max-time 2 -o /dev/null -w '%{http_code}' \
        "http://$EP:$H2C_EP_PORT/" 2>/dev/null)
  if [[ "$a$b" == "200200" ]]; then
    ready=1
    break
  fi
  sleep 1
done
if (( ready )); then
  sockmap_result "HTTP/1.1 and h2c backends ready" "OK"
else
  sockmap_result "HTTP/1.1 and h2c backends ready" "FAILED" "h1=$a h2c=$b"
  echo "RESULT: $SCENARIO [FAILED] (backends)"
  exit 1
fi

sockmap_create_lb_via_api llb1 "$VIP" "$PORT_A" "$H1_EP_PORT" "$EP" both ctl-a >/dev/null
sockmap_create_lb_via_api llb1 "$VIP" "$PORT_B" "$H1_EP_PORT" "$EP" both ctl-b >/dev/null
sockmap_create_lb_via_api llb1 "$VIP" "$PORT_C" "$H2C_EP_PORT" "$EP" both ctl-c >/dev/null
sleep 2

ACTION_PROBE=$(reset_accel 2099)
if action_available; then
  echo "[sockmap] teardown action present; every case is evaluated"
else
  echo "[sockmap] teardown action absent ($ACTION_PROBE); dependent cases are BLOCKED"
fi

# ---------- Step 3: the teardown action ----------
sockmap_section 3 "C-1..C-4 — the action drops only this rule's accelerated connections"
$hexec l3h1 python3 "$CLIENT" keepalive "$VIP" "$PORT_A" 8 100 \
  > "$SOCKMAP_ARTIFACTS_DIR/ctl_a_accel.txt" 2>&1 &
pid_a=$!
$hexec l3h1 python3 "$CLIENT" keepalive "$VIP" "$PORT_B" 8 100 \
  > "$SOCKMAP_ARTIFACTS_DIR/ctl_b_other.txt" 2>&1 &
pid_b=$!
# Never sends a request, so it has no pair and is not accelerated.
$hexec l3h1 python3 "$CLIENT" idle "$VIP" "$PORT_A" 6 \
  > "$SOCKMAP_ARTIFACTS_DIR/ctl_a_idle.txt" 2>&1 &
pid_idle=$!
sleep 3

resp=$(reset_accel "$PORT_A")
n=$(dropped_count "$resp")
if [[ "$resp" == 200\ * && -n "$n" ]] && (( n >= 1 )); then
  sockmap_result "C-1 action reports the connections it dropped" "OK" "dropped=$n"
else
  sockmap_result "C-1 action reports the connections it dropped" "FAILED" "$resp"
fi

wait "$pid_a" 2>/dev/null
wait "$pid_b" 2>/dev/null
wait "$pid_idle" 2>/dev/null
out_a=$(cat "$SOCKMAP_ARTIFACTS_DIR/ctl_a_accel.txt")
out_b=$(cat "$SOCKMAP_ARTIFACTS_DIR/ctl_b_other.txt")
out_idle=$(cat "$SOCKMAP_ARTIFACTS_DIR/ctl_a_idle.txt")

# The dropped client must SEE the drop: its keep-alive loop ends early.
sockmap_result "C-1 accelerated connection was dropped" \
  "$([[ $out_a == FAIL* ]] && echo OK || echo FAILED)" "$out_a"
if action_available; then
  sockmap_result "C-2 never-accelerated connection survives" \
    "$([[ $out_idle == OK* ]] && echo OK || echo FAILED)" "$out_idle"
  sockmap_result "C-3 another rule's connections survive" \
    "$([[ $out_b == OK* ]] && echo OK || echo FAILED)" "$out_b"
else
  sockmap_result_blocked "C-2 never-accelerated connection survives" "$BLOCKED_PRB"
  sockmap_result_blocked "C-3 another rule's connections survive" "$BLOCKED_PRB"
fi

sleep 2
if action_available; then
  v_now=$(sockmap_verdict_sockhash_count llb1)
  p_now=$(sockmap_peer_map_count llb1)
  if (( v_now == VERDICT_BASE && p_now == PEER_BASE )); then
    sockmap_result "C-4 verdict and peer maps back to baseline" "OK" \
      "verdict=$v_now peer=$p_now"
  else
    sockmap_result "C-4 verdict and peer maps back to baseline" "FAILED" \
      "verdict=$v_now (base $VERDICT_BASE) peer=$p_now (base $PEER_BASE)"
  fi
else
  sockmap_result_blocked "C-4 verdict and peer maps back to baseline" "$BLOCKED_PRB"
fi

# ---------- Step 4: configuration changes ----------
sockmap_section 4 "C-5, C-6 — a mode reduction and a delete drop accelerated connections"
$hexec l3h1 python3 "$CLIENT" keepalive "$VIP" "$PORT_A" 8 100 \
  > "$SOCKMAP_ARTIFACTS_DIR/ctl_mode_off.txt" 2>&1 &
pid=$!
sleep 3
sockmap_create_lb_via_api llb1 "$VIP" "$PORT_A" "$H1_EP_PORT" "$EP" off ctl-a >/dev/null
wait "$pid" 2>/dev/null
out=$(cat "$SOCKMAP_ARTIFACTS_DIR/ctl_mode_off.txt")
sockmap_result "C-5 both -> off drops the accelerated connection" \
  "$([[ $out == FAIL* ]] && echo OK || echo FAILED)" "$out"

sockmap_create_lb_via_api llb1 "$VIP" "$PORT_A" "$H1_EP_PORT" "$EP" both ctl-a >/dev/null
sleep 1
$hexec l3h1 python3 "$CLIENT" keepalive "$VIP" "$PORT_A" 8 100 \
  > "$SOCKMAP_ARTIFACTS_DIR/ctl_delete.txt" 2>&1 &
pid=$!
sleep 3
sockmap_delete_lb_via_api llb1 "$VIP" "$PORT_A" >/dev/null
wait "$pid" 2>/dev/null
out=$(cat "$SOCKMAP_ARTIFACTS_DIR/ctl_delete.txt")
sockmap_result "C-6 rule delete drops the accelerated connection" \
  "$([[ $out == FAIL* ]] && echo OK || echo FAILED)" "$out"

# ---------- Step 5: degenerate targets ----------
sockmap_section 5 "C-7, C-8 — nothing to drop, and an unknown rule"
# h2c is never accelerated, so this rule has accelerated connections at no point.
$hexec l3h1 curl -s --http2-prior-knowledge --max-time 5 -o /dev/null \
  "http://$VIP:$PORT_C/?bytes=64" >/dev/null 2>&1
resp=$(reset_accel "$PORT_C")
n=$(dropped_count "$resp")
if [[ "$resp" == 200\ * && "$n" == "0" ]]; then
  sockmap_result "C-7-action nothing accelerated: 200, 0 dropped" "OK"
else
  sockmap_result "C-7-action nothing accelerated: 200, 0 dropped" "FAILED" "$resp"
fi
if action_available; then
  out=$($hexec l3h1 curl -s --http2-prior-knowledge --max-time 5 -o /dev/null -w '%{http_code}' \
          "http://$VIP:$PORT_C/?bytes=64" 2>/dev/null)
  sockmap_result "C-7 h2c service still serving after the action" \
    "$([[ $out == 200 ]] && echo OK || echo FAILED)" "code=$out"
  # The probe taken at the top of the run: a 404 that talks about the RULE, not
  # about a missing route.
  sockmap_result "C-8 unknown rule answers 404" \
    "$([[ $ACTION_PROBE == 404\ * ]] && echo OK || echo FAILED)" "$ACTION_PROBE"
else
  sockmap_result_blocked "C-7 h2c service still serving after the action" "$BLOCKED_PRB"
  sockmap_result_blocked "C-8 unknown rule answers 404" "$BLOCKED_PRB"
fi

# ---------- Step 6: under load ----------
sockmap_section 6 "C-10 — the action under 50 concurrent connections"
rm -f "$SOCKMAP_ARTIFACTS_DIR"/ctl_load_*.txt
load_pids=()
for i in $(seq 1 50); do
  $hexec l3h1 python3 "$CLIENT" keepalive "$VIP" "$PORT_B" 8 50 \
    > "$SOCKMAP_ARTIFACTS_DIR/ctl_load_$i.txt" 2>&1 &
  load_pids+=($!)
done
sleep 3
resp=$(reset_accel "$PORT_B")
n=$(dropped_count "$resp")
# Only the load clients: a bare `wait` would also wait on the backend servers.
for pid in "${load_pids[@]}"; do wait "$pid" 2>/dev/null; done
survivors=$(grep -l '^OK' "$SOCKMAP_ARTIFACTS_DIR"/ctl_load_*.txt 2>/dev/null | wc -l)
if [[ "$resp" == 200\ * && -n "$n" ]] && (( n >= 1 )); then
  sockmap_result "C-10-action answered under load" "OK" "dropped=$n, $survivors/50 undropped"
else
  sockmap_result "C-10-action answered under load" "FAILED" "$resp"
fi
if action_available; then
  if sockmap_wait_api_ready llb1 5 >/dev/null 2>&1; then
    sockmap_result "C-10 daemon still answering after the action" "OK"
  else
    sockmap_result "C-10 daemon still answering after the action" "FAILED" "REST API gone"
  fi
  sleep 2
  v_now=$(sockmap_verdict_sockhash_count llb1)
  p_now=$(sockmap_peer_map_count llb1)
  if (( v_now == VERDICT_BASE && p_now == PEER_BASE )); then
    sockmap_result "C-10 no map leak after the action under load" "OK" \
      "verdict=$v_now peer=$p_now"
  else
    sockmap_result "C-10 no map leak after the action under load" "FAILED" \
      "verdict=$v_now (base $VERDICT_BASE) peer=$p_now (base $PEER_BASE)"
  fi
else
  sockmap_result_blocked "C-10 daemon still answering after the action" "$BLOCKED_PRB"
  sockmap_result_blocked "C-10 no map leak after the action under load" "$BLOCKED_PRB"
fi

sockmap_section 7 "C-9 — verdict passes and failure logs"
sockmap_assert_no_pass llb1 "$PEER_MISS_START" "C-9 no socket ran the verdict without a peer"
fail_cnt=$(sockmap_log_failure_count llb1)
if (( fail_cnt == 0 )); then
  sockmap_result "C-9 no sockmap failure messages in the daemon logs" "OK"
else
  sockmap_result "C-9 no sockmap failure messages in the daemon logs" "FAILED" "$fail_cnt occurrences"
fi

sockmap_finalize "$SCENARIO"
