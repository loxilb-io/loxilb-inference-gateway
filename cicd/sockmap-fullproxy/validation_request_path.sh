#!/bin/bash
#
# sockmap-fullproxy / validation_request_path.sh
#
# Request shapes that used to go through the stream verdict's SK_PASS path, or
# could overtake a request the proxy was still forwarding. The proxy now adds a
# socket to sock_verdict_map only once its pair is installed, and the client
# socket only after userspace has handed the backend every client byte it holds.
#
#   1. boot assets
#   2. backends: request_path_server.js (HTTP/1.1, echoes path/len/sha256) and
#      h2c_server.js (prior-knowledge HTTP/2)
#   3. h2c through off/response/request/both: every request answered. h2 installs
#      no pair, so none of its sockets may run the verdict
#   4. HTTP/1.1 on request and both: split first request with a 1 byte tail, a
#      streamed upload (the request direction activates after the body), five
#      pipelined requests, and a half-closed client not disturbing the service
#      (whether it is ANSWERED is case E-11 of validation_equivalence.sh)
#   5. a live keep-alive connection is undisturbed by a mode change that only ADDS
#      a direction, and a new connection follows the new mode. Taking a direction
#      away, and deleting the rule, drop the accelerated connections instead and
#      belong to validation_control.sh (C-5, C-6)
#   6. PEER_MISS never grows and no sockmap failure is logged

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-request-path"
VIP=10.10.10.254
H1_EP_PORT=9092
H2C_EP_PORT=9093
EPS="31.31.31.1,32.32.32.1"
declare -A H2C_PORT=([off]=2070 [response]=2071 [request]=2072 [both]=2073)
H1_REQ_PORT=2074
H1_BOTH_PORT=2075
CLIENT=./request_path_client.py

cleanup() {
  for p in "${H2C_PORT[@]}" "$H1_REQ_PORT" "$H1_BOTH_PORT"; do
    sockmap_delete_lb_via_api llb1 "$VIP" "$p" >/dev/null 2>&1 || true
  done
  sockmap_kill_tcp_servers
}
trap cleanup EXIT

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

# ---------- Step 2: backends ----------
sockmap_section 2 "Backends"
$hexec l3ep1 node ./request_path_server.js e1 "$H1_EP_PORT" >/dev/null 2>&1 &
$hexec l3ep2 node ./request_path_server.js e2 "$H1_EP_PORT" >/dev/null 2>&1 &
$hexec l3ep1 node ./h2c_server.js e1 "$H2C_EP_PORT" >/dev/null 2>&1 &
$hexec l3ep2 node ./h2c_server.js e2 "$H2C_EP_PORT" >/dev/null 2>&1 &

ready=0
for i in $(seq 1 20); do
  a=$($hexec l3h1 curl -s --max-time 2 -o /dev/null -w '%{http_code}' "http://31.31.31.1:$H1_EP_PORT/" 2>/dev/null)
  b=$($hexec l3h1 curl -s --max-time 2 -o /dev/null -w '%{http_code}' "http://32.32.32.1:$H1_EP_PORT/" 2>/dev/null)
  c=$($hexec l3h1 curl -s --http2-prior-knowledge --max-time 2 -o /dev/null -w '%{http_code}' "http://31.31.31.1:$H2C_EP_PORT/" 2>/dev/null)
  d=$($hexec l3h1 curl -s --http2-prior-knowledge --max-time 2 -o /dev/null -w '%{http_code}' "http://32.32.32.1:$H2C_EP_PORT/" 2>/dev/null)
  if [[ "$a$b$c$d" == "200200200200" ]]; then
    ready=1
    break
  fi
  sleep 1
done
if (( ready )); then
  sockmap_result "HTTP/1.1 and h2c backends ready" "OK"
else
  sockmap_result "HTTP/1.1 and h2c backends ready" "FAILED" "h1=$a,$b h2c=$c,$d"
  echo "RESULT: $SCENARIO [FAILED] (backends)"
  exit 1
fi

# ---------- Step 3: h2c through every mode ----------
sockmap_section 3 "h2c prior knowledge through off/response/request/both"
for mode in off response request both; do
  port=${H2C_PORT[$mode]}
  if ! sockmap_create_lb_via_api llb1 "$VIP" "$port" "$H2C_EP_PORT" "$EPS" "$mode" "rp-h2c-$mode" >/dev/null; then
    sockmap_result "h2c $mode rule created" "FAILED" "API"
    continue
  fi
done
sleep 2

for mode in off response request both; do
  port=${H2C_PORT[$mode]}
  codes=""
  for i in 1 2 3 4 5 6; do
    codes+=$($hexec l3h1 curl -s --http2-prior-knowledge --max-time 5 -o /dev/null -w '%{http_code} ' \
               "http://$VIP:$port/?bytes=64" 2>/dev/null)
  done
  for c in 1 2; do
    # one connection, four requests; -o applies to one URL each
    codes+=$($hexec l3h1 curl -s --http2-prior-knowledge --max-time 8 -w '%{http_code} ' \
               -o /dev/null "http://$VIP:$port/a" -o /dev/null "http://$VIP:$port/b" \
               -o /dev/null "http://$VIP:$port/c" -o /dev/null "http://$VIP:$port/d" 2>/dev/null)
  done
  total=$(wc -w <<< "$codes")
  ok=$(grep -o '200' <<< "$codes" | wc -l)
  if (( total == 14 && ok == 14 )); then
    sockmap_result "h2c $mode: 14/14 answered" "OK"
  else
    sockmap_result "h2c $mode: 14/14 answered" "FAILED" "codes: $codes"
  fi
done

for mode in off response request both; do
  sockmap_delete_lb_via_api llb1 "$VIP" "${H2C_PORT[$mode]}" >/dev/null 2>&1 || true
done

# ---------- Step 4: HTTP/1.1 request shapes on request and both ----------
sockmap_section 4 "HTTP/1.1 request shapes on request and both"
sockmap_create_lb_via_api llb1 "$VIP" "$H1_REQ_PORT" "$H1_EP_PORT" "$EPS" request rp-h1-request >/dev/null
sockmap_create_lb_via_api llb1 "$VIP" "$H1_BOTH_PORT" "$H1_EP_PORT" "$EPS" both rp-h1-both >/dev/null
sleep 2

for port in "$H1_REQ_PORT" "$H1_BOTH_PORT"; do
  label=$([[ $port == "$H1_REQ_PORT" ]] && echo request || echo both)

  out=$($hexec l3h1 python3 "$CLIENT" split "$VIP" "$port" 10 2>&1)
  sockmap_result "$label: split first request, 1 byte tail" "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  req_before=$(sockmap_redirect_req_count llb1)
  out=$($hexec l3h1 python3 "$CLIENT" stream "$VIP" "$port" 4 2>&1)
  req_delta=$(( $(sockmap_redirect_req_count llb1) - req_before ))
  sockmap_result "$label: streamed 4MB upload intact" "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"
  # The three requests after the upload go through the kernel once the request
  # direction is activated at the end of the body.
  if (( req_delta > 0 )); then
    sockmap_result "$label: request direction active after the upload" "OK" "REDIRECT_REQ +$req_delta"
  else
    sockmap_result "$label: request direction active after the upload" "FAILED" "REDIRECT_REQ +$req_delta"
  fi

  out=$($hexec l3h1 python3 "$CLIENT" pipeline "$VIP" "$port" 2>&1)
  sockmap_result "$label: pipelined requests in order" "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  # Whether a half-closed client is ANSWERED is case E-11 of
  # validation_equivalence.sh: sockproxy closes such a connection without
  # answering, with or without sockmap (issue 3, PR-C). What this suite checks is
  # the separate property that such a client does not disturb the service.
  $hexec l3h1 python3 "$CLIENT" halfclose "$VIP" "$port" >/dev/null 2>&1
  out=$($hexec l3h1 python3 "$CLIENT" keepalive "$VIP" "$port" 1 50 2>&1)
  sockmap_result "$label: service undisturbed by a half-closed client" "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"
done

# ---------- Step 5: rule changes under a live connection ----------
# Adding or keeping a direction applies to NEW connections: an existing connection
# is never accelerated retroactively, so one that is already running is undisturbed.
# Taking a direction away is the other case and belongs to validation_control.sh
# (C-5, C-6): those connections are dropped, because the verdict decides on the
# pairing installed when they were accepted and would otherwise keep redirecting
# under a mode that no longer asks for it.
sockmap_section 5 "Rule changes under a live keep-alive connection"
# response -> both ADDS the request direction, so nothing is taken away and the
# live connection keeps running (unaccelerated in that direction, as it has been
# since it was accepted).
sockmap_create_lb_via_api llb1 "$VIP" "$H1_BOTH_PORT" "$H1_EP_PORT" "$EPS" response rp-h1-both >/dev/null
sleep 1
$hexec l3h1 python3 "$CLIENT" keepalive "$VIP" "$H1_BOTH_PORT" 6 100 > "$SOCKMAP_ARTIFACTS_DIR/rp_ka_mode.txt" 2>&1 &
ka_pid=$!
sleep 2
sockmap_create_lb_via_api llb1 "$VIP" "$H1_BOTH_PORT" "$H1_EP_PORT" "$EPS" both rp-h1-both >/dev/null
wait "$ka_pid"
out=$(cat "$SOCKMAP_ARTIFACTS_DIR/rp_ka_mode.txt")
sockmap_result "live connection survives response -> both" "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

req_before=$(sockmap_redirect_req_count llb1)
resp_before=$(sockmap_redirect_resp_count llb1)
out=$($hexec l3h1 python3 "$CLIENT" keepalive "$VIP" "$H1_BOTH_PORT" 1 50 2>&1)
req_delta=$(( $(sockmap_redirect_req_count llb1) - req_before ))
resp_delta=$(( $(sockmap_redirect_resp_count llb1) - resp_before ))
if [[ $out == OK* ]] && (( req_delta > 0 && resp_delta > 0 )); then
  sockmap_result "new connection follows the new mode" "OK" "req=$req_delta resp=$resp_delta"
else
  sockmap_result "new connection follows the new mode" "FAILED" "$out req=$req_delta resp=$resp_delta"
fi

# ---------- Step 6: counters and logs ----------
sockmap_section 6 "Verdict passes and failure logs"
sockmap_assert_no_pass llb1 "$PEER_MISS_START" "no socket ran the verdict without a peer"
fail_cnt=$(sockmap_log_failure_count llb1)
if (( fail_cnt == 0 )); then
  sockmap_result "no sockmap failure messages in the daemon logs" "OK"
else
  sockmap_result "no sockmap failure messages in the daemon logs" "FAILED" "$fail_cnt occurrences"
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
