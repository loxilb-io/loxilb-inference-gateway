#!/bin/bash
#
# sockmap-fullproxy / validation_equivalence.sh
#
# The invariant under test: on a rule that qualifies for acceleration,
# everything the client and the backend observe is identical to sockMapMode off.
# Only CPU differs.
#
# It holds exactly, with no exempt header, because every request- and
# response-rewriting path in the plaintext H1 relay is gated on something a
# qualifying rule does not have: inject_forwarded_headers and
# rewrite_location_header on is_ssl, the HSTS and Set-Cookie injectors on
# have_ssl and an L7 policy, ai_strip_upstream_api_key on a declared
# api_key_auth, and the X-Request-Id injection on ai_gw_mode. This suite is that comparison,
# run differentially: four rules over ONE endpoint, one per mode, driven through
# the same scenarios, with the off arm as the baseline.
#
# One endpoint on purpose — with two, backend selection would differ between arms
# and every record would need its endpoint identity normalized away.
#
#   1. boot assets
#   2. backend: request_path_server.js, which echoes the request headers it saw
#   3. four rules: off / request / response / both on one endpoint
#   4. E-1,E-2  the echo sequence's records are identical to the off arm, client
#               response headers and the request headers the backend saw included
#   5. E-3..E-8, E-10..E-12  self-checking request and response shapes
#   6. PEER_MISS stays zero and no sockmap failure is logged
#
# A case that fails on the OFF arm as well is a sockproxy defect, not an
# acceleration defect. The arms are always reported off first so that is visible.

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-equivalence"
VIP=10.10.10.254
EP=31.31.31.1
EP_PORT=9092
CLIENT=./request_path_client.py
MODES="off request response both"
declare -A PORT=([off]=2080 [request]=2081 [response]=2082 [both]=2083)

# Known defects. A registered case prints XFAIL while it fails and XPASS once it
# passes, so the fix forces the registration to be removed.
sockmap_xfail_register "E-11" \
  "sockproxy closes on a client half-close without answering (issue 3, PR-C)"

cleanup() {
  for m in $MODES; do
    sockmap_delete_lb_via_api llb1 "$VIP" "${PORT[$m]}" >/dev/null 2>&1 || true
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

# ---------- Step 2: backend ----------
sockmap_section 2 "Backend (one endpoint, $EP:$EP_PORT)"
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
if (( ready )); then
  sockmap_result "backend ready" "OK"
else
  sockmap_result "backend ready" "FAILED" "last code: $code"
  echo "RESULT: $SCENARIO [FAILED] (backend)"
  exit 1
fi

# ---------- Step 3: one rule per mode ----------
sockmap_section 3 "Rules: off / request / response / both over one endpoint"
for m in $MODES; do
  if sockmap_create_lb_via_api llb1 "$VIP" "${PORT[$m]}" "$EP_PORT" "$EP" "$m" "eq-$m" >/dev/null; then
    sockmap_result "rule $m on port ${PORT[$m]}" "OK"
  else
    sockmap_result "rule $m on port ${PORT[$m]}" "FAILED" "API"
  fi
done
sleep 2

# ---------- Step 4: E-1,E-2 differential ----------
# The echo sequence sends six requests on ONE connection with bodies of
# 0/100/65535/65536/70000 bytes. Request 1 is always served by userspace; from
# request 2 the kernel carries the accelerated direction, which is where a
# skipped header rewrite or a reordered body would appear.
sockmap_section 4 "E-1,E-2 — observations identical to the off arm"
for m in $MODES; do
  out="$SOCKMAP_ARTIFACTS_DIR/eq_echo_$m.jsonl"
  $hexec l3h1 python3 "$CLIENT" echo "$VIP" "${PORT[$m]}" > "$out" 2>&1
  records=$(grep -c '^{' "$out" 2>/dev/null || echo 0)
  if (( records == 6 )); then
    sockmap_result "E-0 $m: echo sequence answered" "OK" "$records records"
  else
    sockmap_result "E-0 $m: echo sequence answered" "FAILED" \
      "$records/6 records; $(head -c 160 "$out")"
  fi
done

for m in $MODES; do
  [[ $m == off ]] && continue
  detail=$(python3 ./equivalence_diff.py \
             --baseline "$SOCKMAP_ARTIFACTS_DIR/eq_echo_off.jsonl" \
             --candidate "$SOCKMAP_ARTIFACTS_DIR/eq_echo_$m.jsonl" \
             --baseline-port "${PORT[off]}" --candidate-port "${PORT[$m]}" 2>&1)
  sockmap_result "E-1/E-2 $m: identical to off" \
    "$([[ $detail == OK* ]] && echo OK || echo FAILED)" "$detail"
done

# ---------- Step 5: self-checking shapes ----------
# Each of these asserts an absolute expectation rather than equality with off,
# which is the stronger statement. off is run first so a pre-existing sockproxy
# defect is distinguishable from an acceleration defect.
sockmap_section 5 "E-3..E-8, E-10..E-12 — request and response shapes"
for m in $MODES; do
  port=${PORT[$m]}

  out=$($hexec l3h1 python3 "$CLIENT" stream "$VIP" "$port" 4 2>&1)
  sockmap_result "E-3 $m: 4MB streamed upload intact" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  out=$($hexec l3h1 python3 "$CLIENT" chunked "$VIP" "$port" 2>&1)
  sockmap_result "E-4 $m: chunked request framing" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  out=$($hexec l3h1 python3 "$CLIENT" pipeline "$VIP" "$port" 2>&1)
  sockmap_result "E-5 $m: pipelined requests in order" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  out=$($hexec l3h1 python3 "$CLIENT" sizes "$VIP" "$port" 2>&1)
  sockmap_result "E-6 $m: response sizes byte-exact" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  out=$($hexec l3h1 python3 "$CLIENT" special "$VIP" "$port" 2>&1)
  sockmap_result "E-7 $m: 204, 304 and HEAD" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  out=$($hexec l3h1 python3 "$CLIENT" split "$VIP" "$port" 10 2>&1)
  sockmap_result "E-8 $m: split first request, 1 byte tail" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  out=$($hexec l3h1 python3 "$CLIENT" abort "$VIP" "$port" 2>&1)
  sockmap_result "E-10 $m: backend truncates mid-response" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  out=$($hexec l3h1 python3 "$CLIENT" halfclose "$VIP" "$port" 2>&1)
  sockmap_result "E-11 $m: half-closed client is answered" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  out=$($hexec l3h1 python3 "$CLIENT" halfpartial "$VIP" "$port" 2>&1)
  sockmap_result "E-12 $m: partial request then half-close" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"
done

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
