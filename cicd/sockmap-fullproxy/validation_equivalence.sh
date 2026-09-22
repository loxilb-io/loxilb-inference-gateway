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
#   5. E-3..E-8, E-10..E-16  self-checking request and response shapes
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
# E-10 repeats, because the truncation race it guards against is intermittent.
ABORT_REPS=${ABORT_REPS:-40}

# Known defect, in two layers. A client that half-closes after a complete request
# is saying "that was my last request", not "forget the response" — the request is
# already parsed and forwarded, so it is owed an answer. The proxy does not always
# give it one, and the two layers fail at different times, which is why E-11 and
# E-13 are separate cases.
#
# Layer 1 (E-11, off and request): the pair is torn down the moment the client's
# FIN arrives, so the answer is never delivered. Deferring instead needs a signal
# that the response is complete, and the plain userspace relay has none: the
# response framer runs only under pd_framing_v2. Gating on a flag nothing clears
# held every close on every FullProxy rule for 50 ms, which moved load-aware
# routing, so the deferral was confined to rules whose response direction is
# accelerated — where the kernel may be holding response bytes anyway. A
# request-only rule relays its response through userspace exactly like off.
#
# Layer 2 (E-13, every arm): where the teardown IS deferred, the bound is an
# unconditional 50 ms — nothing releases it when the response completes. An
# immediate backend hides this, because it answers inside the bound; a backend
# slower than the bound is cut off, and the client's leg and the backend's leg go
# down together, so the response can also arrive truncated. E-13 is registered on
# all four arms and MUST stay registered until the bound moves to the per-rule
# timeouts: fixing only layer 1 turns this suite green while a slow backend is
# still cut off on every arm.
#
# E-14 is the acceptance test for any fix to either layer. E-13 holds the whole
# answer back, so a proxy that gives up mid-wait always yields a clean EOF and
# the case cannot tell "nothing was sent" from "what was sent got cut" — a fix
# that delivers the opening bytes and drops the remainder passes it. E-14 starts
# the answer at once under a promised Content-Length and finishes it late, which
# is both the shape of real inference traffic and the shape that makes such a
# fix fail. Its body is deliberately small: an unpatched kernel duplicates bytes
# on an accelerated response at multi-megabyte sizes, which would make the
# length check meaningless.
#
# E-15 is E-14 with the FIN arriving AFTER the opening bytes rather than before.
# Every other half-* case shuts the write side down before a response byte
# exists, so none of them produces that order, and it carries two things nothing
# else does. It is the only case that shows layer 1 truncating a stream rather
# than losing it whole — off and request deliver the opening bytes and drop the
# remainder, where E-14 has them deliver nothing. And it is the worst order for
# any fix that answers the FIN by dropping the connection's acceleration, since
# the kernel may already hold response bytes taken for redirect that no
# userspace queue can see. Keep it whichever way that decision goes: the first
# reason stands on its own.
for arm in $MODES; do
  sockmap_xfail_register "E-13 $arm" \
    "the deferred teardown has an unconditional 50 ms bound with no response-complete release, so a backend slower than that is cut off on every arm"
  sockmap_xfail_register "E-14 $arm" \
    "same bound, with the answer already started: the client keeps the opening bytes and loses the remainder"
  sockmap_xfail_register "E-15 $arm" \
    "the same loss with the FIN arriving after the opening bytes, which is also where layer 1 truncates rather than losing the answer whole"
done
# E-16 is registered on TWO arms only, and the asymmetry is the point.
#
# It half-closes while the rest of a 256KB answer is still in the pipeline, which
# is the order that matters to any fix that answers the FIN by dropping the
# connection's acceleration: the unpair then happens on top of bytes the kernel
# has taken for redirect. E-15 cannot produce that state — it waits for the
# opening bytes and the backend then stays silent, so the queue is empty by the
# time the FIN goes out.
#
# Measured before registering, 5/5 on each arm: off and request lose the
# remainder to the immediate teardown, response and both deliver all 262144.
# So the two passing arms are NOT registered — they pass today and must keep
# passing, which is what makes this a regression guard for that fix rather than
# a defect case. Registering them would turn a pass into an XPASS failure, the
# mistake the control suite already made once by registering cases that were
# blocked rather than broken.
for arm in off request; do
  sockmap_xfail_register "E-16 $arm" \
    "the immediate teardown on the arms whose response is not accelerated drops whatever of the answer is still in flight"
  sockmap_xfail_register "E-11 $arm" \
    "a half-closed client is answered only where the response is accelerated; the userspace relay has no response-complete signal to wait for"
done

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
DROP_START=$(sockmap_redirect_drop_count llb1)

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
sockmap_section 5 "E-3..E-8, E-10..E-16 — request and response shapes"
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

  # E-10 is driven many times because what it guards against is a race, not a
  # property. A backend that writes a short response and closes at once used to
  # have its FIN beat its own redirected bytes to the client whenever the response
  # direction was accelerated: the client saw a shorter truncation than the
  # backend performed, sometimes losing the response headers entirely and getting
  # no response at all where off delivered a 200 with a partial body. It reached
  # 52% of attempts on both. A single attempt per arm reported that as a pass most
  # runs, which is why this repeats.
  #
  # Every arm is now held to the same standard: the client sees exactly what the
  # backend sent, every time.
  out=$($hexec l3h1 python3 "$CLIENT" abort "$VIP" "$port" "$ABORT_REPS" 2>&1)
  sockmap_result "E-10 $m: backend truncates mid-response" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  out=$($hexec l3h1 python3 "$CLIENT" halfclose "$VIP" "$port" 2>&1)
  sockmap_result "E-11 $m: half-closed client is answered" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  # Same shape as E-11 but with the answer held past the proxy's deferred-close
  # bound, which is what tells "the response leg is kept open" apart from "the
  # pair is torn down on a timer that the fast path happens to fit inside".
  out=$($hexec l3h1 python3 "$CLIENT" halfslow "$VIP" "$port" 500 2>&1)
  sockmap_result "E-13 $m: half-closed client, slow backend" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  # E-14: the answer has already started when the bound expires. Distinguishes a
  # fix that keeps the response leg open from one that only delivers the opening.
  out=$($hexec l3h1 python3 "$CLIENT" halfsplit "$VIP" "$port" 500 2>&1)
  sockmap_result "E-14 $m: half-closed client, answer cut mid-stream" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  # E-15: the FIN lands on an answer already in flight. See the registration
  # comment for why this is not a duplicate of E-14.
  out=$($hexec l3h1 python3 "$CLIENT" halfmid "$VIP" "$port" 500 2>&1)
  sockmap_result "E-15 $m: half-close after the answer started" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  out=$($hexec l3h1 python3 "$CLIENT" halfinflight "$VIP" "$port" 2>&1)
  sockmap_result "E-16 $m: half-close with the answer in flight" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"

  out=$($hexec l3h1 python3 "$CLIENT" halfpartial "$VIP" "$port" 2>&1)
  sockmap_result "E-12 $m: partial request then half-close" \
    "$([[ $out == OK* ]] && echo OK || echo FAILED)" "$out"
done

# ---------- Step 6: invariant counters ----------
sockmap_section 6 "Verdict passes and failure logs"
sockmap_assert_no_pass llb1 "$PEER_MISS_START" "no socket ran the verdict without a peer"
sockmap_assert_no_redirect_drop llb1 "$DROP_START" "no redirect found its target missing"
fail_cnt=$(sockmap_log_failure_count llb1)
if (( fail_cnt == 0 )); then
  sockmap_result "no sockmap failure messages in the daemon logs" "OK"
else
  sockmap_result "no sockmap failure messages in the daemon logs" "FAILED" "$fail_cnt occurrences"
fi

sockmap_finalize "$SCENARIO"
