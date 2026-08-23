#!/bin/bash
# cicd/llamacpp-lb/validation.sh — llama.cpp plain-LB typed-engine validation
# Legs:
#   A  acceptance + guards: the typed CHWBL rule exists; every KV/P/D shape
#      stays rejected for llamacpp (kvExactMode, pd_disagg_mode, non-default
#      kvZmqPort / kvDpRankCount / kvBlockSize, any explicit kvHashAlgo)
#   B  contract pins via the VIP: non-stream + stream happy path with
#      cached_tokens receipts and [DONE]; unknown request fields SILENTLY
#      tolerated (200 — the anti-TRT posture); malformed JSON relayed as the
#      engine's 500 (the live-pinned taxonomy quirk, not masked)
#   C  ping-through-VIP: a scripted mid-stream stall longer than the mock's
#      --sse-ping-interval must deliver bare ":" comment frames to the
#      client THROUGH the relay, then finish the stream + [DONE] (pins the
#      relay + idle-clock behavior the GPU fleet could never exhibit —
#      prefill there outruns any sane ping interval)
#   D  CHWBL system-prompt affinity (system-prompt keying, positive): two system-prompt
#      families -> each family consistently lands ONE EP; repeats carry
#      cached_tokens>0 receipts; [PREFIX_EXTRACTED] receipts appear in the
#      dp log
#   E  user-only affinity fallback: payloads with NO system message hash a
#      BOUNDED prefix of the first user message ([PREFIX_USER_FALLBACK]
#      receipts) — a shared opening co-locates on ONE EP with warm
#      cached_tokens receipts; bodies with no user message at all (empty
#      messages / assistant-only) still spray (negative stays pinned)
#   F  session-header stickiness on the RR rule: same x-session-id ->
#      one EP across differing bodies; a second session stays consistent
#   G  503-loading window: an EP answering the "Loading model" 503 is
#      health-probed out (zero serves while out), then re-admitted after
#      the window clears
#   H  origin-5xx demotion on plain LB: the first streak of engine 500s is
#      RELAYED (error obj intact, not masked — demotion is not retry), then
#      the breaker opens on the origin streak ([CB_ORIGIN] + pd_cb_flips);
#      the 5xx EP serves ZERO while OPEN and is re-admitted only after a
#      HALF_OPEN probe draws an ORIGIN success (a connect success alone
#      must not close an origin-tripped breaker)
#   I  quad-engine coexistence: llamacpp + trtllm + sglang + vllm rules all
#      serving on ONE gateway
#   J  hygiene: loxilb_ai_engine_info{engine="llamacpp"} exported; the
#      /props admission probe surfaced l3ep3's scripted build mismatch in
#      loxilb_ai_llamacpp_probe_warnings_total

source ../common.sh
exec < /dev/null

VIP="10.10.10.254"
CACERT="/tmp/minica.pem"

echo SCENARIO-llamacpp-lb

RUN="r$$-$RANDOM"
code=0

check() {
  local desc="$1" result="$2"
  if [ "$result" = "0" ]; then
    echo "  PASS: $desc"
  else
    echo "  FAIL: $desc"
    code=1
  fi
}

msum() {  # sum a labelled series by metric-name prefix
  $hexec llb1 curl -s http://localhost:11111/netlox/v1/metrics 2>/dev/null | \
    grep "^$1" | awk '{s+=$NF} END {print s+0}'
}

status_of() { echo "$1" | grep 'HTTPSTATUS:' | tail -1 | cut -d: -f2; }

# chat <reqid> <stream> <port> <system-text|-> <user-text> [extra-curl-args]
chat() {
  local reqid="$1" stream="$2" port="$3" sys="$4" usr="$5"; shift 5
  local msgs
  if [ "$sys" = "-" ]; then
    msgs='[{"role":"user","content":"'"$usr"'"}]'
  else
    msgs='[{"role":"system","content":"'"$sys"'"},{"role":"user","content":"'"$usr"'"}]'
  fi
  $dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
    "https://$VIP:$port/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: $reqid" "$@" \
    -d '{"model":"whatever","messages":'"$msgs"',"max_tokens":16,"temperature":0,"stream":'"$stream"',"stream_options":{"include_usage":true}}' \
    -w "\nHTTPSTATUS:%{http_code}" 2>&1
}

larm() {  # larm <ep> <knob> [json] — llamacpp mock admin (:9700)
  if [ -n "${3:-}" ]; then
    $dexec "$1" curl -s -X POST "http://127.0.0.1:9700/admin/$2" -d "$3" > /dev/null
  else
    $dexec "$1" curl -s -X POST "http://127.0.0.1:9700/admin/$2" > /dev/null
  fi
}

lstatus() {  # lstatus <ep> <field>
  $dexec "$1" curl -s "http://127.0.0.1:9700/admin/status" 2>/dev/null | \
    python3 -c "import json,sys; print(json.load(sys.stdin).get('$2',0))" 2>/dev/null || echo 0
}

ldisarm_all() { larm l3ep1 reset; larm l3ep2 reset; larm l3ep3 reset; }

served_snapshot() {  # -> "s1 s2 s3"
  echo "$(lstatus l3ep1 served) $(lstatus l3ep2 served) $(lstatus l3ep3 served)"
}

eps_advanced() {  # eps_advanced "<before>" "<after>" -> count of EPs that moved
  python3 -c "
b = '$1'.split(); a = '$2'.split()
print(sum(1 for x, y in zip(b, a) if int(y) > int(x)))"
}

cached_of() {  # parse usage cached_tokens out of a chat() capture (non-stream)
  echo "$1" | grep -v 'HTTPSTATUS:' | python3 -c "
import json, sys
try:
    j = json.loads(sys.stdin.read())
    print((j.get('usage', {}).get('prompt_tokens_details') or {}).get('cached_tokens', -1))
except Exception:
    print(-1)" 2>/dev/null
}

prefix_count() {  # [PREFIX_EXTRACTED] receipts in the dp log so far
  $dexec llb1 sh -c "grep -c 'PREFIX_EXTRACTED' /var/log/loxilbdp.log 2>/dev/null || echo 0"
}

fallback_count() {  # [PREFIX_USER_FALLBACK] receipts in the dp log so far
  $dexec llb1 sh -c "grep -c 'PREFIX_USER_FALLBACK' /var/log/loxilbdp.log 2>/dev/null || echo 0"
}

post_neg() {  # post_neg <json> — expect the rule POST to be REJECTED
  local out
  out=$($hexec llb1 curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
    -H 'Content-Type: application/json' -d "$1" 2>/dev/null)
  [ "$out" != "200" ] && [ "$out" != "204" ]
}

# clean knob slate + cold mock prefix stores — makes the suite rerun-safe
# on a standing topology (B2's cold-baseline receipt depends on it)
ldisarm_all

############################################################################
echo "Leg A: acceptance + plain-LB-only guards"
############################################################################

LBS=$($hexec llb1 curl -s "http://localhost:11111/netlox/v1/config/loadbalancer/all" 2>/dev/null)
echo "$LBS" | grep -q '"port":2044' && echo "$LBS" | grep -q '"kvEngineType":"llamacpp"' && \
  echo "$LBS" | grep -q '"port":2045'
check "A1: llamacpp typed rules :2044 (CHWBL) + :2045 (RR+session) accepted and listed" $?

NEG_BASE='{"serviceArguments":{"externalIP":"'"$VIP"'","port":2099,"protocol":"tcp","sel":8,"mode":4,"kvEngineType":"llamacpp","host":"'"$VIP"'"ARGS},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8085,"weight":1},{"endpointIP":"32.32.32.1","targetPort":8085,"weight":1}]}'
post_neg "$(echo "$NEG_BASE" | sed 's/ARGS/,"kvExactMode":1/')"
check "A2: llamacpp + kvExactMode rejected (no KV event plane)" $?
post_neg "$(echo "$NEG_BASE" | sed 's/ARGS/,"pd_disagg_mode":true/')"
check "A3: llamacpp + pd_disagg_mode rejected (no P/D)" $?
post_neg "$(echo "$NEG_BASE" | sed 's/ARGS/,"kvZmqPort":5561/')"
check "A4: llamacpp + non-default kvZmqPort rejected" $?
post_neg "$(echo "$NEG_BASE" | sed 's/ARGS/,"kvDpRankCount":2/')"
check "A5: llamacpp + kvDpRankCount>1 rejected" $?
post_neg "$(echo "$NEG_BASE" | sed 's/ARGS/,"kvBlockSize":32/')"
check "A6: llamacpp + non-default kvBlockSize rejected" $?
post_neg "$(echo "$NEG_BASE" | sed 's/ARGS/,"kvHashAlgo":"sha256_cbor"/')"
check "A7: llamacpp + explicit kvHashAlgo rejected (empty coherence row)" $?

############################################################################
echo "Leg B: contract pins via the VIP (:2044)"
############################################################################

B_OUT=$(chat "$RUN-leg-b1" false 2044 "sys $RUN b" "hello there")
[ "$(status_of "$B_OUT")" = "200" ] && echo "$B_OUT" | grep -q "mock llama.cpp answer"
check "B1: non-stream 200 + content via the typed CHWBL VIP" $?
B1_CT=$(cached_of "$B_OUT")
[ "$B1_CT" = "0" ]
check "B2: first-contact receipt cached_tokens=0 (got $B1_CT — the cold baseline the affinity leg builds on)" $?

B_OUT=$(chat "$RUN-leg-b3" true 2044 "sys $RUN b" "hello there")
B_FRAMES=$(echo "$B_OUT" | grep -c '^data: ')
echo "$B_OUT" | grep -q 'data: \[DONE\]' && [ "$B_FRAMES" -ge 3 ] && \
  echo "$B_OUT" | grep -q '"usage"'
check "B3: SSE stream ($B_FRAMES frames), include_usage final chunk, [DONE] intact" $?

B_OUT=$($dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
  "https://$VIP:2044/v1/chat/completions" -H "Content-Type: application/json" \
  -d '{"model":"m","messages":[{"role":"user","content":"ok"}],"max_tokens":8,"stream":false,"kv_transfer_params":{"do_remote_decode":true},"bootstrap_host":"x","totally_unknown_field_xyz":1}' \
  -w "\nHTTPSTATUS:%{http_code}" 2>&1)
[ "$(status_of "$B_OUT")" = "200" ]
check "B4: unknown/foreign-dialect fields SILENTLY tolerated (200 — the vLLM posture, opposite of TRT's forbid)" $?

B_OUT=$($dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
  "https://$VIP:2044/v1/chat/completions" -H "Content-Type: application/json" \
  -d '{not json' -w "\nHTTPSTATUS:%{http_code}" 2>&1)
B_STATUS=$(status_of "$B_OUT")
[ "$B_STATUS" = "500" ] && echo "$B_OUT" | grep -q '"error"'
check "B5: malformed JSON relayed as the engine's 500 + error obj (got $B_STATUS — the live-pinned quirk; a 400 means something reshaped the taxonomy)" $?

############################################################################
echo "Leg C: ping-through-VIP (scripted stall > sse-ping-interval)"
############################################################################

larm l3ep1 stall '{"secs":6}'
larm l3ep2 stall '{"secs":6}'
larm l3ep3 stall '{"secs":6}'
C_OUT=$(chat "$RUN-leg-c" true 2044 "sys $RUN c" "stall please")
C_PINGS=$(echo "$C_OUT" | grep -c '^:')
C_DONE=$(echo "$C_OUT" | grep -c 'data: \[DONE\]')
[ "$C_PINGS" -ge 2 ] && [ "$C_DONE" = "1" ] && [ "$(status_of "$C_OUT")" = "200" ]
check "C1: $C_PINGS bare ':' ping frames relayed mid-stream, stream still completed + [DONE]" $?
ldisarm_all

############################################################################
echo "Leg D: CHWBL system-prompt affinity + receipts (positive)"
############################################################################

D_PFX_BASE=$(prefix_count)
D_FAIL=0
for fam in famA famB; do
  BEFORE=$(served_snapshot)
  D_CT_LAST=-1
  for rep in 1 2 3; do
    D_OUT=$(chat "$RUN-leg-d-$fam-$rep" false 2044 \
      "You are the $fam corpus assistant for run $RUN. Rules: 111 222 333 444 555 666 777 888 999." \
      "the $fam question, rep $rep")
    [ "$(status_of "$D_OUT")" = "200" ] || D_FAIL=1
    D_CT_LAST=$(cached_of "$D_OUT")
  done
  AFTER=$(served_snapshot)
  MOVED=$(eps_advanced "$BEFORE" "$AFTER")
  [ "$MOVED" = "1" ] || { D_FAIL=1; echo "  $fam spread over $MOVED EPs (want 1): $BEFORE -> $AFTER"; }
  [ "$D_CT_LAST" -gt 0 ] 2>/dev/null || { D_FAIL=1; echo "  $fam rep-3 cached_tokens=$D_CT_LAST (want >0)"; }
done
[ "$D_FAIL" = "0" ]
check "D1: each system-prompt family pinned to exactly ONE EP with warm cached_tokens receipts" $?
sleep 3
D_PFX_NOW=$(prefix_count)
[ "$D_PFX_NOW" -gt "$D_PFX_BASE" ]
check "D2: [PREFIX_EXTRACTED] receipts in the dp log ($D_PFX_BASE -> $D_PFX_NOW) — CHWBL routed on content, not spray" $?

############################################################################
echo "Leg E: user-only affinity fallback (bounded first-user-message prefix)"
############################################################################

sleep 2
E_FB_BASE=$(fallback_count)
# shared opening deliberately LONGER than the 256B fallback bound, with a
# divergent tail per rep — co-location must key on the bounded opening only
E_OPEN=$(python3 -c "print(('user-only $RUN corpus opening sentence for the fallback affinity leg. ' * 6).strip())")
E_BAD=0
E_CT_LAST=-1
E_BEFORE=$(served_snapshot)
for rep in 1 2 3; do
  E_OUT=$(chat "$RUN-leg-e-$rep" false 2044 - "$E_OPEN divergent tail rep $rep")
  [ "$(status_of "$E_OUT")" = "200" ] || E_BAD=$((E_BAD+1))
  E_CT_LAST=$(cached_of "$E_OUT")
done
E_AFTER=$(served_snapshot)
E_MOVED=$(eps_advanced "$E_BEFORE" "$E_AFTER")
sleep 3
E_FB_NOW=$(fallback_count)
[ "$E_BAD" = "0" ] && [ "$E_FB_NOW" -gt "$E_FB_BASE" ]
check "E1: 3/3 user-only requests served WITH [PREFIX_USER_FALLBACK] receipts ($E_FB_BASE -> $E_FB_NOW) — no-system bodies now hash the bounded user opening" $?
[ "$E_MOVED" = "1" ] && [ "$E_CT_LAST" -gt 0 ] 2>/dev/null
check "E2: shared >256B opening with divergent tails co-located on ONE EP ($E_BEFORE -> $E_AFTER) with warm cached_tokens (rep-3: $E_CT_LAST) — the spray is gone" $?

# negative stays pinned: bodies with NO user message at all still spray
E_FB_NEG_BASE=$(fallback_count)
E_PFX_NEG_BASE=$(prefix_count)
E_NEG_BAD=0
for body in '{"model":"m","messages":[],"max_tokens":8,"stream":false}' \
            '{"model":"m","messages":[{"role":"assistant","content":"prior answer only"}],"max_tokens":8,"stream":false}'; do
  E_OUT=$($dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
    "https://$VIP:2044/v1/chat/completions" -H "Content-Type: application/json" \
    -d "$body" -w "\nHTTPSTATUS:%{http_code}" 2>&1)
  [ "$(status_of "$E_OUT")" = "200" ] || E_NEG_BAD=$((E_NEG_BAD+1))
done
sleep 3
[ "$E_NEG_BAD" = "0" ] && [ "$(fallback_count)" = "$E_FB_NEG_BASE" ] && \
  [ "$(prefix_count)" = "$E_PFX_NEG_BASE" ]
check "E3: empty-messages + assistant-only bodies served with ZERO new extraction/fallback receipts — the no-user spray path stays pinned" $?

############################################################################
echo "Leg F: session-header stickiness (:2045, x-session-id)"
############################################################################

F_FAIL=0
for sess in s1 s2; do
  BEFORE=$(served_snapshot)
  for rep in 1 2 3; do
    F_OUT=$(chat "$RUN-leg-f-$sess-$rep" false 2045 - "session $sess body variant $rep" \
      -H "x-session-id: $RUN-$sess")
    [ "$(status_of "$F_OUT")" = "200" ] || F_FAIL=1
  done
  AFTER=$(served_snapshot)
  MOVED=$(eps_advanced "$BEFORE" "$AFTER")
  [ "$MOVED" = "1" ] || { F_FAIL=1; echo "  session $sess spread over $MOVED EPs: $BEFORE -> $AFTER"; }
done
[ "$F_FAIL" = "0" ]
check "F1: same x-session-id -> one EP across differing bodies (both sessions)" $?

############################################################################
echo "Leg G: 503-loading window -> probe hold-out -> re-admission"
############################################################################

larm l3ep1 loading-on
G_OUT_HELD=1
for i in $(seq 1 30); do
  $hexec llb1 curl -s "http://localhost:11111/netlox/v1/config/loadbalancer/all" 2>/dev/null | \
    grep -q '"state":"inactive"' && { G_OUT_HELD=0; break; }
  sleep 1
done
check "G1: loading EP marked inactive by the health probe (~${i}s)" $G_OUT_HELD

G_EP1_BASE=$(lstatus l3ep1 served)
G_BAD=0
for i in $(seq 1 6); do
  G_OUT=$(chat "$RUN-leg-g-$i" false 2045 - "loading drill $i")
  [ "$(status_of "$G_OUT")" = "200" ] || G_BAD=$((G_BAD+1))
done
[ "$G_BAD" = "0" ] && [ "$(lstatus l3ep1 served)" = "$G_EP1_BASE" ]
check "G2: 6/6 requests 200 while the loading EP served ZERO" $?

larm l3ep1 loading-off
G_READMIT=1
for i in $(seq 1 30); do
  chat "$RUN-leg-g-re-$i" false 2045 - "readmit probe $i" > /dev/null
  [ "$(lstatus l3ep1 served)" -gt "$G_EP1_BASE" ] 2>/dev/null && { G_READMIT=0; break; }
  sleep 2
done
check "G3: EP re-admitted after the loading window cleared" $G_READMIT

############################################################################
echo "Leg H: origin-5xx demotion on plain LB (relay intact, then breaker opens)"
############################################################################

H_FLIPS_BASE=$(msum loxilb_pd_cb_flips_total)
larm l3ep2 fail-count '{"count":30}'
H_SAW_500=0
H_MASKED=0
for i in $(seq 1 12); do
  H_OUT=$(chat "$RUN-leg-h-$i" false 2045 - "storm probe $i")
  H_ST=$(status_of "$H_OUT")
  if [ "$H_ST" = "500" ]; then
    H_SAW_500=$((H_SAW_500+1))
    echo "$H_OUT" | grep -q 'injected_fault' || H_MASKED=1
  fi
done
[ "$H_SAW_500" -ge 1 ] && [ "$H_MASKED" = "0" ]
check "H1: the first origin-5xx streak relayed with the error obj intact ($H_SAW_500 seen, none masked — demotion is not retry)" $?

H_FLIPS_NOW=$H_FLIPS_BASE
for i in $(seq 1 20); do
  H_FLIPS_NOW=$(msum loxilb_pd_cb_flips_total)
  [ "$H_FLIPS_NOW" -gt "$H_FLIPS_BASE" ] 2>/dev/null && break
  sleep 1
done
[ "$H_FLIPS_NOW" -gt "$H_FLIPS_BASE" ]
check "H2: breaker flipped on the origin streak (pd_cb_flips $H_FLIPS_BASE -> $H_FLIPS_NOW)" $?
$dexec llb1 grep -q 'CB_ORIGIN' /var/log/loxilbdp.log
check "H3: [CB_ORIGIN] demotion marker in the dp log" $?

H_EP2_OPEN=$(lstatus l3ep2 served)
H_OPEN_BAD=0
for i in $(seq 1 6); do
  H_OUT=$(chat "$RUN-leg-h-open-$i" false 2045 - "post-trip probe $i")
  [ "$(status_of "$H_OUT")" = "200" ] || H_OPEN_BAD=$((H_OPEN_BAD+1))
done
[ "$H_OPEN_BAD" = "0" ] && [ "$(lstatus l3ep2 served)" = "$H_EP2_OPEN" ]
check "H4: 6/6 requests 200 while the demoted EP served ZERO (families re-homed off the 5xx EP)" $?
ldisarm_all

echo "  sitting out the breaker open timeout (35s)..."
sleep 35
H_RECOVERED=1
for i in $(seq 1 20); do
  chat "$RUN-leg-h-rec-$i" false 2045 - "readmit probe $i" > /dev/null
  [ "$(lstatus l3ep2 served)" -gt "$H_EP2_OPEN" ] 2>/dev/null && { H_RECOVERED=0; break; }
  sleep 2
done
check "H5: EP re-admitted after a HALF_OPEN probe drew an ORIGIN success (connect success alone must not close an origin-tripped breaker)" $H_RECOVERED

############################################################################
echo "Leg I: quad-engine coexistence on one gateway"
############################################################################

I_LCP=$(chat "$RUN-leg-i-lcp" false 2044 "sys $RUN i" "hello")
[ "$(status_of "$I_LCP")" = "200" ]
check "I1: llamacpp typed rule :2044 serving" $?

I_TRT=$($dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
  "https://$VIP:2040/v1/completions" -H "Content-Type: application/json" \
  -d '{"model":"m","prompt":"quad-engine check '"$RUN"' 111 222 333 444","max_tokens":8,"stream":false}' \
  -w "\nHTTPSTATUS:%{http_code}" 2>&1)
[ "$(status_of "$I_TRT")" = "200" ]
check "I2: trtllm P/D rule :2040 serving (sequential rewriter untouched)" $?

I_SGL=$($dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
  "https://$VIP:2042/v1/chat/completions" -H "Content-Type: application/json" \
  -d '{"model":"m","messages":[{"role":"user","content":"hello"}],"max_tokens":8,"stream":false}' \
  -w "\nHTTPSTATUS:%{http_code}" 2>&1)
[ "$(status_of "$I_SGL")" = "200" ]
check "I3: sglang P/D rule :2042 serving (dual-dispatch untouched)" $?

I_VLLM=$($dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
  "https://$VIP:2043/v1/chat/completions" -H "Content-Type: application/json" \
  -d '{"model":"m","messages":[{"role":"user","content":"hello"}],"max_tokens":8,"stream":false}' \
  -w "\nHTTPSTATUS:%{http_code}" 2>&1)
[ "$(status_of "$I_VLLM")" = "200" ]
check "I4: vllm P/D rule :2043 serving (sibling sequential untouched)" $?

############################################################################
echo "Leg J: hygiene — engine identity + admission-probe warning surfaced"
############################################################################

J_INFO=$($hexec llb1 curl -s http://localhost:11111/netlox/v1/metrics 2>/dev/null | \
  grep 'loxilb_ai_engine_info' | grep -c 'engine="llamacpp"')
[ "$J_INFO" -ge 1 ]
check "J1: loxilb_ai_engine_info{engine=\"llamacpp\"} exported ($J_INFO series)" $?

J_WARN=0
for i in $(seq 1 30); do
  J_WARN=$(msum 'loxilb_ai_llamacpp_probe_warnings_total')
  [ "$J_WARN" -ge 1 ] 2>/dev/null && break
  sleep 2
done
[ "$J_WARN" -ge 1 ]
check "J2: /props admission probe surfaced l3ep3's scripted build skew (warnings_total=$J_WARN)" $?

echo "#########################################"
echo "Results"
echo "#########################################"

if [ "$code" = "0" ]; then
  echo SCENARIO-llamacpp-lb [OK]
else
  echo SCENARIO-llamacpp-lb [FAILED]
fi

exit $code
