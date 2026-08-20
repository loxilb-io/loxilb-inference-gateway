#!/bin/bash
# cicd/trtllm-pd-disagg/validation.sh — TRT-LLM P/D rewriter-dialect validation
# Legs:
#   A  acceptance: the trtllm P/D rule exists (the config-time guard admits
#      pd_disagg + kvExactMode=1 now) + the still-rejected shapes stay
#      rejected (kvExactMode=2, non-default kvZmqPort, kvDpRankCount>1)
#   B  happy path non-streaming: context_only splice -> buffered ctx response
#      -> generation_only re-splice. The generation mock 400s any opaque
#      state it did not issue, so a 200 with the generation text PROVES the
#      gateway relayed the EXTRACTED span verbatim
#   C  happy path streaming (SSE from the generation leg, [DONE] intact)
#   D  context early exit: a scripted finish_reason=stop context response is
#      relayed to the client, the generation leg is SKIPPED, and
#      pd_trt_ctx_early_exit_total ticks (non-stream + one-chunk SSE re-frame)
#   E  extra="forbid" dialect pin: a client body carrying vLLM
#      kv_transfer_params draws the engine's 400 (relayed, not masked, and
#      never silently stripped)
#   F  origin-5xx demotion: a context mock erroring 500 repeatedly is
#      breaker-demoted ([CB_ORIGIN] + pd_cb_flips) while every client
#      request stays 200 via generation-side recompute; heal re-admits
#   G  KV plane over the polled drain: mode-1 subscribers on the CONTEXT
#      EPs only, admission verdicts, stored-event ingest, event_id
#      gap -> resync -> continued ingest
#   H  tri-engine coexistence: trtllm + sglang + vllm P/D rules on ONE
#      gateway all serving
#   I  hygiene: pd_trt/tier15/subscriber metric families exported

source ../common.sh
exec < /dev/null

VIP="10.10.10.254"
CACERT="/tmp/minica.pem"
MODEL="Qwen/Qwen2.5-7B-Instruct"

echo SCENARIO-trtllm-pd-disagg

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

mget() {  # un-labelled counter (0 if absent)
  local v
  v=$($hexec llb1 curl -s http://localhost:11111/netlox/v1/metrics 2>/dev/null | \
      awk -v n="$1" '$1==n{print $2}')
  echo "${v:-0}"
}

msum() {  # sum a labelled series by metric-name prefix
  $hexec llb1 curl -s http://localhost:11111/netlox/v1/metrics 2>/dev/null | \
    grep "^$1" | awk '{s+=$NF} END {print s+0}'
}

mwait() {  # poll until counter exceeds base (prometheus ingest lags C atomics)
  local name="$1" base="$2" timeout="${3:-20}" v
  for i in $(seq 1 "$timeout"); do
    v=$(mget "$name")
    [ "$v" -gt "$base" ] 2>/dev/null && { echo "$v"; return 0; }
    sleep 1
  done
  echo "${v:-0}"
}

completion() {  # completion <reqid> <stream> <port> [extra-json-fields]
  local reqid="$1" stream="$2" port="$3" extra="${4:-}"
  $dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
    "https://$VIP:$port/v1/completions" \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: $reqid" \
    -d '{"model":"'"$MODEL"'","prompt":"The prefix corpus for run '"$RUN"' block filling: 111 222 333 444 555 666 777 888 999 000 aaa bbb ccc ddd eee fff. Question:","max_tokens":16,"temperature":0,"stream":'"$stream"''"$extra"'}' \
    -w "\nHTTPSTATUS:%{http_code}" 2>&1
}

status_of() { echo "$1" | grep 'HTTPSTATUS:' | tail -1 | cut -d: -f2; }

tarm() {  # tarm <ep> <knob> [json] — trtllm mock admin (:9600)
  if [ -n "${3:-}" ]; then
    $dexec "$1" curl -s -X POST "http://127.0.0.1:9600/admin/$2" -d "$3" > /dev/null
  else
    $dexec "$1" curl -s -X POST "http://127.0.0.1:9600/admin/$2" > /dev/null
  fi
}

tstatus() {  # tstatus <ep> <field>
  $dexec "$1" curl -s "http://127.0.0.1:9600/admin/status" 2>/dev/null | \
    python3 -c "import json,sys; print(json.load(sys.stdin).get('$2',0))" 2>/dev/null || echo 0
}

tdisarm_all() { tarm l3ep1 reset; tarm l3ep2 reset; tarm l3ep3 reset; }

post_neg() {  # post_neg <json> — expect the rule POST to be REJECTED
  local out
  out=$($hexec llb1 curl -s -o /dev/null -w '%{http_code}' \
    -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
    -H 'Content-Type: application/json' -d "$1" 2>/dev/null)
  [ "$out" != "200" ] && [ "$out" != "204" ]
}

############################################################################
echo "Leg A: acceptance + surviving guards"
############################################################################

LBS=$($hexec llb1 curl -s "http://localhost:11111/netlox/v1/config/loadbalancer/all" 2>/dev/null)
echo "$LBS" | grep -q '"port":2040' && echo "$LBS" | grep -q '"kvEngineType":"trtllm"'
check "A1: trtllm P/D rule :2040 accepted and listed (guard flip live)" $?

NEG_BASE='{"serviceArguments":{"externalIP":"'"$VIP"'","port":2099,"protocol":"tcp","sel":0,"mode":4,"pd_disagg_mode":true,"kvEngineType":"trtllm","host":"'"$VIP"'"ARGS},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8355,"weight":1,"ep_role":1},{"endpointIP":"33.33.33.1","targetPort":8355,"weight":1,"ep_role":2}]}'
post_neg "$(echo "$NEG_BASE" | sed 's/ARGS/,"kvExactMode":2/')"
check "A2: trtllm + kvExactMode=2 (nats) still rejected" $?
post_neg "$(echo "$NEG_BASE" | sed 's/ARGS/,"kvExactMode":1,"kvZmqPort":5561/')"
check "A3: trtllm + non-default kvZmqPort still rejected" $?
post_neg "$(echo "$NEG_BASE" | sed 's/ARGS/,"kvExactMode":1,"kvDpRankCount":2/')"
check "A4: trtllm + kvDpRankCount>1 still rejected" $?

############################################################################
echo "Leg B: P/D happy path non-streaming (relay-integrity pinned)"
############################################################################

B_CTX_BASE=$(( $(tstatus l3ep1 ctx_served) + $(tstatus l3ep2 ctx_served) ))
B_GEN_BASE=$(tstatus l3ep3 gen_served)

B_OUT=$(completion "$RUN-leg-b" false 2040)
B_STATUS=$(status_of "$B_OUT")
[ "$B_STATUS" = "200" ]
check "B1: 200 via the trtllm P/D VIP" $?
echo "$B_OUT" | grep -q "answer is 42"
check "B2: generation text relayed (a reconstructed/garbled opaque state would have 400'd)" $?

B_CTX_NOW=$(( $(tstatus l3ep1 ctx_served) + $(tstatus l3ep2 ctx_served) ))
B_GEN_NOW=$(tstatus l3ep3 gen_served)
[ "$B_CTX_NOW" -gt "$B_CTX_BASE" ] && [ "$B_GEN_NOW" -gt "$B_GEN_BASE" ]
check "B3: both legs ran (ctx $B_CTX_BASE->$B_CTX_NOW, gen $B_GEN_BASE->$B_GEN_NOW)" $?

############################################################################
echo "Leg C: P/D happy path streaming"
############################################################################

C_OUT=$(completion "$RUN-leg-c" true 2040)
C_FRAMES=$(echo "$C_OUT" | grep -c '^data: ')
echo "$C_OUT" | grep -q 'data: \[DONE\]' && [ "$C_FRAMES" -ge 2 ] && \
  echo "$C_OUT" | grep -q '42'
check "C1: SSE stream from the generation leg ($C_FRAMES frames + [DONE])" $?

############################################################################
echo "Leg D: context early exit (scripted finish_reason=stop)"
############################################################################

D_BASE=$(mget loxilb_pd_trt_ctx_early_exit_total)
D_GEN_BASE=$(tstatus l3ep3 gen_served)
tarm l3ep1 finish-reason '{"value":"stop"}'
tarm l3ep2 finish-reason '{"value":"stop"}'

D_OUT=$(completion "$RUN-leg-d" false 2040)
D_STATUS=$(status_of "$D_OUT")
[ "$D_STATUS" = "200" ] && echo "$D_OUT" | grep -q "DONE."
check "D1: buffered context response relayed to the client (200 + ctx text)" $?
D_NOW=$(mwait loxilb_pd_trt_ctx_early_exit_total "$D_BASE" 20)
[ "$D_NOW" -gt "$D_BASE" ]
check "D2: pd_trt_ctx_early_exit ticked ($D_BASE -> $D_NOW)" $?
[ "$(tstatus l3ep3 gen_served)" = "$D_GEN_BASE" ]
check "D3: generation leg SKIPPED (gen_served flat at $D_GEN_BASE)" $?
tdisarm_all

tarm l3ep1 finish-reason '{"value":"stop"}'
tarm l3ep2 finish-reason '{"value":"stop"}'
D4_OUT=$(completion "$RUN-leg-d4" true 2040)
echo "$D4_OUT" | grep -q '^data: ' && echo "$D4_OUT" | grep -q 'data: \[DONE\]' && \
  echo "$D4_OUT" | grep -q "DONE."
check "D4: streaming client got the one-chunk SSE re-frame + [DONE]" $?
tdisarm_all

############################################################################
echo "Leg E: extra=forbid dialect pin (client-carried vLLM field)"
############################################################################

E_OUT=$(completion "$RUN-leg-e" false 2040 ',"kv_transfer_params":{"do_remote_decode":true}')
E_STATUS=$(status_of "$E_OUT")
[ "$E_STATUS" = "400" ]
check "E1: engine 400 relayed for a mis-dialected body (got $E_STATUS; a 200 would mean the gateway silently stripped it, a 5xx that it masked it)" $?

############################################################################
echo "Leg F: origin-5xx demotion (context mock repeat-500s)"
############################################################################

F_FLIPS_BASE=$(mget loxilb_pd_cb_flips_total)
tarm l3ep1 fail-count '{"count":30}'
F_BAD=0
for i in $(seq 1 10); do
  F_OUT=$(completion "$RUN-leg-f-$i" false 2040)
  [ "$(status_of "$F_OUT")" = "200" ] || F_BAD=$((F_BAD+1))
done
[ "$F_BAD" = "0" ]
check "F1: 10/10 requests 200 during the 5xx storm (generation recompute held)" $?
F_FLIPS_NOW=$(mwait loxilb_pd_cb_flips_total "$F_FLIPS_BASE" 20)
[ "$F_FLIPS_NOW" -gt "$F_FLIPS_BASE" ]
check "F2: breaker flipped on the origin streak (pd_cb_flips $F_FLIPS_BASE -> $F_FLIPS_NOW)" $?
$dexec llb1 grep -q 'CB_ORIGIN' /var/log/loxilbdp.log
check "F3: [CB_ORIGIN] demotion marker in the dp log" $?

F_CTX1_OPEN=$(tstatus l3ep1 ctx_served)
for i in $(seq 1 4); do completion "$RUN-leg-f-open-$i" false 2040 > /dev/null; done
[ "$(tstatus l3ep1 ctx_served)" = "$F_CTX1_OPEN" ]
check "F4: demoted context EP served ZERO requests while OPEN" $?
tdisarm_all

echo "  sitting out the breaker open timeout (35s)..."
sleep 35
F_RECOVERED=1
for i in $(seq 1 20); do
  completion "$RUN-leg-f-rec-$i" false 2040 > /dev/null
  [ "$(tstatus l3ep1 ctx_served)" -gt "$F_CTX1_OPEN" ] && { F_RECOVERED=0; break; }
  sleep 2
done
check "F5: demoted context EP re-admitted after the heal cycle" $F_RECOVERED

############################################################################
echo "Leg G: KV plane over the polled drain (mode-1, CONTEXT EPs only)"
############################################################################

G_SUBS=$(msum loxilb_kv_subscriber_connected)
[ "$G_SUBS" = "2" ]
check "G1: exactly the 2 CONTEXT EPs subscribed (got $G_SUBS — mode-1 role filter + serving-port dial)" $?

G_SVC=$($hexec llb1 curl -s http://localhost:11111/netlox/v1/metrics 2>/dev/null | \
  sed -n 's/^loxilb_kv_subscriber_connected{ep="[0-9]*",service="\([0-9]*\)".*/\1/p' | head -1)
G_ADM=0
for ep in 0 1; do
  V=$($hexec llb1 curl -s "http://localhost:11111/netlox/v1/config/ai/kv/inventory?service_id=${G_SVC:-1}&ep_idx=$ep" 2>/dev/null | \
    python3 -c "import json,sys; print(json.load(sys.stdin).get('admission',''))" 2>/dev/null)
  [ "$V" = "admitted" ] && G_ADM=$((G_ADM+1))
done
[ "$G_ADM" = "2" ]
check "G2: both CONTEXT EPs admitted via /server_info (v1_block_key/32)" $?

# stored events from the leg-B/C traffic must have drained + ingested
G_INV=0
for ep in 0 1; do
  T=$($hexec llb1 curl -s "http://localhost:11111/netlox/v1/config/ai/kv/inventory?service_id=${G_SVC:-1}&ep_idx=$ep" 2>/dev/null | \
    python3 -c "import json,sys; print(json.load(sys.stdin).get('total',0))" 2>/dev/null)
  G_INV=$(( G_INV + ${T:-0} ))
done
[ "$G_INV" -gt 0 ]
check "G3: stored events ingested into the inventory ($G_INV blocks)" $?

# gap -> resync -> continued ingest (poller survives, queue keeps draining)
tarm l3ep1 event-gap '{"skip":100}'
tarm l3ep1 event-push '{"tokens":64}'
G_DRAINED=1
for i in $(seq 1 15); do
  [ "$(tstatus l3ep1 events_queued)" = "0" ] && { G_DRAINED=0; break; }
  sleep 1
done
check "G4: poller kept draining across an event_id gap of 100 (queue empty again)" $G_DRAINED
sleep 2
tarm l3ep1 event-push '{"tokens":64}'
G_DRAINED2=1
for i in $(seq 1 15); do
  [ "$(tstatus l3ep1 events_queued)" = "0" ] && { G_DRAINED2=0; break; }
  sleep 1
done
check "G5: post-resync ingest continues (self-heal, no permanent wedge)" $G_DRAINED2

############################################################################
echo "Leg H: tri-engine coexistence on one gateway"
############################################################################

H_TRT=$(completion "$RUN-leg-h-trt" false 2040)
[ "$(status_of "$H_TRT")" = "200" ]
check "H1: trtllm P/D rule :2040 serving" $?

H_SGL=$($dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
  "https://$VIP:2042/v1/chat/completions" -H "Content-Type: application/json" \
  -H "X-Request-Id: $RUN-leg-h-sgl" \
  -d '{"model":"'"$MODEL"'","messages":[{"role":"user","content":"hello"}],"max_tokens":16,"stream":false}' \
  -w "\nHTTPSTATUS:%{http_code}" 2>&1)
[ "$(status_of "$H_SGL")" = "200" ]
check "H2: sglang P/D rule :2042 serving (dual-dispatch machine untouched)" $?

H_VLLM=$($dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
  "https://$VIP:2043/v1/chat/completions" -H "Content-Type: application/json" \
  -H "X-Request-Id: $RUN-leg-h-vllm" \
  -d '{"model":"'"$MODEL"'","messages":[{"role":"user","content":"hello"}],"max_tokens":16,"stream":false}' \
  -w "\nHTTPSTATUS:%{http_code}" 2>&1)
[ "$(status_of "$H_VLLM")" = "200" ]
check "H3: vllm P/D rule :2043 serving (sibling sequential machine untouched)" $?

############################################################################
echo "Leg I: hygiene — metric families exported"
############################################################################

I_METRICS=$($hexec llb1 curl -s http://localhost:11111/netlox/v1/metrics 2>/dev/null)
echo "$I_METRICS" | grep -q "loxilb_pd_trt_ctx_early_exit_total" && \
  echo "$I_METRICS" | grep -q "loxilb_kv_subscriber_connected" && \
  echo "$I_METRICS" | grep -q "loxilb_pd_cb_flips_total"
check "I1: pd_trt / kv_subscriber / cb metric families present" $?

echo "#########################################"
echo "Results"
echo "#########################################"

if [ "$code" = "0" ]; then
  echo SCENARIO-trtllm-pd-disagg [OK]
else
  echo SCENARIO-trtllm-pd-disagg [FAILED]
fi

exit $code
