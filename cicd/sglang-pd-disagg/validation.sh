#!/bin/bash
# cicd/sglang-pd-disagg/validation.sh — SGLang P/D dual-dispatch validation
# Legs (design §3.6.2):
#   A  acceptance: the sglang P/D rule exists (the old config-time guard is
#      gone) + pdBootstrapPort on a vLLM rule is still rejected
#   B  happy path non-streaming (rendezvous-blocking prefill => a sequential
#      proxy FAILS this leg by construction) + fresh-room-per-request
#   C  happy path streaming (SSE relay from the decode leg, [DONE] intact)
#   D  prefill-500 -> pair abort: client 502, decode leg closed within N s
#   E  drain-leg death -> PAIR RETRY with a fresh room: client still 200,
#      pd_sg_room_retry ticks, same request id lands on BOTH prefill logs
#      with DIFFERENT rooms
#   F  decode-death -> 502 + the prefill drain leg is closed (not orphaned)
#   G  coexistence: vLLM P/D rule and SGLang P/D rule on one gateway
#   I  prefill-400 -> the origin CLIENT error is relayed to the client
#      VERBATIM (not masked as a gateway 502), decode leg still closed fast
#   J  streamable JSON (body over the inspect cap) -> fail-closed 503
#      pd_sg_oversize_unroutable BEFORE any engine sees a byte
#   H  hygiene: no mock-side contract violations, pd_sg_* metrics exported

source ../common.sh
exec < /dev/null

VIP="10.10.10.254"
CACERT="/tmp/minica.pem"
MODEL="Qwen/Qwen3-0.6B"

echo SCENARIO-sglang-pd-disagg

# Per-run tag: reqids must be unique across reruns against the same live
# environment, or the log-correlation greps match a previous run's lines.
RUN="r$$-$RANDOM"

code=0

check() {
  local desc="$1"
  local result="$2"
  if [ "$result" = "0" ]; then
    echo "  PASS: $desc"
  else
    echo "  FAIL: $desc"
    code=1
  fi
}

# Scrape one un-labelled counter from the Prometheus endpoint (0 if absent).
mget() {
  local name="$1"
  local v
  v=$($hexec llb1 curl -s http://localhost:11111/netlox/v1/metrics 2>/dev/null | \
      awk -v n="$name" '$1==n{print $2}')
  echo "${v:-0}"
}

# mwait <metric> <base> <timeout_s> — poll until the counter exceeds base
# (the prometheus layer ingests the sockproxy snapshot on an interval, so a
# scrape immediately after an event can lag behind the C-side atomics).
# Echoes the final value.
mwait() {
  local name="$1" base="$2" timeout="${3:-20}"
  local v
  for i in $(seq 1 "$timeout"); do
    v=$(mget "$name")
    [ "$v" -gt "$base" ] 2>/dev/null && { echo "$v"; return 0; }
    sleep 1
  done
  echo "${v:-0}"
}

# chat <reqid> <stream:true|false> <port> — POST via the VIP; prints
# "HTTPSTATUS:<code>" on the last line, body before it.
chat() {
  local reqid="$1" stream="$2" port="$3"
  $dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
    "https://$VIP:$port/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: $reqid" \
    -d '{"model":"'"$MODEL"'","messages":[{"role":"user","content":"hello"}],"max_tokens":16,"stream":'"$stream"'}' \
    -w "\nHTTPSTATUS:%{http_code}" 2>&1
}

status_of() { echo "$1" | grep 'HTTPSTATUS:' | tail -1 | cut -d: -f2; }

arm() {  # arm <ep> <knob> — one-shot fault injection on a mock
  $dexec "$1" curl -s -X POST "http://127.0.0.1:9100/admin/$2" > /dev/null
}

disarm_all() {  # clear any leftover one-shot fault knobs on every mock
  arm l3ep1 reset
  arm l3ep2 reset
  arm l3ep3 reset
}

eplog() {  # eplog <ep> <logfile>
  $dexec "$1" cat "/tmp/$2" 2>/dev/null
}

# room_of <log-content> <tag> <reqid> — extract room from "<tag> reqid=<id> room=<r>"
room_of() {
  echo "$1" | grep "$2 reqid=$3 " | head -1 | sed -n 's/.* room=\([0-9-]*\).*/\1/p'
}

############################################################################
echo "Leg A: acceptance (guard flipped) + bootstrap-port coherence rejection"
############################################################################

A_LBS=$($hexec llb1 curl -s "http://localhost:11111/netlox/v1/config/loadbalancer/all" 2>/dev/null)
echo "$A_LBS" | grep -q '"port":2030' && \
  echo "$A_LBS" | grep -q '"kvEngineType":"sglang"' && \
  echo "$A_LBS" | grep -q '"pdBootstrapPort":9998'
check "A1: sglang P/D rule (port 2030, kvEngineType=sglang, pdBootstrapPort=9998) accepted and listed" $?

# Negative: pdBootstrapPort on a vLLM-engine P/D rule must still be rejected.
A_NEG=$($hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' \
  -d '{"serviceArguments":{"externalIP":"'"$VIP"'","port":2039,"protocol":"tcp","sel":0,"mode":4,"pd_disagg_mode":true,"pdBootstrapPort":9998,"host":"'"$VIP"'"},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8100,"weight":1,"ep_role":1},{"endpointIP":"33.33.33.1","targetPort":8100,"weight":1,"ep_role":2}]}' 2>&1)
echo "$A_NEG" | grep -qi "pd_disagg_mode.*sglang\|sglang.*pd_disagg_mode"
check "A2: pdBootstrapPort on a vLLM P/D rule rejected (error names both preconditions)" $?
A_LBS2=$($hexec llb1 curl -s "http://localhost:11111/netlox/v1/config/loadbalancer/all" 2>/dev/null)
! echo "$A_LBS2" | grep -q '"port":2039'
check "A3: rejected rule not present in the rule table" $?

############################################################################
echo "Leg B: happy path non-streaming (rendezvous pins dual dispatch)"
############################################################################

B1=$(chat "$RUN-leg-b-1" false 2030)
B1_ST=$(status_of "$B1")
[ "$B1_ST" = "200" ] && echo "$B1" | grep -q "mock SGLang decode"
check "B1: non-streaming 200 with decode content (prefill blocked until decode joined => concurrent dispatch)" $?

B2=$(chat "$RUN-leg-b-2" false 2030)
B2_ST=$(status_of "$B2")
[ "$B2_ST" = "200" ] && echo "$B2" | grep -q "mock SGLang decode"
check "B2: second non-streaming request 200" $?

# Fresh room per request + in-range + RENDEZVOUS-OK on some prefill.
B_P_LOGS="$(eplog l3ep1 sglang-prefill1.log)
$(eplog l3ep2 sglang-prefill2.log)"
B_R1=$(room_of "$B_P_LOGS" "BOOTSTRAP" "$RUN-leg-b-1")
B_R2=$(room_of "$B_P_LOGS" "BOOTSTRAP" "$RUN-leg-b-2")
[ -n "$B_R1" ] && [ -n "$B_R2" ] && [ "$B_R1" != "$B_R2" ]
check "B3: fresh room per request (leg-b-1=$B_R1 vs leg-b-2=$B_R2)" $?
[ -n "$B_R1" ] && python3 -c "import sys; r=int('$B_R1'); sys.exit(0 if 0 <= r < 2**63 else 1)"
check "B4: room within [0, 2^63) (got $B_R1)" $?
echo "$B_P_LOGS" | grep -q "RENDEZVOUS-OK room=$B_R1"
check "B5: prefill reported RENDEZVOUS-OK for leg-b-1's room" $?

############################################################################
echo "Leg C: happy path streaming (SSE via the decode leg)"
############################################################################

C1=$(chat "$RUN-leg-c-1" true 2030)
C1_ST=$(status_of "$C1")
[ "$C1_ST" = "200" ] && echo "$C1" | grep -q "data: \[DONE\]" && \
  echo "$C1" | grep -q "chat.completion.chunk"
check "C1: SSE stream relayed with chunks and [DONE] terminator" $?
D_LOG=$(eplog l3ep3 sglang-decode3.log)
echo "$D_LOG" | grep -q "DECODE-SERVED room=$(room_of "$D_LOG" "BOOTSTRAP" "$RUN-leg-c-1") mode=sse"
check "C2: decode served leg-c-1 in SSE mode" $?

############################################################################
echo "Leg D: prefill error status -> pair abort (decode leg closed fast)"
############################################################################

disarm_all
D_ABORT_BASE=$(mget loxilb_pd_sg_prefill_abort_decode_total)
arm l3ep1 fail-next
D_HIT=""
for i in $(seq 1 8); do
  D_RESP=$(chat "$RUN-leg-d-$i" false 2030)
  D_ST=$(status_of "$D_RESP")
  if [ "$D_ST" = "502" ]; then
    D_HIT="$RUN-leg-d-$i"
    echo "$D_RESP" | grep -q "pd_sg_prefill_failed"
    check "D1: injected prefill 500 => client 502 pd_sg_prefill_failed (request $D_HIT)" $?
    break
  fi
  [ "$D_ST" = "200" ] || { echo "  FAIL: D-pre: request $RUN-leg-d-$i expected 200 or 502, got $D_ST"; code=1; }
done
[ -n "$D_HIT" ]
check "D2: fail-next consumed within 8 requests (hit=$D_HIT)" $?

D_ABORT_NOW=$(mwait loxilb_pd_sg_prefill_abort_decode_total "$D_ABORT_BASE" 20)
[ "$D_ABORT_NOW" -gt "$D_ABORT_BASE" ]
check "D3: pd_sg_prefill_abort_decode ticked ($D_ABORT_BASE -> $D_ABORT_NOW)" $?

# The decode mock must observe its connection closed by the gateway within
# a few seconds (it was parked pre-output waiting for the KV transfer).
D_ROOM=$(room_of "$(eplog l3ep1 sglang-prefill1.log)" "INJECT-500" "$D_HIT")
D_CLOSED=1
for i in $(seq 1 10); do
  if [ -n "$D_ROOM" ] && eplog l3ep3 sglang-decode3.log | grep -q "DECODE-CONN-CLOSED room=$D_ROOM"; then
    D_CLOSED=0; break
  fi
  sleep 1
done
check "D4: decode leg closed by the gateway (DECODE-CONN-CLOSED room=$D_ROOM)" $D_CLOSED

############################################################################
echo "Leg E: drain-leg transport death -> PAIR RETRY with a fresh room"
############################################################################

disarm_all
E_RETRY_BASE=$(mget loxilb_pd_sg_room_retry_total)
arm l3ep1 die-next
E_HIT=""
for i in $(seq 1 8); do
  E_RESP=$(chat "$RUN-leg-e-$i" false 2030)
  E_ST=$(status_of "$E_RESP")
  [ "$E_ST" = "200" ] || { echo "  FAIL: E-pre: request $RUN-leg-e-$i expected 200 (retry must rescue), got $E_ST"; code=1; }
  # Hit detection reads the MOCK's INJECT-DIE line, not the counter: the
  # prometheus layer ingests the sockproxy snapshot every 10s, and this
  # whole loop can finish faster than that against the mocks (the counter
  # tick is asserted separately below with mwait).
  if eplog l3ep1 sglang-prefill1.log | grep -q "INJECT-DIE reqid=$RUN-leg-e-$i "; then
    E_HIT="$RUN-leg-e-$i"
    break
  fi
done
[ -n "$E_HIT" ]
check "E1: die-next consumed within 8 requests and the client still got 200 (hit=$E_HIT)" $?

E_NOW=$(mwait loxilb_pd_sg_room_retry_total "$E_RETRY_BASE" 20)
[ "$E_NOW" -gt "$E_RETRY_BASE" ]
check "E1b: pd_sg_room_retry ticked ($E_RETRY_BASE -> $E_NOW)" $?

# The dying attempt's room (prefill A log) must DIFFER from the retried
# attempt's room (prefill B log) for the SAME request id.
E_P1_LOG=$(eplog l3ep1 sglang-prefill1.log)
E_P2_LOG=$(eplog l3ep2 sglang-prefill2.log)
E_R1=$(room_of "$E_P1_LOG" "INJECT-DIE" "$E_HIT")
E_R2=$(room_of "$E_P2_LOG" "BOOTSTRAP" "$E_HIT")
[ -n "$E_R1" ] && [ -n "$E_R2" ] && [ "$E_R1" != "$E_R2" ]
check "E2: retry used a FRESH room (attempt1 room=$E_R1 on prefill-A, retry room=$E_R2 on prefill-B)" $?
[ -n "$E_R2" ] && python3 -c "import sys; r=int('$E_R2'); sys.exit(0 if 0 <= r < 2**63 else 1)"
check "E3: retry room within [0, 2^63) (got $E_R2)" $?
[ -n "$E_R2" ] && echo "$E_P2_LOG" | grep -q "RENDEZVOUS-OK room=$E_R2"
check "E4: retried pair completed its rendezvous on prefill-B" $?

############################################################################
echo "Leg F: decode-leg death -> 5xx and the drain leg is not orphaned"
############################################################################

disarm_all
F_DRAIN_BASE=$(mget loxilb_pd_sg_decode_close_drain_total)
arm l3ep3 die-next
F_RESP=$(chat "$RUN-leg-f-1" false 2030)
F_ST=$(status_of "$F_RESP")
[ "$F_ST" = "502" ] && echo "$F_RESP" | grep -q "pd_decode_backend_died"
check "F1: decode transport death => client 502 pd_decode_backend_died (got $F_ST)" $?

F_DRAIN_NOW=$(mwait loxilb_pd_sg_decode_close_drain_total "$F_DRAIN_BASE" 20)
[ "$F_DRAIN_NOW" -gt "$F_DRAIN_BASE" ]
check "F2: pd_sg_decode_close_drain ticked ($F_DRAIN_BASE -> $F_DRAIN_NOW)" $?

# The prefill drain leg (parked in its rendezvous wait) must observe the
# close instead of being orphaned until its 20s timeout.
F_P_LOGS="$(eplog l3ep1 sglang-prefill1.log)
$(eplog l3ep2 sglang-prefill2.log)"
F_ROOM=$(room_of "$F_P_LOGS" "BOOTSTRAP" "$RUN-leg-f-1")
F_CLOSED=1
for i in $(seq 1 10); do
  F_P_LOGS="$(eplog l3ep1 sglang-prefill1.log)
$(eplog l3ep2 sglang-prefill2.log)"
  if [ -n "$F_ROOM" ] && echo "$F_P_LOGS" | grep -q "PREFILL-CONN-CLOSED room=$F_ROOM"; then
    F_CLOSED=0; break
  fi
  sleep 1
done
check "F3: prefill drain leg closed by the gateway (PREFILL-CONN-CLOSED room=$F_ROOM)" $F_CLOSED

############################################################################
echo "Leg G: coexistence — vLLM P/D and SGLang P/D on one gateway"
############################################################################

G1=$(chat "$RUN-leg-g-1" false 2031)
G1_ST=$(status_of "$G1")
[ "$G1_ST" = "200" ] && echo "$G1" | grep -q "mock vLLM decode response"
check "G1: vLLM P/D rule (port 2031) non-streaming 200 via the sequential machine" $?

G2=$(chat "$RUN-leg-g-2" true 2031)
G2_ST=$(status_of "$G2")
[ "$G2_ST" = "200" ] && echo "$G2" | grep -q "data: \[DONE\]"
check "G2: vLLM P/D rule SSE stream with [DONE]" $?

G3=$(chat "$RUN-leg-g-3" false 2030)
G3_ST=$(status_of "$G3")
[ "$G3_ST" = "200" ] && echo "$G3" | grep -q "mock SGLang decode"
check "G3: SGLang P/D rule still healthy after vLLM traffic (both flavors coexist)" $?

############################################################################
echo "Leg I: prefill client-error status -> origin 4xx relayed verbatim"
############################################################################

disarm_all
I_RELAY_BASE=$(mget loxilb_pd_sg_prefill_reject_relay_total)
I_ABORT_BASE=$(mget loxilb_pd_sg_prefill_abort_decode_total)
arm l3ep1 reject-next
I_HIT=""
for i in $(seq 1 8); do
  I_RESP=$(chat "$RUN-leg-i-$i" false 2030)
  I_ST=$(status_of "$I_RESP")
  if [ "$I_ST" = "400" ]; then
    I_HIT="$RUN-leg-i-$i"
    echo "$I_RESP" | grep -q "mock_client_reject"
    check "I1: injected prefill 400 relayed VERBATIM to the client (origin body intact, request $I_HIT)" $?
    break
  fi
  [ "$I_ST" = "200" ] || { echo "  FAIL: I-pre: request $RUN-leg-i-$i expected 200 or 400, got $I_ST"; code=1; }
done
[ -n "$I_HIT" ]
check "I2: reject-next consumed within 8 requests (hit=$I_HIT)" $?

I_RELAY_NOW=$(mwait loxilb_pd_sg_prefill_reject_relay_total "$I_RELAY_BASE" 20)
[ "$I_RELAY_NOW" -gt "$I_RELAY_BASE" ]
check "I3: pd_sg_prefill_reject_relay ticked ($I_RELAY_BASE -> $I_RELAY_NOW)" $?

# A client error must not be misclassified as a prefill abort (502 family).
I_ABORT_NOW=$(mget loxilb_pd_sg_prefill_abort_decode_total)
[ "$I_ABORT_NOW" = "$I_ABORT_BASE" ]
check "I4: pd_sg_prefill_abort_decode FLAT across the reject ($I_ABORT_BASE)" $?

# The decode leg (parked pre-output in its KV wait) is still torn down fast.
I_ROOM=$(room_of "$(eplog l3ep1 sglang-prefill1.log)" "INJECT-400" "$I_HIT")
I_CLOSED=1
for i in $(seq 1 10); do
  if [ -n "$I_ROOM" ] && eplog l3ep3 sglang-decode3.log | grep -q "DECODE-CONN-CLOSED room=$I_ROOM"; then
    I_CLOSED=0; break
  fi
  sleep 1
done
check "I5: decode leg closed by the gateway (DECODE-CONN-CLOSED room=$I_ROOM)" $I_CLOSED

############################################################################
echo "Leg J: streamable JSON over the inspect cap -> fail-closed 503"
############################################################################

J_OVR_BASE=$(mget loxilb_pd_sg_oversize_reject_total)
# ~900KB JSON body: over the gateway JSON inspection cap (3/4 of the 1MB
# sock buffer), so body buffering — and with it bootstrap injection — is
# impossible. Built inside the client container with shell only.
$dexec l3h1 sh -c 'printf "{\"model\":\"'"$MODEL"'\",\"messages\":[{\"role\":\"user\",\"content\":\"" > /tmp/leg-j.json;
  head -c 900000 /dev/zero | tr "\0" "x" >> /tmp/leg-j.json;
  printf "\"}],\"max_tokens\":16,\"stream\":false}" >> /tmp/leg-j.json'
J_RESP=$($dexec l3h1 curl -sk --cacert "$CACERT" -m 30 \
  "https://$VIP:2030/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: $RUN-leg-j-1" \
  -d @/tmp/leg-j.json \
  -w "\nHTTPSTATUS:%{http_code}" 2>&1)
J_ST=$(status_of "$J_RESP")
[ "$J_ST" = "503" ] && echo "$J_RESP" | grep -q "pd_sg_oversize_unroutable"
check "J1: oversize JSON refused fail-closed 503 pd_sg_oversize_unroutable (got $J_ST)" $?

J_OVR_NOW=$(mwait loxilb_pd_sg_oversize_reject_total "$J_OVR_BASE" 20)
[ "$J_OVR_NOW" -gt "$J_OVR_BASE" ]
check "J2: pd_sg_oversize_reject ticked ($J_OVR_BASE -> $J_OVR_NOW)" $?

# Fail-closed means REFUSED BEFORE BACKEND BYTES: no mock may have seen it.
J_ALL_LOGS="$(eplog l3ep1 sglang-prefill1.log)
$(eplog l3ep2 sglang-prefill2.log)
$(eplog l3ep3 sglang-decode3.log)"
! echo "$J_ALL_LOGS" | grep -q "$RUN-leg-j-1"
check "J3: no engine observed the oversize request (refused pre-dispatch)" $?

############################################################################
echo "Leg H: hygiene — no mock-side contract violations, metrics exported"
############################################################################

H_ALL_LOGS="$(eplog l3ep1 sglang-prefill1.log)
$(eplog l3ep2 sglang-prefill2.log)
$(eplog l3ep3 sglang-decode3.log)"
! echo "$H_ALL_LOGS" | grep -qE "TRIPLE-MISSING|PORT-MISMATCH|HOST-MISMATCH|ROOM-RANGE-ERROR|TRIPLE-MISMATCH|JOIN-FAILED"
check "H1: zero bootstrap-contract violations across all mock logs" $?

H_METRICS=$($hexec llb1 curl -s http://localhost:11111/netlox/v1/metrics 2>/dev/null)
echo "$H_METRICS" | grep -q "loxilb_pd_sg_room_retry_total" && \
  echo "$H_METRICS" | grep -q "loxilb_pd_sg_prefill_abort_decode_total" && \
  echo "$H_METRICS" | grep -q "loxilb_pd_sg_decode_close_drain_total" && \
  echo "$H_METRICS" | grep -q "loxilb_pd_sg_prefill_reject_relay_total" && \
  echo "$H_METRICS" | grep -q "loxilb_pd_sg_oversize_reject_total"
check "H2: pd_sg_* counter family present on the metrics endpoint" $?

echo "#########################################"
echo "Results"
echo "#########################################"

if [ "$code" = "0" ]; then
  echo SCENARIO-sglang-pd-disagg [OK]
else
  echo SCENARIO-sglang-pd-disagg [FAILED]
fi

exit $code
