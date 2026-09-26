#!/bin/bash
# Validates the inference-path audit trail (stage 1b):
#
#   T14  one request, one key: an admitted request leaves exactly one
#        completion and one settle joined by request_id, a refused one
#        leaves exactly one deny carrying a non-empty request_id and the
#        tenant of the credential that was refused
#   T4   the record's tokens are the tokens that were charged, for a split
#        non-streaming body and for an SSE stream with include_usage
#   T2   the drop counter is reachable: with the writer stalled the data
#        path keeps serving and the drop counter rises
#   T18  what was dropped before the writer is named exactly, per producer
#        and per stream, and nothing lands unattributed
#   T21  two producers enqueuing out of order is not a drop
#
# The join key is the client's own X-Request-Id: the gateway adopts a
# supplied one before the admission gate decides, so every record of a
# request carries the value this script chose and no assertion has to
# guess which record belongs to which request.
#
# Rules: every refusal asserts the reason, not just the status; whether a
# refused request reached the backend is read from the backend's own
# namespace, never inferred from the gateway's answer; a count that could
# be satisfied by an empty trail is paired with a floor.

cd "$(dirname "$0")"
source ../common.sh
source .state
echo SCENARIO-audit-data
code=0

require_host_tools jq || { echo "SCENARIO-audit-data [FAILED]"; exit 1; }

API=http://$VIP:11111/netlox/v1
GW_BIN=/root/loxilb-io/loxilb/loxilb
BACKEND=http://31.31.31.1:8080

# ── verdict helpers ─────────────────────────────────────────────────────────
ok()  { echo "  [$1] $2 [OK]"; }
bad() { echo "  [$1] $2 [FAILED] — $3"; code=1; }
chk()     { if [[ "$4" == "$3" ]]; then ok "$1" "$2 = '$4'"; else bad "$1" "$2" "expected '$3' got '$4'"; fi; }
chk_ne()  { if [[ "$4" != "$3" ]]; then ok "$1" "$2 = '$4'"; else bad "$1" "$2" "must not be '$3'"; fi; }
chk_has() { if [[ "$4" == *"$3"* ]]; then ok "$1" "$2"; else bad "$1" "$2" "no '$3' in: ${4:0:240}"; fi; }
chk_ge()  { if [[ "$4" =~ ^[0-9]+$ && "$4" -ge "$3" ]]; then ok "$1" "$2 = $4 (>= $3)"; else bad "$1" "$2" "expected >= $3 got '$4'"; fi; }
chk_gt()  { if [[ "$4" =~ ^[0-9]+$ && "$3" =~ ^[0-9]+$ && "$4" -gt "$3" ]]; then ok "$1" "$2 = $4 (> $3)"; else bad "$1" "$2" "expected > $3 got '$4'"; fi; }
chk_nonempty() { if [[ -n "$3" ]]; then ok "$1" "$2 = '${3:0:80}'"; else bad "$1" "$2" "empty"; fi; }

# ── requests ────────────────────────────────────────────────────────────────
# Every request carries an X-Request-Id this script chose and an
# X-Test-Nonce the backend counts. The first is the trail's join key; the
# second answers whether the request reached the backend at all.
# new_rid sets LAST_RID. It deliberately does not print the id: read through
# a command substitution the counter would advance inside a subshell and
# every request would reuse one id, which makes every per-request assertion
# score against whichever record happened to land first.
RID_N=0
new_rid() { RID_N=$((RID_N + 1)); LAST_RID="audit-data-$$-$RID_N"; }

infer() { # infer <port> <rid> <body> [curl args...] → RESP_CODE, RESP_BODY
  local port=$1 rid=$2 body=$3 out; shift 3
  out=$($hexec l3h1 curl -s -m 25 -w '\n%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    -H "X-Request-Id: $rid" \
    -H "X-Test-Nonce: $rid" \
    "$@" -d "$body" \
    "http://$VIP:$port/v1/chat/completions")
  RESP_CODE=${out##*$'\n'}
  RESP_BODY=${out%$'\n'*}
  [[ "$RESP_BODY" == "$out" ]] && RESP_BODY=""
}

receipt() { # receipt <nonce> → how many requests with that nonce reached the backend
  $hexec l3ep1 curl -s -m 5 "$BACKEND/__receipts/$1" 2>/dev/null | jq -r '.count // "unreadable"'
}

body_for() { # body_for <model> [stream]
  local model=$1 stream=${2:-false}
  if [[ "$stream" == true ]]; then
    printf '{"model":"%s","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}' "$model"
  else
    printf '{"model":"%s","messages":[{"role":"user","content":"hi"}]}' "$model"
  fi
}

# ── the trail ───────────────────────────────────────────────────────────────
# Every record of every segment (active, sealed, gzipped) as one JSON object
# per line. Segment headers and footers carry "kind" and are dropped here.
trail_raw() {
  docker exec llb1 sh -c "cd '$AUDIT_DIR' 2>/dev/null || exit 0; for f in *.jsonl; do [ -f \"\$f\" ] && cat \"\$f\"; done; for f in *.jsonl.gz; do [ -f \"\$f\" ] && zcat \"\$f\"; done" 2>/dev/null
}
trail() { trail_raw | jq -c -R 'fromjson? | select(type=="object" and .event_type != null)'; }
records() { trail | jq -c "select($1)"; }
count()   { records "$1" | wc -l | tr -d ' '; }

# for_rid <request_id> <event_type> → the matching records
for_rid() { records ".request_id==\"$1\" and .event_type==\"$2\""; }
# wait_for <request_id> <event_type> → waits, bounded, for the record to land
wait_for() {
  local i
  for i in $(seq 1 40); do
    [[ "$(count ".request_id==\"$1\" and .event_type==\"$2\"")" -ge 1 ]] && return 0
    sleep 0.5
  done
  return 1
}

astatus() { $hexec l3h1 curl -s -m 5 "$API/audit/status"; }

metric_val() { # metric_val <family> [<label substring>] → the summed value
  local fam=$1 lab=${2:-} body
  body=$($hexec l3h1 curl -s -m 8 "$API/metrics" 2>/dev/null)
  case "$body" in *loxilb_*) ;; *) echo "unreadable"; return ;; esac
  printf '%s\n' "$body" | awk -v f="$fam" -v l="$lab" '
    $0 ~ ("^" f "([{ ]|$)") {
      if (l != "" && index($0, l) == 0) next
      v = $NF; if (v + 0 == v) s += v
    }
    END { printf "%.0f", s + 0 }'
}

# ── the gateway process (the audit-mgmt pattern) ────────────────────────────
gw_wait_dead() {
  local i
  for i in $(seq 1 "$1"); do
    docker exec llb1 pgrep -f "$GW_BIN" >/dev/null 2>&1 || return 0
    sleep 1
  done
  return 1
}
gw_stop() {
  docker exec llb1 pkill -f "$GW_BIN" >/dev/null 2>&1
  gw_wait_dead 20 && return 0
  echo "  (the gateway survived SIGTERM for 20s; escalating)"
  docker exec llb1 pkill -9 -f "$GW_BIN" >/dev/null 2>&1
  gw_wait_dead 10 && return 0
  echo "  FATAL: the old gateway process would not die"; return 1
}
gw_start() { # gw_start [env assignments...] — the flags come from .state
  local i ifc envs="$*"
  docker exec llb1 ip link del llb0 >/dev/null 2>&1
  for ifc in $(docker exec llb1 ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    [ "$ifc" = "lo" ] && continue
    docker exec llb1 ip link set dev "$ifc" xdpgeneric off >/dev/null 2>&1
    docker exec llb1 tc qdisc del dev "$ifc" clsact >/dev/null 2>&1
  done
  docker exec llb1 umount /opt/loxilb/dp >/dev/null 2>&1
  # Appending, not truncating: the boots before this one are evidence.
  docker exec -d llb1 bash -c "ulimit -l unlimited; $envs $GW_BIN -p --loglevel debug $GW_ARGS >> /tmp/loxilb.out 2>> /tmp/loxilb.err"
  for i in $(seq 1 40); do
    $hexec l3h1 curl -sf -m 3 "$API/version" >/dev/null 2>&1 && break
    sleep 2
  done
  if ! $hexec l3h1 curl -sf -m 3 "$API/version" >/dev/null 2>&1; then
    echo "  the gateway did not come back; stderr tail:"
    docker exec llb1 tail -20 /tmp/loxilb.err
    return 1
  fi
  for i in $(seq 1 40); do
    if ! $hexec l3h1 curl -s -m 3 -X POST "$API/config/loadbalancer" -H 'Content-Type: application/json' -d '{}' \
         | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
      return 0
    fi
    sleep 2
  done
  echo "  boot config replay never settled"; return 1
}

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "Preflight"
echo "════════════════════════════════════════════════════════════════════════"
ST=$(astatus)
chk PRE-1 "the trail is available" true "$(printf '%s' "$ST" | jq -r '.available')"
chk PRE-2 "the writer is running"  true "$(printf '%s' "$ST" | jq -r '.running')"

# The fault arms below stall the writer on purpose, which only a build that
# compiled the fault points in can do. A bed without one cannot run them,
# and a scenario that quietly skipped them would report a green that proves
# nothing — so it is named here and scored at the end.
BUILD_TAGS=$(docker exec llb1 sh -c "$GW_BIN --version 2>/dev/null" | awk -F': ' '/build tags/ {print $2}')
FAULTS_AVAILABLE=no
case "$BUILD_TAGS" in
  *audit_faults*) FAULTS_AVAILABLE=yes ;;
esac
echo "  [PRE-3] gateway build tags = '${BUILD_TAGS:-none}', fault points available = $FAULTS_AVAILABLE"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T14: one request, one key"
echo "════════════════════════════════════════════════════════════════════════"

# ── the refused arm ─────────────────────────────────────────────────────────
# The key is valid and names a tenant, but not this model. That is the arm
# that must still carry the tenant: a refusal naming nobody cannot be
# investigated, and it is the case the 403 fix was about.
# The model goes in the body alone. Naming a different one in X-Model as
# well would be a body/header disagreement, which the gate refuses one
# stage earlier as a conflict — a 400 that never reaches the allow-list and
# so never proves the tenant is carried on the authorization refusal.
new_rid; RID_DENY=$LAST_RID
infer 2020 "$RID_DENY" "$(body_for other-model)" -H "X-Api-Key: $K_MODEL"
chk     T14-1a "a model outside the key's list is refused" 403 "$RESP_CODE"
chk_has T14-1b "the refusal names the reason" model_not_allowed "$RESP_BODY"
chk     T14-1c "the refused request never reached the backend" 0 "$(receipt "$RID_DENY")"

wait_for "$RID_DENY" sec.ai.deny || bad T14-1d "a deny record for the refused request" "none arrived within 20s"
chk T14-1e "exactly one deny record" 1 "$(count ".request_id==\"$RID_DENY\" and .event_type==\"sec.ai.deny\"")"
chk T14-1f "and no completion record"  0 "$(count ".request_id==\"$RID_DENY\" and .event_type==\"data.ai.complete\"")"
chk T14-1g "and no settle record"      0 "$(count ".request_id==\"$RID_DENY\" and .event_type==\"data.ai.settle\"")"

DENY=$(for_rid "$RID_DENY" sec.ai.deny | head -n1)
chk_nonempty T14-2a "the deny carries a request id" "$(printf '%s' "$DENY" | jq -r '.request_id // empty')"
chk T14-2b "the deny names the refused credential's tenant" "$TENANT" "$(printf '%s' "$DENY" | jq -r '.actor.tenant // empty')"
chk T14-2c "the deny is a security record"     security "$(printf '%s' "$DENY" | jq -r '.class // empty')"
chk T14-2d "on the data stream"                data     "$(printf '%s' "$DENY" | jq -r '.stream // empty')"
chk T14-2e "with the status the client got"    403      "$(printf '%s' "$DENY" | jq -r '.outcome.status')"
chk T14-2f "and the reason the refusal was"    authz    "$(printf '%s' "$DENY" | jq -r '.outcome.reason')"
chk T14-2g "naming the stage that refused it"  auth     "$(printf '%s' "$DENY" | jq -r '.detail.stage // empty')"
chk T14-2h "and the code it answered with"     model_not_allowed "$(printf '%s' "$DENY" | jq -r '.detail.decision // empty')"

# The credential itself must be nowhere in the record.
chk T14-2i "the raw key appears in no record of the refusal" 0 \
  "$(for_rid "$RID_DENY" sec.ai.deny | grep -c -- "$K_MODEL")"

# ── the admitted non-streaming arm ──────────────────────────────────────────
new_rid; RID_NS=$LAST_RID
infer 2020 "$RID_NS" "$(body_for "$MODEL")" -H "X-Api-Key: $K_ALL"
chk T14-3a "an admitted non-streaming request is served" 200 "$RESP_CODE"
chk T14-3b "and it reached the backend once" 1 "$(receipt "$RID_NS")"

wait_for "$RID_NS" data.ai.complete || bad T14-3c "a completion record" "none arrived within 20s"
chk T14-3d "exactly one completion record" 1 "$(count ".request_id==\"$RID_NS\" and .event_type==\"data.ai.complete\"")"
chk T14-3e "and no deny record"            0 "$(count ".request_id==\"$RID_NS\" and .event_type==\"sec.ai.deny\"")"
wait_for "$RID_NS" data.ai.settle || bad T14-3f "a settle record" "none arrived within 20s"
chk T14-3g "exactly one settle, joined by request id" 1 "$(count ".request_id==\"$RID_NS\" and .event_type==\"data.ai.settle\"")"

CNS=$(for_rid "$RID_NS" data.ai.complete | head -n1)
chk T14-4a "the completion is on the data stream" data "$(printf '%s' "$CNS" | jq -r '.stream')"
chk T14-4b "it carries no security class"         ""   "$(printf '%s' "$CNS" | jq -r '.class // ""')"
chk T14-4c "the status the client got"            200  "$(printf '%s' "$CNS" | jq -r '.outcome.status')"
chk T14-4d "the tenant that was admitted"   "$TENANT"  "$(printf '%s' "$CNS" | jq -r '.actor.tenant // empty')"
chk T14-4e "and the service it went through" "$VIP:2020" "$(printf '%s' "$CNS" | jq -r '.detail.service // empty')"

# ── the admitted SSE arm ────────────────────────────────────────────────────
new_rid; RID_SSE=$LAST_RID
infer 2021 "$RID_SSE" "$(body_for "$MODEL" true)" -H "X-Api-Key: $K_ALL"
chk     T14-5a "an admitted SSE request is served" 200 "$RESP_CODE"
chk_has T14-5b "the stream terminated"    "[DONE]" "$RESP_BODY"
chk     T14-5c "and it reached the backend once" 1 "$(receipt "$RID_SSE")"

wait_for "$RID_SSE" data.ai.complete || bad T14-5d "a completion record for the stream" "none arrived within 20s"
chk T14-5e "exactly one completion record for the stream" 1 "$(count ".request_id==\"$RID_SSE\" and .event_type==\"data.ai.complete\"")"
wait_for "$RID_SSE" data.ai.settle || bad T14-5f "a settle record for the stream" "none arrived within 20s"
chk T14-5g "exactly one settle for the stream" 1 "$(count ".request_id==\"$RID_SSE\" and .event_type==\"data.ai.settle\"")"
chk T14-5h "the completion says it was a stream" true \
  "$(for_rid "$RID_SSE" data.ai.complete | head -n1 | jq -r '.detail.stream')"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T4: the recorded tokens are the charged tokens"
echo "════════════════════════════════════════════════════════════════════════"

# The backend reports the counts it is asked for, so a record that echoed a
# constant would fail here. The Prometheus counter is charged from the
# settle path, so the two must move by the same amount.

# ── split non-streaming body ────────────────────────────────────────────────
# The body is cut mid-usage-object across two TCP writes: a reader that
# parses only the first segment sees no counts at all.
CONSUMED0=$(metric_val loxilb_audit_records_written_total 'stream="data"')
TOK0=$(metric_val loxilb_ai_tokens_consumed_total "tenant=\"$TENANT\"")
new_rid; RID_SPLIT=$LAST_RID
$hexec l3h1 curl -s -m 25 -o /dev/null -X POST \
  -H 'Content-Type: application/json' \
  -H "X-Request-Id: $RID_SPLIT" -H "X-Test-Nonce: $RID_SPLIT" \
  -H "X-Api-Key: $K_ALL" \
  -d "$(body_for "$MODEL")" \
  "http://$VIP:2020/v1/chat/completions?pt=41&ct=9&split=1"

wait_for "$RID_SPLIT" data.ai.settle || bad T4-1a "a settle for the split body" "none arrived within 20s"
SPLIT_SETTLE=$(for_rid "$RID_SPLIT" data.ai.settle | head -n1)
chk T4-1b "the settle records the prompt tokens the backend reported"     41 "$(printf '%s' "$SPLIT_SETTLE" | jq -r '.detail.tokens_in')"
chk T4-1c "and the completion tokens"                                      9 "$(printf '%s' "$SPLIT_SETTLE" | jq -r '.detail.tokens_out')"
SPLIT_COMPLETE=$(for_rid "$RID_SPLIT" data.ai.complete | head -n1)
chk T4-1d "the completion record agrees with the settle on tokens in"     41 "$(printf '%s' "$SPLIT_COMPLETE" | jq -r '.detail.tokens_in')"
chk T4-1e "and on tokens out"                                              9 "$(printf '%s' "$SPLIT_COMPLETE" | jq -r '.detail.tokens_out')"

sleep 2
TOK1=$(metric_val loxilb_ai_tokens_consumed_total "tenant=\"$TENANT\"")
if [[ "$TOK0" =~ ^[0-9]+$ && "$TOK1" =~ ^[0-9]+$ ]]; then
  chk T4-1f "the charge counter moved by what the record says" 50 "$((TOK1 - TOK0))"
else
  bad T4-1f "the charge counter moved by what the record says" "metrics unreadable ('$TOK0' → '$TOK1')"
fi

# ── SSE with include_usage ──────────────────────────────────────────────────
TOK2=$(metric_val loxilb_ai_tokens_consumed_total "tenant=\"$TENANT\"")
new_rid; RID_SU=$LAST_RID
$hexec l3h1 curl -s -m 25 -o /dev/null -X POST \
  -H 'Content-Type: application/json' \
  -H "X-Request-Id: $RID_SU" -H "X-Test-Nonce: $RID_SU" \
  -H "X-Api-Key: $K_ALL" \
  -d "$(body_for "$MODEL" true)" \
  "http://$VIP:2021/v1/chat/completions?pt=21&ct=13"

wait_for "$RID_SU" data.ai.settle || bad T4-2a "a settle for the stream" "none arrived within 20s"
SU_SETTLE=$(for_rid "$RID_SU" data.ai.settle | head -n1)
chk T4-2b "the stream's settle records the prompt tokens" 21 "$(printf '%s' "$SU_SETTLE" | jq -r '.detail.tokens_in')"
chk T4-2c "and the completion tokens"                     13 "$(printf '%s' "$SU_SETTLE" | jq -r '.detail.tokens_out')"

sleep 2
TOK3=$(metric_val loxilb_ai_tokens_consumed_total "tenant=\"$TENANT\"")
EST=$(metric_val loxilb_ai_tokens_estimated_total "tenant=\"$TENANT\"")
if [[ "$TOK2" =~ ^[0-9]+$ && "$TOK3" =~ ^[0-9]+$ ]]; then
  chk T4-2d "the stream's charge counter moved by what the record says" 34 "$((TOK3 - TOK2))"
else
  bad T4-2d "the stream's charge counter moved by what the record says" "metrics unreadable ('$TOK2' → '$TOK3')"
fi
chk T4-2e "the stream's counts were exact, not estimated" 0 "$EST"

# ── the refused charge ──────────────────────────────────────────────────────
# One admitted request puts the limited tenant's bucket in debt; the next is
# refused at admission. No timing is in this oracle.
new_rid; RID_Q1=$LAST_RID
infer 2020 "$RID_Q1" "$(body_for "$MODEL")" -H "X-Api-Key: $K_QUOTA"
chk T4-3a "the limited tenant's first request is admitted" 200 "$RESP_CODE"
sleep 3
new_rid; RID_Q2=$LAST_RID
infer 2020 "$RID_Q2" "$(body_for "$MODEL")" -H "X-Api-Key: $K_QUOTA"
chk     T4-3b "its second request is refused by what the first spent" 429 "$RESP_CODE"
chk_has T4-3c "and the refusal names the token quota" token_quota_exceeded "$RESP_BODY"
chk     T4-3d "the refused request never reached the backend" 0 "$(receipt "$RID_Q2")"

wait_for "$RID_Q2" sec.ai.deny || bad T4-3e "a deny record for the quota refusal" "none arrived within 20s"
Q2=$(for_rid "$RID_Q2" sec.ai.deny | head -n1)
chk T4-3f "the quota refusal is recorded against its tenant" "$QUOTA_TENANT" "$(printf '%s' "$Q2" | jq -r '.actor.tenant // empty')"
chk T4-3g "with the quota reason"       quota "$(printf '%s' "$Q2" | jq -r '.outcome.reason')"
chk T4-3h "naming the rate-limit stage"  ratelimit "$(printf '%s' "$Q2" | jq -r '.detail.stage // empty')"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T2 / T18 / T21: what is lost before the writer is named exactly"
echo "════════════════════════════════════════════════════════════════════════"

if [[ "$FAULTS_AVAILABLE" != yes ]]; then
  bad T2-0 "the fault points are compiled in" \
    "this image has build tags '${BUILD_TAGS:-none}'; rebuild with HAVE_AUDIT_FAULTS=1 (the drop, gap and reorder arms cannot run without a writer that can be stalled)"
else
  # The stall is given a budget: it holds the first STALL_BUDGET records and
  # then releases on its own. An unbounded stall could only be released by
  # restarting, and a restart takes the producers' drop rings with it — the
  # gap records below are written FROM those rings, so the evidence of what
  # was lost would die with the process that lost it.
  #
  # The stall costs a second per record, so the budget is also how many
  # seconds it lasts. The load below runs a little over two minutes and
  # fills the queue well inside that, so 250 keeps the writer stalled for
  # the whole of it with room to spare, and the backlog drains at full
  # speed once the budget is spent.
  STALL_BUDGET=250
  echo "  restarting the gateway with the writer stalled"
  gw_stop || code=1
  gw_start "LOXILB_AUDIT_FAULT=writer.stall:$STALL_BUDGET" || { bad T2-0 "the stalled gateway came back" "it did not"; code=1; }

  # The trail is a fresh boot's; the records below are this boot's.
  DROP0=$(metric_val loxilb_audit_records_dropped_total 'stream="data"')
  UNATTR0=$(metric_val loxilb_audit_records_unattributed_total)

  # Saturate the data channel. The writer drains roughly one record a
  # second while stalled, and each admitted request enqueues a completion
  # and a settle, so the queue fills long before this finishes. The
  # requests go out concurrently from several connections, which is what
  # puts more than one sockproxy worker behind them — the per-producer
  # assertions below have nothing to say otherwise.
  echo "  driving load against the stalled writer (this takes a minute)"
  for w in $(seq 1 12); do
    (
      for n in $(seq 1 450); do
        $hexec l3h1 curl -s -m 10 -o /dev/null -X POST \
          -H 'Content-Type: application/json' \
          -H "X-Api-Key: $K_ALL" \
          -d "$(body_for "$MODEL")" \
          "http://$VIP:2020/v1/chat/completions" 2>/dev/null
      done
    ) &
  done
  wait

  # ── T2: the drop counter is reachable ─────────────────────────────────────
  DROP1=$(metric_val loxilb_audit_records_dropped_total 'stream="data"')
  if [[ "$DROP0" =~ ^[0-9]+$ && "$DROP1" =~ ^[0-9]+$ ]]; then
    chk_gt T2-1a "the data drop counter rose under saturation" "$DROP0" "$DROP1"
  else
    bad T2-1a "the data drop counter rose under saturation" "metrics unreadable ('$DROP0' → '$DROP1')"
  fi
  # The point of the drop path is that the data path keeps serving.
  new_rid; RID_LIVE=$LAST_RID
  infer 2020 "$RID_LIVE" "$(body_for "$MODEL")" -H "X-Api-Key: $K_ALL"
  chk T2-1b "the data path still serves while records are being dropped" 200 "$RESP_CODE"
  chk T2-1c "and the request still reached the backend" 1 "$(receipt "$RID_LIVE")"

  # A management record must not have been dropped by a data flood: the
  # security and control queues are separate channels.
  SECDROP=$(metric_val loxilb_audit_records_dropped_total 'stream="mgmt"')
  chk T2-1d "the management stream dropped nothing while data was flooded" 0 "$SECDROP"

  # ── release the writer and let the gaps be written ────────────────────────
  # No restart here: the stall's budget has been spent by the load above, so
  # the writer is already draining. Waiting for the queue to empty keeps the
  # producers — and their drop rings — alive into the heartbeat below.
  echo "  releasing the writer"
  # The budget is spent a record a second, so the wait has to cover the rest
  # of the stall plus the backlog that drains at full speed after it. It ends
  # as soon as the queue is empty, so a generous ceiling costs nothing.
  for i in $(seq 1 300); do
    [[ "$(astatus | jq -r '.queue_depth.data // 0')" == "0" ]] && break
    sleep 2
  done
  # Gap records are drained into the trail at the heartbeat, which is every
  # 30 seconds; the boot's first one follows shortly after start.
  echo "  waiting for the heartbeat that drains the drop rings"
  for i in $(seq 1 45); do
    [[ "$(count '.event_type=="sys.producer.gap"')" -ge 1 ]] && break
    sleep 2
  done

  # ── T18: the gaps name exactly what was lost, per producer ────────────────
  GAPS=$(count '.event_type=="sys.producer.gap"')
  chk_ge T18-1a "gap records were written for the dropped ranges" 1 "$GAPS"

  if [[ "$GAPS" -ge 1 ]]; then
    chk T18-1b "every gap names a producer" 0 \
      "$(records '.event_type=="sys.producer.gap"' | jq -r 'select((.detail.producer_id // "") == "")' | wc -l | tr -d ' ')"
    chk T18-1c "every gap names the stream it lost records on" 0 \
      "$(records '.event_type=="sys.producer.gap"' | jq -r 'select((.detail.stream // "") == "")' | wc -l | tr -d ' ')"
    chk T18-1d "every gap states whether its range is exact" 0 \
      "$(records '.event_type=="sys.producer.gap"' | jq -r 'select(.detail.exact == null)' | wc -l | tr -d ' ')"
    chk T18-1f "no gap runs backwards" 0 \
      "$(records '.event_type=="sys.producer.gap"' | jq -r 'select(.detail.pseq_to < .detail.pseq_from)' | wc -l | tr -d ' ')"

    # An exact range is not reachable here, and that is arithmetic rather
    # than a gap in the proof. Nothing is dropped until the 8192-deep queue
    # is full, and by the time a producer has been refused at all it has
    # been refused far more times than its 256-entry drop ring can name —
    # so every gap this bed can produce is a conservative one. The exact
    # range is proven where it can be: the unit drives a four-deep queue,
    # where the whole drop set fits the ring (pkg/audit,
    # TestProducerDropAccounting, which asserts exact ranges covering the
    # producer's own count). What the bed owns is the shape below.
    chk T18-1e "a gap too large for the ring says so rather than guessing" 0 \
      "$(records '.event_type=="sys.producer.gap" and .detail.exact==false' \
         | jq -r 'select((.detail.pseq_to - .detail.pseq_from) + 1 < (.detail.counter_delta // 0))' | wc -l | tr -d ' ')"

    # The ranges are what was lost; the counter is how much was lost. An
    # exact range reports the two as one number; an overflowed one reports a
    # range that covers at least the count, never less — a gap that
    # understated the loss would be worse than no gap at all.
    SUMMED=$(records '.event_type=="sys.producer.gap"' \
      | jq -s 'map(.detail.counter_delta // ((.detail.pseq_to - .detail.pseq_from) + 1)) | add // 0')
    chk_ge T18-2a "the gaps account for the records the counter lost" 1 "$SUMMED"
    MISMATCH=$(records '.event_type=="sys.producer.gap" and .detail.exact==true' \
      | jq -r 'select(.detail.counter_delta != ((.detail.pseq_to - .detail.pseq_from) + 1))' | wc -l | tr -d ' ')
    chk T18-2b "every exact range covers exactly the count it reports" 0 "$MISMATCH"

    # More than one producer must appear, or the per-producer claim was
    # never actually exercised.
    PRODUCERS=$(records '.event_type=="sys.producer.gap"' | jq -r '.detail.producer_id' | sort -u | wc -l | tr -d ' ')
    chk_ge T18-2c "the gaps came from more than one producer" 2 "$PRODUCERS"
    echo "        producers seen: $(records '.event_type=="sys.producer.gap"' | jq -r '.detail.producer_id' | sort -u | tr '\n' ' ')"
  fi

  # Nothing may land without a producer identity: that counter is the one
  # that says a loss cannot be reconciled at all.
  UNATTR1=$(metric_val loxilb_audit_records_unattributed_total)
  chk T18-3a "no record reached the writer unattributed" 0 "$UNATTR1"

  # ── T21: a reorder is not a drop ──────────────────────────────────────────
  # With the writer running normally, concurrent traffic from several
  # workers interleaves their records — two producers' sequences arrive out
  # of order with respect to each other. A per-producer sequence reports no
  # gap for that; a single global one would invent them.
  GAPS_BEFORE=$(count '.event_type=="sys.producer.gap"')
  echo "  driving concurrent traffic with the writer healthy"
  for w in $(seq 1 8); do
    (
      for n in $(seq 1 25); do
        $hexec l3h1 curl -s -m 10 -o /dev/null -X POST \
          -H 'Content-Type: application/json' \
          -H "X-Api-Key: $K_ALL" \
          -d "$(body_for "$MODEL")" \
          "http://$VIP:2020/v1/chat/completions" 2>/dev/null
      done
    ) &
  done
  wait
  echo "  waiting for the next heartbeat"
  sleep 35
  GAPS_AFTER=$(count '.event_type=="sys.producer.gap"')
  chk T21-1a "interleaved producers produced no new gap" "$GAPS_BEFORE" "$GAPS_AFTER"

  DROP_MGMT=$(metric_val loxilb_audit_records_dropped_total 'stream="mgmt"')
  chk T21-1b "and nothing was dropped on the management stream" 0 "$DROP_MGMT"
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "Trail integrity"
echo "════════════════════════════════════════════════════════════════════════"
# A torn line inside a segment is a finding, not a parse convenience: the
# reader above drops what it cannot parse, so it is counted here.
TOTAL_LINES=$(trail_raw | wc -l | tr -d ' ')
PARSED=$(trail_raw | jq -c -R 'fromjson? | select(type=="object")' | wc -l | tr -d ' ')
chk_ge INT-1 "the trail has records to read" 1 "$PARSED"
chk INT-2 "every line of every segment parses" "$TOTAL_LINES" "$PARSED"

# No record on any stream may carry the raw credentials this bed created.
for k in "$K_ALL" "$K_MODEL" "$K_QUOTA"; do
  [ -z "$k" ] && continue
  n=$(trail_raw | grep -c -- "$k")
  chk INT-3 "a raw API key appears in no segment" 0 "$n"
done

echo ""
if [ "$code" -eq 0 ]; then
  echo "SCENARIO-audit-data [OK]"
else
  echo "SCENARIO-audit-data [FAILED]"
fi
exit $code
