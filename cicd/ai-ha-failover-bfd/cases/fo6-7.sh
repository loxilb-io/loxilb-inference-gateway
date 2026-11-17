# FAILOVER-6, FAILOVER-7  Work in flight through one failover.   (sourced by validation.sh)
#
#   FAILOVER-6  a paced SSE stream is mid-body when the MASTER dies. RECORDED: what
#         the client holds when its connection ends (status line, events,
#         bytes, how it ended, curl's exit code for the same request), what
#         the backend saw, and what the tenant was charged. PASS/FAIL: the
#         same request with the same credential, sent again, completes.
#   FAILOVER-7  the flow-control ceiling (2) is saturated with two held requests and
#         four more are parked in the queue when the MASTER dies. RECORDED:
#         each client's outcome, the new master's admission gauges after
#         promotion, when fc_effective appears relative to the listener, and
#         the peak number of requests the backend itself had in flight while
#         requests admitted by the old master and by the new one overlap.
#
# One failover serves both. The backend is hafo_backend.py: it keeps its own
# in-flight count and a record of how each request ended as it saw it.
#
# Mutation: fo6-backend-down stops the witness backend after the fault, so the
# retry cannot complete and FAILOVER-6 must FAIL.

echo; echo "FAILOVER-6 / FAILOVER-7  A stream in flight and admission state through a failover"
E_DIR="$OUT/fo6-7"; mkdir -p "$E_DIR"
e_notrun() { for c in FAILOVER-6 FAILOVER-7; do verdict "$c" NOT_RUN "$1"; done; }
STREAM_HDRS=(--header "X-Test-Chunks: 240" --header "X-Test-Pace-Ms: 250")   # a 60 s body
# fc_gauges <node> -> "inflight=N queued=N" summed over the bands of the
# flow-control rule's fc_effective read-back ("none" when it is null), then
# the node's raw admission gauge lines for that rule.
fc_gauges() {
  local g
  g=$(fc_effective_of "$1" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    d = None
if not isinstance(d, dict):
    print('none')
else:
    b = [v for v in (d.get('bands') or {}).values() if isinstance(v, dict)]
    print('inflight=%d queued=%d' % (sum(x.get('inflight', 0) for x in b), sum(x.get('queued', 0) for x in b)))")
  echo "$g"
}
fc_metric_lines() { # <node> -> the non-zero admission gauge series of the flow-control rule, one line
  local page
  page=$($hexec "$1" curl -s --max-time 8 http://127.0.0.1:11111/netlox/v1/metrics 2>/dev/null)
  [ -z "$page" ] && { echo "(the metrics scrape returned nothing)"; return; }
  page=$(printf '%s\n' "$page" | grep -E '^loxilb_ai_admission_(inflight|limit|effective_limit|queued)' | grep "service=\"$VIP:$PORT_FC\"")
  [ -z "$page" ] && { echo "(no admission series for $VIP:$PORT_FC on this node)"; return; }
  printf '%s\n' "$page" | grep -v ' 0$' | sed 's/pool="[^"]*",//; s/,service="[^"]*"//; s/service="[^"]*"//; s/loxilb_ai_admission_//' | tr '\n' ' '
}
# fc_client <index> <delay-ms> <tag> <dir>: one request on the flow-control
# rule, in the background, its whole record in <dir>/<tag>-<index>.json
fc_client() {
  sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" retry --vip $VIP --port $PORT_FC \
    --model $MODEL_FC --header "X-Test-Delay-Ms: $2" --max 0 --timeout 45 --tag "$3-$$-$1" \
    > "$4/$3-$1.json" 2>/dev/null &
}
fc_outcomes() { # <dir> <tag> -> "label xN ..." over the clients' records
  python3 - "$1" "$2" <<'PY'
import glob, json, sys
c = {}
for f in sorted(glob.glob("%s/%s-*.json" % (sys.argv[1], sys.argv[2]))):
    try:
        a = json.load(open(f))["first_attempt"]
    except (ValueError, KeyError):
        lab = "no-record"
    else:
        lab = a["cls"] if a["cls"] != "refusal" else "refusal:%s:%s" % (a.get("status"), a.get("error", ""))
        lab += "@%dms" % (a["t_done"] - a["t_send"])
    c[lab] = c.get(lab, 0) + 1
print(", ".join("%s x%d" % kv for kv in sorted(c.items())) or "none")
PY
}

if ! fo_begin; then
  e_notrun "roles did not hold before the fault ($ROLE_LAST)"
else
  K6=$(key_raw fo6-key)
  pre_ok=1
  # ---- FAILOVER-6 state: two identical streams, one read by the tool, one by curl.
  tok_before=$($hexec "$M" curl -s -m 5 http://127.0.0.1:11111/netlox/v1/metrics | grep -e '^loxilb_ai_token_' -e '^loxilb_ai_tokens_' | grep 'fo6-stream')
  sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" retry --vip $VIP --port $PORT_WIT \
    --model $MODEL_WIT --header "X-Api-Key: $K6" "${STREAM_HDRS[@]}" --stream --max 0 --timeout 30 \
    --tag "fo6-stream-$$" > "$E_DIR/fo6-stream.json" 2>/dev/null &
  $hexec $CLIENT curl -sN --connect-timeout 2 --max-time 90 -D "$E_DIR/fo6-curl.headers" -o "$E_DIR/fo6-curl.body" \
    -w '%{http_code} %{size_download} %{exitcode} %{time_total}\n' -X POST \
    -H 'Content-Type: application/json' -H "X-Api-Key: $K6" -H "X-Test-Nonce: fo6-curl-$$" \
    -H 'X-Test-Chunks: 240' -H 'X-Test-Pace-Ms: 250' \
    --data '{"model":"'"$MODEL_WIT"'","stream":true,"messages":[{"role":"user","content":"hi"}]}' \
    "http://$VIP:$PORT_WIT/v1/chat/completions" > "$E_DIR/fo6-curl.result" 2>/dev/null &

  # ---- FAILOVER-7 state: two holders, then four that have to queue, then one more.
  witness_reset_peak
  for k in 1 2; do fc_client "$k" 30000 fo7-hold "$E_DIR"; done
  for _ in $(seq 1 25); do case "$(fc_gauges "$M")" in inflight=2\ *) break ;; esac; sleep 0.2; done
  for k in 1 2 3 4; do fc_client "$k" 100 fo7-park "$E_DIR"; done
  for _ in $(seq 1 25); do [ "$(fc_gauges "$M")" = "inflight=2 queued=4" ] && break; sleep 0.2; done
  VREQ_TIMEOUT=10; vreq $PORT_FC $MODEL_FC "X-Test-Delay-Ms: 100" fo7-over; over=$VREQ_OUT; unset VREQ_TIMEOUT
  g_before=$(fc_gauges "$M"); w_before=$(witness_state)
  {
    echo "$M (MASTER) before the fault: $g_before"
    echo "$S (BACKUP) before the fault: $(fc_gauges "$S") fc_effective=$(fc_effective_of "$S")"
    echo "$M fc_effective=$(fc_effective_of "$M")"
    echo "a seventh request, past ceiling 2 + queue 4: $over"
    echo "witness backend: $w_before"
    echo "$M raw admission gauges: $(fc_metric_lines "$M")"
  } | tee "$E_DIR/fo7-before.txt"
  [ "$g_before" = "inflight=2 queued=4" ] || \
    { pre_ok=0; note "FAILOVER-7 pre: the gate was not saturated on $M ($g_before; want inflight=2 queued=4)"; }
  # The FAILOVER-6 stream must be mid-body at the fault: events arrived, no terminator.
  ev=$(grep -c '^data: ' "$E_DIR/fo6-curl.body" 2>/dev/null)
  { [ "${ev:-0}" -ge 2 ] && ! grep -q 'data: \[DONE\]' "$E_DIR/fo6-curl.body" 2>/dev/null; } || \
    { pre_ok=0; note "FAILOVER-6 pre: the stream was not mid-body before the fault (events=${ev:-0})"; }

  if [ "$pre_ok" != 1 ]; then
    e_notrun "a precondition failed before the fault; see notes.log and fo6-7/fo7-before.txt"
    wait 2>/dev/null
  elif ! fo_fault; then
    e_notrun "the survivor $S held no listener on $VIP:$PORT_KEY within 60 s of the fault"
    wait 2>/dev/null; fo_restore
  else
    note "FAILOVER-6/7: node death of $M at t0=$T0 with a stream mid-body ($ev events), 2 held and 4 parked; $S listener after ${LISTEN_MS} ms"
    # ---- FAILOVER-7 on the new master, as soon as it listens: when fc_effective
    # appears, and what the gauges read before anything new is sent.
    fce_ms=""
    for _ in $(seq 1 100); do
      fce=$(fc_effective_of "$S")
      case "$fce" in null|unreadable|no-rule|'') sleep 0.2 ;; *) fce_ms=$(( $(now_ms) - T0 )); break ;; esac
    done
    g_promoted="$(fc_gauges "$S"); raw: $(fc_metric_lines "$S")"
    # New work while the old master's two admitted requests are still held at
    # the backend: two holders and four behind them.
    while ! $hexec "$S" ss -Hltn 2>/dev/null | awk '{print $4}' | grep -q "^$VIP:$PORT_FC\$"; do
      [ $(( $(now_ms) - T0 )) -gt 60000 ] && break; sleep 0.1
    done
    fc_listen_ms=$(( $(now_ms) - T0 ))
    for k in 1 2; do fc_client "$k" 8000 fo7-new-hold "$E_DIR"; done
    sleep 1
    for k in 1 2 3 4; do fc_client "$k" 100 fo7-new-park "$E_DIR"; done
    sleep 1.5
    g_loaded="$(fc_gauges "$S"); raw: $(fc_metric_lines "$S")"; w_overlap=$(witness_state)

    # ---- FAILOVER-6: the retry, same request, same credential.
    if [ "${HAFO_MUTATE:-}" = fo6-backend-down ]; then
      note "FAILOVER-6: MUTATION, the witness backend is stopped before the retry"
      for bp in /proc/[0-9]*/cmdline; do
        tr "\0" " " < "$bp" 2>/dev/null | grep -q "hafo_backend.py ha-fo-witness " && sudo kill -9 "$(basename "$(dirname "$bp")")"
      done
    fi
    r=$(sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" retry --vip $VIP --port $PORT_WIT \
        --model $MODEL_WIT --header "X-Api-Key: $K6" --header "X-Test-Chunks: 8" --header "X-Test-Pace-Ms: 100" \
        --stream --max 30 --timeout 10 --tag "fo6-retry-$$")
    echo "$r" > "$E_DIR/fo6-retry.json"
    got=$(receipts "$(echo "$r" | jget "d['last_nonce']")")
    seq=$(echo "$r" | jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])")
    wait 2>/dev/null     # every background client has ended or timed out by itself
    if [ "$(echo "$r" | jget "d['ok']")" = True ] && [ "$(echo "$r" | jget "d['last_attempt']['done_seen']")" = True ] && [ "$got" = 1 ]; then
      verdict FAILOVER-6 PASS "the same streaming request with the same key completed on the new master ($seq; $(echo "$r" | jget "d['last_attempt']['events']") events and the terminator; receipts=1)"
    else
      verdict FAILOVER-6 FAIL "the retried stream did not complete within 30 s: $seq (receipts=$got)"
    fi
    w_end=$(witness_state); echo "$w_end" > "$E_DIR/witness-end.json"
    a=$(cat "$E_DIR/fo6-stream.json")
    verdict FAILOVER-6.client RECORDED "the stream cut by the fault, as the client saw it: status line $(echo "$a" | jget "d['first_attempt'].get('status_seen')"), $(echo "$a" | jget "d['first_attempt'].get('events')") events, $(echo "$a" | jget "d['first_attempt'].get('bytes')") bytes, last byte $(echo "$a" | jget "d['first_attempt'].get('t_last_byte', 0) - $T0") ms relative to the fault, ended as $(echo "$a" | jget "d['first_attempt']['cls']") after $(echo "$a" | jget "d['first_attempt']['t_done'] - $T0") ms (the tool gives up after 30 s without a byte); curl for the same request (no idle timeout, --max-time 90): http_code size exit time = $(tr '\n' ' ' < "$E_DIR/fo6-curl.result")"
    verdict FAILOVER-6.backend RECORDED "how the backend saw the two cut streams end: $(echo "$w_end" | jget "'; '.join('%s: %s after %s chunks, %d ms after the fault' % (k.split('-')[1], v.get('how'), v.get('chunks_written'), v['t_end'] - $T0) for k, v in sorted(d['ended'].items()) if k.startswith('fo6-stream') or k.startswith('fo6-curl')) or 'neither had ended when the case finished: the backend kept writing to a gateway that was gone'")"
    tok_after=$($hexec "$S" curl -s -m 5 http://127.0.0.1:11111/netlox/v1/metrics | grep -e '^loxilb_ai_token_' -e '^loxilb_ai_tokens_' | grep 'fo6-stream')
    { echo "## $M (old master) before the stream"; echo "$tok_before"; echo "## $S (new master) after the retry"; echo "$tok_after"; } > "$E_DIR/fo6-charge.txt"
    verdict FAILOVER-6.charge RECORDED "token series of tenant fo6-stream on the new master after the cut streams and one completed retry (13 tokens): $(echo "$tok_after" | tr '\n' ' ' | cut -c1-400); full before/after in fo6-7/fo6-charge.txt"

    # ---- FAILOVER-7 verdicts
    verdict FAILOVER-7.parked RECORDED "the old master's clients: held [$(fc_outcomes "$E_DIR" fo7-hold)]; parked in its queue [$(fc_outcomes "$E_DIR" fo7-park)]"
    verdict FAILOVER-7.gauges RECORDED "new master $S: fc_effective first non-null at +${fce_ms:-never within 20 s} ms (listener on :$PORT_KEY at +${LISTEN_MS} ms, on :$PORT_FC by +${fc_listen_ms} ms); gauges right after promotion [$g_promoted]; with 2 new holders and 4 behind them [$g_loaded]; the old master read [$g_before] at the fault"
    verdict FAILOVER-7.backend-peak RECORDED "requests in flight at the backend, by its own count: $(echo "$w_before" | jget "d['inflight']") before the fault (both FAILOVER-6 streams and the 2 held); $(echo "$w_overlap" | jget "d['inflight']") while the new master's 2 holders ran, peak $(echo "$w_overlap" | jget "d['peak']"); the rule's ceiling is 2 and the 2 streams are on another rule. New clients: held [$(fc_outcomes "$E_DIR" fo7-new-hold)]; behind them [$(fc_outcomes "$E_DIR" fo7-new-park)]"
    verdict FAILOVER-7 RECORDED "see FAILOVER-7.parked, FAILOVER-7.gauges and FAILOVER-7.backend-peak; no threshold is set for admission state through a failover"
    if [ "${HAFO_MUTATE:-}" = fo6-backend-down ]; then
      $hexec $WITNESS_HOST sh -c "nohup python3 $HAFO_DIR/hafo_backend.py ha-fo-witness $WITNESS_PORT >/tmp/ha-fo-witness.log 2>&1 &"
      sleep 1
    fi
    fo_restore
  fi
fi
