# FAILOVER-5, FAILOVER-8  State through one failover.   (sourced by validation.sh)
#
#   FAILOVER-5   a tenant in token-quota debt on the old master is refused on the
#          new one, with zero backend receipts; a control tenant is admitted.
#          The debt is one answer that reports 60 tokens against a bound of
#          10 per minute. How long the refusal must last is taken from the
#          gateway's own Retry-After, never from a constant here: an admission
#          earlier than the latest Retry-After allowed is the failure.
#          Separately RECORDED: what a spent RPS bucket does.
#   FAILOVER-8a  the session_header_name rule: which mechanism picks the endpoint,
#          and what share of 100 pinned conversations lands on the same
#          endpoint after the fault. RECORDED.
#   FAILOVER-8b  the same question as a PASS/FAIL at 0.90 (the documented claim),
#          with the precondition that the peer held the entries before the
#          fault. Only meaningful when the choice is held as synced state.
#
# Mutations: fo5-cut-xsync / fo8-cut-xsync cut the sync channel before the
# state is created (the three guards are then skipped on purpose, so the
# oracle itself has to fail); fo8-ep-order gives the peer the affinity rule
# with its endpoints in the opposite order (config.sh).

echo; echo "FAILOVER-5 / FAILOVER-8  Quota debt and conversation affinity through a failover"
D_DIR="$OUT/fo5-8"; mkdir -p "$D_DIR"
d_notrun() { for c in FAILOVER-5 FAILOVER-8a FAILOVER-8b; do verdict "$c" NOT_RUN "$1"; done; }
conv_gauge() { metric "$1" loxilb_proxy_conversation_sessions; }
sess_push()  { metric "$1" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="SockproxySessionMod"'; }

if ! fo_begin; then
  d_notrun "roles did not hold before the fault ($ROLE_LAST)"
else
  CUT=0
  case "${HAFO_MUTATE:-}" in
    fo5-cut-xsync|fo8-cut-xsync)
      CUT=1; xsync_cut; sleep 1
      note "FAILOVER-5/8: MUTATION, the sync channel is cut before any state is created" ;;
  esac
  KD=$(key_raw fo5-debt-key); KC=$(key_raw fo5-ctl-key); KR=$(key_raw fo5-rps-key)
  pre_ok=1
  cold_before="$M=$(metric "$M" loxilb_ai_token_quota_cold_open_total) $S=$(metric "$S" loxilb_ai_token_quota_cold_open_total)"
  conv_before_s=$(conv_gauge "$S"); push_before=$(sess_push "$M")

  # ---- FAILOVER-5 state: the tenant goes into debt on the old master.
  debt_spend "$KD" fo5
  echo "old master: first=$DEBT_A1 second=$DEBT_A2 (receipts of the second=$DEBT_G2) Retry-After=$DEBT_RETRY_AFTER horizon=$DEBT_HORIZON" > "$D_DIR/fo5-before.txt"
  { [ "${DEBT_A1%% *}" = 200 ] && [ "$DEBT_A2" = "429 token_quota_exceeded" ] && [ "$DEBT_G2" = 0 ] && [ "$DEBT_HORIZON" -gt 0 ]; } || \
    { pre_ok=0; note "FAILOVER-5 pre: the debt was not established on the old master (first=$DEBT_A1 second=$DEBT_A2 receipts=$DEBT_G2 Retry-After=$DEBT_RETRY_AFTER)"; }
  # RPS: five requests at once against a 1/s bucket.
  rps_before=$(for k in 1 2 3 4 5; do vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $KR" fo5-rps-pre; echo "$VREQ_OUT" | tr ' ' ':'; done | sort | uniq -c | tr '\n' ' ')

  # ---- FAILOVER-8 state: 100 conversations, two turns each, on the old master.
  vconv $PORT_AFF $MODEL_AFF "c$$" 100 > "$D_DIR/conv-turn1.json"
  vconv $PORT_AFF $MODEL_AFF "c$$" 100 > "$D_DIR/conv-turn2.json"
  read -r pin_same pin_total pin_share pin_distinct <<<"$(conv_share "$D_DIR/conv-turn1.json" "$D_DIR/conv-turn2.json")"
  note "FAILOVER-8 pre: on $M, turn 2 landed on turn 1's endpoint for $pin_same of $pin_total conversations over $pin_distinct endpoints"
  { [ "$pin_same" = "$pin_total" ] && [ "$pin_distinct" -ge 2 ]; } || \
    { pre_ok=0; note "FAILOVER-8 pre: pinning is not proved on one node (share $pin_share over $pin_distinct endpoints)"; }
  # A control without the header shows the rule does spread: same client,
  # no conversation id, 40 requests.
  sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" conv --vip $VIP --port $PORT_AFF --model $MODEL_AFF \
    --prefix "nohdr$$" --n 40 --conv-header X-Not-A-Session > "$D_DIR/conv-noheader.json"
  nohdr_distinct=$(jget "len(set(d.values()))" < "$D_DIR/conv-noheader.json")

  # ---- guards
  sync_mark
  vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $(key_raw fo-seed-key)" d-seed
  if sync_advanced; then sync_txt="advanced $SYNC_MARK -> $SYNC_NOW"; else sync_txt="did NOT advance ($SYNC_MARK)"; [ "$CUT" = 1 ] || pre_ok=0; fi
  sleep 1
  conv_after_s=$(conv_gauge "$S"); conv_m=$(conv_gauge "$M"); push_after=$(sess_push "$M")
  peer_held=$(awk "BEGIN{print ($conv_after_s - $conv_before_s >= 100) ? 1 : 0}" 2>/dev/null)
  {
    echo "RateLimiterSync push count on $M: $sync_txt"
    echo "SockproxySessionMod push count on $M: $push_before -> $push_after"
    echo "loxilb_proxy_conversation_sessions: $M=$conv_m; $S before pinning=$conv_before_s after=$conv_after_s"
    echo "no-header control: 40 requests landed on $nohdr_distinct distinct endpoints"
    [ "$CUT" = 1 ] && echo "sync channel cut: packets dropped so far=$(xsync_dropped)"
  } | tee "$D_DIR/guards.txt"

  if [ "$pre_ok" != 1 ]; then
    [ "$CUT" = 1 ] && xsync_restore
    d_notrun "a precondition failed before the fault; see notes.log and fo5-8/guards.txt"
  elif ! fo_fault; then
    [ "$CUT" = 1 ] && xsync_restore
    d_notrun "the survivor $S held no listener on $VIP:$PORT_KEY within 60 s of the fault"
    fo_restore
  else
    note "FAILOVER-5/8: node death of $M at t0=$T0; $S listener after ${LISTEN_MS} ms"
    # ---- FAILOVER-5: the debt tenant keeps asking for 25 s.
    w=$(debt_watch "$KD" 25 fo5-debt "$D_DIR/fo5-debt-watch.jsonl" "$DEBT_HORIZON" "$T0"); echo "$w" > "$D_DIR/fo5-debt-watch.json"
    seq=$(echo "$w" | jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])")
    read -r leak_rcpt n_ok <<<"$(debt_receipts "$w")"
    leaks=$(echo "$w" | jget "d['leaks']"); n429=$(echo "$w" | jget "d['refused_429_after_mark']")
    rc=$(vretry $PORT_KEY $MODEL_KEY "X-Api-Key: $KC" 60 fo5-ctl); echo "$rc" > "$D_DIR/fo5-ctl-retry.json"
    gctl=$(receipts "$(echo "$rc" | jget "d['last_nonce']")")
    ctl_ok=$(echo "$rc" | jget "d['ok']")
    detail="on the new master: $seq; Retry-After values seen: $(echo "$w" | jget "','.join(d['retry_after_seen'])") s; admissions earlier than the gateway's own Retry-After allowed: $leaks; refused attempts that reached a backend: $leak_rcpt; control tenant ok=$ctl_ok receipts=$gctl"
    if [ "$leaks" != 0 ] || [ "$leak_rcpt" != 0 ]; then
      verdict FAILOVER-5 FAIL "the tenant in debt was served $detail; first early admission: $(echo "$w" | jget "d['first_leak']")"
    elif [ "$ctl_ok" != True ] || [ "$gctl" != 1 ]; then
      verdict FAILOVER-5 FAIL "the control tenant was not admitted $detail"
    elif [ "$n429" -ge 5 ]; then
      verdict FAILOVER-5 PASS "the tenant in debt stayed refused ($n429 refusals after the fault) $detail"
    else
      verdict FAILOVER-5 NOT_RUN "only $n429 refusals were seen after the fault, too few to decide; $detail"
    fi
    verdict FAILOVER-5.cold-open RECORDED "loxilb_ai_token_quota_cold_open_total before the fault: $cold_before; on $S now: $(metric "$S" loxilb_ai_token_quota_cold_open_total)"
    rps_after=$(for k in 1 2 3 4 5; do vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $KR" fo5-rps-post; echo "$VREQ_OUT" | tr ' ' ':'; done | sort | uniq -c | tr '\n' ' ')
    verdict FAILOVER-5.rps RECORDED "five quick requests against a 1/s tenant bucket: on the old master [$rps_before]; on the new master $(( $(now_ms) - T0 )) ms after the fault [$rps_after]. A 1/s bucket refills faster than any failover measured here completes, so a carried-over bucket could not be told from a fresh one"

    # ---- FAILOVER-8: turn 3, through the VIP, on the new master.
    vconv $PORT_AFF $MODEL_AFF "c$$" 100 > "$D_DIR/conv-turn3.json"
    read -r same total share distinct <<<"$(conv_share "$D_DIR/conv-turn1.json" "$D_DIR/conv-turn3.json")"
    failed3=$(jget "sum(1 for v in d.values() if v.startswith('!'))" < "$D_DIR/conv-turn3.json")
    verdict FAILOVER-8a RECORDED "after the fault $same of $total conversations landed on their pinned endpoint (share $share; $failed3 requests failed). Peer table gauge on $S before the fault: $conv_before_s -> $conv_after_s; session pushes on $M: $push_before -> $push_after; sync cut: $CUT"
    if [ "$peer_held" != 1 ]; then
      # No downgrade and no PASS by another mechanism: 8b judges synced
      # state only, and says so when there was none to judge.
      verdict FAILOVER-8b NOT_RUN "precondition: the peer's conversation table did not show the 100 entries before the fault (gauge on $S $conv_before_s -> $conv_after_s; sync cut: $CUT), so the share of $share above was not produced by synced state"
    elif awk "BEGIN{exit !($share >= 0.90)}"; then
      verdict FAILOVER-8b PASS "same-endpoint share $share >= 0.90 over $total conversations (four endpoints, chance 0.25); the peer held the entries before the fault ($conv_before_s -> $conv_after_s)"
    else
      verdict FAILOVER-8b FAIL "same-endpoint share $share < 0.90 over $total conversations ($failed3 requests failed)"
    fi
    [ "$CUT" = 1 ] && { note "sync cut dropped $(xsync_dropped) packets"; xsync_restore; }
    fo_restore
  fi
fi
