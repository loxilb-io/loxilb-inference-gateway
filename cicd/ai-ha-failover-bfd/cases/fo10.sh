# FAILOVER-10  Promotion of a standby that just restarted.   (sourced by validation.sh)
#
# State is built on the MASTER (a tenant in quota debt, 100 pinned
# conversations). The standby is then taken away and returned (reboot
# emulation), and the moment the roles hold for two samples the MASTER dies.
# Judge quota continuity using the old master's Retry-After and independent
# backend receipts. Record the affinity share and cold-open metric.

echo; echo "FAILOVER-10  Promotion of a standby that just restarted"
F10_DIR="$OUT/fo10"; mkdir -p "$F10_DIR"

if ! fo_begin; then
  verdict FAILOVER-10 NOT_RUN "roles did not hold before the case ($ROLE_LAST)"
else
  pre_ok=1
  KD=$(key_raw fo10-debt-key); KC=$(key_raw fo10-ctl-key)
  debt_spend "$KD" fo10
  { [ "${DEBT_A1%% *}" = 200 ] && [ "${DEBT_A2%% *}" = 429 ] && [ "$DEBT_G2" = 0 ]; } || \
    { pre_ok=0; note "FAILOVER-10 pre: the debt was not established on $M (first=$DEBT_A1 second=$DEBT_A2 receipts=$DEBT_G2)"; }
  vconv $PORT_AFF $MODEL_AFF "t$$" 100 > "$F10_DIR/conv-turn1.json"
  vconv $PORT_AFF $MODEL_AFF "t$$" 100 > "$F10_DIR/conv-turn2.json"
  read -r pin_same pin_total pin_share pin_distinct <<<"$(conv_share "$F10_DIR/conv-turn1.json" "$F10_DIR/conv-turn2.json")"
  { [ "$pin_same" = "$pin_total" ] && [ "$pin_distinct" -ge 2 ]; } || \
    { pre_ok=0; note "FAILOVER-10 pre: pinning is not proved on one node (share $pin_share over $pin_distinct endpoints)"; }
  conv_s_before=$(metric "$S" loxilb_proxy_conversation_sessions)
  cold_before="$M=$(metric "$M" loxilb_ai_token_quota_cold_open_total) $S=$(metric "$S" loxilb_ai_token_quota_cold_open_total)"

  if [ "$pre_ok" != 1 ]; then
    verdict FAILOVER-10 NOT_RUN "a precondition failed; see notes.log"
  else
    # The standby goes away and comes back.
    node_death "$S" >/dev/null
    rs0=$(now_ms)
    if ! ret=$(node_return "$S" 2>>"$F10_DIR/restore.err") || ! apply_cfg "$S" "" returning 2>>"$F10_DIR/restore.err"; then
      verdict FAILOVER-10 NOT_RUN "the standby $S did not return: $(tr '\n' ' ' < "$F10_DIR/restore.err" | cut -c1-200)"
    elif ! wait_roles 240 2 || [ "$MASTER_NODE" != "$M" ]; then
      verdict FAILOVER-10 NOT_RUN "after the standby returned the roles were $ROLE_LAST (want $M MASTER, $S BACKUP)"
    else
      conv_ms=$(( $(now_ms) - rs0 ))
      # The debt's horizon has to come from a refusal that is recent.
      debt_refresh "$KD" fo10; refresh_ok=$?
      conv_s_restarted=$(metric "$S" loxilb_proxy_conversation_sessions)
      cold_restarted=$(metric "$S" loxilb_ai_token_quota_cold_open_total)
      if ! fo_fault; then
        verdict FAILOVER-10 NOT_RUN "the restarted standby $S held no listener on $VIP:$PORT_KEY within 60 s of the fault"
      else
        note "FAILOVER-10: $S returned ($ret), roles held $conv_ms ms after its return began, $M died $(( T0 - rs0 - conv_ms )) ms later; $S listener after ${LISTEN_MS} ms"
        w=$(debt_watch "$KD" 25 fo10-debt "$F10_DIR/debt-watch.jsonl" "$DEBT_HORIZON" "$T0"); echo "$w" > "$F10_DIR/debt-watch.json"
        read -r leak_rcpt n_ok <<<"$(debt_receipts "$w")"
        rc=$(vretry $PORT_KEY $MODEL_KEY "X-Api-Key: $KC" 60 fo10-ctl); echo "$rc" > "$F10_DIR/ctl-retry.json"
        vconv $PORT_AFF $MODEL_AFF "t$$" 100 > "$F10_DIR/conv-turn3.json"
        read -r same total share distinct <<<"$(conv_share "$F10_DIR/conv-turn1.json" "$F10_DIR/conv-turn3.json")"
        leaks=$(echo "$w" | jget "d['leaks']")
        n429=$(echo "$w" | jget "d['refused_429_after_mark']")
        gctl=$(receipts "$(echo "$rc" | jget "d['last_nonce']")")
        ctl_ok=$(echo "$rc" | jget "d['ok']")
        detail="Retry-After refresh saw $DEBT_REFRESH; early admissions=$leaks refusals=$n429 refused receipts=$leak_rcpt control ok=$ctl_ok receipts=$gctl"
        if [ "$refresh_ok" != 0 ]; then
          verdict FAILOVER-10.quota NOT_RUN "no usable Retry-After from the incumbent; $detail"
        elif [ "$leaks" != 0 ] || [ "$leak_rcpt" != 0 ] || [ "$ctl_ok" != True ] || [ "$gctl" != 1 ]; then
          verdict FAILOVER-10.quota FAIL "$detail"
        elif [ "$n429" -ge 5 ]; then
          verdict FAILOVER-10.quota PASS "$detail"
        else
          verdict FAILOVER-10.quota NOT_RUN "too few refusals after failover; $detail"
        fi
        verdict FAILOVER-10.affinity RECORDED "$same of $total conversations pinned before the standby restarted landed on their endpoint after it was promoted (share $share, four endpoints); conversation gauge on $S: $conv_s_before before its restart, $conv_s_restarted after it, before the fault"
        verdict FAILOVER-10.cold-open RECORDED "loxilb_ai_token_quota_cold_open_total: before [$cold_before]; on $S after its restart $cold_restarted, after promotion $(metric "$S" loxilb_ai_token_quota_cold_open_total)"
        verdict FAILOVER-10 RECORDED "roles held $conv_ms ms after the standby's return began and the master died $(( T0 - rs0 - conv_ms )) ms after that; see FAILOVER-10.quota, FAILOVER-10.affinity, FAILOVER-10.cold-open"
      fi
      fo_restore
    fi
  fi
fi
