# FO-12, FO-13  A gateway on its own, and a node that returns with an old
# configuration.   (sourced by validation.sh; both record-only)
#
#   FO-12b  after a node-death failover the survivor's gateway is restarted
#           while the peer is still dead. Recorded for 5 minutes: role, each
#           rule write's answer, VIP and listeners, whether the rules it saved
#           are served and from when.
#   FO-12c  the peer then returns: time until the VIP serves.
#   FO-12a  both nodes are down and ONE is started; its peer never answers.
#           The same records for 5 minutes, then the peer returns.
#   FO-13   with one node dead, one rule is deleted on the survivor and the
#           flow-control ceiling of another is changed. The dead node returns
#           and the list is NOT re-applied. Recorded: its read-back against
#           the survivor's, whether anything (API, log, metric) flags the
#           difference, and after failing over to it what the client gets on
#           the deleted rule's port and which ceiling is in force. Parity is
#           then restored and checked.
#
# FO-12 runs b, c, a so that one node death serves b and c.

LONE_WATCH_S=${HAFO_LONE_WATCH_S:-300}
F12_DIR="$OUT/fo12"; F13_DIR="$OUT/fo13"; mkdir -p "$F12_DIR" "$F13_DIR"

# apply_record <node> <file>: every write of the list, never stopping; one
# line per write "<code> <method> <path> <start of the answer>".
apply_record() {
  local n=$1 f=$2 m p b resp code
  while IFS=$'\t' read -r m p b; do
    [ -z "$m" ] && continue
    resp=$(api "$n" "$m" "$p" "$b"); code=$(printf '%s\n' "$resp" | sed -n 's/^http_code=//p')
    echo "${code:-none} $m $p $(printf '%s' "$resp" | head -1 | cut -c1-160)" >> "$f"
  done < "$HAFO_DIR/.cfg-list"
  awk '{c[$1]++} END{for (k in c) printf "%s x%d ", k, c[k]}' "$f"
}
# lone_watch <node> <seconds> <file> <t0-ms>: every 5 s the node's role, VIP
# and listeners, and what one keyed request through the VIP gets.
lone_watch() {
  local n=$1 max=$2 f=$3 t0=$4 a
  while [ $(( $(now_ms) - t0 )) -lt $(( max * 1000 )) ]; do
    vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $(key_raw fo-seed-key)" lone; a=$VREQ_OUT
    echo "$(( $(now_ms) - t0 )) role=$(role "$n") $(vip_state "$n") client=[${a% }]" >> "$f"
    sleep 5
  done
}
# lone_summary <file> -> role sequence, first listener, first 200, last line
lone_summary() {
  python3 - "$1" <<'PY'
import re, sys
rows = [ln.rstrip("\n") for ln in open(sys.argv[1]) if ln.strip()]
roles, last, first_listen, first_200, n200 = [], None, None, None, 0
for ln in rows:
    ms = int(ln.split()[0]); r = re.search(r"role=(\S+)", ln).group(1)
    if r != last:
        roles.append("%s@%d" % (r, ms)); last = r
    if first_listen is None and "listeners=none" not in ln:
        first_listen = ms
    if "client=[200" in ln:
        n200 += 1
        if first_200 is None:
            first_200 = ms
cl = {}
for ln in rows:
    c = re.search(r"client=\[([^\]]*)\]", ln).group(1)
    cl[c] = cl.get(c, 0) + 1
print("roles %s; first listener on the VIP at %s ms; first 200 at %s ms; client answers over %d samples: %s; last sample: %s"
      % (" -> ".join(roles), first_listen, first_200, len(rows),
         ", ".join("%s x%d" % kv for kv in sorted(cl.items())), rows[-1] if rows else "none"))
print("SERVED=%d" % n200)
PY
}
ha_lines() { # <node> <file>: the gateway's own HA lines
  docker exec "$1" sh -c 'grep -h -E "Added BFD|BFD State|HA stage|ka-gate|kept without a listener|ci-change instance|snapshot|not an address of this gateway" /var/log/loxilb$(hostname).log | tail -n 200' > "$2" 2>&1
}

if want FO-12; then
echo; echo "FO-12  Lone start (record-only)"
if ! fo_begin; then
  verdict FO-12 NOT_RUN "roles did not hold before the case ($ROLE_LAST)"
elif ! fo_fault; then
  verdict FO-12 NOT_RUN "the survivor $S held no listener on $VIP:$PORT_KEY within 60 s of the fault"
  fo_restore
else
  r=$(vretry $PORT_KEY $MODEL_KEY "X-Api-Key: $(key_raw fo-seed-key)" 60 fo12-pre)
  note "FO-12b: $M died at t0=$T0; $S serves ($(echo "$r" | jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])")); now restarting the gateway on $S with the peer dead"
  # ---- b: restart the survivor's gateway, peer still dead.
  pid=$(loxilb_pid "$S"); r0=$(now_ms)
  sudo kill -TERM "$pid"
  while [ -e "/proc/$pid" ] && [ $(( $(now_ms) - r0 )) -lt 40000 ]; do sleep 0.05; done
  echo "after SIGTERM, before the start: exit after $(( $(now_ms) - r0 )) ms; $(vip_state "$S")" > "$F12_DIR/b-watch.head"
  r0=$(now_ms)
  docker exec -d "$S" bash -c "$(cat "$HAFO_DIR/.${S}-cmdline") >> /tmp/loxilb.out 2>> /tmp/loxilb.err"
  ams=$(wait_api "$S" 120) || ams="timeout($ams)"
  w=$(apply_record "$S" "$F12_DIR/b-writes.txt")
  lone_watch "$S" "$LONE_WATCH_S" "$F12_DIR/b-watch.txt" "$r0"
  ha_lines "$S" "$F12_DIR/b-ha-lines.txt"
  sum=$(lone_summary "$F12_DIR/b-watch.txt"); b_served=$(echo "$sum" | sed -n 's/^SERVED=//p')
  verdict FO-12b RECORDED "gateway on $S restarted with its peer dead ($(cat "$F12_DIR/b-watch.head")): REST API ready after $ams ms; the list's writes were answered [$w]; over $LONE_WATCH_S s: $(echo "$sum" | head -1)"
  # ---- c: the peer returns.
  # A client that keeps asking every 0.5 s through the whole return.
  sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" debtwatch --vip $VIP --port $PORT_KEY --model $MODEL_KEY \
    --header "X-Api-Key: $(key_raw fo-seed-key)" --max 300 --tag "fo12-c-$$" --out "$F12_DIR/c-watch.jsonl" --interval 0.5 \
    > "$F12_DIR/c-watch.json" 2>/dev/null &
  c0=$(now_ms)
  fo_restore; wait_roles 240 6; c_roles=$(( $(now_ms) - c0 ))
  sleep 10
  sudo touch "$F12_DIR/c-watch.jsonl.stop"; wait 2>/dev/null; sudo rm -f "$F12_DIR/c-watch.jsonl.stop"
  verdict FO-12c RECORDED "the peer $M returned: the roles read [$ROLE_LAST] $c_roles ms after its return began; a client asking every 0.5 s from the start of the return until 10 s after the roles held saw: $(jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])" < "$F12_DIR/c-watch.json")"

  # ---- a: both down, one starts, its peer never answers.
  if ! wait_roles 60 6; then
    verdict FO-12a NOT_RUN "the pair was not healthy after FO-12c ($ROLE_LAST)"
    a_served=unknown
  else
    LONE=llb1; PEER=llb2
    node_death "$BACKUP_NODE" >/dev/null; node_death "$MASTER_NODE" >/dev/null
    a0=$(now_ms)
    ret=$(node_return "$LONE" 2>>"$F12_DIR/a-restore.err") || ret="node_return failed: $(tail -1 "$F12_DIR/a-restore.err")"
    w=$(apply_record "$LONE" "$F12_DIR/a-writes.txt")
    lone_watch "$LONE" "$LONE_WATCH_S" "$F12_DIR/a-watch.txt" "$a0"
    ha_lines "$LONE" "$F12_DIR/a-ha-lines.txt"
    sum=$(lone_summary "$F12_DIR/a-watch.txt"); a_served=$(echo "$sum" | sed -n 's/^SERVED=//p')
    verdict FO-12a RECORDED "$LONE started alone after both nodes were down ($ret); the list's writes were answered [$w]; over $LONE_WATCH_S s: $(echo "$sum" | head -1)"
    vretry $PORT_KEY $MODEL_KEY "X-Api-Key: $(key_raw fo-seed-key)" 300 fo12-a2 0.5 > "$F12_DIR/a-peer-retry.json" &
    p0=$(now_ms)
    if ret=$(node_return "$PEER" 2>>"$F12_DIR/a-restore.err") && apply_cfg "$PEER" "" returning 2>>"$F12_DIR/a-restore.err"; then
      wait_roles 240 6
      # The lone node refused or held its writes; give it the list again now.
      apply_cfg "$LONE" "" returning 2>>"$F12_DIR/a-restore.err"
      echo "after the peer returned, list on $LONE: created=$APPLY_NEW already-held=$APPLY_HELD" >> "$F12_DIR/a-writes.txt"
    fi
    wait 2>/dev/null
    verdict FO-12a.peer-up RECORDED "then $PEER started ($ret): roles [$ROLE_LAST] $(( $(now_ms) - p0 )) ms later; a client asking every 0.5 s saw: $(jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])" < "$F12_DIR/a-peer-retry.json"), first 200 after $(jget "d['first_200_after_ms']" < "$F12_DIR/a-peer-retry.json") ms"
  fi
  verdict FO-12 RECORDED "can one healthy gateway started with --ka serve the VIP while its peer does not answer? Keyed requests answered 200 in $b_served of the samples after a restart of the survivor, and in $a_served of the samples after a cold start of one node (one sample every 5 s for $LONE_WATCH_S s each)"
fi
fi

if want FO-13; then
echo; echo "FO-13  Stale snapshot (record-only)"
if ! fo_begin; then
  verdict FO-13 NOT_RUN "roles did not hold before the case ($ROLE_LAST)"
elif ! fo_fault; then
  verdict FO-13 NOT_RUN "the survivor $S held no listener on $VIP:$PORT_KEY within 60 s of the fault"
  fo_restore
else
  OLD=$M; NEW=$S     # OLD is dead and will return with what it saved
  # ---- on the survivor: one rule deleted, one ceiling changed.
  d1=$(lb_delete "$NEW" $PORT_AFF $MODEL_AFF); rule_present "$NEW" $PORT_AFF && gone=no || gone=yes
  fc_line=$(awk -F'\t' -v p="\"port\":$PORT_FC," 'index($3, p)' "$HAFO_DIR/.cfg-list")
  fc_new=$(printf '%s' "$fc_line" | cut -f3 | sed 's/"fc_max_outstanding":2/"fc_max_outstanding":3/')
  d2=$(lb_delete "$NEW" $PORT_FC $MODEL_FC)
  c2=$(api "$NEW" POST /config/loadbalancer "$fc_new" | sed -n 's/^http_code=//p')
  {
    echo "on $NEW with $OLD dead: delete :$PORT_AFF -> HTTP $d1, rule gone from the read-back: $gone"
    echo "on $NEW: ceiling change on :$PORT_FC as delete (HTTP $d2) + create with fc_max_outstanding 3 (HTTP $c2)"
    echo "$NEW now reads back fc_max_outstanding=$(fc_configured "$NEW")"
  } | tee "$F13_DIR/changes.txt"
  if [ "$gone" != yes ] || [ "${c2:-0}" -ge 300 ]; then
    verdict FO-13 NOT_RUN "the changes could not be made on the survivor; see fo13/changes.txt"
    lb_delete "$NEW" $PORT_FC $MODEL_FC >/dev/null; apply_cfg "$NEW" "" returning 2>/dev/null
    fo_restore
  else
    # ---- the dead node returns; the list is NOT re-applied.
    t_ret=$(now_ms)
    if ! ret=$(node_return "$OLD" 2>>"$F13_DIR/restore.err"); then
      verdict FO-13 NOT_RUN "the dead node did not return: $(tail -1 "$F13_DIR/restore.err")"
    else
      wait_roles 240 6; roles_txt=$ROLE_LAST
      snapshot_readbacks fo13-stale
      differ=$(readbacks_equal fo13-stale) || true
      for n in $NODES; do
        docker exec "$n" sh -c 'grep -h -i -E "parity|mismatch|diverg|drift|out of sync|inconsisten|config.*differ" /var/log/loxilb$(hostname).log | tail -n 40' > "$F13_DIR/flag-log-$n.txt" 2>&1
        $hexec "$n" curl -s -m 8 http://127.0.0.1:11111/netlox/v1/metrics | grep -i -E "^[a-z_]*(parity|mismatch|diverg|drift|config_hash|config_generation|config_version)[a-z_]*[{ ]" > "$F13_DIR/flag-metrics-$n.txt" 2>&1
      done
      api_get "$OLD" /config/cistate/all > "$F13_DIR/cistate-$OLD.json"; api_get "$NEW" /config/cistate/all > "$F13_DIR/cistate-$NEW.json"
      verdict FO-13.readback RECORDED "$OLD returned with what it had saved and no list was applied (roles $roles_txt): read-backs that differ from $NEW:${differ:- none} (diffs under readback-fo13-stale/); $OLD reads back rule :$PORT_AFF $(rule_present "$OLD" $PORT_AFF && echo present || echo absent), $NEW $(rule_present "$NEW" $PORT_AFF && echo present || echo absent)"
      verdict FO-13.flagged RECORDED "lines that name a difference between the two nodes: log $OLD=$(grep -c . "$F13_DIR/flag-log-$OLD.txt") $NEW=$(grep -c . "$F13_DIR/flag-log-$NEW.txt"); metric series whose name suggests a configuration comparison: $OLD=$(grep -c . "$F13_DIR/flag-metrics-$OLD.txt") $NEW=$(grep -c . "$F13_DIR/flag-metrics-$NEW.txt") (files fo13/flag-*; the cluster-state read-backs are in fo13/cistate-*.json)"
      # ---- fail over to the node with the old configuration.
      if [ "$(role "$OLD")" != BACKUP ]; then
        verdict FO-13.failover NOT_RUN "the returned node is $(role "$OLD"), not BACKUP; nothing to fail over to"
      else
        M=$NEW; S=$OLD
        if ! fo_fault; then
          verdict FO-13.failover NOT_RUN "$OLD held no listener on $VIP:$PORT_KEY within 60 s"
        else
          sleep 4   # past the quota warm-up answers, which every rule gives
          vreq $PORT_AFF $MODEL_AFF "X-Conversation-Id: fo13-$$" fo13-deleted; a=$VREQ_OUT; g=$(receipts "$VREQ_NONCE")
          vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $(key_raw fo13-key)" fo13-key; k=$VREQ_OUT
          verdict FO-13.failover RECORDED "after failing over to $OLD (listener after ${LISTEN_MS} ms): the rule deleted on $NEW answers [${a% }] on :$PORT_AFF with backend receipts=$g; a keyed request answers [${k% }]; flow-control ceiling in force on $OLD: read-back fc_max_outstanding=$(fc_configured "$OLD"), loxilb_ai_admission_limit{role=service}=$(metric "$OLD" loxilb_ai_admission_limit "role=\"service\",service=\"$VIP:$PORT_FC\"") (the node that died had been changed to 3; the list and this node's saved configuration say 2)"
        fi
        # ---- restore parity: the node that carried the changes returns.
        ret=$(node_return "$NEW" 2>>"$F13_DIR/restore.err") || note "FO-13: $NEW did not return: $(tail -1 "$F13_DIR/restore.err" | cut -c1-160)"
      fi
      # Whatever path was taken, both nodes get the list again. Only once the
      # roles hold: a node that has no role yet refuses a new rule on the VIP.
      wait_roles 240 6
      for n in $NODES; do
        [ "$(role "$n")" = UNREACHABLE ] && continue
        fc_effective_of "$n" >/dev/null
        api_get "$n" /config/loadbalancer/all | grep -q '"fc_max_outstanding":[ ]*3' && lb_delete "$n" $PORT_FC $MODEL_FC >/dev/null
        apply_cfg "$n" "" returning 2>>"$F13_DIR/restore.err"
      done
      if wait_roles 240 6; then
        snapshot_readbacks fo13-restored
        if differ=$(readbacks_equal fo13-restored); then
          verdict FO-13.restore PASS "harness check: both nodes read back the list again after the case"
        else
          verdict FO-13.restore FAIL "harness check: read-backs still differ after the case:$differ"
        fi
      else
        verdict FO-13.restore NOT_RUN "the pair did not become healthy after the case ($ROLE_LAST)"
      fi
      verdict FO-13 RECORDED "see FO-13.readback, FO-13.flagged, FO-13.failover"
    fi
  fi
fi
fi
