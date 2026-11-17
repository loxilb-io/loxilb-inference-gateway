# FAILOVER-12, FAILOVER-13  A gateway on its own, and a node that returns with an old
# configuration.   (sourced by validation.sh)
#
#   FAILOVER-12b  after a node-death failover the survivor's gateway is restarted
#           while the peer is still dead. Recorded for 5 minutes: role, each
#           rule write's answer, VIP and listeners, whether the rules it saved
#           are served and from when.
#   FAILOVER-12c  the peer then returns: time until the VIP serves.
#   FAILOVER-12a  both nodes are down and ONE is started; its peer never answers.
#           The same records for 5 minutes, then the peer returns.
#   FAILOVER-13   with one node dead, one rule is deleted on the survivor and the
#           flow-control ceiling of another is changed. The dead node returns
#           and the list is NOT re-applied. Recorded: its read-back against
#           the survivor's, whether anything (API, log, metric) flags the
#           difference, and after failing over to it what the client gets on
#           the deleted rule's port and which ceiling is in force. Parity is
#           then restored and checked.
#
# FAILOVER-12 runs b, c, a so that one node death serves b and c.

LONE_WATCH_S=${HAFO_LONE_WATCH_S:-300}
LONE_READY_MS=120000
PEER_RETURN_S=45
declare -A LONE_RESULT
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
# lone_summary <file> -> role sequence and first healthy owner/service sample.
lone_summary() {
  python3 - "$1" "$LONE_READY_MS" <<'PY'
import re, sys
rows = [ln.rstrip("\n") for ln in open(sys.argv[1]) if ln.strip()]
roles, last, first_listen, first_200, first_owned, n200 = [], None, None, None, None, 0
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
        if first_owned is None and r == "MASTER" and "vip_on_lo=1" in ln:
            first_owned = ms
limit = int(sys.argv[2])
# Require the end of the observation to still be healthy and owned locally.
healthy = lambda row: all(x in row for x in ("role=MASTER ", "vip_on_lo=1 ", "client=[200"))
passed = (first_owned is not None and first_owned <= limit and len(rows) >= 3
          and all(healthy(row) for row in rows[-3:]))
cl = {}
for ln in rows:
    c = re.search(r"client=\[([^\]]*)\]", ln).group(1)
    cl[c] = cl.get(c, 0) + 1
print("roles %s; first listener on the VIP at %s ms; first 200 at %s ms; client answers over %d samples: %s; last sample: %s"
      % (" -> ".join(roles), first_listen, first_200, len(rows),
         ", ".join("%s x%d" % kv for kv in sorted(cl.items())), rows[-1] if rows else "none"))
print(f"owner with HTTP 200 at {first_owned} ms; limit {limit} ms; last three samples must remain healthy")
print("RESULT=" + ("PASS" if passed else "FAIL"))
PY
}
lone_verdict() { # <case> <prefix> <details>
  local id=$1 prefix=$2 detail=$3 summary result
  summary=$(lone_summary "$F12_DIR/$prefix-watch.txt")
  result=$(sed -n 's/^RESULT=//p' <<< "$summary")
  if ! grep -Eq 'reason=active_alone.*start_wait_seconds=95' "$F12_DIR/$prefix-ha-lines.txt"; then
    result=FAIL
    detail="$detail; missing the active_alone log with the 95 s start allowance"
  fi
  LONE_RESULT[$id]=${result:-FAIL}
  verdict "$id" "${LONE_RESULT[$id]}" "$detail; $(sed -n '2p' <<< "$summary"); $(head -1 <<< "$summary")"
}

peer_return_verdict() { # <case> <owner> <peer> <elapsed-ms> <probe json>
  local id=$1 owner=$2 peer=$3 elapsed=$4 probe=$5 status=FAIL
  local attempts ok owner_vip peer_vip
  attempts=$(jget "d['attempts']" < "$probe")
  ok=$(jget "d['ok_after_mark']" < "$probe")
  owner_vip=$(vip_state "$owner")
  peer_vip=$(vip_state "$peer")
  if [ "$elapsed" -le $((PEER_RETURN_S * 1000)) ] &&
     [ "$MASTER_NODE" = "$owner" ] && [ "$BACKUP_NODE" = "$peer" ] &&
     [[ "$owner_vip" == vip_on_lo=1\ * && "$peer_vip" == vip_on_lo=0\ * ]] &&
     [[ "$attempts" =~ ^[0-9]+$ && "$ok" == "$attempts" ]] && [ "$attempts" -ge 10 ]; then
    status=PASS
  fi
  LONE_RESULT[$id]=$status
  verdict "$id" "$status" "convergence $elapsed ms (limit ${PEER_RETURN_S} s); roles [$ROLE_LAST], expected $owner MASTER ($owner_vip) and $peer BACKUP ($peer_vip); ${ok:-0}/${attempts:-0} HTTP 200 (at least 10 requests and zero failures)"
}

ha_lines() { # <node> <file>: the gateway's own HA lines
  docker exec "$1" sh -c 'grep -h -E "Added BFD|BFD State|HA stage|ka-gate|kept without a listener|ci-change instance|reason=active_alone|snapshot|not an address of this gateway" /var/log/loxilb$(hostname).log | tail -n 200' > "$2" 2>&1
}

if want FAILOVER-12; then
echo; echo "FAILOVER-12  Lone start"
if ! fo_begin; then
  verdict FAILOVER-12 NOT_RUN "roles did not hold before the case ($ROLE_LAST)"
elif ! fo_fault; then
  verdict FAILOVER-12 NOT_RUN "the survivor $S held no listener on $VIP:$PORT_KEY within 60 s of the fault"
  fo_restore
else
  r=$(vretry $PORT_KEY $MODEL_KEY "X-Api-Key: $(key_raw fo-seed-key)" 60 fo12-pre)
  note "FAILOVER-12b: $M died at t0=$T0; $S serves ($(echo "$r" | jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])")); now restarting the gateway on $S with the peer dead"
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
  lone_verdict FAILOVER-12b b "survivor $S restarted with peer dead; API ready after $ams ms; rule writes [$w]"

  # ---- c: the peer returns while the client probes the existing owner.
  sudo ip netns exec "$CLIENT" python3 "$HAFO_DIR/hafo_tools.py" debtwatch --vip "$VIP" --port "$PORT_KEY" --model "$MODEL_KEY" \
    --header "X-Api-Key: $(key_raw fo-seed-key)" --max 300 --tag "fo12-c-$$" --out "$F12_DIR/c-watch.jsonl" --interval 0.5 \
    > "$F12_DIR/c-watch.json" 2>/dev/null &
  c_probe=$!
  c0=$(now_ms)
  c_ok=0
  if fo_restore && wait_roles "$PEER_RETURN_S" 6; then c_ok=1; fi
  c_roles=$(( $(now_ms) - c0 ))
  sleep 10
  sudo touch "$F12_DIR/c-watch.jsonl.stop"; wait "$c_probe"; sudo rm -f "$F12_DIR/c-watch.jsonl.stop"
  [ "$c_ok" = 1 ] || c_roles=$((PEER_RETURN_S * 1000 + 1))
  peer_return_verdict FAILOVER-12c "$S" "$M" "$c_roles" "$F12_DIR/c-watch.json"

  # ---- a: both down, one starts, its peer never answers.
  if ! wait_roles 60 6; then
    verdict FAILOVER-12a NOT_RUN "the pair was not healthy after FAILOVER-12c ($ROLE_LAST)"
    LONE_RESULT[FAILOVER-12a]=NOT_RUN
  else
    LONE=llb1; PEER=llb2
    node_death "$BACKUP_NODE" >/dev/null; node_death "$MASTER_NODE" >/dev/null
    a0=$(now_ms)
    ret=$(node_return "$LONE" 2>>"$F12_DIR/a-restore.err") || ret="node_return failed: $(tail -1 "$F12_DIR/a-restore.err")"
    w=$(apply_record "$LONE" "$F12_DIR/a-writes.txt")
    lone_watch "$LONE" "$LONE_WATCH_S" "$F12_DIR/a-watch.txt" "$a0"
    ha_lines "$LONE" "$F12_DIR/a-ha-lines.txt"
    lone_verdict FAILOVER-12a a "$LONE started after both nodes were down ($ret); rule writes [$w]"
    sudo ip netns exec "$CLIENT" python3 "$HAFO_DIR/hafo_tools.py" debtwatch --vip "$VIP" --port "$PORT_KEY" --model "$MODEL_KEY" \
      --header "X-Api-Key: $(key_raw fo-seed-key)" --max 300 --tag "fo12-a2-$$" --out "$F12_DIR/a-peer.jsonl" --interval 0.5 \
      > "$F12_DIR/a-peer.json" 2>/dev/null &
    a_probe=$!
    p0=$(now_ms)
    p_ok=0
    if node_return "$PEER" 2>>"$F12_DIR/a-restore.err" &&
       apply_cfg "$PEER" "" returning 2>>"$F12_DIR/a-restore.err" &&
       wait_roles "$PEER_RETURN_S" 6; then p_ok=1; fi
    p_roles=$(( $(now_ms) - p0 ))
    sleep 10
    sudo touch "$F12_DIR/a-peer.jsonl.stop"; wait "$a_probe"; sudo rm -f "$F12_DIR/a-peer.jsonl.stop"
    [ "$p_ok" = 1 ] || p_roles=$((PEER_RETURN_S * 1000 + 1))
    peer_return_verdict FAILOVER-12a.peer-up "$LONE" "$PEER" "$p_roles" "$F12_DIR/a-peer.json"
  fi
  f12_status=PASS
  for id in FAILOVER-12b FAILOVER-12c FAILOVER-12a FAILOVER-12a.peer-up; do
    [ "${LONE_RESULT[$id]:-NOT_RUN}" = PASS ] || f12_status=FAIL
  done
  verdict FAILOVER-12 "$f12_status" "both lone starts and both peer returns must pass their ownership and service limits"
fi
fi

if want FAILOVER-13; then
echo; echo "FAILOVER-13  Stale snapshot (record-only)"
if ! fo_begin; then
  verdict FAILOVER-13 NOT_RUN "roles did not hold before the case ($ROLE_LAST)"
elif ! fo_fault; then
  verdict FAILOVER-13 NOT_RUN "the survivor $S held no listener on $VIP:$PORT_KEY within 60 s of the fault"
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
    verdict FAILOVER-13 NOT_RUN "the changes could not be made on the survivor; see fo13/changes.txt"
    lb_delete "$NEW" $PORT_FC $MODEL_FC >/dev/null; apply_cfg "$NEW" "" returning 2>/dev/null
    fo_restore
  else
    # ---- the dead node returns; the list is NOT re-applied.
    t_ret=$(now_ms)
    if ! ret=$(node_return "$OLD" 2>>"$F13_DIR/restore.err"); then
      verdict FAILOVER-13 NOT_RUN "the dead node did not return: $(tail -1 "$F13_DIR/restore.err")"
    else
      wait_roles 240 6; roles_txt=$ROLE_LAST
      snapshot_readbacks fo13-stale
      differ=$(readbacks_equal fo13-stale) || true
      for n in $NODES; do
        docker exec "$n" sh -c 'grep -h -i -E "parity|mismatch|diverg|drift|out of sync|inconsisten|config.*differ" /var/log/loxilb$(hostname).log | tail -n 40' > "$F13_DIR/flag-log-$n.txt" 2>&1
        $hexec "$n" curl -s -m 8 http://127.0.0.1:11111/netlox/v1/metrics | grep -i -E "^[a-z_]*(parity|mismatch|diverg|drift|config_hash|config_generation|config_version)[a-z_]*[{ ]" > "$F13_DIR/flag-metrics-$n.txt" 2>&1
      done
      api_get "$OLD" /config/cistate/all > "$F13_DIR/cistate-$OLD.json"; api_get "$NEW" /config/cistate/all > "$F13_DIR/cistate-$NEW.json"
      verdict FAILOVER-13.readback RECORDED "$OLD returned with what it had saved and no list was applied (roles $roles_txt): read-backs that differ from $NEW:${differ:- none} (diffs under readback-fo13-stale/); $OLD reads back rule :$PORT_AFF $(rule_present "$OLD" $PORT_AFF && echo present || echo absent), $NEW $(rule_present "$NEW" $PORT_AFF && echo present || echo absent)"
      verdict FAILOVER-13.flagged RECORDED "lines that name a difference between the two nodes: log $OLD=$(grep -c . "$F13_DIR/flag-log-$OLD.txt") $NEW=$(grep -c . "$F13_DIR/flag-log-$NEW.txt"); metric series whose name suggests a configuration comparison: $OLD=$(grep -c . "$F13_DIR/flag-metrics-$OLD.txt") $NEW=$(grep -c . "$F13_DIR/flag-metrics-$NEW.txt") (files fo13/flag-*; the cluster-state read-backs are in fo13/cistate-*.json)"
      # ---- fail over to the node with the old configuration.
      if [ "$(role "$OLD")" != BACKUP ]; then
        verdict FAILOVER-13.failover NOT_RUN "the returned node is $(role "$OLD"), not BACKUP; nothing to fail over to"
      else
        M=$NEW; S=$OLD
        if ! fo_fault; then
          verdict FAILOVER-13.failover NOT_RUN "$OLD held no listener on $VIP:$PORT_KEY within 60 s"
        else
          sleep 4   # past the quota warm-up answers, which every rule gives
          vreq $PORT_AFF $MODEL_AFF "X-Conversation-Id: fo13-$$" fo13-deleted; a=$VREQ_OUT; g=$(receipts "$VREQ_NONCE")
          vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $(key_raw fo13-key)" fo13-key; k=$VREQ_OUT
          verdict FAILOVER-13.failover RECORDED "after failing over to $OLD (listener after ${LISTEN_MS} ms): the rule deleted on $NEW answers [${a% }] on :$PORT_AFF with backend receipts=$g; a keyed request answers [${k% }]; flow-control ceiling in force on $OLD: read-back fc_max_outstanding=$(fc_configured "$OLD"), loxilb_ai_admission_limit{role=service}=$(metric "$OLD" loxilb_ai_admission_limit "role=\"service\",service=\"$VIP:$PORT_FC\"") (the node that died had been changed to 3; the list and this node's saved configuration say 2)"
        fi
        # ---- restore parity: the node that carried the changes returns.
        ret=$(node_return "$NEW" 2>>"$F13_DIR/restore.err") || note "FAILOVER-13: $NEW did not return: $(tail -1 "$F13_DIR/restore.err" | cut -c1-160)"
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
          verdict FAILOVER-13.restore PASS "harness check: both nodes read back the list again after the case"
        else
          verdict FAILOVER-13.restore FAIL "harness check: read-backs still differ after the case:$differ"
        fi
      else
        verdict FAILOVER-13.restore NOT_RUN "the pair did not become healthy after the case ($ROLE_LAST)"
      fi
      verdict FAILOVER-13 RECORDED "see FAILOVER-13.readback, FAILOVER-13.flagged, FAILOVER-13.failover"
    fi
  fi
fi
fi
