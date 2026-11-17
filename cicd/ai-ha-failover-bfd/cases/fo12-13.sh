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
HAFO_START_GATE_MS=95000
HAFO_START_MARGIN_MS=25000
PEER_RETURN_WATCH_S=120
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
gateway_start_ms() {
  local pid
  pid=$(loxilb_pid "$1")
  [ -n "$pid" ] || return 1
  python3 - "$pid" <<'PY2'
import os, sys, time
with open(f"/proc/{sys.argv[1]}/stat") as stat:
    ticks = int(stat.read().rsplit(") ", 1)[1].split()[19])
boot_epoch = time.time() - time.clock_gettime(time.CLOCK_BOOTTIME)
print(round(1000 * (boot_epoch + ticks / os.sysconf("SC_CLK_TCK"))))
PY2
}

lone_node_monitor() {
  sudo ip netns exec "$1" python3 "$HAFO_DIR/hafo_tools.py" node --vip "$VIP" \
    --interval "${3:-0.25}" --out "$2/node.jsonl" >/dev/null 2>&1 &
}
lone_cold_hook() { lone_node_monitor "$1" "$F12_DIR/a"; }
peer_return_hook() { lone_node_monitor "$1" "$peer_monitor_dir" 0.5; }

lone_http_monitor() {
  sudo ip netns exec "$CLIENT" python3 "$HAFO_DIR/hafo_tools.py" probe --vip "$VIP" \
    --port "$PORT_KEY" --model "$MODEL_KEY" --header "X-Api-Key: $(key_raw fo-seed-key)" \
    --rate 5 --tag "lone-$(basename "$1")" --out "$1/probe.jsonl" >/dev/null 2>&1 &
}

lone_verdict() {
  local id=$1 prefix=$2 start=$3 finish=$4 limit result
  limit=$((HAFO_START_GATE_MS + HAFO_START_MARGIN_MS))
  while [ "$(( $(now_ms) - finish ))" -lt "$((LONE_WATCH_S * 1000))" ]; do sleep 1; done
  sudo touch "$F12_DIR/$prefix/"{node,probe}.jsonl.stop
  wait 2>/dev/null
  ha_lines "$5" "$F12_DIR/$prefix-ha-lines.txt"
  result=$(python3 "$HAFO_DIR/lone_oracle.py" "$F12_DIR/$prefix" "$start" "$limit" "$PORT_KEY")
  local status detail
  read -r status detail <<< "${result%%$'\n'*}"
  LONE_RESULT[$id]=${status:-FAIL}
  verdict "$id" "${LONE_RESULT[$id]}" "${detail:-missing process or role data}"
  verdict "$id.http" RECORDED "${result#*$'\n'}"
}

peer_return_verdict() {
  local id=$1 owner=$2 peer=$3 prefix=$4
  local d="$F12_DIR/$prefix" t0 pid probe status attempts ok losses exec_ms api_end writes_end settled
  local returned=0 peer_monitor_dir="$F12_DIR/$prefix/peer"
  mkdir -p "$peer_monitor_dir"
  lone_node_monitor "$owner" "$d"
  sudo ip netns exec "$CLIENT" python3 "$HAFO_DIR/hafo_tools.py" debtwatch --vip "$VIP" --port "$PORT_KEY" --model "$MODEL_KEY" \
    --header "X-Api-Key: $(key_raw fo-seed-key)" --max 300 --tag "fo12-$prefix-$$" \
    --out "$d/http.jsonl" --interval 0.5 > "$d/http.json" 2>/dev/null &
  pid=$!
  t0=$(now_ms)
  exec_ms=unknown
  if NODE_RETURN_HOOK=peer_return_hook node_return "$peer" >> "$d/return.log" 2>&1; then
    returned=1
    exec_ms=$(gateway_start_ms "$peer")
    api_end=$(now_ms)
    apply_cfg "$peer" "" returning >> "$d/return.log" 2>&1
  fi
  writes_end=$(now_ms)
  wait_roles "$PEER_RETURN_WATCH_S" 6
  sleep 10
  sudo touch "$d/"{http,node}.jsonl.stop "$peer_monitor_dir/node.jsonl.stop"; wait "$pid"; wait 2>/dev/null
  settled=$(python3 "$HAFO_DIR/peer_observe.py" "$d" "$t0")
  ha_lines "$peer" "$d/peer-ha-lines.txt"
  probe="$d/http.json"
  attempts=$(jget "d['attempts']" < "$probe")
  ok=$(jget "d['ok_after_mark']" < "$probe")
  losses=$(python3 -c 'import json,sys; a=list(map(json.loads,open(sys.argv[1]))); print(sum(r["vip"]!=1 for r in a) if a else -1)' "$d/node.jsonl")
  status=FAIL
  if [[ "$attempts" =~ ^[0-9]+$ && "$ok" == "$attempts" && "$losses" == 0 ]] &&
     [ "$returned" = 1 ] && [ "$attempts" -ge 10 ] && [ "$(role "$owner")" = MASTER ] &&
     [[ "$(vip_state "$peer")" == vip_on_lo=0\ * ]]; then status=PASS; fi
  LONE_RESULT[$id]=$status
  verdict "$id" "$status" "$owner retains VIP (missing samples=$losses); ${ok:-0}/${attempts:-0} HTTP 200, minimum 10 with zero failures"
  verdict "$id.stabilisation" RECORDED "return to six stable roles: $settled ms; return_epoch_ms=$t0 process_epoch_ms=$exec_ms API_epoch_ms=${api_end:-unknown} writes_done_epoch_ms=$writes_end; $ROLE_LAST"
}

ha_lines() { # <node> <file>: the gateway's own HA lines
  docker exec "$1" sh -c 'grep -h -E "Added BFD|BFD State|HA stage|ka-gate|kept without a listener|ci-change instance|reason=active_(alone|without_bfd)|snapshot|not an address of this gateway" /var/log/loxilb$(hostname).log | tail -n 200' > "$2" 2>&1
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
  mkdir -p "$F12_DIR/b"
  r0=$(now_ms)
  lone_node_monitor "$S" "$F12_DIR/b"
  lone_http_monitor "$F12_DIR/b"
  docker exec -d "$S" bash -c "$(cat "$HAFO_DIR/.${S}-cmdline") >> /tmp/loxilb.out 2>> /tmp/loxilb.err"
  ams=$(wait_api "$S" 120) || ams="timeout($ams)"
  process_start=$(gateway_start_ms "$S")
  apply_record "$S" "$F12_DIR/b-writes.txt" >/dev/null
  lone_verdict FAILOVER-12b b "${process_start:-0}" "$r0" "$S"
  peer_return_verdict FAILOVER-12c "$S" "$M" c

  # ---- a: both down, one starts, its peer never answers.
  if ! wait_roles 60 6; then
    verdict FAILOVER-12a NOT_RUN "the pair was not healthy after FAILOVER-12c ($ROLE_LAST)"
    LONE_RESULT[FAILOVER-12a]=NOT_RUN
  else
    LONE=llb1; PEER=llb2
    node_death "$BACKUP_NODE" >/dev/null; node_death "$MASTER_NODE" >/dev/null
    mkdir -p "$F12_DIR/a"
    a0=$(now_ms)
    lone_http_monitor "$F12_DIR/a"
    NODE_RETURN_HOOK=lone_cold_hook node_return "$LONE" >> "$F12_DIR/a-restore.log" 2>&1
    process_start=$(gateway_start_ms "$LONE")
    apply_record "$LONE" "$F12_DIR/a-writes.txt" >/dev/null
    lone_verdict FAILOVER-12a a "${process_start:-0}" "$a0" "$LONE"
    peer_return_verdict FAILOVER-12a.peer-up "$LONE" "$PEER" a-peer
  fi
  f12_status=PASS
  for id in FAILOVER-12b FAILOVER-12c FAILOVER-12a FAILOVER-12a.peer-up; do
    [ "${LONE_RESULT[$id]:-NOT_RUN}" = PASS ] || f12_status=FAIL
  done
  verdict FAILOVER-12 "$f12_status" "both lone starts and both peer returns must pass their ownership and service limits"
fi
fi

bfd_cut_at_start() {
  sudo ip netns exec "$1" iptables -w -I INPUT -p udp --dport 3784 -j DROP &&
  sudo ip netns exec "$1" iptables -w -I OUTPUT -p udp --dport 3784 -j DROP &&
  touch "$F12_DIR/$1.bfd-cut"
}

fo12_bfd_only_at_start() {
  local n low high status=FAIL launch1 launch2 rc1=0 rc2=0
  wait_roles 60 6 || { verdict FAILOVER-12.bfd-only NOT_RUN "$ROLE_LAST"; return; }
  read -r low high < <(for n in $NODES; do echo "$(node_eth0 "$n") $n"; done |
    sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | awk '{print $2}' | xargs)
  # loxilb uses the higher IPv4 address as the tiebreak for two active ranks.
  node_death "$BACKUP_NODE" >/dev/null; node_death "$MASTER_NODE" >/dev/null
  if ! node_start_pair > "$F12_DIR/bfd-pair-start.log" 2>&1; then
    verdict FAILOVER-12.bfd-only NOT_RUN "could not start both BFD test containers"
    return
  fi
  NODE_RETURN_HOOK=bfd_cut_at_start node_return "$low" > "$F12_DIR/$low.bfd-cut.log" 2>&1 &
  launch1=$!
  NODE_RETURN_HOOK=bfd_cut_at_start node_return "$high" > "$F12_DIR/$high.bfd-cut.log" 2>&1 &
  launch2=$!
  wait "$launch1" || rc1=$?
  wait "$launch2" || rc2=$?
  if [ "$rc1" -ne 0 ] || [ "$rc2" -ne 0 ]; then
    verdict FAILOVER-12.bfd-only NOT_RUN "the BFD test gateways failed to start"
    return
  fi
  local start clean=1
  start=$(now_ms)
  while [ "$(( $(now_ms) - start ))" -lt 100000 ]; do
    if [ "$(role "$low")" = MASTER ] && [ "$(role "$high")" = MASTER ] &&
       [[ "$(vip_state "$low")" == vip_on_lo=1\ * && "$(vip_state "$high")" == vip_on_lo=1\ * ]]; then break; fi
    sleep .5
  done
  for n in "$low" "$high"; do
    ha_lines "$n" "$F12_DIR/$n.bfd-only-ha.txt"
    if [ ! -f "$F12_DIR/$n.bfd-cut" ] ||
       ! grep -q 'HA stage=ka-gate result=ready' "$F12_DIR/$n.bfd-only-ha.txt" ||
       ! docker exec "$n" cat "$(node_log "$n")" | grep -q 'reason=active_without_bfd'; then clean=0; fi
  done
  if [ "$(role "$low")" != MASTER ] || [ "$(role "$high")" != MASTER ]; then clean=0; fi
  for n in "$low" "$high"; do
    sudo ip netns exec "$n" iptables -w -D INPUT -p udp --dport 3784 -j DROP || clean=0
    sudo ip netns exec "$n" iptables -w -D OUTPUT -p udp --dport 3784 -j DROP || clean=0
  done
  if wait_roles 60 6 && [ "$clean" = 1 ] && [ "$MASTER_NODE" = "$high" ] &&
     [[ "$(vip_state "$high")" == vip_on_lo=1\ * && "$(vip_state "$low")" == vip_on_lo=0\ * ]]; then status=PASS; fi
  for n in "$low" "$high"; do apply_cfg "$n" "" returning >> "$F12_DIR/$n.bfd-cut.log" 2>&1; done
  verdict FAILOVER-12.bfd-only "$status" "XSync-ready starts became active_without_bfd in the cut; after reconnect expected $high alone with the VIP, observed $ROLE_LAST"
}

if want FAILOVER-12; then fo12_bfd_only_at_start; fi

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
