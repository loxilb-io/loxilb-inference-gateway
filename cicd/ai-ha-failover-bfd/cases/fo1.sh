# FAILOVER-1  How long is the service down?   (sourced by validation.sh)
#
# An open-loop probe (a new connection per request, valid API key) runs
# against the VIP while the MASTER is taken away, four ways:
#
#   death   node death: every link of the node down (t0), then SIGKILL
#   stop    container stop: `docker stop` (t0). In this harness the gateway is
#           not PID 1, so it keeps serving through docker's grace period and
#           is then killed; the links go down when the container has exited.
#   term    SIGTERM to loxilb (t0). The node itself stays up, as a host does
#           when an operator stops the service; what the gateway does on its
#           way out is recorded. The node is powered off afterwards.
#   crash   kill -9 loxilb (t0), container and namespace stay, nothing is
#           cleared. Record-only.
#
# Per repetition the timeline is: t0, survivor reports MASTER, VIP on the
# survivor, listener on the VIP, first 200, and the probe's outcome histogram
# in between. All RECORDED. The one PASS/FAIL is a HARNESS BOUND, not a
# product budget: 200s are stable again within 60 s. A PASS on it does not
# say the outage is acceptable.
#
# Mutations: HAFO_MUTATE=fo1-skip-fault skips the fault, and
# HAFO_MUTATE=fo1-backend-down stops the backend first; every repetition must
# then end NOT_RUN (no failover observed / control not all-200).

FO1_REPS=${HAFO_FO1_REPS:-5}
FO1_CRASH_REPS=${HAFO_FO1_CRASH_REPS:-3}
FO1_BOUND_MS=60000
FO1_DIR="$OUT/fo1"
mkdir -p "$FO1_DIR"
: > "$FO1_DIR/summary.jsonl"

# fo1_wait_settled <dir> <t0> <max-s>: until the survivor's listener is up and
# the probe has answered 200 for 3 s, or the bound passes.
fo1_wait_settled() {
  local d=$1 t0=$2 max=$3
  sleep 3
  while [ $(( $(now_ms) - t0 )) -lt $(( max * 1000 )) ]; do
    probe_tail_ok "$d" 3 && return 0
    sleep 0.5
  done
  return 1
}

# fo1_rep <mode> <index>
fo1_rep() {
  local mode=$1 i=$2 d="$FO1_DIR/$1-$2" M S t0 pid t_exit="" t_off="" extra=""
  echo; echo "--- FAILOVER-1 $mode #$i"
  if ! wait_roles 240 6; then
    verdict "FAILOVER-1.$mode.$i" NOT_RUN "roles did not hold before the fault ($ROLE_LAST)"
    return 1
  fi
  M=$MASTER_NODE; S=$BACKUP_NODE
  local mmac smac; mmac=$(node_mac "$M"); smac=$(node_mac "$S")
  mkdir -p "$d"
  pid=$(loxilb_pid "$M"); echo "$pid" > "$d/pid-$M"; loxilb_pid "$S" > "$d/pid-$S"
  if [ "${HAFO_MUTATE:-}" = "fo1-backend-down" ]; then
    note "FAILOVER-1 $mode #$i: MUTATION, the backend behind the key rule is stopped"
    for bp in /proc/[0-9]*/cmdline; do
      tr "\0" " " < "$bp" 2>/dev/null | grep -q "hdr_echo.py ha-fo-hfe1 " && sudo kill -9 "$(basename "$(dirname "$bp")")"
    done
  fi
  monitors_start "$d"
  if ! probe_control "$d" 30; then
    monitors_stop "$d"
    # Every verdict of this repetition is NOT_RUN; it also does not count
    # towards the mode's bound, which then needs another repetition.
    verdict "FAILOVER-1.$mode.$i.before" NOT_RUN "with roles holding ($M MASTER, $S BACKUP) the probe did not reach 3 s of 200s within 30 s; it got: ${PROBE_PRE_HIST:-nothing}"
    verdict "FAILOVER-1.$mode.$i" NOT_RUN "control failed: the probe was not all-200 for 3 s within 30 s before the fault (it got: ${PROBE_PRE_HIST:-nothing})"
    return 1
  fi
  # The roles held and the pair still was not serving cleanly: recorded, with
  # which node was MASTER, because nothing had been done to the pair here.
  [ -n "$PROBE_PRE_HIST" ] && verdict "FAILOVER-1.$mode.$i.before" RECORDED "before any fault, with roles holding ($M MASTER, $S BACKUP), the probe needed $PROBE_SETTLE_MS ms to reach 3 s of 200s and got: $PROBE_PRE_HIST. The MASTER's gateway process had been running for $(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ') s"
  if [ "${HAFO_MUTATE:-}" = "fo1-skip-fault" ]; then
    t0=$(now_ms); note "FAILOVER-1 $mode #$i: MUTATION, no fault applied"
  else
    case "$mode" in
      death)
        t0=$(node_death "$M") ;;
      stop)
        t0=$(now_ms)
        docker stop "$M" >/dev/null 2>&1
        t_exit=$(now_ms)
        node_death "$M" >/dev/null; t_off=$(now_ms) ;;
      term)
        t0=$(now_ms)
        sudo kill -TERM "$pid"
        while [ -e "/proc/$pid" ] && [ $(( $(now_ms) - t0 )) -lt 40000 ]; do sleep 0.02; done
        [ -e "/proc/$pid" ] && extra="loxilb_still_alive_after_40s" || t_exit=$(now_ms) ;;
      crash)
        t0=$(now_ms)
        sudo kill -9 "$pid" ;;
    esac
  fi
  note "FAILOVER-1 $mode #$i: fault on $M (MASTER) at t0=$t0${t_exit:+, exit at +$((t_exit - t0)) ms}${t_off:+, links down at +$((t_off - t0)) ms}"
  local settled=1
  fo1_wait_settled "$d" "$t0" 75 || settled=0
  # A stopped service leaves the host up; a crash leaves everything. Record
  # what the dead node's namespace still holds before anything is changed.
  echo "$M (faulted) at +$(( $(now_ms) - t0 )) ms: role=$(role "$M") $(vip_state "$M") loxilb_pid=$(loxilb_pid "$M")" > "$d/faulted-node-state.txt"
  echo "$S (survivor): role=$(role "$S") $(vip_state "$S")" >> "$d/faulted-node-state.txt"
  local restart_obs=""
  if [ "$mode" = crash ] && [ "${HAFO_MUTATE:-}" != "fo1-skip-fault" ]; then
    # Start the gateway again in the namespace as the crash left it.
    local r0; r0=$(now_ms)
    docker exec -d "$M" bash -c "$(cat "$HAFO_DIR/.${M}-cmdline") >> /tmp/loxilb.out 2>> /tmp/loxilb.err"
    local ams; ams=$(wait_api "$M" 120) || ams="timeout($ams)"
    loxilb_pid "$M" > "$d/pid-$M.restarted"
    restart_obs="restart_api_ms=$ams; just after API ready: role=$(role "$M") $(vip_state "$M")"
    : > "$d/crash-restart-watch.txt"
    local k
    for k in $(seq 1 60); do
      echo "$(( $(now_ms) - r0 )) $M role=$(role "$M") $(vip_state "$M") | $S role=$(role "$S") $(vip_state "$S")" >> "$d/crash-restart-watch.txt"
      sleep 0.5
    done
    restart_obs="$restart_obs; 30 s later: role=$(role "$M") $(vip_state "$M"); survivor role=$(role "$S")"
    echo "$restart_obs" >> "$d/faulted-node-state.txt"
  fi
  sleep 2
  monitors_stop "$d"
  python3 "$HAFO_DIR/hafo_tools.py" timeline --dir "$d" --t0 "$t0" --mode "$mode" --dead "$M" --survivor "$S" \
    --dead-ip "$(node_eth0 "$M")" --survivor-ip "$(node_eth0 "$S")" --dead-mac "$mmac" --survivor-mac "$smac" \
    --port $PORT_KEY --nports $NPORTS > "$d/timeline.json"
  python3 - "$d/timeline.json" "$mode" "$i" "${t_exit:+$((t_exit - t0))}" "${t_off:+$((t_off - t0))}" "$extra" >> "$FO1_DIR/summary.jsonl" <<'PY'
import json, sys
tl = json.load(open(sys.argv[1]))
tl["rep"] = int(sys.argv[3])
tl["exit_ms"] = int(sys.argv[4]) if sys.argv[4] else None
tl["links_down_ms"] = int(sys.argv[5]) if sys.argv[5] else None
tl["extra"] = sys.argv[6]
print(json.dumps(tl, sort_keys=True))
PY
  # The repetition counts only if a fault actually happened.
  local became
  became=$(python3 -c "import json,sys; t=json.load(open(sys.argv[1])); print(t['survivor_master_ms'] if t['survivor_role_before']!='MASTER' else '')" "$d/timeline.json")
  if [ -z "$became" ] || [ "$became" = None ]; then
    verdict "FAILOVER-1.$mode.$i" NOT_RUN "no failover observed: the survivor never changed to MASTER after t0"
  else
    verdict "FAILOVER-1.$mode.$i" RECORDED "$(python3 - "$d/timeline.json" <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))
g = lambda k: t.get(k)
print("master +%s ms, VIP +%s ms, listener +%s ms, first 200 +%s ms, stable 200 from +%s ms, VIP-without-listener %s ms; fault..stable: %s"
      % (g("survivor_master_ms"), g("survivor_vip_ms"), g("survivor_listen_ms"), g("first_200_after_fault_ms"),
         g("stable_200_from_ms"), g("vip_without_listener_ms"),
         ", ".join("%s=%d" % kv for kv in sorted(g("histogram_fault_to_stable").items()))))
PY
)"
  fi
  # Restore the pair for the next repetition.
  case "$mode" in
    crash)
      if [ "${HAFO_MUTATE:-}" != "fo1-skip-fault" ]; then
        apply_cfg "$M" "" returning 2>>"$d/restore.err"
        note "FAILOVER-1 $mode #$i: $M restarted in place; list re-applied: created=$APPLY_NEW already-held=$APPLY_HELD"
      fi ;;
    *)
      if [ "${HAFO_MUTATE:-}" != "fo1-skip-fault" ]; then
        [ "$mode" = term ] && { node_death "$M" >/dev/null; }
        local ret
        if ret=$(node_return "$M" 2>>"$d/restore.err") && apply_cfg "$M" "" returning 2>>"$d/restore.err"; then
          note "FAILOVER-1 $mode #$i: $M returned ($ret); list re-applied: created=$APPLY_NEW already-held=$APPLY_HELD"
        else
          note "FAILOVER-1 $mode #$i: $M did not return cleanly: $(tr '\n' ' ' < "$d/restore.err" | cut -c1-200)"
        fi
      fi ;;
  esac
  return 0
}

for mode in death stop term; do
  for i in $(seq 1 "$FO1_REPS"); do fo1_rep "$mode" "$i"; done
done
for i in $(seq 1 "$FO1_CRASH_REPS"); do fo1_rep crash "$i"; done
wait_roles 240 6 || note "FAILOVER-1: roles did not hold after the last repetition ($ROLE_LAST)"

# Per-mode summary: median and worst of each interval, and the harness bound.
python3 - "$FO1_DIR/summary.jsonl" "$FO1_BOUND_MS" > "$FO1_DIR/summary.txt" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
bound = int(sys.argv[2])
keys = ["bfd_detection_ms", "survivor_master_ms", "survivor_vip_ms", "survivor_listen_ms",
        "vip_without_listener_ms", "client_neigh_to_survivor_ms", "first_non200_ms",
        "first_200_after_fault_ms", "stable_200_from_ms", "exit_ms", "links_down_ms",
        "dead_vip_last_ms", "dead_listen_last_ms", "last_arp_claim_from_dead_ms",
        "seconds_with_two_arp_answerers", "dual_master_samples"]
for mode in ["death", "stop", "term", "crash"]:
    rs = [r for r in rows if r["mode"] == mode and r.get("survivor_master_ms") is not None
          and r.get("survivor_role_before") != "MASTER"]
    print("MODE %s reps=%d" % (mode, len(rs)))
    for k in keys:
        v = sorted(r[k] for r in rs if r.get(k) is not None)
        if v:
            print("  %-34s n=%d median=%d worst=%d all=%s" % (k, len(v), v[len(v) // 2], v[-1], v))
    h = {}
    for r in rs:
        for c, n in r["histogram_fault_to_stable"].items():
            h[c] = h.get(c, 0) + n
    print("  histogram fault..stable (all reps): %s" % ", ".join("%s=%d" % kv for kv in sorted(h.items())))
    w = {}
    for r in rs:
        for c, n in (r.get("vip_without_listener_probe") or {}).items():
            w[c] = w.get(c, 0) + n
    print("  probe while VIP present, no listener: %s" % (", ".join("%s=%d" % kv for kv in sorted(w.items())) or "none"))
    sp = [r.get("bfd_tx_spacing_ms_dead", {}).get("median") for r in rs if r.get("bfd_tx_spacing_ms_dead")]
    if sp:
        print("  BFD TX spacing median per rep (ms): %s" % sp)
    worst = [r.get("stable_200_from_ms") for r in rs]
    ok = bool(rs) and all(x is not None and x <= bound for x in worst)
    print("  BOUND %s %s" % (mode, "PASS" if ok else "FAIL"))
PY
cat "$FO1_DIR/summary.txt"
for mode in death stop term; do
  want_n=$FO1_REPS
  got_n=$(sed -n "s/^MODE $mode reps=//p" "$FO1_DIR/summary.txt")
  if [ "${got_n:-0}" -lt "$want_n" ]; then
    verdict "FAILOVER-1.$mode.bound" NOT_RUN "only ${got_n:-0} of $want_n repetitions produced a failover"
  elif grep -q "BOUND $mode PASS" "$FO1_DIR/summary.txt"; then
    verdict "FAILOVER-1.$mode.bound" PASS "HARNESS BOUND, not a product budget: 200s were stable again within $((FO1_BOUND_MS / 1000)) s in all $got_n repetitions"
  else
    verdict "FAILOVER-1.$mode.bound" FAIL "HARNESS BOUND: in at least one of $got_n repetitions 200s were not stable again within $((FO1_BOUND_MS / 1000)) s"
  fi
done
verdict FAILOVER-1.params RECORDED "probe ${PROBE_RATE}/s open loop, connect timeout ${PROBE_CONNECT_TIMEOUT} s, request timeout ${PROBE_TIMEOUT} s; node sampler every ${SAMPLE_INTERVAL} s; neighbour sampler every 0.05 s; ARP observer every 0.1 s"
