# FO-11  Failback.   (sourced by validation.sh)
#
# The MASTER dies, the survivor serves, a tenant goes into quota debt on it,
# and then the dead node returns (reboot emulation, list re-applied). The
# FO-1 probe runs through all of it, a sampler runs in the returning node's
# new namespace from before its gateway starts, and the tenant in debt keeps
# asking.
#
#   FO-11.single-master  PASS/FAIL  no sample pair (within 100 ms) in which
#                        both nodes report MASTER, from the return on.
#                        In FO-11r it is RECORDED: there the overlap is
#                        0-100 ms, which a sampler running every 25 ms per
#                        node cannot judge, so it reports the count and the
#                        sampling interval instead of a verdict
#   FO-11.probe          PASS/FAIL  the probe answers 200 from the start of
#                        the return until 15 s after the roles hold again
#   FO-11.debt           PASS/FAIL  the tenant in debt is never admitted
#                        earlier than the gateway's own Retry-After allowed
#   FO-11.return         RECORDED   how long the returning node stays out,
#                        the time with no standby, whether traffic moves back
#
# The case runs twice (validation.sh sources this file with F11_ID set):
#
#   FO-11   as the pair stands
#   FO-11r  with the pair first brought into the state in which a return
#           changes the roles: the node that wins a fresh election (the one
#           that was MASTER when the pair first started) is MASTER, and its
#           standby has been taken away and returned since. On the build this
#           scenario was written against the returning node then takes MASTER
#           back, so this failback contains a second role change. Without the
#           preparation, whether that happens depends on which nodes earlier
#           cases restarted; FO-11r makes it happen on every run.
#
# Mutation: fo11-no-debt skips the spend, so FO-11.debt has no refusal to
# stand on and must end NOT_RUN, never PASS.

F11_ID=${F11_ID:-FO-11}
echo; echo "$F11_ID  Failback$([ "$F11_ID" = FO-11r ] && echo ' after the standby was restarted first')"
F11_DIR="$OUT/$(echo "$F11_ID" | tr 'A-Z' 'a-z' | tr -d '-')"; mkdir -p "$F11_DIR"
f11_notrun() { for c in $F11_ID.single-master $F11_ID.probe $F11_ID.debt; do verdict "$c" NOT_RUN "$1"; done; }
f11_hook() { # a sampler in the returning node's new namespace, before its gateway starts
  sudo ip netns exec "$1" python3 "$HAFO_DIR/hafo_tools.py" node --vip $VIP --interval $SAMPLE_INTERVAL \
    --out "$F11_DIR/node-$1-returned.jsonl" >/dev/null 2>&1 &
}
f11_pre_ok=1
if [ "$F11_ID" = FO-11r ]; then
  # f11_cycle <node>: node death, return, list re-applied.
  f11_cycle() {
    local ret
    node_death "$1" >/dev/null
    ret=$(node_return "$1" 2>>"$F11_DIR/restore.err") && apply_cfg "$1" "" returning 2>>"$F11_DIR/restore.err" || return 1
    note "FO-11r preparation: $1 taken away and returned ($ret)"
  }
  F11_FIRST=$(sed -n 's/.*master=\([a-z0-9]*\).*/\1/p' "$OUT/startup-times.txt")
  if [ -z "$F11_FIRST" ] || ! fo_begin; then
    f11_pre_ok=0
  else
    # 1. the first-election winner must hold MASTER
    if [ "$M" != "$F11_FIRST" ]; then f11_cycle "$M" && fo_begin || f11_pre_ok=0; fi
    # 2. its standby is taken away and returned, twice: the first time
    #    leaves the standby freshly started, the second is the restart the
    #    MASTER has to have lived through.
    for _ in 1 2; do
      if [ "$f11_pre_ok" = 1 ] && [ "$M" = "$F11_FIRST" ]; then
        f11_cycle "$S" && fo_begin || f11_pre_ok=0
      fi
    done
    [ "$f11_pre_ok" = 1 ] && [ "$M" != "$F11_FIRST" ] && f11_pre_ok=0
  fi
fi
if [ "$f11_pre_ok" != 1 ]; then
  f11_notrun "the pair could not be prepared: wanted ${F11_FIRST:-?} as MASTER with a restarted standby, roles are $ROLE_LAST"
elif ! fo_begin; then
  f11_notrun "roles did not hold before the fault ($ROLE_LAST)"
else
  f11_lc=$(echo "$F11_ID" | tr 'A-Z' 'a-z' | tr -d '-')      # fo11 / fo11r: its own tenants
  KD=$(key_raw "$f11_lc-debt-key"); KC=$(key_raw "$f11_lc-ctl-key")
  mmac=$(node_mac "$M"); smac=$(node_mac "$S")
  loxilb_pid "$M" > "$F11_DIR/pid-$M"; loxilb_pid "$S" > "$F11_DIR/pid-$S"
  monitors_start "$F11_DIR"
  if ! probe_control "$F11_DIR" 30; then
    monitors_stop "$F11_DIR"
    f11_notrun "control failed: the probe was not all-200 for 3 s within 30 s before the fault (it got: ${PROBE_PRE_HIST:-nothing})"
  else
    T0=$(node_death "$M")
    if ! probe_wait_settled "$F11_DIR" "$T0" 75; then
      monitors_stop "$F11_DIR"
      f11_notrun "the survivor $S did not serve 200s within 75 s of the fault"
      fo_restore
    else
      t_stable=$(now_ms)
      DEBT_HORIZON=0
      if [ "${HAFO_MUTATE:-}" = fo11-no-debt ]; then
        note "$F11_ID: MUTATION, the tenant is not put in debt"
      else
        debt_spend "$KD" "$(echo "$F11_ID" | tr "A-Z" "a-z")"
      fi
      note "$F11_ID: $M died at t0=$T0; $S served again by +$(( t_stable - T0 )) ms; debt on $S: first=${DEBT_A1:-} second=${DEBT_A2:-} Retry-After=${DEBT_RETRY_AFTER:-}"
      debt_watch "$KD" 400 "$(echo "$F11_ID" | tr "A-Z" "a-z")-debt" "$F11_DIR/debt-watch.jsonl" "$DEBT_HORIZON" "$(now_ms)" 1 > "$F11_DIR/debt-watch.json" &
      # ---- the return
      t_ret=$(now_ms)
      NODE_RETURN_HOOK=f11_hook
      ret=$(node_return "$M" 2>>"$F11_DIR/restore.err"); ret_rc=$?
      unset NODE_RETURN_HOOK
      t_api=$(now_ms)
      [ $ret_rc = 0 ] && apply_cfg "$M" "" returning 2>>"$F11_DIR/restore.err"
      roles_ok=0; wait_roles 240 6 && roles_ok=1
      t_roles=$(now_ms)
      sleep 15
      t_end=$(now_ms)
      sudo touch "$F11_DIR/debt-watch.jsonl.stop" "$F11_DIR/node-$M-returned.jsonl.stop"
      monitors_stop "$F11_DIR"       # waits for every background reader
      sudo rm -f "$F11_DIR"/*.stop
      note "$F11_ID: return of $M began at +$(( t_ret - T0 )) ms ($ret), roles $ROLE_LAST at +$(( t_roles - T0 )) ms (held=$roles_ok)"
      python3 - "$F11_DIR" "$M" "$S" "$T0" "$t_ret" "$t_end" "$mmac" "$smac" > "$F11_DIR/failback.json" <<'PY'
import json, sys
d, M, S, t0, t_ret, t_end, mmac, smac = sys.argv[1], sys.argv[2], sys.argv[3], *map(int, sys.argv[4:7]), sys.argv[7], sys.argv[8]
def load(name):
    rows = []
    try:
        for ln in open("%s/%s" % (d, name)):
            try: rows.append(json.loads(ln))
            except ValueError: pass
    except OSError:
        pass
    return rows
surv = [r for r in load("node-%s.jsonl" % S) if t_ret <= r["t"] <= t_end]
back = [r for r in load("node-%s-returned.jsonl" % M) if r["t"] <= t_end]
probe = [r for r in load("probe.jsonl") if t_ret <= r["t_send"] <= t_end]
neigh = [r for r in load("neigh.jsonl") if r["t"] >= t_ret]
out = {"survivor_samples": len(surv), "returned_samples": len(back)}
dual, j = [], 0
for r in surv:
    if r["role"] != "MASTER":
        continue
    while j + 1 < len(back) and back[j + 1]["t"] <= r["t"]:
        j += 1
    if back and abs(back[j]["t"] - r["t"]) < 100 and back[j]["role"] == "MASTER":
        dual.append(r["t"] - t0)
out["dual_master_samples"] = len(dual)
out["dual_master_first_ms"] = dual[0] if dual else None
bad = [r for r in probe if r["cls"] != "ok"]
h = {}
for r in bad:
    lab = r["cls"] if r["cls"] != "refusal" else "refusal:%s:%s" % (r.get("status"), r.get("error", ""))
    h[lab] = h.get(lab, 0) + 1
out["probe"] = {"n": len(probe), "not_ok": len(bad), "histogram": h,
                "first_not_ok_ms_after_return": (bad[0]["t_send"] - t_ret) if bad else None,
                "last_not_ok_ms_after_return": (bad[-1]["t_send"] - t_ret) if bad else None}
def first(rows, pred):
    return next((r["t"] - t_ret for r in rows if pred(r)), None)
out["returned_api_first_answer_ms"] = first(back, lambda r: r["role"] not in ("UNREACHABLE", "UNPARSED"))
roles, last = [], None
for r in back:
    if r["role"] != last:
        roles.append([r["role"], r["t"] - t_ret]); last = r["role"]
out["returned_role_sequence"] = roles
out["returned_first_backup_ms"] = first(back, lambda r: r["role"] == "BACKUP")
out["returned_first_master_ms"] = first(back, lambda r: r["role"] == "MASTER")
out["returned_vip_first_ms"] = first(back, lambda r: r["vip"] == 1)
out["returned_listen_first_ms"] = first(back, lambda r: r["listen"])
out["returned_vip_at_end"] = back[-1]["vip"] if back else None
out["returned_listen_at_end"] = back[-1]["listen"] if back else None
sroles, last = [], None
for r in surv:
    if r["role"] != last:
        sroles.append([r["role"], r["t"] - t_ret]); last = r["role"]
out["survivor_role_sequence"] = sroles
moves, last = [], smac
for r in neigh:
    if r["mac"] and r["mac"] != last:
        moves.append([("returned" if r["mac"] == mmac else "survivor" if r["mac"] == smac else r["mac"]), r["t"] - t_ret])
        last = r["mac"]
out["client_neighbour_moves"] = moves
json.dump(out, sys.stdout, indent=1, sort_keys=True)
PY
      fb() { jget "$1" < "$F11_DIR/failback.json"; }
      if [ $ret_rc != 0 ] || [ "$(fb "d['returned_samples']")" -lt 100 ] || [ "$(fb "d['survivor_samples']")" -lt 100 ]; then
        f11_notrun "the return could not be observed (node_return rc=$ret_rc, samples: survivor $(fb "d['survivor_samples']"), returned $(fb "d['returned_samples']"))"
      else
        if [ "$F11_ID" = FO-11r ]; then
          verdict $F11_ID.single-master RECORDED "both nodes reported MASTER in $(fb "d['dual_master_samples']") sample pairs$( [ "$(fb "d['dual_master_first_ms']")" != None ] && echo ", first $(fb "d['dual_master_first_ms']") ms after the fault"), over $(fb "d['survivor_samples']") and $(fb "d['returned_samples']") samples from the start of the return to 15 s after the roles held; each node sampled every ${SAMPLE_INTERVAL} s, pairs matched within 100 ms. An overlap shorter than the sampling interval is not always seen, so this is not judged"
        elif [ "$(fb "d['dual_master_samples']")" = 0 ]; then
          verdict $F11_ID.single-master PASS "no sample in which both nodes reported MASTER, over $(fb "d['survivor_samples']") and $(fb "d['returned_samples']") samples from the start of the return to 15 s after the roles held"
        else
          verdict $F11_ID.single-master FAIL "both nodes reported MASTER in $(fb "d['dual_master_samples']") samples, first $(fb "d['dual_master_first_ms']") ms after the fault"
        fi
        if [ "$roles_ok" != 1 ]; then
          verdict $F11_ID.probe NOT_RUN "the roles did not hold again within 240 s of the return ($ROLE_LAST)"
        elif [ "$(fb "d['probe']['not_ok']")" = 0 ] && [ "$(fb "d['probe']['n']")" -gt 100 ]; then
          verdict $F11_ID.probe PASS "all $(fb "d['probe']['n']") probe requests answered 200 from the start of the return to 15 s after the roles held"
        else
          verdict $F11_ID.probe FAIL "$(fb "d['probe']['not_ok']") of $(fb "d['probe']['n']") probe requests did not answer 200 during the return: $(fb "', '.join('%s=%d' % kv for kv in sorted(d['probe']['histogram'].items()))"), first $(fb "d['probe']['first_not_ok_ms_after_return']") ms and last $(fb "d['probe']['last_not_ok_ms_after_return']") ms after the return began"
        fi
        w=$(cat "$F11_DIR/debt-watch.json")
        read -r leak_rcpt n_ok <<<"$(debt_receipts "$w")"
        leaks=$(echo "$w" | jget "d['leaks']"); n429=$(echo "$w" | jget "d['refused_429_after_mark']")
        detail="over the return: $(echo "$w" | jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])"); Retry-After values seen: $(echo "$w" | jget "','.join(d['retry_after_seen'])") s; admissions earlier than the gateway's own Retry-After allowed: $leaks; refused attempts that reached a backend: $leak_rcpt"
        rc=$(vretry $PORT_KEY $MODEL_KEY "X-Api-Key: $KC" 30 "$(echo "$F11_ID" | tr "A-Z" "a-z")-ctl"); gctl=$(receipts "$(echo "$rc" | jget "d['last_nonce']")")
        if [ "$DEBT_HORIZON" = 0 ]; then
          verdict $F11_ID.debt NOT_RUN "no refusal with a Retry-After was seen before the return, so there is nothing to hold the gateway to; $detail"
        elif [ "$leaks" != 0 ] || [ "$leak_rcpt" != 0 ]; then
          verdict $F11_ID.debt FAIL "the tenant in debt was served $detail; first early admission: $(echo "$w" | jget "d['first_leak']")"
        elif [ "$(echo "$rc" | jget "d['ok']")" != True ] || [ "$gctl" != 1 ]; then
          verdict $F11_ID.debt FAIL "the control tenant was not admitted after the return (receipts=$gctl); $detail"
        elif [ "$n429" -ge 5 ]; then
          verdict $F11_ID.debt PASS "the tenant in debt stayed refused $detail; control tenant admitted"
        else
          verdict $F11_ID.debt NOT_RUN "only $n429 refusals were seen during the return, too few to decide; $detail"
        fi
      fi
      verdict $F11_ID.return RECORDED "returning node $M: REST API first answered $(fb "d['returned_api_first_answer_ms']") ms after the return began, roles $(fb "' -> '.join('%s@%d' % (a, b) for a, b in d['returned_role_sequence'])"); survivor $S: $(fb "' -> '.join('%s@%d' % (a, b) for a, b in d['survivor_role_sequence'])"); the pair had no standby for $(( t_roles - T0 )) ms (fault until the roles held for six samples; $(( t_ret - T0 )) ms of that passed before the return began); client neighbour entry for the VIP after the return: $(fb "' -> '.join('%s@%d' % (a, b) for a, b in d['client_neighbour_moves']) or 'never left the survivor'"); returned node at the end: vip_on_lo=$(fb "d['returned_vip_at_end']") listeners=$(fb "d['returned_listen_at_end']")"
    fi
  fi
fi
