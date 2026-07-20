#!/bin/bash
# validation-xsync.sh — Production xSync gate for sockproxy HA sync.
#
# Validates the ONE thing that matters for production: an X-Conversation-Id
# binding established on the MASTER survives a MASTER failover — the promoted
# BACKUP routes the same conversation to the same backend because sockproxy
# xSync replicated the conv_map entry while both nodes were alive.
#
# Sub-cases:
#   XS1 — Graceful failover (docker stop --time=2): restore_rate >= 0.90
#   XS2 — Abrupt failover (docker kill SIGKILL):    restore_rate >= 0.90
#   XS3 — Prometheus sync metric spot-check         (warn, non-blocking)
#
# Validates: sockproxy xSync conv_map replication survives MASTER failover.
# Topology: PHASE_L_HA=1 PHASE_L_HA_MODE=vrrp (VIP=11.11.11.11)
#   VIP floats via keepalived; llb1=11.11.11.1, llb2=11.11.11.2
#   port-2024 LB rule: externalIP=11.11.11.11, ep_role=0, l3ep1(11.11.11.3) + l3ep2(11.11.11.4)
#   EP detection: log-line delta on /tmp/vllm-server{1,2}.log (no response-header dependency)
#
# Prerequisite: PHASE_L_HA=1 PHASE_L_HA_MODE=vrrp bash ./config.sh

source ../common.sh
exec < /dev/null

echo SCENARIO-vllm-pd-disagg-xsync

VIP=11.11.11.11
PORT=2024          # X-Conversation-Id stickiness rule (ep_role=0, l3ep1+l3ep2)
MODEL="Qwen/Qwen3-0.6B"
NCONV=10           # 10 distinct conversations — defeats 50%-by-chance false-pass on 2 backends
REQS=3             # curl requests per conversation per measurement phase
MIN_RESTORE_RATE="0.90"

code=0
check() {
  if [ "$2" = "0" ]; then echo "  PASS: $1"; else echo "  FAIL: $1"; code=1; fi
}
warn() {
  if [ "$2" = "0" ]; then echo "  WARN-PASS: $1"
  else echo "  WARN: $1"; fi
}

# ── Helpers ───────────────────────────────────────────────────────────────────

# ep_reqs <container> <logfile> — count /v1/completions lines (not /health probes)
ep_reqs() {
  $dexec "$1" sh -c "grep -c '/v1/completions' '$2' 2>/dev/null" 2>/dev/null | tr -d '[:space:]'
}

# detect_master <llb> → MASTER|BACKUP|UNKNOWN
detect_master() {
  $hexec "$1" curl -s 'http://127.0.0.1:11111/netlox/v1/config/cistate/all' 2>/dev/null | \
    python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  for a in d.get('Attr', []):
    if a.get('instance') == 'llb-inst0':
      print(a.get('state', 'UNKNOWN')); break
  else:
    print('UNKNOWN')
except Exception:
  print('UNKNOWN')
" 2>/dev/null | head -1
}

# find_master → llb1|llb2|none
find_master() {
  for _llb in llb1 llb2; do
    [ "$(detect_master "$_llb")" = "MASTER" ] && { echo "$_llb"; return 0; }
  done
  echo none
}

# wait_vip_ready <max_sec> — blocks until VIP:PORT responds HTTP 200 or times out
wait_vip_ready() {
  local max="${1:-30}" rc i
  for i in $(seq 1 "$max"); do
    rc=$($dexec l3h1 curl -sk --connect-timeout 2 --max-time 4 \
      -o /dev/null -w '%{http_code}' \
      "https://${VIP}:${PORT}/v1/models" 2>/dev/null)
    [ "$rc" = "200" ] && { echo "  VIP ready after ${i}s"; return 0; }
    sleep 1
  done
  echo "  VIP NOT ready after ${max}s (last_http=$rc)"
  return 1
}

# send_conv <conv_id> <count> — POST to VIP:PORT from l3h1 with X-Conversation-Id
send_conv() {
  local cid="$1" n="$2" _i
  for _i in $(seq 1 "$n"); do
    $dexec l3h1 curl -sk --connect-timeout 3 --max-time 5 \
      "https://${VIP}:${PORT}/v1/completions" \
      -H "Content-Type: application/json" \
      -H "X-Conversation-Id: $cid" \
      -d "{\"model\":\"${MODEL}\",\"prompt\":\"xs ${cid} ${_i}\",\"max_tokens\":2}" \
      >/dev/null 2>&1
  done
}

# probe_ep_conv <conv_id> <count> → 1|2|none|split
# Detects which backend served the request via log-line delta on l3ep1/l3ep2.
probe_ep_conv() {
  local b1 b2 a1 a2 d1 d2
  b1=$(ep_reqs l3ep1 /tmp/vllm-server1.log); b1=${b1:-0}
  b2=$(ep_reqs l3ep2 /tmp/vllm-server2.log); b2=${b2:-0}
  send_conv "$1" "$2"
  sleep 1
  a1=$(ep_reqs l3ep1 /tmp/vllm-server1.log); a1=${a1:-0}
  a2=$(ep_reqs l3ep2 /tmp/vllm-server2.log); a2=${a2:-0}
  d1=$(( a1 - b1 )); d2=$(( a2 - b2 ))
  if   [ "$d1" -gt 0 ] && [ "$d2" -eq 0 ]; then echo 1
  elif [ "$d2" -gt 0 ] && [ "$d1" -eq 0 ]; then echo 2
  elif [ "$d1" -eq 0 ] && [ "$d2" -eq 0 ]; then echo none
  else echo split; fi
}

# restart_ka_sidecar <llb>
# VRRP-mode restoration: restart ONLY the keepalived sidecar. The loxilb
# container (with its vlan11 bridge and veth wiring created by config.sh)
# stays alive throughout the test. Killing only ka_$llb lets VRRP re-elect
# cleanly; $llb rejoins as BACKUP once its sidecar is back.
# Killing the loxilb container would destroy vlan11 (it lives in the
# container's netns) → ka restart inside the new netns sees no vlan11
# → CONFIG crash-loop. Follow ha1/validation.sh: never kill loxilb.
restart_ka_sidecar() {
  local llb="$1"
  docker start "ka_${llb}" >/dev/null 2>&1 || true
  sleep 5  # VRRP dead-timer (3s) + cistate POST delivery
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
echo ""
echo "=== Pre-flight ==="

if ! docker inspect llb2 >/dev/null 2>&1; then
  echo "  FAIL: llb2 not found — run: PHASE_L_HA=1 PHASE_L_HA_MODE=vrrp bash ./config.sh"
  echo "SCENARIO-vllm-pd-disagg-xsync [FAILED]"; exit 1
fi

INIT_M=$(find_master)
check "pre: MASTER exists (found '$INIT_M')" \
  $([ "$INIT_M" != "none" ] && echo 0 || echo 1)
[ "$INIT_M" = "none" ] && { echo "SCENARIO-vllm-pd-disagg-xsync [FAILED]"; exit 1; }

S1=$(detect_master llb1); S2=$(detect_master llb2)
PRE_CLEAN=0
{ [ "$S1" = "MASTER" ] && [ "$S2" = "BACKUP" ]; } || \
{ [ "$S1" = "BACKUP" ] && [ "$S2" = "MASTER" ]; } && PRE_CLEAN=1
check "pre: clean MASTER/BACKUP pair (llb1=$S1 llb2=$S2)" \
  $([ "$PRE_CLEAN" = "1" ] && echo 0 || echo 1)
[ "$PRE_CLEAN" = "0" ] && { echo "  split-brain or not converged — abort"; echo "SCENARIO-vllm-pd-disagg-xsync [FAILED]"; exit 1; }

if wait_vip_ready 30; then check "pre: VIP ${VIP}:${PORT} serves HTTP 200" 0
else check "pre: VIP ${VIP}:${PORT} serves HTTP 200" 1
  echo "SCENARIO-vllm-pd-disagg-xsync [FAILED]"; exit 1; fi

echo "  initial: master=$INIT_M, VIP=$VIP"

# ── Core test runner ──────────────────────────────────────────────────────────
# run_xs_case <LABEL> <MODE=graceful|abrupt>
# Sets XS_RESULT_<LABEL> to "PASS" or "FAIL" and XS_RATE_<LABEL> to rate string.
run_xs_case() {
  local LABEL="$1" MODE="$2"
  local PFXLABEL="xsync-$$-${LABEL}"
  local TMP_PRE="/tmp/xsync_${LABEL}_pre_$$.txt"
  rm -f "$TMP_PRE"

  local CUR_M; CUR_M=$(find_master)
  local CUR_B; [ "$CUR_M" = "llb1" ] && CUR_B=llb2 || CUR_B=llb1
  echo "  master=$CUR_M  backup=$CUR_B"

  # ── Step 1: establish NCONV conv→EP bindings on current MASTER ──────────
  echo "  -- $LABEL/phase1: pin $NCONV conversations on $CUR_M --"
  local k PINNED=0
  for k in $(seq 1 $NCONV); do
    local ep; ep=$(probe_ep_conv "${PFXLABEL}-${k}" "$REQS")
    echo "    conv $k → EP${ep}"
    echo "${k}:${ep}" >> "$TMP_PRE"
    { [ "$ep" = "1" ] || [ "$ep" = "2" ]; } && PINNED=$((PINNED+1))
  done
  check "$LABEL/phase1: all $NCONV conversations pinned (pinned=$PINNED/$NCONV)" \
    $([ "$PINNED" -eq "$NCONV" ] && echo 0 || echo 1)

  # Allow the xSync batch window (100ms flush + RTT) to replicate to BACKUP.
  sleep 2

  # ── Step 2: trigger failover ─────────────────────────────────────────────
  echo "  -- $LABEL/phase2: $MODE failover of $CUR_M --"
  # Kill ONLY the keepalived sidecar — never the loxilb container. Killing
  # loxilb destroys vlan11 (it lives in the container netns) so any restart
  # leaves keepalived with no vlan11 → CONFIG crash-loop (see ha1 pattern).
  # Stopping ka_$CUR_M causes $CUR_B's VRRP dead-timer (3s) to fire →
  # $CUR_B promotes to MASTER, calls notify.sh → loxilb becomes MASTER.
  # xSync port 22222 (on vlan11) stays alive on both nodes throughout.
  if [ "$MODE" = "graceful" ]; then
    docker stop --time=2 "ka_${CUR_M}" >/dev/null 2>&1 || true
  else
    docker kill "ka_${CUR_M}" >/dev/null 2>&1 || true
  fi

  local NEW_M=none WAIT=0
  while [ "$WAIT" -lt 30 ]; do
    local _st; _st=$(detect_master "$CUR_B")
    if [ "$_st" = "MASTER" ]; then NEW_M="$CUR_B"; echo "    $CUR_B promoted after ${WAIT}s"; break; fi
    sleep 1; WAIT=$((WAIT+1))
  done
  check "$LABEL/phase2: BACKUP promoted (was $CUR_M, now $NEW_M)" \
    $([ "$NEW_M" != "none" ] && [ "$NEW_M" != "$CUR_M" ] && echo 0 || echo 1)

  if [ "$NEW_M" = "none" ]; then
    eval "XS_RESULT_${LABEL}=FAIL"; eval "XS_RATE_${LABEL}=0.000"
    restart_ka_sidecar "$CUR_M"; rm -f "$TMP_PRE"; return
  fi

  # Flush stale ARP on r1 so first post-failover packet re-ARPs to promoted node.
  sudo ip netns exec r1 ip neigh flush dev vlan11 2>/dev/null || true

  # Capture log position on promoted node to scope NS_STICKY corroboration.
  # tr strips leading spaces from wc -l output to prevent arithmetic errors.
  local LOGMARK; LOGMARK=$(docker exec "$NEW_M" sh -c \
    'wc -l < /var/log/loxilb/loxilb-stdout.log 2>/dev/null || echo 0' 2>/dev/null | tr -d '[:space:]')
  LOGMARK=${LOGMARK:-0}

  # Wait for VIP to migrate (gARP + r1 bridge re-learn) before measuring.
  if wait_vip_ready 30; then check "$LABEL/phase2b: VIP routes again on $NEW_M" 0
  else check "$LABEL/phase2b: VIP routes again on $NEW_M" 1; fi

  # ── Step 3: replay — same convs must route to the SAME EP ───────────────
  echo "  -- $LABEL/phase3: replay $NCONV conversations on $NEW_M --"
  local MATCH=0 TOTAL=0
  while IFS=: read -r k PRE_EP; do
    local ep; ep=$(probe_ep_conv "${PFXLABEL}-${k}" "$REQS")
    TOTAL=$((TOTAL+1))
    if [ "$ep" = "$PRE_EP" ]; then
      MATCH=$((MATCH+1)); echo "    conv $k → EP${ep}  (pre=EP${PRE_EP})  MATCH"
    else
      echo "    conv $k → EP${ep}  (pre=EP${PRE_EP})  MISMATCH"
    fi
  done < "$TMP_PRE"

  local RATE; RATE=$(echo "scale=3; $MATCH / ${TOTAL:-1}" | bc 2>/dev/null || echo "0.000")
  eval "XS_RATE_${LABEL}=$RATE"
  echo "  $LABEL restore_rate: $MATCH / $TOTAL = $RATE"

  # Corroborate via NS_STICKY log markers on promoted node (xSync delivered entries).
  local HITS MISSES
  # grep -c exits 1 on 0 matches; outer '|| echo 0' would append a second 0
  # making HITS='0\n0'. Drop the outer fallback; use ${:-0} for empty output.
  HITS=$(docker exec "$NEW_M" sh -c \
    "tail -n +$((LOGMARK+1)) /var/log/loxilb/loxilb-stdout.log 2>/dev/null | grep -c 'NS_STICKY_HIT'" \
    2>/dev/null); HITS=${HITS:-0}
  MISSES=$(docker exec "$NEW_M" sh -c \
    "tail -n +$((LOGMARK+1)) /var/log/loxilb/loxilb-stdout.log 2>/dev/null | grep -c 'NS_STICKY_MISS'" \
    2>/dev/null); MISSES=${MISSES:-0}
  echo "  ${NEW_M} post-failover: NS_STICKY_HIT=${HITS:-0}  NS_STICKY_MISS=${MISSES:-0}"
  warn "$LABEL: promoted node has NS_STICKY_HIT > 0 (xSync delivered conv_map)" \
    $([ "${HITS:-0}" -gt 0 ] && echo 0 || echo 1)

  local PASS_BIT; PASS_BIT=$(echo "$RATE >= $MIN_RESTORE_RATE" | bc 2>/dev/null || echo 0)
  eval "XS_RESULT_${LABEL}=$([ \"$PASS_BIT\" = \"1\" ] && echo PASS || echo FAIL)"

  # Restore the failed node so topology is healthy for the next sub-case.
  # Only restart the ka sidecar; loxilb+vlan11 are still running.
  restart_ka_sidecar "$CUR_M"
  rm -f "$TMP_PRE"
}

# ── XS1: Graceful failover ────────────────────────────────────────────────────
echo ""
echo "=== XS1: Graceful failover (docker stop) ==="
run_xs_case XS1 graceful
XS1_RATE="${XS_RATE_XS1:-0.000}"
XS1_PASS_BIT=$(echo "$XS1_RATE >= $MIN_RESTORE_RATE" | bc 2>/dev/null || echo 0)
check "XS1 (graceful): conv_map restore_rate=$XS1_RATE >= $MIN_RESTORE_RATE" \
  $([ "$XS1_PASS_BIT" = "1" ] && echo 0 || echo 1)

# ── XS2: Abrupt failover ─────────────────────────────────────────────────────
echo ""
echo "=== XS2: Abrupt failover (docker kill SIGKILL) ==="
run_xs_case XS2 abrupt
XS2_RATE="${XS_RATE_XS2:-0.000}"
XS2_PASS_BIT=$(echo "$XS2_RATE >= $MIN_RESTORE_RATE" | bc 2>/dev/null || echo 0)
check "XS2 (abrupt):   conv_map restore_rate=$XS2_RATE >= $MIN_RESTORE_RATE" \
  $([ "$XS2_PASS_BIT" = "1" ] && echo 0 || echo 1)

# ── XS3: Prometheus sync metric corroboration (warn, non-blocking) ───────────
echo ""
echo "=== XS3: Prometheus sync metrics (warn) ==="
M_FINAL=$(find_master)
if [ "$M_FINAL" != "none" ]; then
  _METRICS=$($hexec "$M_FINAL" curl -s http://127.0.0.1:11111/netlox/v1/metrics 2>/dev/null)
  _PUSH_LAT_COUNT=$(echo "$_METRICS" | grep -v '^#' | \
    grep 'loxilb_sockproxy_sync_push_latency_seconds_count' | awk '{print $NF}' | head -1)
  _OVERFLOW=$(echo "$_METRICS" | grep -v '^#' | \
    grep 'loxilb_sockproxy_sync_overflow_total{kind="session"}' | awk '{print $NF}' | head -1)
  _INFLIGHT=$(echo "$_METRICS" | grep -v '^#' | \
    grep 'loxilb_sockproxy_sync_inflight_rpc' | awk '{print $NF}' | head -1)
  echo "  master=$M_FINAL  push_latency_count=${_PUSH_LAT_COUNT:-N/A}  overflow_session=${_OVERFLOW:-N/A}  inflight_rpc=${_INFLIGHT:-N/A}"
  warn "XS3: sync_push_latency_seconds_count > 0 (xSync RPCs were issued)" \
    $([ -n "$_PUSH_LAT_COUNT" ] && [ "${_PUSH_LAT_COUNT:-0}" != "0" ] && echo 0 || echo 1)
  warn "XS3: sync_overflow_session < 5000" \
    $(echo "${_OVERFLOW:-0} < 5000" | bc 2>/dev/null || echo 0)
else
  warn "XS3: no master found for Prometheus scrape" 1
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Summary ==="
echo "  XS1_RESTORE_RATE=$XS1_RATE  (${XS_RESULT_XS1:-?})"
echo "  XS2_RESTORE_RATE=$XS2_RATE  (${XS_RESULT_XS2:-?})"
if [ "$code" -eq 0 ]; then
  echo "SCENARIO-vllm-pd-disagg-xsync [OK]"
else
  echo "SCENARIO-vllm-pd-disagg-xsync [FAILED]"
fi
exit $code
