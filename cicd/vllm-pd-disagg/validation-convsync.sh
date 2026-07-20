#!/bin/bash
# validation-convsync.sh — targeted conv_map xSync test.
#
# Proves the ONE thing we care about: an X-Conversation-Id binding established
# on the MASTER survives a MASTER failover — the BACKUP, once promoted, routes
# the same conversation to the same backend. That binding lives in
# conversation_mapping (conv_map) and is carried by sockproxy xSync; the
# receiver-apply fix (sockproxy_sync.c apply_conv_sync_entry) is what makes it
# land in conv_map on the BACKUP instead of being dropped into pd_session_map.
#
# Vehicle: the vrrp HA topology (config.sh PHASE_L_HA=1 PHASE_L_HA_MODE=vrrp),
# which has a real keepalived-managed floating VIP (11.11.11.11) — so the SAME
# URL is hit before and after failover, no per-node IP juggling. Uses the PLAIN
# port-2024 session-header rule (NOT P/D). Two mock backends (l3ep1/l3ep2) each
# log one line per request; routing is detected by counting /v1/completions log
# lines (health probes hit /health, so they do not pollute the delta).
#
# Prerequisite: PHASE_L_HA=1 PHASE_L_HA_MODE=vrrp bash ./config.sh

source ../common.sh
exec < /dev/null

echo SCENARIO-vllm-pd-disagg-convsync

VIP=11.11.11.11
PORT=2024
MODEL="Qwen/Qwen3-0.6B"
NCONV=5          # distinct conversations (defeats the 2-backend 50%-by-chance false pass)
REQS=3           # requests per conversation per phase

code=0
check() {
  if [ "$2" = "0" ]; then echo "  PASS: $1"; else echo "  FAIL: $1"; code=1; fi
}

# Count ONLY /v1/completions lines (mock logs one per request) so periodic
# health probes (GET /health) on the non-served EP do not pollute the delta.
ep_reqs() { $dexec "$1" sh -c "grep -c '/v1/completions' '$2' 2>/dev/null" 2>/dev/null | tr -d '[:space:]'; }

# served_ep <d1> <d2> -> 1 | 2 | none | split
served_ep() {
  if   [ "$1" -gt 0 ] && [ "$2" -eq 0 ]; then echo 1
  elif [ "$2" -gt 0 ] && [ "$1" -eq 0 ]; then echo 2
  elif [ "$1" -eq 0 ] && [ "$2" -eq 0 ]; then echo none
  else echo split; fi
}

# cistate via $hexec (host curl/python3 in the container's netns — the loxilb
# container itself has neither curl nor python3, only wget).
detect_master() {
  for llb in llb1 llb2; do
    st=$($hexec "$llb" curl -s 'http://127.0.0.1:11111/netlox/v1/config/cistate/all' 2>/dev/null | \
      python3 -c "import sys,json
try:
 d=json.load(sys.stdin)
 [print(a.get('state','UNKNOWN')) for a in d.get('Attr',[]) if a.get('instance')=='llb-inst0']
except: print('UNKNOWN')" 2>/dev/null | head -1)
    [ "$st" = "MASTER" ] && { echo "$llb"; return; }
  done
  echo none
}

# Poll the VIP until it serves (routing + backend health + post-failover VIP
# migration all settled). Returns 0 once a GET /v1/models returns 200.
wait_vip_ready() {
  local max="${1:-30}" rc
  for i in $(seq 1 "$max"); do
    rc=$($dexec l3h1 curl -sk --connect-timeout 2 --max-time 4 -o /dev/null -w '%{http_code}' \
      "https://${VIP}:${PORT}/v1/models" 2>/dev/null)
    [ "$rc" = "200" ] && { echo "  VIP ready after ${i}s (http 200)"; return 0; }
    sleep 1
  done
  echo "  VIP NOT ready after ${max}s (last http=$rc)"
  return 1
}

# send_conv <conv_id> <count> — all requests go to the floating VIP.
send_conv() {
  for i in $(seq 1 "$2"); do
    $dexec l3h1 curl -sk --connect-timeout 3 --max-time 5 \
      "https://${VIP}:${PORT}/v1/completions" \
      -H "Content-Type: application/json" \
      -H "X-Conversation-Id: $1" \
      -d "{\"model\":\"${MODEL}\",\"prompt\":\"convsync ${1} ${i}\",\"max_tokens\":3}" >/dev/null 2>&1
  done
}

# probe_ep <conv_id> <count> -> served EP (1|2|none|split) via log delta
probe_ep() {
  local b1 b2 a1 a2
  b1=$(ep_reqs l3ep1 /tmp/vllm-server1.log); b1=${b1:-0}
  b2=$(ep_reqs l3ep2 /tmp/vllm-server2.log); b2=${b2:-0}
  send_conv "$1" "$2"
  sleep 1
  a1=$(ep_reqs l3ep1 /tmp/vllm-server1.log); a1=${a1:-0}
  a2=$(ep_reqs l3ep2 /tmp/vllm-server2.log); a2=${a2:-0}
  served_ep $((a1 - b1)) $((a2 - b2))
}

CONV_PREFIX="convsync-$$"

# ── Pre-flight ───────────────────────────────────────────────────────────────
if ! docker inspect llb2 >/dev/null 2>&1; then
  echo "  FAIL: llb2 not present — run 'PHASE_L_HA=1 PHASE_L_HA_MODE=vrrp bash ./config.sh' first"
  exit 1
fi
M1=$(detect_master)
check "pre: a MASTER exists (found '$M1')" $([ "$M1" != "none" ] && echo 0 || echo 1)
[ "$M1" = "none" ] && { echo "SCENARIO-vllm-pd-disagg-convsync [FAILED]"; exit 1; }
echo "  initial master=$M1, VIP=$VIP:$PORT"

# Warm up: wait for VIP routing + backend health before measuring, so the first
# conversations are not lost to bring-up races.
if wait_vip_ready 30; then check "pre: VIP routes before measurement" 0
else check "pre: VIP routes before measurement" 1; echo "SCENARIO-vllm-pd-disagg-convsync [FAILED]"; exit 1; fi

# ── Step 1: establish conv→EP bindings on the MASTER (via the VIP) ──────────
echo ""
echo "=== Step 1: pin $NCONV conversations on master $M1 ==="
declare -A PRE_EP
PINNED=0
for k in $(seq 1 $NCONV); do
  ep=$(probe_ep "${CONV_PREFIX}-$k" "$REQS")
  PRE_EP[$k]=$ep
  echo "  conv $k → EP$ep"
  [ "$ep" = "1" ] || [ "$ep" = "2" ] && PINNED=$((PINNED + 1))
done
check "Step1: all $NCONV conversations pinned to a single backend ($PINNED/$NCONV)" \
  $([ "$PINNED" -eq "$NCONV" ] && echo 0 || echo 1)

# ── Step 2: kill the master (sidecar first), await promotion ────
echo ""
echo "=== Step 2: kill master $M1, await VIP failover ==="
docker kill "ka_${M1}" >/dev/null 2>&1 || true   # stop keepalived adverts atomically
docker kill "$M1" >/dev/null 2>&1
M2=none
for i in $(seq 1 30); do
  cur=$(detect_master)
  if [ "$cur" != "none" ] && [ "$cur" != "$M1" ]; then M2=$cur; echo "  $M2 promoted after ${i}s"; break; fi
  sleep 1
done
check "Step2: backup promoted to MASTER (was $M1, now $M2)" \
  $([ "$M2" != "none" ] && [ "$M2" != "$M1" ] && echo 0 || echo 1)
[ "$M2" = "none" ] && { echo "SCENARIO-vllm-pd-disagg-convsync [FAILED]"; exit 1; }
# Mark the new master's log position so we scan ONLY post-failover lines.
LOGMARK=$(docker exec "$M2" sh -c 'wc -l < /var/log/loxilb/loxilb-stdout.log' 2>/dev/null || echo 0)
LOGMARK=${LOGMARK:-0}
# Defensive: flush r1's stale VIP neighbor entry so the next packet re-ARPs and
# resolves to the promoted node immediately (complements arp_accept=1 in
# config.sh; covers any garp/timeout race).
sudo ip netns exec r1 ip neigh flush dev vlan11 2>/dev/null || true
# Wait for the VIP to migrate to the promoted node (keepalived gratuitous ARP +
# r1 bridge re-learn) before measuring — this is what the fixed 3s wait missed.
if wait_vip_ready 30; then check "Step2b: VIP routes again after failover" 0
else check "Step2b: VIP routes again after failover" 1; fi

# ── Step 3: same conversations must route to the SAME backend on the new master
echo ""
echo "=== Step 3: replay $NCONV conversations after failover (VIP now on $M2) ==="
MATCH=0
for k in $(seq 1 $NCONV); do
  ep=$(probe_ep "${CONV_PREFIX}-$k" "$REQS")
  if [ "$ep" = "${PRE_EP[$k]}" ]; then
    MATCH=$((MATCH + 1)); echo "  conv $k → EP$ep  (pre=EP${PRE_EP[$k]})  MATCH"
  else
    echo "  conv $k → EP$ep  (pre=EP${PRE_EP[$k]})  MISMATCH"
  fi
done
check "Step3: all conversations routed to the SAME backend after failover ($MATCH/$NCONV)" \
  $([ "$MATCH" -eq "$NCONV" ] && echo 0 || echo 1)

# Corroborating evidence: the promoted node logged conv_map HITs (not MISSes)
# for the synced conversations. Without the receiver-apply fix, conv_map is
# empty on the new master → every line is [NS_STICKY_MISS].
HITS=$(docker exec "$M2" sh -c "tail -n +$((LOGMARK + 1)) /var/log/loxilb/loxilb-stdout.log 2>/dev/null | grep -c '\[NS_STICKY_HIT\].*${CONV_PREFIX}'" 2>/dev/null || echo 0)
MISSES=$(docker exec "$M2" sh -c "tail -n +$((LOGMARK + 1)) /var/log/loxilb/loxilb-stdout.log 2>/dev/null | grep -c '\[NS_STICKY_MISS\].*${CONV_PREFIX}'" 2>/dev/null || echo 0)
echo "  promoted-node post-failover conv_map: HITs=$HITS MISSes=$MISSES (for ${CONV_PREFIX}-*)"

# ── Cleanup: restore the failed node so rmconfig.sh can tear down cleanly.
# Plain `docker start` is NOT sufficient in VRRP mode: loxilb runs via
# `docker exec -dt` (not as entrypoint), so after docker kill/stop the
# loxilb process is gone.  We must re-launch it with --cluster/--self so
# the node can rejoin the xSync mesh, then rebuild the keepalived sidecar.
_peer_vip=11.11.11.2; _self_ord=0; _blacklist=ellb1r1
[ "$M1" = "llb2" ] && { _peer_vip=11.11.11.1; _self_ord=1; _blacklist=ellb2r1; }
docker start "$M1" >/dev/null 2>&1 || true
sleep 3
docker exec -dt "$M1" bash -c \
  "/root/loxilb-io/loxilb/loxilb --cluster=${_peer_vip} --self=${_self_ord} --blacklist=${_blacklist} \
  >/var/log/loxilb/loxilb-stdout.log 2>&1"
sleep 3
docker rm -f "ka_${M1}" 2>/dev/null || true
_kpath="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/keepalived_config"
sudo mkdir -p "/etc/shared/${M1}"
docker run -u root --cap-add SYS_ADMIN --restart unless-stopped --privileged -dit \
  --network=container:"$M1" \
  -v "${_kpath}:/container/service/keepalived/assets/" \
  -v "/etc/shared/${M1}:/etc/shared" \
  --name "ka_${M1}" osixia/keepalived:2.0.20
sleep 5

if [ "$code" -eq 0 ]; then
  echo "SCENARIO-vllm-pd-disagg-convsync [OK]"
else
  echo "SCENARIO-vllm-pd-disagg-convsync [FAILED]"
fi
exit $code
