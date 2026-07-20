#!/bin/bash
# cicd/vllm-fullproxy/validation-ha.sh — HA-pair verification.
#
# OPT-IN — invoke only after `PHASE_L_HA=1 bash ./config.sh` has brought up the
# 2-loxilb HA topology AND deployed the locally-built ./loxilb binary into both
# containers via `docker cp`. The caller (not validation-all.sh — this script
# has a topology prerequisite the default flow does not satisfy) is responsible
# for ensuring config.sh was run with PHASE_L_HA=1.
#
# Subtests:
#   HA1: llb1 (initial MASTER) emits [SOCKPROXY_SYNC] consumerLoop start peer=
#        within 10s of bringup → proves the Go fix (OnStateChange MASTER
#        promotion respawns per-peer consumers) is wired and firing on the
#        locally-built binary.
#   HA2: Both nodes establish bidirectional XSync netRPC ... Connected → proves
#        the xsync gRPC channel is up in both directions, so session updates
#        can flow either way.
#   HA3: abrupt kill of the llb1 container → llb2 promotes to MASTER within
#        30s; then llb2 emits
#        a NEW [SOCKPROXY_SYNC] consumerLoop start peer= line for the new peer
#        set → proves the fix fires on EVERY MASTER transition, not
#        just at boot.
#
# CRITICAL: every log-read uses `docker exec <llb> ... /var/log/loxilb/loxilb-stdout.log`
# (NEVER the docker-side log-capture subcommand on the container — its
# entrypoint is /bin/bash, so that subcommand returns empty; see memory
# entry loxilb_docker_logs_vs_loxilb_stdout).
source ../common.sh

echo SCENARIO-vllm-fullproxy-ha

code=0
check() {
  local desc="$1"
  local result="$2"
  if [ "$result" = "0" ]; then
    echo "  PASS: $desc"
  else
    echo "  FAIL: $desc"
    code=1
  fi
}

# ─── HA1: SockproxySync consumerLoop spawned on MASTER ──────────────────────
echo ""
echo "=== HA1: SockproxySync consumerLoop spawned on MASTER ==="
sleep 10  # let OnStateChange + spawn settle after config.sh exits

LLB1_CONS=$(docker exec llb1 sh -c 'grep -c "\[SOCKPROXY_SYNC\] consumerLoop start peer=" /var/log/loxilb/loxilb-stdout.log' 2>/dev/null || echo 0)
LLB2_CONS=$(docker exec llb2 sh -c 'grep -c "\[SOCKPROXY_SYNC\] consumerLoop start peer=" /var/log/loxilb/loxilb-stdout.log' 2>/dev/null || echo 0)
echo "  llb1: consumerLoop start peer= count = $LLB1_CONS"
echo "  llb2: consumerLoop start peer= count = $LLB2_CONS"
# llb1 = initial MASTER → MUST have consumerLoop >= 1 (fix verification)
check "HA1a: llb1 (initial MASTER) consumerLoop count >= 1 (fix)" \
  $([ "${LLB1_CONS:-0}" -ge 1 ] && echo 0 || echo 1)

# ─── HA2: xsync gRPC channel established ────────────────────────────────────
echo ""
echo "=== HA2: xsync gRPC channel established (bidirectional) ==="
LLB1_XSYNC=$(docker exec llb1 sh -c 'grep -c "XSync netRPC.*Connected" /var/log/loxilb/loxilb-stdout.log' 2>/dev/null || echo 0)
LLB2_XSYNC=$(docker exec llb2 sh -c 'grep -c "XSync netRPC.*Connected" /var/log/loxilb/loxilb-stdout.log' 2>/dev/null || echo 0)
echo "  llb1: XSync netRPC ... Connected count = $LLB1_XSYNC"
echo "  llb2: XSync netRPC ... Connected count = $LLB2_XSYNC"
check "HA2a: llb1 xsync Connected >= 1" $([ "${LLB1_XSYNC:-0}" -ge 1 ] && echo 0 || echo 1)
check "HA2b: llb2 xsync Connected >= 1" $([ "${LLB2_XSYNC:-0}" -ge 1 ] && echo 0 || echo 1)

# ─── HA3: Failover llb1 → llb2 + post-promotion consumerLoop spawn ──────────
echo ""
echo "=== HA3: Failover llb1 → llb2 (kill MASTER, BACKUP promotes) ==="

# Drive 5 baseline /v1/models requests so the inbound ring has events to drain.
# LB rules are installed on both nodes by config.sh, so traffic via .254 works now.
for i in $(seq 1 5); do
  $dexec l3h1 curl -sk --cacert /tmp/minica.pem https://10.10.10.254:2020/v1/models >/dev/null 2>&1
  sleep 0.2
done

# Capture pre-failover llb2 consumerLoop count (expect 0 — was BACKUP).
LLB2_CONS_PRE=$(docker exec llb2 sh -c 'grep -c "\[SOCKPROXY_SYNC\] consumerLoop start peer=" /var/log/loxilb/loxilb-stdout.log' 2>/dev/null || echo 0)
echo "  llb2 pre-failover consumerLoop count = $LLB2_CONS_PRE (expect 0 — was BACKUP)"

echo "  killing llb1 (docker kill — abrupt)..."
docker kill llb1 >/dev/null 2>&1

# Wait up to 30s for llb2 to promote — pattern from cicd/vllm-pd-disagg/validation.sh:1706-1724.
# Filter by instance == 'llb-inst0' (cmn.CIDefault).
PROMOTED=0
for i in $(seq 1 30); do
  STATE=$(docker exec llb2 curl -s 'http://127.0.0.1:11111/netlox/v1/config/cistate/all' 2>/dev/null | \
    python3 -c "import sys,json
try:
  d=json.load(sys.stdin)
  for a in d.get('Attr',[]):
    if a.get('instance')=='llb-inst0':
      print(a.get('state','UNKNOWN'))
      break
except: print('UNKNOWN')" 2>/dev/null)
  if [ "$STATE" = "MASTER" ]; then
    PROMOTED=1
    echo "  llb2 promoted after ${i}s (state=MASTER)"
    break
  fi
  sleep 1
done
check "HA3a: llb2 promoted to MASTER within 30s after llb1 killed" \
  $([ "$PROMOTED" -eq 1 ] && echo 0 || echo 1)

# Fix verification — post-promotion llb2 spawns its consumerLoop.
sleep 5
LLB2_CONS_POST=$(docker exec llb2 sh -c 'grep -c "\[SOCKPROXY_SYNC\] consumerLoop start peer=" /var/log/loxilb/loxilb-stdout.log' 2>/dev/null || echo 0)
echo "  llb2 post-failover consumerLoop count = $LLB2_CONS_POST"
check "HA3b: llb2 spawned consumerLoop after promotion (count > pre-failover)" \
  $([ "$LLB2_CONS_POST" -gt "$LLB2_CONS_PRE" ] && echo 0 || echo 1)

# Cleanup — restart llb1 so rmconfig.sh teardown can find it.
docker start llb1 >/dev/null 2>&1 || true
sleep 3

if [ $code -eq 0 ]; then
  echo "SCENARIO-vllm-fullproxy-ha [OK]"
else
  echo "SCENARIO-vllm-fullproxy-ha [FAILED]"
fi
exit $code
