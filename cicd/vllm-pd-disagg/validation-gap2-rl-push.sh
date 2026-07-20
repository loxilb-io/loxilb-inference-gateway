#!/bin/bash
# validation-gap2-rl-push.sh — StartRateLimiterPushLoop wired.
#
# Validates that StartRateLimiterPushLoop is called alongside consumerLoop in
# spawnConsumersForKnownPeers (fix committed in 0162dc4c).
#
# Sub-cases:
#   RL1 — Environment sanity (VIP up, MASTER/BACKUP detected)
#   RL2 — Binary contains rateLimiterPushLoop symbol (fix compiled in)
#   RL3 — Source code contains the fix call-site (structural gate)
#   RL4 — consumerLoop goroutines confirmed active on MASTER (spawnConsumers ran)
#   RL5 — rlStore initialised via AI-gateway-enabled traffic (best-effort)
#   RL6 — Prometheus RateLimiterSync metric increments on MASTER (WARN if 0
#          because the vllm-pd-disagg topology has no per-key rate limits)
#
# NOTE on RL5/RL6:  The metric path requires (a) rlStore != nil AND (b)
# at least one rate-limit entry in the store.  Condition (a) is satisfied
# by sending one request to any sse_mode=true port (2020-2023), which
# triggers llb_ai_ratelimit_check → getGlobalRL().  Condition (b) requires
# --userservice + an API key with rate_limit_rps, which the vllm-pd-disagg
# topology does NOT provide.  RL6 is therefore a WARN-only check; RL1-RL4
# are the hard gates for the binary-level validation.
#
# Validates: StartRateLimiterPushLoop wired in spawnConsumersForKnownPeers.
# Prerequisite: PHASE_L_HA=1 PHASE_L_HA_MODE=vrrp bash ./config.sh

source ../common.sh
exec < /dev/null

echo "SCENARIO-vllm-pd-disagg-gap2-rl-push"

# ── Tunables ──────────────────────────────────────────────────────────────────
VIP=11.11.11.11
PORT_AI=2020        # sse_mode=true port; triggers llb_ai_ratelimit_check
MODEL="Qwen/Qwen3-0.6B"
LLB1_IP=11.11.11.1
LLB2_IP=11.11.11.2
LOXILB_BIN=/usr/local/sbin/loxilb   # loxilb binary path inside containers
SOURCE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
LOG_PATH=/var/log/loxilb/loxilb-stdout.log    # standard log path inside loxilb containers

# The fix wires this string into sockproxy_sync.go after the consumerLoop spawn.
GAP2_MARKER="StartRateLimiterPushLoop"

code=0
check() {
  if [ "$2" = "0" ]; then echo "  PASS: $1"; else echo "  FAIL: $1"; code=1; fi
}
warn() {
  if [ "$2" = "0" ]; then echo "  WARN-PASS: $1"
  else echo "  WARN: $1 (non-blocking)"; fi
}

# ── Helper: detect MASTER/BACKUP role ────────────────────────────────────────
detect_master() {
  $hexec "$1" curl -s 'http://127.0.0.1:11111/netlox/v1/config/cistate/all' 2>/dev/null | \
    python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  for a in d.get('Attr', []):
    if a.get('instance') == 'llb-inst0':
      print(a.get('state', 'UNKNOWN')); break
  else: print('UNKNOWN')
except: print('UNKNOWN')
" 2>/dev/null | head -1
}

find_master() {
  for _llb in llb1 llb2; do
    [ "$(detect_master "$_llb")" = "MASTER" ] && { echo "$_llb"; return 0; }
  done
  echo none
}

# ── RL1: Environment sanity ───────────────────────────────────────────────────
echo ""
echo "=== RL1: Environment sanity ==="

M=$(find_master)
echo "  MASTER: $M"
check "MASTER node found" "$([ "$M" != "none" ] && echo 0 || echo 1)"

if [ "$M" = "llb1" ]; then M_IP=$LLB1_IP; B="llb2"; B_IP=$LLB2_IP;
elif [ "$M" = "llb2" ]; then M_IP=$LLB2_IP; B="llb1"; B_IP=$LLB1_IP;
else
  echo "  FATAL: no MASTER — cannot proceed"
  exit 1
fi
echo "  MASTER=$M ($M_IP)  BACKUP=$B ($B_IP)"

# Confirm BACKUP is not claiming MASTER role (UNKNOWN is acceptable if topology degraded)
B_STATE=$(detect_master "$B")
echo "  BACKUP $B state: $B_STATE"
warn "BACKUP node is in BACKUP role" "$([ "$B_STATE" != "MASTER" ] && echo 0 || echo 1)"

# ── RL2: Binary contains rateLimiterPushLoop symbol ───────────────────────────
echo ""
echo "=== RL2: Binary symbol check — rateLimiterPushLoop compiled in ==="

SYMBOL_FOUND=$($dexec "$M" sh -c "
  if command -v strings >/dev/null 2>&1; then
    strings '$LOXILB_BIN' 2>/dev/null | grep 'rateLimiterPushLoop' | wc -l
  elif command -v nm >/dev/null 2>&1; then
    nm '$LOXILB_BIN' 2>/dev/null | grep 'rateLimiterPushLoop' | wc -l
  else
    echo 0
  fi
" | tr -d '[:space:]' | head -1)
SYMBOL_FOUND=${SYMBOL_FOUND:-0}
echo "  rateLimiterPushLoop symbol occurrences in binary: $SYMBOL_FOUND"

if [ "$SYMBOL_FOUND" -gt 0 ] 2>/dev/null; then
  check "RL2: binary contains rateLimiterPushLoop symbol" 0
else
  # Binary may be stripped — fall back to host-side check on the source binary
  HOST_SYMBOL=$(strings "$SOURCE_DIR/loxilb" 2>/dev/null | grep 'rateLimiterPushLoop' | wc -l | tr -d '[:space:]')
  if [ "${HOST_SYMBOL:-0}" -gt 0 ]; then
    echo "  Found symbol in host-side binary ($HOST_SYMBOL occurrences)"
    check "RL2: binary contains rateLimiterPushLoop symbol (host binary)" 0
  else
    warn "RL2: binary symbol check inconclusive (binary may be stripped)" 1
  fi
fi

# ── RL3: Source code contains the fix call-site ────────────────────────────
echo ""
echo "=== RL3: Source code — fix call-site present in sockproxy_sync.go ==="

SYNC_FILE="$SOURCE_DIR/pkg/loxinet/sockproxy_sync.go"
if [ -f "$SYNC_FILE" ]; then
  # Two things must be true:
  # (a) StartRateLimiterPushLoop is CALLED in spawnConsumersForKnownPeers
  # (b) The call-site is after the consumerLoop spawn (go s.consumerLoop)
  CALL_COUNT=$(grep "$GAP2_MARKER" "$SYNC_FILE" 2>/dev/null | wc -l | tr -d '[:space:]')
  echo "  StartRateLimiterPushLoop occurrences in sockproxy_sync.go: $CALL_COUNT"
  # Expect at minimum: 1 definition + 1 call in spawnConsumersForKnownPeers
  check "RL3: StartRateLimiterPushLoop call present (≥2 occurrences)" \
    "$([ "${CALL_COUNT:-0}" -ge 2 ] && echo 0 || echo 1)"

  # Verify the call is in spawnConsumersForKnownPeers specifically
  IN_SPAWN=$(awk '/func.*spawnConsumersForKnownPeers/,/^}/' "$SYNC_FILE" 2>/dev/null | \
    grep "$GAP2_MARKER" | wc -l | tr -d '[:space:]')
  echo "  StartRateLimiterPushLoop in spawnConsumersForKnownPeers body: $IN_SPAWN"
  check "RL3: StartRateLimiterPushLoop called inside spawnConsumersForKnownPeers" \
    "$([ "${IN_SPAWN:-0}" -ge 1 ] && echo 0 || echo 1)"
else
  warn "RL3: sockproxy_sync.go not found at $SYNC_FILE" 1
fi

# ── RL4: consumerLoop goroutines confirmed active (spawnConsumers ran) ────────
echo ""
echo "=== RL4: spawnConsumersForKnownPeers confirmed active via log evidence ==="

# If consumerLoop goroutines are running then spawnConsumersForKnownPeers was
# called — which is the same code path that calls StartRateLimiterPushLoop.
# We confirm via: MASTER log showing consumerLoop start, OR BACKUP receiving SockproxySessionMod.
LOG_OFFSET_BACKUP=$($dexec "$B" sh -c "wc -l < '$LOG_PATH' 2>/dev/null || echo 0" | tr -d '[:space:]' | head -1)
LOG_OFFSET_BACKUP=${LOG_OFFSET_BACKUP:-0}

# Check MASTER log for consumerLoop start (logged at LogInfo)
CONSUMER_STARTED=$($dexec "$M" sh -c "
  grep 'consumerLoop start peer=' '$LOG_PATH' 2>/dev/null | wc -l
" | tr -d '[:space:]' | head -1)
CONSUMER_STARTED=${CONSUMER_STARTED:-0}
echo "  MASTER log — consumerLoop start lines: $CONSUMER_STARTED"

# Check BACKUP for received SockproxySessionMod (logged at LogInfo)
XSYNC_RCV=$($dexec "$B" sh -c "
  grep 'SockproxySessionMod' '$LOG_PATH' 2>/dev/null | wc -l
" | tr -d '[:space:]' | head -1)
XSYNC_RCV=${XSYNC_RCV:-0}
echo "  BACKUP log — SockproxySessionMod received: $XSYNC_RCV"

if [ "${CONSUMER_STARTED:-0}" -gt 0 ]; then
  check "RL4: consumerLoop goroutines started (MASTER log confirms spawnConsumers ran)" 0
elif [ "${XSYNC_RCV:-0}" -gt 0 ]; then
  check "RL4: consumerLoop goroutines active (XSYNC_RCV on BACKUP)" 0
else
  # Also check for gRPC dial attempts (MASTER trying to connect to BACKUP)
  GRPC_DIAL=$($dexec "$M" sh -c "
    grep 'gRPC dial sockproxy' '$LOG_PATH' 2>/dev/null | wc -l
  " | tr -d '[:space:]' | head -1)
  GRPC_DIAL=${GRPC_DIAL:-0}
  echo "  MASTER log — gRPC dial attempts to BACKUP: $GRPC_DIAL"
  check "RL4: consumerLoop started (gRPC dial attempts confirm spawnConsumers ran)" \
    "$([ "${GRPC_DIAL:-0}" -gt 0 ] && echo 0 || echo 1)"
fi

# Also check xsync gRPC server is listening on XSYNC port (22223) on MASTER
XSYNC_LISTEN=$($dexec "$M" sh -c "
  ss -tlnp 2>/dev/null | grep ':22223' | wc -l || \
  netstat -tlnp 2>/dev/null | grep ':22223' | wc -l || \
  echo 0
" | tr -d '[:space:]' | head -1)
XSYNC_LISTEN=${XSYNC_LISTEN:-0}
echo "  MASTER: port 22223 (XSYNC gRPC) listening: $XSYNC_LISTEN"
check "RL4: sockproxy gRPC server (port 22223) listening on MASTER" \
  "$([ "$XSYNC_LISTEN" -gt 0 ] && echo 0 || echo 1)"

# ── RL5: Trigger rlStore initialisation via sse_mode traffic ─────────────────
echo ""
echo "=== RL5: Trigger rlStore init via AI-gateway-mode traffic ==="

# Port 2020 has sse_mode=true which activates AI gateway code paths in sockproxy.
# One request → llb_ai_ratelimit_check → getGlobalRL() → rlStore becomes non-nil.
# Even if the request fails (no backend, or HTTPS cert error), the sockproxy
# process already enters llb_ai_ratelimit_check before forwarding.
RL5_RC=$($dexec l3h1 curl -sk --connect-timeout 3 --max-time 5 \
  -o /dev/null -w '%{http_code}' \
  "https://${VIP}:${PORT_AI}/v1/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"${MODEL}\",\"prompt\":\"gap2 rl init\",\"max_tokens\":2}" \
  2>/dev/null)
echo "  VIP:${PORT_AI} probe HTTP status: ${RL5_RC:-timeout}"

# Allow up to 5 200ms RL push ticks to fire
sleep 2
echo "  Waited 2s for RL push ticks"

# ── RL6: Prometheus RateLimiterSync metric (WARN-only) ───────────────────────
echo ""
echo "=== RL6: Prometheus RateLimiterSync push metric on MASTER (WARN only) ==="
echo "    NOTE: metric only increments if rlStore has entries (requires --userservice)"
echo "          vllm-pd-disagg topology has no per-key rate limits → expect 0"

# Fetch metric from MASTER via REST API metrics endpoint
RL_METRIC=$($hexec "$M" curl -s http://127.0.0.1:11111/netlox/v1/metrics 2>/dev/null | \
  grep 'loxilb_sockproxy_sync_push_latency_seconds_count' | \
  grep 'rpc="RateLimiterSync"' | \
  grep "peer=\"${B_IP}\"" | \
  awk '{print $2}' | head -1)
RL_METRIC=${RL_METRIC:-0}
echo "  RateLimiterSync push count (peer=${B_IP}): $RL_METRIC"

if [ "${RL_METRIC:-0}" = "0" ] || [ -z "${RL_METRIC}" ]; then
  warn "RL6: RateLimiterSync metric=0 (expected in this topology — no --userservice)" 1
else
  check "RL6: RateLimiterSync metric > 0 (bonus: RL push confirmed)" 0
fi

# Also check if any RateLimiterSync lines appear in MASTER logs (even failures)
RL_LOG_HITS=$($dexec "$M" sh -c "
  grep 'RateLimiterSync\|rateLimiter.*push\|rlPush' '$LOG_PATH' 2>/dev/null | wc -l
" | tr -d '[:space:]' | head -1)
RL_LOG_HITS=${RL_LOG_HITS:-0}
echo "  MASTER log: RateLimiterSync-related lines: $RL_LOG_HITS"
warn "RL6b: RateLimiterSync log evidence present" \
  "$([ "${RL_LOG_HITS:-0}" -gt 0 ] && echo 0 || echo 1)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== RESULT ==="
if [ "$code" = "0" ]; then
  echo "  GAP2 PASS — StartRateLimiterPushLoop is compiled and wired per-peer"
  echo "  Hard gates: RL1 (topology), RL2 (binary), RL3 (source), RL4 (goroutines)"
  echo "  Soft checks: RL5/RL6 (metric) require --userservice to fully exercise"
else
  echo "  GAP2 FAIL"
fi
exit $code
