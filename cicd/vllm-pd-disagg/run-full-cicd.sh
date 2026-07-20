#!/usr/bin/env bash
# cicd/vllm-pd-disagg/run-full-cicd.sh — Converged full test runner.
#
# Runs ALL vLLM P/D disaggregation test suites in two separate topology cycles:
#
#   Cycle 1 — Single-loxilb (VIP 10.10.10.254, direct l3h1↔llb1 veth)
#   ─────────────────────────────────────────────────────────────────────────
#   Suite                          Script                           Topology
#   ─────────────────────────────  ───────────────────────────────  ────────────────────
#   vllm-pd-disagg-A-K             validation.sh (phases A–K)       1-loxilb (llb1)
#
#   Cycle 2 — 2-loxilb VRRP HA (VIP 11.11.11.11, r1 bridge, keepalived)
#   ─────────────────────────────────────────────────────────────────────────
#   Suite                          Script                           Topology
#   ─────────────────────────────  ───────────────────────────────  ────────────────────
#   vllm-pd-disagg-L               validation.sh (phase L only)     2-loxilb VRRP HA
#   vllm-pd-disagg-convsync        validation-convsync.sh           2-loxilb VRRP HA
#   vllm-pd-disagg-xsync           validation-xsync.sh              2-loxilb VRRP HA
#   vllm-pd-disagg-gap1-bulkget    validation-gap1-bulkget.sh       2-loxilb VRRP HA
#   vllm-pd-disagg-gap2-rl-push    validation-gap2-rl-push.sh       2-loxilb VRRP HA
#
# WHY two cycles?  config.sh under PHASE_L_HA_MODE=vrrp uses a completely
# different network topology (vlan11 bridge via r1, VIP 11.11.11.11) and
# SKIPS the direct veths + 10.10.10.254 LB rules needed by phases A-K.
# The two topologies are MUTUALLY EXCLUSIVE — NOT additive in VRRP mode.
# Each cycle: config.sh → validation suites → rmconfig.sh.
#
# Usage:
#   ./run-full-cicd.sh [--bail-on-fail] [--skip-ha] [--ha-mode=vrrp|bfd]
#
# Flags:
#   --bail-on-fail   Abort on the first FAIL in any suite.
#   --skip-ha        Skip Cycle 2 (HA suites L, convsync, xsync, bulkget, rl-push).
#                    Runs Cycle 1 (A–K) only.
#   --ha-mode=MODE   Override PHASE_L_HA_MODE for Cycle 2 (default: vrrp).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/run-full-cicd-${TIMESTAMP}.log"

# ── Defaults ──────────────────────────────────────────────────────────────────
BAIL_ON_FAIL=0
ENABLE_HA=1
HA_MODE="vrrp"
# Arguments forwarded verbatim to the A–K validation.sh call only.
VALIDATION_ARGS_AK=()

for arg in "$@"; do
  case "$arg" in
    --bail-on-fail)
      BAIL_ON_FAIL=1
      VALIDATION_ARGS_AK+=("--bail-on-fail")
      ;;
    --skip-ha)
      ENABLE_HA=0
      ;;
    --ha-mode=*)
      HA_MODE="${arg#--ha-mode=}"
      ;;
    *)
      echo "Unknown flag: $arg" >&2
      echo "Usage: $0 [--bail-on-fail] [--skip-ha] [--ha-mode=vrrp|bfd]" >&2
      exit 1
      ;;
  esac
done

echo "=== vLLM P/D Disaggregation FULL CICD ===" | tee -a "$LOG_FILE"
echo "  Cycle 1 : A-K (single-loxilb, VIP 10.10.10.254)" | tee -a "$LOG_FILE"
echo "  Cycle 2 : $([ "$ENABLE_HA" -eq 1 ] && echo "L, convsync, xsync, bulkget, rl-push (2-loxilb VRRP HA, VIP 11.11.11.11)" || echo "disabled (--skip-ha)")" | tee -a "$LOG_FILE"
echo "  HA mode : $HA_MODE" | tee -a "$LOG_FILE"
echo "  Log     : $LOG_FILE" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# ── Cleanup helper ────────────────────────────────────────────────────────────
# Runs rmconfig.sh to tear down whatever topology is currently active.
# Called explicitly between cycles and via the EXIT trap on unexpected abort.
run_rmconfig() {
  echo "" | tee -a "$LOG_FILE"
  echo "=== Cleanup: running rmconfig.sh ===" | tee -a "$LOG_FILE"
  bash "${SCRIPT_DIR}/rmconfig.sh" 2>&1 | tee -a "$LOG_FILE" || true
}

# Trap ensures cleanup even on bail/abort.  rmconfig.sh is idempotent.
trap run_rmconfig EXIT

# ── Cycle 1: Single-loxilb topology (phases A–K) ─────────────────────────────
echo "=== Cycle 1: Setup — single-loxilb (VIP 10.10.10.254) ===" | tee -a "$LOG_FILE"
# Do NOT export PHASE_L_HA here — config.sh must set up the direct l3h1↔llb1
# veth + 10.10.10.254 LB rules required by phases A-K.
# Under PHASE_L_HA_MODE=vrrp config.sh skips those entirely (vlan11/r1 only).
unset PHASE_L_HA PHASE_L_HA_MODE 2>/dev/null || true
if bash "${SCRIPT_DIR}/config.sh" 2>&1 | tee -a "$LOG_FILE"; then
  echo "  Cycle 1 Setup: PASS" | tee -a "$LOG_FILE"
else
  echo "  Cycle 1 Setup: FAIL — aborting" | tee -a "$LOG_FILE"
  exit 1
fi
echo "" | tee -a "$LOG_FILE"

# ── Scenario runner ───────────────────────────────────────────────────────────
# Associative arrays keyed by scenario name.
declare -A SCENARIO_EXIT SCENARIO_PASS SCENARIO_FAIL SCENARIO_WARN
SCENARIO_ORDER=()

# run_scenario <NAME> <SCRIPT> [ARGS...]
# Runs SCRIPT, tees stdout+stderr to LOG_FILE and a temp file for counting.
# Populates SCENARIO_{EXIT,PASS,FAIL,WARN}[NAME].
# Honours --bail-on-fail: aborts the whole suite if BAIL_ON_FAIL=1 and
# the scenario exits non-zero.
run_scenario() {
  local name="$1"
  local script="$2"
  shift 2
  local args=("$@")
  local tmplog
  tmplog=$(mktemp)

  SCENARIO_ORDER+=("$name")

  echo "━━━ Scenario: $name ━━━" | tee -a "$LOG_FILE"
  echo "" | tee -a "$LOG_FILE"

  local exit_code=0
  # NOTE: pipefail is active, so the pipeline exit status reflects bash script.sh
  # exit code (first non-zero in the pipeline, per bash pipefail semantics).
  bash "${SCRIPT_DIR}/${script}" "${args[@]+"${args[@]}"}" 2>&1 \
    | tee -a "$LOG_FILE" \
    | tee "$tmplog" \
    || exit_code=$?

  # Count PASS / FAIL / WARN lines from scenario output.
  # grep -c always prints the count (including 0) and exits 1 on no-match.
  # Using || true prevents set -e from aborting when there are no matches,
  # while still capturing the count that grep already printed to stdout.
  local pass fail warn
  pass=$(grep -c '^  PASS:' "$tmplog" 2>/dev/null) || pass=0
  fail=$(grep -c '^  FAIL:' "$tmplog" 2>/dev/null) || fail=0
  # Both "  WARN:" (validation.sh) and "  WARN-PASS:" (xsync/gap scripts) count.
  warn=$(grep -cE '^  WARN' "$tmplog" 2>/dev/null) || warn=0
  rm -f "$tmplog"

  SCENARIO_EXIT[$name]=$exit_code
  SCENARIO_PASS[$name]=$pass
  SCENARIO_FAIL[$name]=$fail
  SCENARIO_WARN[$name]=$warn

  echo "" | tee -a "$LOG_FILE"
  if [ "$exit_code" -eq 0 ] && [ "$fail" -eq 0 ]; then
    echo "  ⟹  $name: PASS (pass=$pass warn=$warn)" | tee -a "$LOG_FILE"
  else
    echo "  ⟹  $name: FAIL (pass=$pass fail=$fail warn=$warn exit=$exit_code)" | tee -a "$LOG_FILE"
    if [ "$BAIL_ON_FAIL" -eq 1 ]; then
      echo "" | tee -a "$LOG_FILE"
      echo "BAIL: --bail-on-fail set — aborting after first FAIL." | tee -a "$LOG_FILE"
      exit 1
    fi
  fi
  echo "" | tee -a "$LOG_FILE"
}

# ── Run all suites ────────────────────────────────────────────────────────────
echo "=== Validation suites ===" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Suite 1: Functional phases A–K (single-node loxilb, VIP 10.10.10.254).
# Always skip Phase L here — Phase L is run separately as suite 2 so it
# appears as its own row in the summary table.
run_scenario "vllm-pd-disagg-A-K" \
  "validation.sh" \
  --skip-phase=L \
  "${VALIDATION_ARGS_AK[@]+"${VALIDATION_ARGS_AK[@]}"}"

# ── Between cycles: tear down Cycle 1, set up Cycle 2 ────────────────────────
if [ "$ENABLE_HA" -eq 1 ]; then

  echo "=== Cycle 1→2 transition: rmconfig.sh ===" | tee -a "$LOG_FILE"
  bash "${SCRIPT_DIR}/rmconfig.sh" 2>&1 | tee -a "$LOG_FILE" || true
  echo "" | tee -a "$LOG_FILE"

  echo "=== Cycle 2: Setup — 2-loxilb VRRP HA (VIP 11.11.11.11) ===" | tee -a "$LOG_FILE"
  export PHASE_L_HA=1
  export PHASE_L_HA_MODE="${HA_MODE}"
  echo "  PHASE_L_HA=1  PHASE_L_HA_MODE=${PHASE_L_HA_MODE}" | tee -a "$LOG_FILE"
  if bash "${SCRIPT_DIR}/config.sh" 2>&1 | tee -a "$LOG_FILE"; then
    echo "  Cycle 2 Setup: PASS" | tee -a "$LOG_FILE"
  else
    echo "  Cycle 2 Setup: FAIL — aborting HA suites" | tee -a "$LOG_FILE"
    # Still print A-K result in summary; mark remaining HA suites as not run.
    # Bail here so the EXIT trap cleans up.
    exit 1
  fi
  echo "" | tee -a "$LOG_FILE"

  # Suite 2: Phase L — HA session restoration (2-loxilb failover).
  run_scenario "vllm-pd-disagg-L" \
    "validation.sh" \
    --phase=L

  # Suite 3: convsync — targeted conv_map xSync test.
  # 5 conversations pinned on MASTER → MASTER failover → same backends on BACKUP.
  run_scenario "vllm-pd-disagg-convsync" \
    "validation-convsync.sh"

  # Suite 4: xsync — full xSync gate.
  # XS1 (graceful): restore_rate >= 0.90 after docker stop --time=2 on MASTER.
  # XS2 (abrupt):   restore_rate >= 0.90 after docker kill SIGKILL on MASTER.
  # XS3 (metrics):  Prometheus sync metric spot-check (WARN, non-blocking).
  run_scenario "vllm-pd-disagg-xsync" \
    "validation-xsync.sh"

  # Suite 5: bulk-get — SockproxySessionBulkGet gRPC snapshot (CGO fix).
  # GB1–GB5: VIP up → pin conversations → gRPC bulk-get → session count ≥ N.
  run_scenario "vllm-pd-disagg-gap1-bulkget" \
    "validation-gap1-bulkget.sh"

  # Suite 6: rl-push — StartRateLimiterPushLoop wired in spawnConsumersForKnownPeers.
  # RL1–RL6: MASTER/BACKUP detected → binary symbol present → goroutines active.
  run_scenario "vllm-pd-disagg-gap2-rl-push" \
    "validation-gap2-rl-push.sh"

fi  # ENABLE_HA

# ── Summary table ─────────────────────────────────────────────────────────────
echo "=== Full CICD Summary (Cycle 1: A-K | Cycle 2: HA) ===" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Column widths: scenario name is longest — 36 chars covers all suite names.
printf "%-36s %-6s %-6s %-6s %-8s\n" \
  "Scenario" "PASS" "FAIL" "WARN" "Status" | tee -a "$LOG_FILE"
printf "%-36s %-6s %-6s %-6s %-8s\n" \
  "$(printf '%0.s─' {1..36})" "──────" "──────" "──────" "────────" | tee -a "$LOG_FILE"

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_WARN=0
ALL_PASS=0  # becomes 1 if any suite fails (re-uses run-pd-cicd.sh convention)

for name in "${SCENARIO_ORDER[@]}"; do
  P=${SCENARIO_PASS[$name]:-0}
  F=${SCENARIO_FAIL[$name]:-0}
  W=${SCENARIO_WARN[$name]:-0}
  E=${SCENARIO_EXIT[$name]:-0}

  if [ "$E" -eq 0 ] && [ "$F" -eq 0 ]; then
    STATUS="PASS"
  else
    STATUS="FAIL"
    ALL_PASS=1
  fi

  TOTAL_PASS=$(( TOTAL_PASS + P ))
  TOTAL_FAIL=$(( TOTAL_FAIL + F ))
  TOTAL_WARN=$(( TOTAL_WARN + W ))

  printf "%-36s %-6s %-6s %-6s %-8s\n" \
    "$name" "$P" "$F" "$W" "$STATUS" | tee -a "$LOG_FILE"
done

printf "%-36s %-6s %-6s %-6s %-8s\n" \
  "$(printf '%0.s─' {1..36})" "──────" "──────" "──────" "────────" | tee -a "$LOG_FILE"
printf "%-36s %-6s %-6s %-6s\n" \
  "TOTAL" "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_WARN" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# ── Final verdict ─────────────────────────────────────────────────────────────
if [ "$ALL_PASS" -eq 0 ]; then
  echo "=== SCENARIO-vllm-pd-disagg-FULL [PASS] ===" | tee -a "$LOG_FILE"
  exit 0
else
  echo "=== SCENARIO-vllm-pd-disagg-FULL [FAILED] ===" | tee -a "$LOG_FILE"
  exit 1
fi
