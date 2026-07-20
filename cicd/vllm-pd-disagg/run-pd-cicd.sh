#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"  # ensure ../common.sh resolves and minica cert output lands here in child scripts
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/run-pd-cicd-${TIMESTAMP}.log"

# Default flags
BAIL_ON_FAIL=0
VALIDATION_ARGS=()
ENABLE_PHASE_L=0  # set to 1 if --phase=L (or --phase=l) is requested

for arg in "$@"; do
  case "$arg" in
    --bail-on-fail)
      BAIL_ON_FAIL=1
      VALIDATION_ARGS+=("--bail-on-fail")
      ;;
    --phase=L|--phase=l)
      # Phase L needs 2-loxilb topology, which config.sh
      # creates only when PHASE_L_HA=1 is set in its environment. Propagate
      # the flag automatically so `./run-pd-cicd.sh --phase=L` "just works".
      ENABLE_PHASE_L=1
      VALIDATION_ARGS+=("$arg")
      ;;
    --phase=*|--skip-phase=*)
      VALIDATION_ARGS+=("$arg")
      ;;
    --enable-phase-l)
      # Explicit override: enable Phase L topology even when the validation
      # phase selector picks something else (e.g. running A-K + L together).
      ENABLE_PHASE_L=1
      ;;
    *)
      echo "Unknown flag: $arg" >&2
      echo "Usage: $0 [--bail-on-fail] [--phase=A] [--skip-phase=B] [--enable-phase-l]" >&2
      exit 1
      ;;
  esac
done

echo "=== vLLM P/D Disaggregation CICD ==="
echo "Log: $LOG_FILE"
echo ""

# ---- cleanup trap ---------------------------------------------------------
cleanup() {
  local EXIT_CODE=$?
  echo ""
  echo "=== Cleanup: running rmconfig.sh ==="
  bash "${SCRIPT_DIR}/rmconfig.sh" 2>&1 || true
  if [ $EXIT_CODE -ne 0 ]; then
    echo "CICD exited with code $EXIT_CODE" | tee -a "$LOG_FILE"
  fi
}
trap cleanup EXIT

# ---- Step 1: Setup --------------------------------------------------------
echo "=== Step 1: Setup (config.sh) ===" | tee -a "$LOG_FILE"
# When Phase L is requested, export PHASE_L_HA=1 so the
# config.sh additive block runs (spawn llb2, BFD, iptables DNAT). Otherwise
# Phase A-K runs on the original 1-loxilb topology unchanged.
if [ "$ENABLE_PHASE_L" -eq 1 ]; then
  export PHASE_L_HA=1
  # default Phase L HA topology is ha1-style vrrp under
  # `--phase=L`. Operator override is preserved via `:-` fallback —
  # `PHASE_L_HA_MODE=bfd bash ./run-pd-cicd.sh --phase=L` exercises the
  # legacy path (smoke-test only; no restore_rate gate under bfd).
  export PHASE_L_HA_MODE="${PHASE_L_HA_MODE:-vrrp}"
  echo "  Phase L enabled — exporting PHASE_L_HA=1 PHASE_L_HA_MODE=$PHASE_L_HA_MODE" | tee -a "$LOG_FILE"
fi
if bash "${SCRIPT_DIR}/config.sh" 2>&1 | tee -a "$LOG_FILE"; then
  echo "  Setup: PASS" | tee -a "$LOG_FILE"
else
  echo "  Setup: FAIL — aborting" | tee -a "$LOG_FILE"
  exit 1
fi

echo "" | tee -a "$LOG_FILE"

# ---- Step 2: Validate -----------------------------------------------------
echo "=== Step 2: Validation (validation.sh) ===" | tee -a "$LOG_FILE"
VALIDATION_EXIT=0
bash "${SCRIPT_DIR}/validation.sh" "${VALIDATION_ARGS[@]+"${VALIDATION_ARGS[@]}"}" 2>&1 \
  | tee -a "$LOG_FILE" \
  || VALIDATION_EXIT=$?
echo "" | tee -a "$LOG_FILE"

# ---- Summarize results from log -------------------------------------------
echo "=== Phase Summary ===" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_WARN=0

# Extract per-phase results from log (lines like "PHASE A — ...", "  PASS:", "  FAIL:")
declare -A PHASE_PASS PHASE_FAIL PHASE_WARN
CUR_PHASE=""

while IFS= read -r line; do
  # Widened regex from [A-K] to [A-L] to include Phase L
  # (HA session restoration). Phase L block lives at end of validation.sh.
  if echo "$line" | grep -qE '^PHASE ([A-L]) —'; then
    CUR_PHASE=$(echo "$line" | grep -oE '^PHASE ([A-L])' | awk '{print $2}')
    PHASE_PASS[$CUR_PHASE]=0
    PHASE_FAIL[$CUR_PHASE]=0
    PHASE_WARN[$CUR_PHASE]=0
  elif [ -n "$CUR_PHASE" ]; then
    if echo "$line" | grep -q '^\[PASS\]\|^  PASS:'; then
      PHASE_PASS[$CUR_PHASE]=$(( ${PHASE_PASS[$CUR_PHASE]:-0} + 1 ))
      TOTAL_PASS=$(( TOTAL_PASS + 1 ))
    elif echo "$line" | grep -q '^\[FAIL\]\|^  FAIL:'; then
      PHASE_FAIL[$CUR_PHASE]=$(( ${PHASE_FAIL[$CUR_PHASE]:-0} + 1 ))
      TOTAL_FAIL=$(( TOTAL_FAIL + 1 ))
    elif echo "$line" | grep -q '^\[WARN\]\|^  WARN:'; then
      PHASE_WARN[$CUR_PHASE]=$(( ${PHASE_WARN[$CUR_PHASE]:-0} + 1 ))
      TOTAL_WARN=$(( TOTAL_WARN + 1 ))
    fi
  fi
done < "$LOG_FILE"

# Print summary table
printf "%-12s %-6s %-6s %-6s %-8s\n" "Phase" "PASS" "FAIL" "WARN" "Status" | tee -a "$LOG_FILE"
printf "%-12s %-6s %-6s %-6s %-8s\n" "------------" "------" "------" "------" "--------" | tee -a "$LOG_FILE"

ALL_PASS=0
# Summary-loop extended to include Phase L (HA session
# restoration via 2-loxilb docker-compose + BFD). Phase L is only counted when
# validation.sh ran it (gated by PHASE_L_HA=1 in config.sh + should_run_phase L
# in validation.sh). When skipped it shows as SKIP in the summary.
for PHASE in A B C D E F G H I J K L; do
  P=${PHASE_PASS[$PHASE]:-"-"}
  F=${PHASE_FAIL[$PHASE]:-"-"}
  W=${PHASE_WARN[$PHASE]:-"-"}
  if [ "$P" = "-" ] && [ "$F" = "-" ]; then
    STATUS="SKIP"
  elif [ "${PHASE_FAIL[$PHASE]:-0}" -eq 0 ]; then
    STATUS="PASS"
  else
    STATUS="FAIL"
    ALL_PASS=1
  fi
  printf "%-12s %-6s %-6s %-6s %-8s\n" "$PHASE" "$P" "$F" "$W" "$STATUS" | tee -a "$LOG_FILE"
done

printf "%-12s %-6s %-6s %-6s %-8s\n" "------------" "------" "------" "------" "--------" | tee -a "$LOG_FILE"
printf "%-12s %-6s %-6s %-6s\n" "TOTAL" "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_WARN" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Final result
if [ "$VALIDATION_EXIT" -eq 0 ] && [ "$ALL_PASS" -eq 0 ]; then
  echo "=== SCENARIO-vllm-pd-disagg [PASS] ===" | tee -a "$LOG_FILE"
  exit 0
else
  echo "=== SCENARIO-vllm-pd-disagg [FAILED] ===" | tee -a "$LOG_FILE"
  exit 1
fi
