#!/usr/bin/env bash
#
# Scenario wrapper for the local CICD runner.
#
# The runner used to invoke each scenario as three bare commands under `set -e`:
#
#   cd <scenario>/ ; ./config.sh ; ./validation.sh ; ./rmconfig.sh ; cd -
#
# which has two failure modes that cost more than the test they protect:
#
#   1. A failing validation skips that scenario's own ./rmconfig.sh, so its
#      containers, network namespaces and mock processes survive. The next
#      scenario to claim the same names, VIPs or netns then fails for a reason
#      that has nothing to do with the code under test.
#   2. `set -e` stops the whole suite at the first failure, so one broken
#      scenario hides the state of every scenario after it. A periodic quality
#      run wants the opposite: collect independent failures in one pass.
#
# This wrapper always cleans up, always keeps running, and reports the original
# failure rather than the cleanup's exit code.
#
# Usage:
#
#   source "$(dirname "$0")/scenario_runner.sh"
#   scenario_preflight                       # optional; cheap gates first
#   run_scenario <dir> [label] -- <step>...  # steps are shell strings
#   scenario_summary                         # returns non-zero if any failed
#
# Each step runs with the scenario directory as cwd, so steps read exactly the
# way they did inline: './config.sh', 'EXPECT=fixed ./validation.sh'.
#
# Knobs (all optional):
#   SCENARIO_TIMEOUT  per-step timeout in seconds            (default 1800)
#   FAIL_FAST         1 = stop at the first failed scenario   (default 0)
#   LEAK_STRICT       1 = leftover state fails the scenario   (default 1)
#   CLEANUP_CMD       cleanup step, always run                (default ./rmconfig.sh)
#   ARTIFACT_DIR      where failure logs are kept
#
# Leftover state is a failure by default and that is deliberate: a scenario
# whose rmconfig does not fully clean up is a defect in that scenario, and the
# next run is the one that pays for it. Set LEAK_STRICT=0 only to triage.

_SR_RESULTS=()
_SR_FAILED=0
_SR_START_ALL=$(date +%s)
: "${SCENARIO_TIMEOUT:=1800}"
: "${FAIL_FAST:=0}"
: "${LEAK_STRICT:=1}"
: "${CLEANUP_CMD:=./rmconfig.sh}"
: "${ARTIFACT_DIR:=/tmp/cicd-artifacts-$(date +%Y%m%d-%H%M%S)}"

mkdir -p "$ARTIFACT_DIR"

# ---------------------------------------------------------------------------
# Provenance. A result that cannot name the tree and image it ran against is
# not evidence, so record it once, up front, into the artifact directory.
# ---------------------------------------------------------------------------
_sr_provenance() {
  local root; root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  {
    echo "timestamp_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "host:          $(hostname)"
    echo "kernel:        $(uname -r)"
    echo "docker:        $(docker --version 2>/dev/null || echo unavailable)"
    echo "gateway_commit: $(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "gateway_dirty:  $(test -n "$(git -C "$root" status --porcelain 2>/dev/null)" && echo yes || echo no)"
    echo "ebpf_gitlink:   $(git -C "$root" rev-parse HEAD:loxilb-ebpf 2>/dev/null || echo unknown)"
    local img="${LOXILB_DOCKER_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:latest}"
    echo "image:          $img"
    echo "image_id:       $(docker image inspect --format '{{.Id}}' "$img" 2>/dev/null || echo not-present)"
  } > "$ARTIFACT_DIR/provenance.txt"
  echo "==== run provenance ===="
  cat "$ARTIFACT_DIR/provenance.txt"
  echo
}

# ---------------------------------------------------------------------------
# Leftover-state detection. Snapshot before, compare after cleanup.
#
# Helper processes are matched on the scenario's own directory appearing in the
# argv, which is how the mocks are launched ("python3 $SDIR/hdr_echo.py ...").
# That is deliberately narrower than a name match: `hexec` is `ip netns exec`,
# so the mocks share the HOST pid namespace and a name-based sweep would both
# see and kill processes belonging to other scenarios.
# ---------------------------------------------------------------------------
_sr_snapshot() {
  local dir=$1
  docker ps -aq 2>/dev/null | sort
  echo "--netns--"
  ip netns list 2>/dev/null | awk '{print $1}' | sort
  echo "--procs--"
  pgrep -f "cicd/${dir}/" 2>/dev/null | sort
}

_sr_leaks_now() {
  local before=$1 after=$2
  diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") 2>/dev/null \
    | grep '^>' | sed 's/^> //' | grep -v '^--' | tr '\n' ' '
}

# Leftover state is what PERSISTS. `docker stop` on a --rm container returns
# before the container is reaped, and a netns can linger for a moment after its
# last process exits, so a snapshot taken the instant cleanup returns reports
# leaks that are merely mid-teardown. Re-check until the set is stable or the
# settle budget runs out, and report only what is still there at the end —
# otherwise LEAK_STRICT fails scenarios that cleaned up correctly.
_sr_leaks() {
  local dir=$1 before=$2 leaks="" i
  for i in $(seq 1 "${LEAK_SETTLE_TRIES:-6}"); do
    leaks=$(_sr_leaks_now "$before" "$(_sr_snapshot "$dir")")
    [[ -z ${leaks// /} ]] && { printf ''; return 0; }
    sleep 1
  done
  printf '%s' "$leaks"
}

# ---------------------------------------------------------------------------
# run_scenario <dir> [label] -- <step>...
# ---------------------------------------------------------------------------
run_scenario() {
  local dir=$1; shift
  local label=$dir
  if [[ ${1:-} != "--" ]]; then label=$1; shift; fi
  [[ ${1:-} == "--" ]] && shift

  local steps=("$@")
  local here; here=$(pwd)

  if [[ ! -d $dir ]]; then
    echo "[SKIP] $label — directory $dir does not exist"
    _SR_RESULTS+=("$label|missing|0|-|")
    _SR_FAILED=1
    return 0
  fi

  echo
  echo "======================================================================"
  echo ">>> $label"
  echo "======================================================================"

  local log="$ARTIFACT_DIR/${label//[^A-Za-z0-9._-]/_}.log"
  local before; before=$(_sr_snapshot "$dir")
  local t0; t0=$(date +%s)
  local rc=0 failed_stage="-"

  local step
  for step in "${steps[@]}"; do
    echo "--- $label: $step"
    # Each step is timed out independently. --foreground so a Ctrl-C in an
    # interactive run still reaches the scenario.
    #
    # The step's status must be read out of PIPESTATUS, never from the
    # pipeline: `tee` is the last element, it succeeds whatever the step did,
    # and testing the pipeline makes every scenario pass unconditionally.
    timeout --foreground "$SCENARIO_TIMEOUT" \
      bash -c "cd '$dir' && $step" 2>&1 | tee -a "$log"
    rc=${PIPESTATUS[0]}
    if [[ $rc != 0 ]]; then
      # timeout(1) reports 124 for the deadline; say so rather than leaving a
      # bare exit code that reads like a product failure.
      if [[ $rc == 124 ]]; then
        echo "[TIMEOUT] $label: '$step' exceeded ${SCENARIO_TIMEOUT}s"
      fi
      failed_stage=$step
      echo "[FAIL] $label: '$step' exited $rc — remaining steps skipped, cleanup still runs"
      break
    fi
  done

  # --- cleanup ALWAYS runs, and never overwrites the scenario's verdict -----
  local crc=0
  echo "--- $label: $CLEANUP_CMD (always)"
  timeout --foreground "$SCENARIO_TIMEOUT" \
    bash -c "cd '$dir' && $CLEANUP_CMD" 2>&1 | tee -a "$log"
  crc=${PIPESTATUS[0]}
  if [[ $crc != 0 ]]; then
    echo "[WARN] $label: cleanup exited $crc"
    # A cleanup failure is only the verdict when the scenario itself passed;
    # otherwise the original failure is the more useful one to report.
    if [[ $rc == 0 ]]; then rc=$crc; failed_stage="$CLEANUP_CMD"; fi
  fi

  local t1; t1=$(date +%s)
  local secs=$((t1 - t0))

  # --- leftover state -------------------------------------------------------
  local leaks; leaks=$(_sr_leaks "$dir" "$before")
  if [[ -n ${leaks// /} ]]; then
    echo "[LEAK] $label: state survived cleanup: $leaks"
    if [[ $LEAK_STRICT == 1 && $rc == 0 ]]; then
      rc=90; failed_stage="leftover-state"
    fi
  fi

  cd "$here" || true

  if [[ $rc == 0 ]]; then
    echo "[PASS] $label (${secs}s)"
    rm -f "$log"                       # keep artifacts only for failures
    _SR_RESULTS+=("$label|pass|$secs|-|")
  else
    echo "[FAIL] $label (${secs}s, rc=$rc, stage: $failed_stage) — log: $log"
    _SR_RESULTS+=("$label|fail:$rc|$secs|$failed_stage|$leaks")
    _SR_FAILED=1
    if [[ $FAIL_FAST == 1 ]]; then
      echo "FAIL_FAST=1 — stopping after $label"
      scenario_summary
      exit 1
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Cheap gates, before anything spends minutes on containers. None of these
# needs a Gateway or a topology; each one has caught a real defect before.
# ---------------------------------------------------------------------------
scenario_preflight() {
  local root; root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  local rc=0
  echo "==== preflight ===="

  # The C header and the Go export must agree on arity: a mismatch is a link
  # or a silent ABI error, not a compile error.
  echo "--- preflight: source invariants (incl. C/Go arity lockstep)"
  bash "$root/scripts/check-source-invariants.sh" || rc=1

  # The bearer verifier: its token corpus, claim mapping, model authorization,
  # rotation and staleness tests.
  echo "--- preflight: pkg/jwtauth"
  ( cd "$root" && go test -count=1 ./pkg/jwtauth ) || rc=1

  # The datapath halves of admission and identity forwarding.
  echo "--- preflight: eBPF admission/identity unit tests"
  make -C "$root/loxilb-ebpf/common" test_aisec   || rc=1
  make -C "$root/loxilb-ebpf/common" test_aiident || rc=1

  # Every declared response status must actually be reachable, and a mutating
  # operation has to declare some success status.
  #
  # api/restapi links the datapath static library, so unlike the gates above it
  # needs a built tree. The local runner otherwise needs only a prebuilt
  # container image, so say so plainly instead of failing with a linker error
  # that reads like a product defect. An unbuilt tree is a hard stop by
  # default; PREFLIGHT_ALLOW_UNBUILT=1 downgrades it to a skip that is recorded
  # in the summary, because a silent skip is how a gate stops being one.
  echo "--- preflight: declared-status matrix"
  if [[ -f "$root/loxilb-ebpf/kernel/libloxilbdp.a" ]]; then
    ( cd "$root" && go test -count=1 -run 'TestDeclared|TestMutatingOperationsDeclareSomeSuccess' ./api/restapi ) || rc=1
  elif [[ ${PREFLIGHT_ALLOW_UNBUILT:-0} == 1 ]]; then
    echo "[SKIP] declared-status matrix: no built tree (loxilb-ebpf/kernel/libloxilbdp.a absent)"
    echo "       approved by PREFLIGHT_ALLOW_UNBUILT=1 — this gate did NOT run"
    _SR_RESULTS+=("preflight:declared-status|skipped|0|unbuilt-tree|")
  else
    echo "[FAIL] declared-status matrix needs a built tree:"
    echo "       loxilb-ebpf/kernel/libloxilbdp.a is absent, so api/restapi cannot link."
    echo "       Run 'make' at the repository root first, or re-run with"
    echo "       PREFLIGHT_ALLOW_UNBUILT=1 to record it as an explicit skip."
    rc=1
  fi

  if [[ $rc != 0 ]]; then
    echo "[FAIL] preflight failed — not spending time on container scenarios"
    _SR_RESULTS+=("preflight|fail|0|preflight|")
    _SR_FAILED=1
    scenario_summary
    exit 1
  fi
  echo "[PASS] preflight"
  echo
}

# ---------------------------------------------------------------------------
# Aggregate. Non-zero exit when anything failed, so a scheduled run has a
# single honest verdict.
# ---------------------------------------------------------------------------
scenario_summary() {
  local total=$((  $(date +%s) - _SR_START_ALL ))
  echo
  echo "======================================================================"
  echo "SCENARIO SUMMARY  (${total}s total, artifacts: $ARTIFACT_DIR)"
  echo "======================================================================"
  printf '%-44s %-10s %6s  %s\n' "SCENARIO" "RESULT" "SECS" "FAILED STAGE"
  local row name res secs stage leaks passes=0 fails=0 skips=0
  for row in "${_SR_RESULTS[@]}"; do
    IFS='|' read -r name res secs stage leaks <<< "$row"
    printf '%-44s %-10s %6s  %s\n' "$name" "$res" "$secs" "$stage"
    case $res in
      pass)    passes=$((passes+1)) ;;
      skipped) skips=$((skips+1))   ;;   # approved, and visible — never silent
      *)       fails=$((fails+1))   ;;
    esac
    [[ -n ${leaks// /} ]] && printf '%-44s %-10s %6s  leftover: %s\n' "" "" "" "$leaks"
  done
  echo "----------------------------------------------------------------------"
  echo "passed: $passes   failed: $fails   skipped: $skips   total: ${#_SR_RESULTS[@]}"
  if [[ $_SR_FAILED != 0 ]]; then
    echo "RESULT: FAIL"
    return 1
  fi
  echo "RESULT: PASS"
  return 0
}

_sr_provenance
