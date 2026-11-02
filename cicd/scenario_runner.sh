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
#   run_scenario [--needs <cap>[,<cap>]] <dir> [label] -- <step>...
#   scenario_summary                         # returns non-zero if any failed
#
# Each step runs with the scenario directory as cwd, so steps read exactly the
# way they did inline: './config.sh', 'EXPECT=fixed ./validation.sh'.
#
# --needs names host capabilities the scenario cannot run without (sctp, ipv6,
# minica; see preflight-caps.sh). When one is missing the scenario is skipped
# with the reason, not run into a failure that reads like a product defect.
#
# Knobs (all optional):
#   SCENARIO_TIMEOUT  per-step timeout in seconds            (default 1800)
#   FAIL_FAST         1 = stop at the first failed scenario   (default 0)
#   LEAK_STRICT       1 = leftover state fails the scenario   (default 1)
#   CLEANUP_CMD       cleanup step, always run                (default ./rmconfig.sh)
#   ARTIFACT_DIR      where failure logs are kept
#   ONLY              run only the scenarios matching these   (default: all)
#   SKIP              skip the scenarios matching these       (default: none)
#
# ONLY and SKIP take shell glob patterns, separated by commas or spaces,
# matched against a scenario's label and its directory:
#
#   ONLY='ai-* kv-*' ./run_local_cicd.sh
#   SKIP=tcpsctpperf,ai-tenant ./run_local_cicd.sh
#
# A scenario left out by either is recorded as skipped in the summary, so a
# partial run cannot be mistaken for a full one.
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
: "${ONLY:=}"
: "${SKIP:=}"

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
    local img="${LOXILB_DOCKER_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:main}"
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
# _sr_run <dir> <log> <cmd> — run one command under the step timeout and
# publish its exit status in _SR_RC.
#
# The command's output goes to the LOG FILE, and the bytes it appended are
# replayed to the console afterwards. It used to be
#
#     timeout ... bash -c "cd '$dir' && $cmd" 2>&1 | tee -a "$log"
#
# which hangs the entire suite. A scenario that daemonises a helper — and
# ai-sse-quota's config.sh does, leaving its mock server running for the
# validation step that follows — hands that process fds 1 and 2, the WRITE
# end of tee's pipe. tee then waits for an EOF that cannot arrive while the
# daemon holds the pipe open, and the shell waits for tee. The runner blocks
# forever on a step whose command exited minutes earlier.
#
# The per-step timeout does NOT save it: timeout bounds the step, and the step
# is not what is stuck. Measured, not reasoned: the runner sat on
# ai-sse-quota's config.sh for twenty minutes with no child process but tee,
# and /proc showed the leaked mock holding fds 1 and 2 on the same pipe inode
# that tee held as fd 0.
#
# A regular file cannot be held against us this way — the daemon inherits a
# file descriptor nobody is waiting on. The cost is that a step's output
# appears when the step ends rather than as it is produced. The alternative, a
# `tail -f` follower, races the step's final lines and adds a process the
# runner would then have to guarantee it kills, which is the class of bug this
# is fixing.
# ---------------------------------------------------------------------------
# _sr_say <log> <msg> — say it on the console AND in the artifact.
#
# A step's verdict has to survive in the log, not only on the console. The
# runner tells the caller to follow "$log", and "$log" is what gets archived,
# but the verdict lines were echoed to stdout only. An archived log therefore
# ended mid-run with no verdict, and a step killed at the deadline was
# indistinguishable from a crash, a hang, or a product failure. Measured, not
# reasoned: a scenario stopped at exactly SCENARIO_TIMEOUT left 42 passing
# assertions, zero failing ones and no closing line, and establishing why took
# a timeline reconstruction from file mtimes. Say it in both places.
_sr_say() {
  local log=$1; shift
  echo "$*"
  printf '%s\n' "$*" >> "$log" 2>/dev/null || true
}

_SR_RC=0
_sr_run() {
  local dir=$1 log=$2 cmd=$3
  : >> "$log"
  local from; from=$(wc -c < "$log")
  # Name the log before the step runs, not after. Because output is replayed
  # only once the step RETURNS (see above), a long step shows the console
  # nothing at all, and silence is indistinguishable from a hang - the reason
  # a caller cannot tell a twenty-minute scenario from a wedged one. This line
  # costs nothing, reintroduces no pipe for a daemon to hold, and gives the
  # caller something to follow while waiting.
  echo "    (running; follow with: tail -f $log)"
  timeout --foreground "$SCENARIO_TIMEOUT" \
    bash -c "cd '$dir' && $cmd" >> "$log" 2>&1
  _SR_RC=$?
  # Replay by BYTE offset, not line count: a step whose last write lacks a
  # trailing newline would otherwise lose that line or repeat it.
  tail -c "+$((from + 1))" "$log"
}

# ---------------------------------------------------------------------------
# Selection and capabilities: the two reasons a scenario is skipped instead of
# run. Both record the skip in the summary with its reason.
# ---------------------------------------------------------------------------

# _sr_listed <patterns> <name>... — true when any name matches any pattern.
# `read -a` splits the list without pathname expansion, so each pattern
# reaches the [[ == ]] match as written rather than as the files it names.
_sr_listed() {
  local list=$1; shift
  local -a pats
  local pat name
  IFS=', ' read -r -a pats <<< "$list"
  for pat in "${pats[@]}"; do
    [[ -z $pat ]] && continue
    for name in "$@"; do
      # shellcheck disable=SC2053  # $pat is a glob on purpose
      [[ $name == $pat ]] && return 0
    done
  done
  return 1
}

_sr_skip() {
  local label=$1 reason=$2
  echo "[SKIP] $label — $reason"
  _SR_RESULTS+=("$label|skipped|0|$reason|")
}

# Capability name -> "" when present, the reason when missing. A name that is
# not a key at all is one preflight-caps.sh does not probe.
declare -A _SR_CAP_MISSING=()
_SR_CAPS_PROBED=0

# _sr_caps_probe — run preflight-caps.sh once and record its verdicts. Returns
# the probe's exit status: non-zero means something every scenario needs is
# broken, which scenario_preflight treats as a preflight failure.
_sr_caps_probe() {
  local out rc=0 tag name state reason
  # `|| rc=$?`, not a bare assignment: run_local_cicd.sh runs under set -e.
  out=$(bash "$(dirname "${BASH_SOURCE[0]}")/preflight-caps.sh" 2>&1) || rc=$?
  printf '%s\n' "$out"
  while read -r tag name state reason; do
    [[ $tag == cap ]] || continue
    if [[ $state == ok ]]; then
      _SR_CAP_MISSING[$name]=""
    else
      _SR_CAP_MISSING[$name]=${reason:-missing}
    fi
  done <<< "$out"
  _SR_CAPS_PROBED=1
  return $rc
}

# ---------------------------------------------------------------------------
# run_scenario <dir> [label] -- <step>...
# ---------------------------------------------------------------------------
run_scenario() {
  local needs=""
  if [[ ${1:-} == "--needs" ]]; then needs=$2; shift 2; fi
  local dir=$1; shift
  local label=$dir
  if [[ ${1:-} != "--" ]]; then label=$1; shift; fi
  [[ ${1:-} == "--" ]] && shift

  local steps=("$@")
  local here; here=$(pwd)

  if [[ -n $ONLY ]] && ! _sr_listed "$ONLY" "$label" "$dir"; then
    _sr_skip "$label" "not in ONLY"
    return 0
  fi
  if [[ -n $SKIP ]] && _sr_listed "$SKIP" "$label" "$dir"; then
    _sr_skip "$label" "in SKIP"
    return 0
  fi

  if [[ -n $needs ]]; then
    # Probed here only when scenario_preflight did not run; a broken common
    # binary is preflight's verdict to give, so it does not fail this one.
    [[ $_SR_CAPS_PROBED == 1 ]] || _sr_caps_probe >/dev/null || true
    local cap
    for cap in ${needs//,/ }; do
      if [[ -z ${_SR_CAP_MISSING[$cap]+set} ]]; then
        # A typo here would otherwise skip or run the scenario silently.
        echo "[FAIL] $label — --needs names an unknown capability '$cap'"
        _SR_RESULTS+=("$label|fail:needs|0|unknown capability $cap|")
        _SR_FAILED=1
        return 0
      fi
      if [[ -n ${_SR_CAP_MISSING[$cap]} ]]; then
        _sr_skip "$label" "needs $cap: ${_SR_CAP_MISSING[$cap]}"
        return 0
      fi
    done
  fi

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
    # Each step is timed out independently, and _sr_run keeps the step's
    # status honest: there is no pipeline whose last element could report
    # success on the step's behalf, and no pipe a daemonised helper can hold
    # open to stall the runner. See _sr_run.
    _sr_run "$dir" "$log" "$step"
    rc=$_SR_RC
    if [[ $rc != 0 ]]; then
      # timeout(1) reports 124 for the deadline; say so rather than leaving a
      # bare exit code that reads like a product failure.
      if [[ $rc == 124 ]]; then
        _sr_say "$log" "[TIMEOUT] $label: '$step' exceeded ${SCENARIO_TIMEOUT}s"
      fi
      failed_stage=$step
      _sr_say "$log" "[FAIL] $label: '$step' exited $rc — remaining steps skipped, cleanup still runs"
      break
    fi
  done

  # --- cleanup ALWAYS runs, and never overwrites the scenario's verdict -----
  local crc=0
  echo "--- $label: $CLEANUP_CMD (always)"
  _sr_run "$dir" "$log" "$CLEANUP_CMD"
  crc=$_SR_RC
  if [[ $crc != 0 ]]; then
    _sr_say "$log" "[WARN] $label: cleanup exited $crc"
    # A cleanup failure is only the verdict when the scenario itself passed;
    # otherwise the original failure is the more useful one to report.
    if [[ $rc == 0 ]]; then rc=$crc; failed_stage="$CLEANUP_CMD"; fi
  fi

  local t1; t1=$(date +%s)
  local secs=$((t1 - t0))

  # --- leftover state -------------------------------------------------------
  local leaks; leaks=$(_sr_leaks "$dir" "$before")
  if [[ -n ${leaks// /} ]]; then
    _sr_say "$log" "[LEAK] $label: state survived cleanup: $leaks"
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
    # The closing verdict goes into the log too: the archived artifact is often
    # the only thing a reader has, and it must say how it ended. (The pass
    # branch above deletes the log, so there is nothing to record there.)
    _sr_say "$log" "[FAIL] $label (${secs}s, rc=$rc, stage: $failed_stage) — log: $log"
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

  # Host dependencies first: they are the cheapest gate and the one whose
  # absence is least legible downstream. A bed without jq does not fail with
  # "jq missing" - it fails as dozens of assertions reading an empty field,
  # which reads as a broken gateway. Settle it before anything else runs.
  echo "--- preflight: host dependencies"
  bash "$(dirname "${BASH_SOURCE[0]}")/preflight-deps.sh" || rc=1

  # Capabilities only some scenarios need. A missing one is not a preflight
  # failure: the scenarios that declare it (--needs) are skipped, with the
  # reason, when their turn comes.
  echo "--- preflight: host capabilities (a scenario that --needs a missing one is skipped)"
  _sr_caps_probe || rc=1

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
  printf '%-44s %-10s %6s  %s\n' "SCENARIO" "RESULT" "SECS" "FAILED STAGE / SKIP REASON"
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
