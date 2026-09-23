#!/usr/bin/env bash
#
# Self-test for scenario_runner.sh.
#
# WHY THIS EXISTS
#
#   The runner is the thing that decides whether every other scenario passed.
#   When it is wrong, it is wrong about all of them at once, and it is wrong
#   quietly — a wrapper that reports the wrong status, or one that never
#   returns at all, looks exactly like a slow suite.
#
#   Each case below pins a property that has actually broken. They run in
#   seconds, need no Docker, no topology and no gateway image, and each one
#   fails if its property regresses.
#
# USAGE
#
#   ./scenario_runner_selftest.sh
#
# EXIT CODE
#
#   0 only if every case passes.

set -uo pipefail
cd "$(dirname "$0")" || exit 1

fails=0
ok()   { echo "  [OK]     $1"; }
bad()  { echo "  [FAILED] $1"; fails=1; }

SELFTEST_TMP=$(mktemp -d)
trap 'rm -rf "$SELFTEST_TMP"' EXIT

# Each case runs the runner in its own subshell: scenario_runner.sh keeps
# suite state in globals, and a case must not inherit the previous case's.
run_case() {
  local scen=$1 timeout_s=$2 cleanup=$3; shift 3
  (
    export ARTIFACT_DIR="$SELFTEST_TMP/artifacts-$scen"
    export SCENARIO_TIMEOUT="$timeout_s"
    export CLEANUP_CMD="$cleanup"
    export LEAK_STRICT=0
    mkdir -p "$ARTIFACT_DIR"
    # shellcheck disable=SC1091
    source ./scenario_runner.sh
    run_scenario "$scen" -- "$@"
    scenario_summary
  )
}

# ---------------------------------------------------------------------------
# Case 1: a step that daemonises a helper must not stall the runner.
#
# THE BUG THIS PINS: the step used to be piped into `tee`. A scenario that
# leaves a background process running for a later step — ai-sse-quota's mock
# server is launched exactly this way — hands that process fds 1 and 2, the
# write end of tee's pipe. tee waits for an EOF that cannot arrive, the shell
# waits for tee, and the runner hangs on a step whose command already exited.
# The per-step timeout does not help: it bounds the step, not the pipe.
#
# Measured before the fix: twenty minutes on a step that took one second.
# ---------------------------------------------------------------------------
scen=sr-selftest-daemon
mkdir -p "$scen"
cat > "$scen/step.sh" <<'EOF'
#!/usr/bin/env bash
# Daemonise a helper that outlives this step and keeps stdout open, which is
# what every mock-server scenario does.
sleep 120 &
echo "$!" > helper.pid
echo "step done, helper $! still running"
exit 0
EOF
cat > "$scen/kill.sh" <<'EOF'
#!/usr/bin/env bash
# Kill by RECORDED PID, never by pattern. `pkill -f "sleep 120"` would reap
# any other user's matching process on a shared testbed -- the same mistake
# that made a name-based sweep kill other scenarios' mock servers, since
# `ip netns exec` shares the host pid namespace.
[[ -f helper.pid ]] && kill "$(cat helper.pid)" 2>/dev/null
rm -f helper.pid
exit 0
EOF
chmod +x "$scen/step.sh" "$scen/kill.sh"

echo "SR-1: a step that leaves a background process does not stall the runner"
start=$(date +%s)
# The guard is wall clock, not the runner's own verdict: a hang produces no
# verdict at all, so only an external clock can catch it. 60s is far above the
# ~1s this needs and far below the 20 minutes the bug produced.
timeout 60 bash -c "$(declare -f run_case); SELFTEST_TMP='$SELFTEST_TMP'; \
  cd '$(pwd)' && run_case $scen 30 ./kill.sh ./step.sh" > "$SELFTEST_TMP/case1.out" 2>&1
case1_rc=$?
elapsed=$(( $(date +%s) - start ))
if [[ $case1_rc == 124 ]]; then
  bad "SR-1 the runner HUNG on a step that daemonised a helper (${elapsed}s, killed at 60s)"
elif grep -q "\[PASS\] $scen" "$SELFTEST_TMP/case1.out"; then
  ok "SR-1 completed in ${elapsed}s and reported the scenario passed"
else
  bad "SR-1 finished (${elapsed}s) but did not report a pass:"
  sed 's/^/        /' "$SELFTEST_TMP/case1.out" | tail -15
fi
rm -rf "$scen"

# ---------------------------------------------------------------------------
# Case 2: a failing step is reported as a failure.
#
# THE BUG THIS PINS: with the step piped into tee, `if ! cmd | tee` tests the
# PIPELINE, and tee succeeds whatever the step did — so every failing scenario
# passed. The status must come from the step itself.
# ---------------------------------------------------------------------------
scen=sr-selftest-fail
mkdir -p "$scen"
printf '#!/usr/bin/env bash\necho "about to fail"\nexit 7\n' > "$scen/step.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "$scen/kill.sh"
chmod +x "$scen/step.sh" "$scen/kill.sh"

echo "SR-2: a step that exits non-zero is reported as a failure, with its code"
run_case "$scen" 30 ./kill.sh ./step.sh > "$SELFTEST_TMP/case2.out" 2>&1
if grep -q "\[FAIL\] $scen" "$SELFTEST_TMP/case2.out" && \
   grep -q "exited 7" "$SELFTEST_TMP/case2.out"; then
  ok "SR-2 reported the failure and preserved exit code 7"
else
  bad "SR-2 did not report the step's failure:"
  sed 's/^/        /' "$SELFTEST_TMP/case2.out" | tail -15
fi
rm -rf "$scen"

# ---------------------------------------------------------------------------
# Case 3: the step's output reaches both the console and the artifact log.
#
# Redirecting to a file instead of a pipe is what fixes case 1; this pins that
# the output did not get lost on the way. A silent runner would be a poor
# trade for one that does not hang.
# ---------------------------------------------------------------------------
scen=sr-selftest-output
mkdir -p "$scen"
printf '#!/usr/bin/env bash\necho "MARKER-STDOUT"\necho "MARKER-STDERR" >&2\nexit 1\n' \
  > "$scen/step.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "$scen/kill.sh"
chmod +x "$scen/step.sh" "$scen/kill.sh"

echo "SR-3: a step's stdout and stderr reach the console and the retained log"
run_case "$scen" 30 ./kill.sh ./step.sh > "$SELFTEST_TMP/case3.out" 2>&1
console_ok=0
grep -q MARKER-STDOUT "$SELFTEST_TMP/case3.out" && \
  grep -q MARKER-STDERR "$SELFTEST_TMP/case3.out" && console_ok=1
log_ok=0
if [[ -f "$SELFTEST_TMP/artifacts-$scen/$scen.log" ]]; then
  grep -q MARKER-STDOUT "$SELFTEST_TMP/artifacts-$scen/$scen.log" && \
    grep -q MARKER-STDERR "$SELFTEST_TMP/artifacts-$scen/$scen.log" && log_ok=1
fi
if [[ $console_ok == 1 && $log_ok == 1 ]]; then
  ok "SR-3 both streams reached the console and the failure artifact"
else
  bad "SR-3 output lost (console=$console_ok artifact=$log_ok)"
  sed 's/^/        /' "$SELFTEST_TMP/case3.out" | tail -15
fi
rm -rf "$scen"

# ---------------------------------------------------------------------------
# Case 4: a step killed at the deadline says so IN THE ARTIFACT, not only on
# the console.
#
# THE BUG THIS PINS: [TIMEOUT] and [FAIL] were echoed to stdout only. The
# runner tells the caller to follow the log, and the log is what gets archived,
# so a scenario stopped at SCENARIO_TIMEOUT left an artifact that ended
# mid-run with no verdict — indistinguishable from a crash, a hang, or a
# product failure.
#
# Measured before the fix: a scenario killed at exactly the deadline left 42
# passing assertions, zero failing ones and no closing line, and establishing
# the cause took a timeline reconstruction from file mtimes.
# ---------------------------------------------------------------------------
scen=sr-selftest-timeout
mkdir -p "$scen"
# Emit a line, then overrun the budget: the artifact must keep BOTH the output
# and the verdict, so a reader can see where it got to and why it stopped.
printf '#!/usr/bin/env bash\necho "MARKER-BEFORE-DEADLINE"\nsleep 60\n' > "$scen/step.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "$scen/kill.sh"
chmod +x "$scen/step.sh" "$scen/kill.sh"

echo "SR-4: a step killed at the deadline records its verdict in the artifact log"
run_case "$scen" 3 ./kill.sh ./step.sh > "$SELFTEST_TMP/case4.out" 2>&1
sr4_log="$SELFTEST_TMP/artifacts-$scen/$scen.log"
if [[ -f $sr4_log ]] &&
   grep -q "MARKER-BEFORE-DEADLINE" "$sr4_log" &&
   grep -q "\[TIMEOUT\] $scen" "$sr4_log" &&
   grep -q "\[FAIL\] $scen" "$sr4_log"; then
  ok "SR-4 the artifact carries the step's output AND the timeout verdict"
else
  bad "SR-4 the artifact does not say how the run ended:"
  if [[ -f $sr4_log ]]; then
    sed 's/^/        LOG| /' "$sr4_log" | tail -10
  else
    echo "        (no artifact log was retained)"
  fi
fi
rm -rf "$scen"

echo
if [[ $fails == 0 ]]; then
  echo "SCENARIO-scenario-runner-selftest [OK]"
else
  echo "SCENARIO-scenario-runner-selftest [FAILED]"
fi
exit $fails
