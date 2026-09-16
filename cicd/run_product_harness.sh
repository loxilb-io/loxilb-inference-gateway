#!/usr/bin/env bash
#
# Product harness — the AI Gateway scenarios owned by the product-harness
# programme, runnable on their own, repeatedly, by whoever owns quality next.
#
# WHY THIS EXISTS, SEPARATELY FROM run_local_cicd.sh
#
#   run_local_cicd.sh runs all 64 scenarios and takes hours. That is the right
#   thing before a release and the wrong thing when you want to know whether
#   the AI Gateway's own behaviour still holds. This script runs only the
#   scenarios this programme built or adopted, so a full pass is minutes, not
#   an afternoon, and a QA engineer can run it on a cadence rather than as an
#   event.
#
#   It deliberately reuses scenario_runner.sh rather than re-implementing the
#   run loop. Everything that wrapper guarantees applies here unchanged:
#   cleanup always runs, the original failure survives the cleanup, one broken
#   scenario does not hide the ones after it, every step is timed out, failure
#   logs are retained, leftover containers/netns/processes fail the scenario,
#   and the aggregate exit code is honest.
#
# USAGE
#
#   ./run_product_harness.sh                  # every scenario in the registry
#   ./run_product_harness.sh --list           # show the registry and exit
#   ./run_product_harness.sh ai-apikey        # one or more scenarios by name
#   ./run_product_harness.sh --phase 2        # everything a phase delivered
#   ./run_product_harness.sh --no-preflight   # skip the runner self-test and
#                                             # the cheap source gates
#
#   Knobs are scenario_runner.sh's, unchanged:
#     SCENARIO_TIMEOUT  per-step timeout, seconds        (default 1800)
#     FAIL_FAST=1       stop at the first failure        (default 0: collect all)
#     LEAK_STRICT=0     downgrade leftover state to a warning (default 1: fail)
#     ARTIFACT_DIR      where failure logs and provenance land
#
# PREREQUISITES
#
#   - A built gateway container image, tagged as the scenarios expect. These
#     scenarios need a running image, not a built source tree; the one
#     exception is the PF-4 preflight gate, which links the datapath library
#     and so needs a built tree. Without one it fails with an explanation;
#     PREFLIGHT_ALLOW_UNBUILT=1 turns that into a recorded skip.
#   - Docker, and the loxilb cicd helpers on PATH the same way the other
#     scenarios expect them (see cicd/common.sh).
#   - Run as a user that can drive docker and create network namespaces.
#   - Linux. These scenarios build network topology; they do not run on macOS.
#
# EXIT CODE
#
#   0 only if every selected scenario passed. Any failure, any leftover state,
#   any missing scenario directory is non-zero. A skip is reported as a skip
#   and is visible in the summary — it is never silently folded into a pass.

set -uo pipefail

cd "$(dirname "$0")" || exit 1

# scenario_runner.sh is sourced *after* argument parsing, deliberately:
# sourcing it stamps provenance and creates an artifact directory, and
# `--list` and `--help` should not leave a directory behind in /tmp or print a
# provenance banner nobody asked for.

# ---------------------------------------------------------------------------
# The registry.
#
# One row per scenario:  <name> | <phase> | <cleanup> | <step>[; <step>...]
#
# `cleanup` is per-scenario on purpose. scenario_runner.sh takes CLEANUP_CMD as
# a single global, which is correct for a suite where every scenario is a
# container trio, and wrong here: ai-multitier-contract is a unit gate with no
# config/validation/rmconfig trio at all. Driving './rmconfig.sh' at it would
# exit 127, and because the scenario itself passed, that cleanup failure would
# become the reported verdict — a green test filed as a failure. `true` is the
# honest cleanup for a scenario that creates nothing.
#
# The phase tag is a delivery grouping, so that `--phase N` can re-run exactly
# the set of scenarios one piece of work put under automation. A scenario may
# be touched by several pieces of work; the tag records which one first brought
# it under automation, so `--phase` answers "what did that work deliver", not
# "what does it touch". `-` means the scenario predates the grouping.
#
# 🚨 A step must be the thing CI runs, not something adjacent to it. This row
# pointed at ai-multitier-contract's run-unit.sh, which is the evidence-
# producing baseline rail: it takes two mandatory arguments and exits 2
# without them, and it is committed non-executable, so './run-unit.sh' exited
# 126. The row could never have passed — and even repaired it would have run
# twelve Docker gates, where what CI actually gates on is three commands.
# Those now live in run-ci-gates.sh, which the workflow and this row both
# call, so the two cannot drift apart again. Measured, not predicted: the
# first execution of this registry is what exposed it.
# ---------------------------------------------------------------------------
REGISTRY=(
  "ai-apikey|2|./rmconfig.sh|./config.sh;./validation.sh"
  "ai-jwtauth|0|./rmconfig.sh|./config.sh;./validation.sh"
  "ai-model-conflict|0|./rmconfig.sh|./config.sh;./validation.sh"
  "ai-ephealth|0|./rmconfig.sh|./config.sh;./validation.sh"
  "ai-multitier-contract|0|true|./run-ci-gates.sh"
  "ai-sse-quota|-|./rmconfig.sh|./config.sh;./validation.sh"
  "ai-model-routing|-|./rmconfig.sh|./config.sh;./validation.sh"
  "ai-qos-ha-sync|5|./rmconfig.sh|./config.sh;./validation.sh"
)

usage() { sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

list_registry() {
  printf '%-26s %-7s %-14s %s\n' "SCENARIO" "PHASE" "CLEANUP" "STEPS"
  local row name phase cleanup steps
  for row in "${REGISTRY[@]}"; do
    IFS='|' read -r name phase cleanup steps <<< "$row"
    printf '%-26s %-7s %-14s %s\n' "$name" "$phase" "$cleanup" "${steps//;/ , }"
  done
}

WANT_PHASE=""
WANT_NAMES=()
DO_PREFLIGHT=1

while [[ $# -gt 0 ]]; do
  case $1 in
    --list)         list_registry; exit 0 ;;
    --phase)        WANT_PHASE="${2:?--phase needs a value}"; shift 2 ;;
    --no-preflight) DO_PREFLIGHT=0; shift ;;
    -h|--help)      usage ;;
    -*)             echo "unknown option: $1" >&2; exit 2 ;;
    *)              WANT_NAMES+=("$1"); shift ;;
  esac
done

# A name that matches nothing is a typo, and a typo that silently runs the
# whole suite (or nothing at all, reporting success) is exactly the class of
# quiet miss this programme exists to remove. Refuse it up front.
if [[ ${#WANT_NAMES[@]} -gt 0 ]]; then
  for want in "${WANT_NAMES[@]}"; do
    found=0
    for row in "${REGISTRY[@]}"; do
      [[ ${row%%|*} == "$want" ]] && { found=1; break; }
    done
    if [[ $found == 0 ]]; then
      echo "error: '$want' is not in the registry. Run --list to see the names." >&2
      exit 2
    fi
  done
fi

selected=()
for row in "${REGISTRY[@]}"; do
  IFS='|' read -r name phase _ _ <<< "$row"
  if [[ -n $WANT_PHASE && $phase != "$WANT_PHASE" ]]; then continue; fi
  if [[ ${#WANT_NAMES[@]} -gt 0 ]]; then
    match=0
    for want in "${WANT_NAMES[@]}"; do [[ $want == "$name" ]] && match=1; done
    [[ $match == 1 ]] || continue
  fi
  selected+=("$row")
done

if [[ ${#selected[@]} -eq 0 ]]; then
  echo "error: selection matched no scenarios (phase='${WANT_PHASE:-any}')." >&2
  echo "Run --list to see the registry." >&2
  exit 2
fi

echo "======================================================================"
echo "PRODUCT HARNESS — ${#selected[@]} scenario(s) selected"
echo "======================================================================"
for row in "${selected[@]}"; do echo "  - ${row%%|*}"; done
echo

# Only now, with a non-empty valid selection, take on the side effects:
# sourcing stamps provenance and creates the artifact directory.
# shellcheck source=cicd/scenario_runner.sh
source ./scenario_runner.sh

if [[ $DO_PREFLIGHT == 1 ]]; then
  # The runner proves itself before it spends an afternoon on scenarios.
  # It is the thing that decides whether every other scenario passed, so when
  # it is wrong it is wrong about all of them at once, and quietly: a wrapper
  # that misreports a status, or one that never returns, is indistinguishable
  # from a slow suite. This costs about a second and needs no Docker, no
  # topology and no image.
  #
  # Deliberately NOT a workflow step. The product harness is QA's to run on
  # their own cadence, and nothing here belongs in CI.
  echo "==== preflight: scenario runner self-test ===="
  if [[ -x ./scenario_runner_selftest.sh ]]; then
    if ! ./scenario_runner_selftest.sh; then
      echo "[FAIL] the scenario runner failed its own self-test — every verdict"
      echo "       below would be suspect, so nothing else is run"
      exit 1
    fi
  else
    # Loud, never silent: a missing self-test is a gate that did not run, and
    # it must not read as one that passed.
    echo "[SKIP] scenario_runner_selftest.sh absent or not executable —"
    echo "       this gate did NOT run"
  fi
  echo

  scenario_preflight
fi

for row in "${selected[@]}"; do
  IFS='|' read -r name phase cleanup steps <<< "$row"

  # Split the step list on ';' into the argv run_scenario expects.
  IFS=';' read -r -a step_arr <<< "$steps"

  # Per-scenario cleanup, restored afterwards so one row cannot leak its
  # cleanup choice into the next.
  _saved_cleanup=$CLEANUP_CMD
  CLEANUP_CMD=$cleanup
  run_scenario "$name" -- "${step_arr[@]}"
  CLEANUP_CMD=$_saved_cleanup
done

scenario_summary
