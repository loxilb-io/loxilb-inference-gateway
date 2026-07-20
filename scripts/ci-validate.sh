#!/usr/bin/env bash
#
# ci-validate.sh — dispatch loxilb-inference-gateway CI workflows and report a
# pass/fail matrix. Use during Stage 3/4 validation of the PRIVATE repo (see
# docs/RELEASE-OPERATIONS.md) to drive the whole suite from one command instead
# of clicking each workflow in the Actions tab.
#
# Prerequisites:
#   - gh CLI authenticated for the repo:   gh auth status
#   - run from the repo root, repo pushed to GitHub, on a dispatchable ref
#   - eBPF submodule repo already PUBLIC (so submodule checkout succeeds)
#
# Usage:
#   scripts/ci-validate.sh <tier> [--ref REF] [--no-watch]
#   scripts/ci-validate.sh list <tier>        # dry run: print tier membership only
#
# Tiers:
#   publish     docker-multiarch, docker-image, docker-image-u24  (run FIRST — builds images)
#   ai          ai-gateway / mcp / l7-proxy / vllm-proxy sanity
#   hosted      GitHub-hosted sanity matrix (dispatchable, not self-hosted, not publish)
#   selfhosted  self-hosted matrix (k8s/k3s/etc.) — needs runners registered
#   all         publish, then ai+hosted, then selfhosted
#
# Notes:
#   - Workflows guarded off on this repo (e.g. dormant rh9) will dispatch but the
#     job's `if:` skips them; they report "skipped" (not a failure).
#   - Dispatchable workflows use their input defaults; override per-workflow by
#     editing INPUTS_* below if a required input lacks a default.
set -uo pipefail

WF_DIR=".github/workflows"
REF="main"
WATCH=1

PUBLISH_WFS="docker-multiarch.yml docker-image.yml docker-image-u24.yml"
AI_WFS="ai-gateway-sanity.yml mcp-sanity.yml l7-proxy-sanity.yml vllm-proxy-sanity.yml"

die() { echo "error: $*" >&2; exit 1; }

command -v gh >/dev/null 2>&1 || die "gh CLI not found"
[ -d "$WF_DIR" ] || die "run from the repo root ($WF_DIR not found)"

is_selfhosted() { grep -qE 'runs-on:.*self-hosted' "$WF_DIR/$1" 2>/dev/null; }
is_dispatchable() { grep -qE '^[[:space:]]*workflow_dispatch:' "$WF_DIR/$1" 2>/dev/null; }

# Dormant on this repo: guarded to upstream 'loxilb-io/loxilb' only (never runs on
# the fork), e.g. the rh9 workflows pending a runner check. Excluded from tiers so
# we don't dispatch runs that just skip.
is_dormant() {
  grep -qE "== 'loxilb-io/loxilb'" "$WF_DIR/$1" 2>/dev/null \
    && ! grep -qE "== 'loxilb-io/loxilb-inference-gateway'" "$WF_DIR/$1" 2>/dev/null
}

# Echo the space-separated workflow file list for a tier.
tier_list() {
  local tier="$1" f base out=""
  case "$tier" in
    publish) echo "$PUBLISH_WFS" ;;
    ai)      echo "$AI_WFS" ;;
    hosted)
      for f in "$WF_DIR"/*.yml "$WF_DIR"/*.yaml; do
        [ -f "$f" ] || continue
        base="$(basename "$f")"
        is_dispatchable "$base" || continue
        is_dormant "$base" && continue
        is_selfhosted "$base" && continue
        case " $PUBLISH_WFS $AI_WFS " in *" $base "*) continue ;; esac
        out="$out $base"
      done
      echo "$out" ;;
    selfhosted)
      for f in "$WF_DIR"/*.yml "$WF_DIR"/*.yaml; do
        [ -f "$f" ] || continue
        base="$(basename "$f")"
        is_dispatchable "$base" || continue
        is_dormant "$base" && continue
        is_selfhosted "$base" && out="$out $base"
      done
      echo "$out" ;;
    all) echo "$PUBLISH_WFS $AI_WFS $(tier_list hosted) $(tier_list selfhosted)" ;;
    *) die "unknown tier: $tier (publish|ai|hosted|selfhosted|all)" ;;
  esac
}

# Dispatch one workflow; echo the new run's databaseId (empty on failure).
dispatch_one() {
  local wf="$1"
  gh workflow run "$wf" --ref "$REF" >/dev/null 2>&1 || { echo ""; return; }
  # Give GitHub a moment to register the run, then grab the newest dispatch run.
  local id=""
  for _ in 1 2 3 4 5 6; do
    sleep 2
    id="$(gh run list --workflow="$wf" -e workflow_dispatch -b "$REF" -L 1 \
            --json databaseId -q '.[0].databaseId' 2>/dev/null)"
    [ -n "$id" ] && break
  done
  echo "$id"
}

# ---- arg parsing ----
[ $# -ge 1 ] || die "usage: scripts/ci-validate.sh <tier> [--ref REF] [--no-watch]"
MODE="run"
if [ "$1" = "list" ]; then MODE="list"; shift; fi
[ $# -ge 1 ] || die "missing tier"
TIER="$1"; shift
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="$2"; shift 2 ;;
    --no-watch) WATCH=0; shift ;;
    *) die "unknown arg: $1" ;;
  esac
done

WFS="$(tier_list "$TIER")"
WFS="$(echo "$WFS" | tr -s ' ')"
[ -n "${WFS// /}" ] || die "no workflows in tier '$TIER'"

if [ "$MODE" = "list" ]; then
  echo "Tier '$TIER' (ref=$REF):"
  for wf in $WFS; do
    tag="hosted"; is_selfhosted "$wf" && tag="self-hosted"
    printf "  %-40s %s\n" "$wf" "$tag"
  done
  exit 0
fi

echo "Dispatching tier '$TIER' on ref '$REF'..."
RESULTS=""   # newline-separated "wf|status|url"
for wf in $WFS; do
  id="$(dispatch_one "$wf")"
  if [ -z "$id" ]; then
    printf "  %-40s %s\n" "$wf" "DISPATCH-FAILED (required input? guard? gh auth?)"
    RESULTS="$RESULTS
$wf|dispatch-failed|-"
    continue
  fi
  url="$(gh run view "$id" --json url -q .url 2>/dev/null)"
  printf "  %-40s run %s\n" "$wf" "$id"
  RESULTS="$RESULTS
$wf|$id|$url"
done

if [ "$WATCH" = "0" ]; then
  echo; echo "Dispatched (not watching). Track with: gh run watch <id>"
  exit 0
fi

echo; echo "Watching runs to completion..."
FINAL=""     # newline-separated "wf|conclusion|url"
FAILED=0
# Iterate via a temp file (redirect, not pipe) so FINAL/FAILED persist in this shell.
TMP="$(mktemp)"; printf "%s\n" "$RESULTS" > "$TMP"
while IFS='|' read -r wf id url; do
  [ -n "$wf" ] || continue
  if [ "$id" = "dispatch-failed" ]; then
    FINAL="$FINAL
$wf|dispatch-failed|$url"; FAILED=1; continue
  fi
  gh run watch "$id" --exit-status >/dev/null 2>&1
  concl="$(gh run view "$id" --json conclusion -q .conclusion 2>/dev/null)"
  [ -n "$concl" ] || concl="unknown"
  case "$concl" in success|skipped) : ;; *) FAILED=1 ;; esac
  FINAL="$FINAL
$wf|$concl|$url"
done < "$TMP"
rm -f "$TMP"

echo
echo "================ CI validation matrix (tier: $TIER) ================"
printf "%-40s %-16s %s\n" "WORKFLOW" "RESULT" "URL"
printf "%s\n" "$FINAL" | while IFS='|' read -r wf concl url; do
  [ -n "$wf" ] || continue
  printf "%-40s %-16s %s\n" "$wf" "$concl" "$url"
done
echo "==================================================================="
if [ "$FAILED" = "0" ]; then echo "ALL PASSED ✓"; else echo "SOME FAILED ✗"; exit 1; fi
