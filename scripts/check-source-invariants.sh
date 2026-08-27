#!/usr/bin/env bash
#
# Source invariants that the compiler cannot express.
#
# Each check here exists because a specific class of defect got into the tree
# once already and was expensive to find. They are cheap greps; run them in CI
# and before a release.
#
# Usage: scripts/check-source-invariants.sh
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
FAILED=0

fail() { printf '  FAIL  %s\n' "$1"; FAILED=1; }
pass() { printf '  ok    %s\n' "$1"; }

echo "==== source invariants ===="

# ---------------------------------------------------------------------------
# 1. The AI-gateway-mode derivation has exactly one definition.
#
# It was previously spelled out independently in the eBPF rule installer and
# twice in the DOCA backend. When the derivation gained a third input, the
# copies disagreed: a service enforcing an API key but doing neither streaming
# mode got AI accounting in sockproxy and the short TCP aging in DOCA, which
# silently reaps long-lived inference connections — on DPU deployments only,
# so it never reproduced on the standard testbed.
#
# The predicate is aiGwModeFor() in pkg/loxinet/rules.go. Nothing else may
# spell the expression out.
# ---------------------------------------------------------------------------
# Match the DERIVATION shape specifically -- an OR of the streaming mode with
# the disaggregation mode. A comparison such as "eRule.sseMode != serv.SSEMode"
# is not a derivation and must not trip this.
hits="$(grep -rn --include='*.go' -E '[sS][sS][eE]Mode[[:space:]]*\|\|[[:space:]]*[a-zA-Z_.]*[pP][dD][a-zA-Z]*' pkg/ \
        | grep -v '_test\.go' || true)"
total="$(printf '%s' "$hits" | grep -c . || true)"
outside="$(printf '%s' "$hits" | grep -v 'pkg/loxinet/rules\.go' | grep -c . || true)"
if [ "$total" -eq 1 ] && [ "$outside" -eq 0 ]; then
  pass "ai-gateway-mode derivation appears only in its predicate"
else
  fail "ai-gateway-mode derivation must appear exactly once (found $total, $outside outside rules.go):"
  printf '%s\n' "$hits" | sed 's/^/          /'
fi

# ---------------------------------------------------------------------------
# 2. The data-plane decision values are documented consistently.
#
# The allowed decision values are described in prose in more than one place,
# and two of those descriptions had already fallen behind the code — they
# stopped at the 403 and omitted the 429 that exists. Grepping any single
# spelling therefore finds only some of them, and a partial edit stays
# invisible until somebody trusts the stale comment.
#
# This check does not police the wording; it asserts that every site which
# documents the ladder mentions the same highest value, so adding one cannot
# land in a subset of them.
# ---------------------------------------------------------------------------
DOC_FILES="pkg/loxinet/ai_gateway_dp.go loxilb-ebpf/common/sockproxy_ai_gw.h"

# The ladder is written two ways in this tree -- "deny_401" in the Go comments
# and "deny with 401" in the C header -- so normalise both to the bare status
# number before comparing. Matching only one spelling silently reduced this
# check to a single file, which is how a stale header would have slipped past.
ladder_max() { # ladder_max <file> -> highest HTTP status the file's ladder names
  { grep -ohE 'deny_[0-9]{3}' "$1" 2>/dev/null | grep -oE '[0-9]{3}'
    grep -ohE 'deny with [0-9]{3}' "$1" 2>/dev/null | grep -oE '[0-9]{3}'
  } | sort -un | tail -1
}

tree_max=""; sites=0
for f in $DOC_FILES; do
  [ -f "$f" ] || continue
  m="$(ladder_max "$f")"
  [ -n "$m" ] || continue
  sites=$((sites + 1))
  [ -n "$tree_max" ] && [ "$tree_max" -ge "$m" ] || tree_max="$m"
done

if [ "$sites" -lt 2 ]; then
  fail "expected the decision ladder in at least 2 files, found $sites - did a comment move or change wording?"
else
  bad=""
  for f in $DOC_FILES; do
    [ -f "$f" ] || continue
    m="$(ladder_max "$f")"
    [ -n "$m" ] || continue
    [ "$m" = "$tree_max" ] || bad="$bad $f(stops at $m, tree has $tree_max)"
  done
  if [ -n "$bad" ]; then
    fail "decision-value docs disagree on the highest status:$bad"
  else
    pass "decision ladder agrees across $sites files (highest: $tree_max)"
  fi
fi

echo "==========================="
if [ "$FAILED" = "0" ]; then echo "ALL INVARIANTS HOLD"; else echo "INVARIANTS VIOLATED"; fi
exit "$FAILED"
