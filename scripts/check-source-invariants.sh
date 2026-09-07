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

# ---------------------------------------------------------------------------
# 3. The wire field apikey_auth is derived from the service's own policy only.
#
# Authentication used to ride on whether a service streamed: an operator could
# not enable SSE without enabling auth, nor authenticate a service that did not
# stream. Splitting the two axes is only real while they stay independent, and
# that independence is invisible to the compiler -- nothing fails to build when
# the guard quietly gains a streaming term, and the resulting service admits
# unauthenticated traffic without logging anything.
#
# The unit gate in pkg/loxinet/apikey_policy_test.go pins the VALUE the
# predicate computes. This pins the TEXT of the assignment, which is the half a
# value test cannot see: that the installer asks the predicate at all.
# ---------------------------------------------------------------------------
INSTALLER=pkg/loxinet/dpebpf_linux.go
if [ ! -f "$INSTALLER" ]; then
  fail "$INSTALLER is missing - has the eBPF rule installer moved?"
else
  # The guard spans from just above the FIRST assignment to the LAST one:
  # the derivation is now a chain (required / declared-disabled / unset), and
  # a window that stopped at the first branch would let a streaming term
  # smuggle into a later else-if unseen.
  ln="$(grep -n 'dat\.apikey_auth[[:space:]]*=' "$INSTALLER" | head -1 | cut -d: -f1)"
  lnend="$(grep -n 'dat\.apikey_auth[[:space:]]*=' "$INSTALLER" | tail -1 | cut -d: -f1)"
  if [ -z "$ln" ]; then
    fail "no assignment to dat.apikey_auth in $INSTALLER - the wire field is no longer set"
  else
    # Strip // comments before matching. The block above this assignment
    # explains in prose that the field is NOT set from the streaming modes, and
    # a check that read its own documentation as a violation would be unfixable
    # without deleting the explanation.
    guard="$(sed -n "$((ln > 5 ? ln - 5 : 1)),${lnend}p" "$INSTALLER" | sed 's|//.*||')"
    bad=""
    printf '%s' "$guard" | grep -qE 'SSEMode|sseMode' && bad="$bad sse"
    printf '%s' "$guard" | grep -qE 'PDDisagg|pdDisagg' && bad="$bad pd"
    if printf '%s' "$guard" | grep -q 'apiKeyAuthWireValue'; then
      # The derivation lives in the named predicate: apply the same rules to
      # the predicate's body — it must ask ResolveApiKeyAuth and must not
      # read the streaming modes. Scanning the body keeps this check as
      # strong as it was when the chain was inline: a streaming term cannot
      # hide behind the function name.
      pred="$(awk '/^func apiKeyAuthWireValue\(/,/^}/' pkg/loxinet/rules.go | sed 's|//.*||')"
      if [ -z "$pred" ]; then
        bad="$bad predicate-missing"
      else
        printf '%s' "$pred" | grep -qE 'SSEMode|sseMode' && bad="$bad pred-sse"
        printf '%s' "$pred" | grep -qE 'PDDisagg|pdDisagg' && bad="$bad pred-pd"
        printf '%s' "$pred" | grep -q 'ResolveApiKeyAuth' || bad="$bad pred-no-ResolveApiKeyAuth"
      fi
    else
      printf '%s' "$guard" | grep -q 'ResolveApiKeyAuth' || bad="$bad no-ResolveApiKeyAuth"
    fi
    if [ -n "$bad" ]; then
      fail "dat.apikey_auth guard reads more than the service policy ($bad):"
      printf '%s\n' "$guard" | sed 's/^/          /'
    else
      pass "wire apikey_auth is derived from the service policy alone"
    fi
  fi
fi


# ---------------------------------------------------------------------------
# 4. The API-key policy is stored and reported AS DECLARED, never resolved.
#
# The wire encodes three states — unset, required, declared-disabled — and
# keys two different behaviours on the difference between unset and
# declared-disabled: a declared service has claimed the gateway credential
# namespace and gets X-Api-Key stripped upstream, an undeclared one must
# keep byte-identical proxying for non-AI backends that consume their own.
# Resolving the default at the storage or display site erases that
# difference before the encoder can see it: every undeclared service became
# declared-disabled, and the strip armed fleet-wide. The default belongs at
# the point of DECISION (the encoder, the mode predicate), nowhere earlier.
# ---------------------------------------------------------------------------
store_line="$(grep -n 'r\.apiKeyAuth[[:space:]]*=' pkg/loxinet/rules.go | grep -v '==' || true)"
store_resolved="$(printf '%s' "$store_line" | grep -c 'ResolveApiKeyAuth' || true)"
store_count="$(printf '%s' "$store_line" | grep -c . || true)"
display_resolved="$(grep -n 'APIKeyAuth[[:space:]]*=' api/restapi/handler/loadbalancer.go | grep -c 'ResolveApiKeyAuth' || true)"
if [ "$store_count" -ge 1 ] && [ "$store_resolved" -eq 0 ] && [ "$display_resolved" -eq 0 ]; then
  pass "api-key policy stored and displayed as declared (resolution only at decision sites)"
else
  fail "api-key policy resolved before the wire (store hits=$store_count resolved-store=$store_resolved resolved-display=$display_resolved)"
  printf '%s\n' "$store_line"
fi

echo "==========================="
if [ "$FAILED" = "0" ]; then echo "ALL INVARIANTS HOLD"; else echo "INVARIANTS VIOLATED"; fi
exit "$FAILED"
