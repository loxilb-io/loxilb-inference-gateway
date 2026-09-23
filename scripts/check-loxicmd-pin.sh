#!/usr/bin/env bash
#
# check-loxicmd-pin.sh — the embedded CLI is one revision, on main, everywhere.
#
# Every image Dockerfile installs loxicmd-inference-gateway at the commit in
# ARG LOXICMD_TAG. Each Dockerfile already refuses a value that is not a full
# 40-hex SHA resolving to itself, so a branch or tag name cannot slip in. Two
# things no single Dockerfile can check are covered here:
#
#   1. the pins agree with each other — the release workflow attests the
#      embedded CLI by reading ARG LOXICMD_TAG out of one Dockerfile, so a
#      bump that misses a variant ships a CLI the attestation does not
#      describe;
#   2. the pinned commit is reachable from the CLI repository's main — an
#      image must never embed a revision that only lived on a topic branch or
#      was rebased away, because nobody could rebuild it from the published
#      history.
#
# Usage:
#   scripts/check-loxicmd-pin.sh [--repo <url-or-path>] [--branch <name>] [--offline]
#
#   --repo <url-or-path>  CLI repository to check reachability against
#                         (default: the one the Dockerfiles clone)
#   --branch <name>       branch the pin must be reachable from (default: main)
#   --offline             skip the reachability check; agreement and format only
#
# Exit: 0 = the pin is sound, 1 = a finding, 2 = usage.
set -u

REPO=https://github.com/loxilb-io/loxicmd-inference-gateway.git
BRANCH=main
OFFLINE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --offline) OFFLINE=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.." || exit 2

FAIL=0
fail() { FAIL=1; printf 'FAIL: %s\n' "$1"; }
pass() { printf 'ok:   %s\n' "$1"; }

# Every Dockerfile that installs the CLI must carry the pin: a variant that
# clones the repository without one builds whatever main happens to be.
FILES=$(grep -l 'loxicmd-inference-gateway' Dockerfile* 2>/dev/null | sort)
if [ -z "$FILES" ]; then
  fail "no Dockerfile installs loxicmd-inference-gateway"
  exit 1
fi

PIN=""
COUNT=0
for f in $FILES; do
  v=$(sed -n 's/^ARG LOXICMD_TAG=\(.*\)$/\1/p' "$f")
  if [ -z "$v" ]; then
    fail "$f installs the CLI but declares no ARG LOXICMD_TAG"
    continue
  fi
  if ! printf '%s' "$v" | grep -Eq '^[0-9a-f]{40}$'; then
    fail "$f pins LOXICMD_TAG to '$v', not a full 40-hex commit SHA"
    continue
  fi
  if [ -z "$PIN" ]; then
    PIN=$v
  elif [ "$v" != "$PIN" ]; then
    fail "$f pins LOXICMD_TAG to $v, the other Dockerfiles to $PIN"
    continue
  fi
  COUNT=$((COUNT + 1))
done
[ "$FAIL" = 0 ] && pass "LOXICMD_TAG is $PIN in all $COUNT Dockerfiles"

if [ -z "$PIN" ] || [ "$FAIL" != 0 ]; then
  exit 1
fi

if [ "$OFFLINE" = 1 ]; then
  echo "skip: reachability from $BRANCH (--offline)"
  exit 0
fi

# A bare, single-branch clone carries the whole history of the branch and
# nothing else, which is exactly what an ancestry test needs. Blobs are left
# out where the transport supports it; only commits matter here.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
CLONE_OPTS="--quiet --bare --single-branch --branch $BRANCH"
case "$REPO" in
  https://*|http://*|ssh://*|git@*) CLONE_OPTS="$CLONE_OPTS --filter=blob:none" ;;
esac
if ! git clone $CLONE_OPTS "$REPO" "$TMP/cli" 2>"$TMP/err"; then
  fail "cannot fetch $BRANCH of $REPO: $(head -1 "$TMP/err")"
elif git -C "$TMP/cli" merge-base --is-ancestor "$PIN" "$BRANCH" 2>/dev/null; then
  pass "pin $PIN is reachable from $BRANCH of $REPO"
else
  fail "pin $PIN is not reachable from $BRANCH of $REPO (a topic-branch or rebased-away commit cannot be attested)"
fi

exit $FAIL
