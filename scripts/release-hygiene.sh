#!/usr/bin/env bash
#
# release-hygiene.sh — repeatable hygiene gate for the public repository.
#
# Fails non-zero on any finding. Run locally before pushing and in CI on
# every PR. Checks the *committed* tree (HEAD) and the commit range being
# published, not the working tree.
#
# Usage:
#   scripts/release-hygiene.sh [--base <ref>] [--skip-gitleaks]
#
#   --base <ref>      history range to audit is <ref>..HEAD
#                     (default: upstream merge-base, i.e. commits unique to
#                     this repository; falls back to full history)
#   --skip-gitleaks   skip the gitleaks secret scan (e.g. when the binary
#                     is unavailable in a restricted CI job)
set -u

BASE=""
SKIP_GITLEAKS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --base) BASE="$2"; shift 2 ;;
    --skip-gitleaks) SKIP_GITLEAKS=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

FAIL=0
fail() { FAIL=1; printf 'FAIL: %s\n' "$1"; }
pass() { printf 'ok:   %s\n' "$1"; }

# Resolve the history range to audit.
if [ -z "$BASE" ]; then
  for cand in upstream/main origin/main; do
    if git rev-parse -q --verify "$cand" >/dev/null 2>&1; then
      BASE=$(git merge-base "$cand" HEAD 2>/dev/null) && break
    fi
  done
fi
RANGE=${BASE:+$BASE..}HEAD

# 1. AI attribution / internal process jargon in commit messages ---------------
if git log --format='%an %ae %B' "$RANGE" 2>/dev/null \
     | grep -qiE 'claude|anthropic|copilot|openai codex|co-authored-by:.*(bot|ai)'; then
  fail "AI attribution found in commit messages ($RANGE)"
else
  pass "commit messages clean ($RANGE)"
fi

# 2. AI tooling artifacts tracked ---------------------------------------------
if git ls-files | grep -qE '(^|/)(CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.mcp\.json)$|(^|/)(\.claude|claudedocs|\.planning|\.serena|claude-agents)/'; then
  fail "AI tooling artifacts are tracked"
else
  pass "no AI tooling artifacts tracked"
fi

# 3. Internal hosts / infrastructure identifiers ------------------------------
# (.gitignore and this script are allowlisted: they name the patterns
# themselves. The instance-id regex requires a non-word char before "i-" so
# public AMI ids such as ami-0cca... do not match.)
HOSTS_RE='kv-loxilb|elice-loxilb|loxilb-enterprise|(^|[^a-z])i-0[0-9a-f]{8,}'
if git grep -Iqn -E "$HOSTS_RE" HEAD -- \
     ':(exclude).gitignore' ':(exclude)scripts/release-hygiene.sh' 2>/dev/null; then
  fail "internal host/infrastructure identifiers in tracked files:"
  git grep -In -E "$HOSTS_RE" HEAD -- \
     ':(exclude).gitignore' ':(exclude)scripts/release-hygiene.sh' | head -20
else
  pass "no internal host identifiers"
fi

# 4. Personal identifiers (home directories, personal paths) ------------------
if git grep -Iqn -E '/Users/[a-z]+|/home/(kong|gongseoghwan)' HEAD 2>/dev/null; then
  fail "personal paths in tracked files:"
  git grep -In -E '/Users/[a-z]+|/home/(kong|gongseoghwan)' HEAD | head -20
else
  pass "no personal paths"
fi

# 5. Links into docs/internal/ from tracked files -----------------------------
if git grep -Iqn 'docs/internal/' HEAD -- \
     ':(exclude).gitignore' ':(exclude)scripts/release-hygiene.sh' 2>/dev/null; then
  fail "tracked files link into docs/internal/:"
  git grep -In 'docs/internal/' HEAD -- \
     ':(exclude).gitignore' ':(exclude)scripts/release-hygiene.sh' | head -20
else
  pass "no docs/internal references"
fi

# 6. Private key material (belt-and-braces on top of gitleaks) ----------------
if git grep -Iqn -E 'BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY' HEAD 2>/dev/null; then
  fail "private key material in tracked files:"
  git grep -In -E 'BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY' HEAD | head -10
else
  pass "no private key material"
fi

# 7. Secrets — gitleaks over the published history ----------------------------
if [ "$SKIP_GITLEAKS" = 1 ]; then
  echo "skip: gitleaks (--skip-gitleaks)"
elif command -v gitleaks >/dev/null 2>&1; then
  if [ -n "$BASE" ]; then LOGOPTS="$BASE..HEAD"; else LOGOPTS="--all"; fi
  if gitleaks detect --source . --log-opts="$LOGOPTS" --no-banner --redact -v >/dev/null 2>&1; then
    pass "gitleaks clean ($LOGOPTS)"
  else
    fail "gitleaks found candidate secrets — run: gitleaks detect --source . --log-opts=\"$LOGOPTS\" --redact -v"
  fi
else
  fail "gitleaks not installed (use --skip-gitleaks to bypass locally)"
fi

exit $FAIL
