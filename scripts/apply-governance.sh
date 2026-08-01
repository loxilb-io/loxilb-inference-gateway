#!/usr/bin/env bash
#
# apply-governance.sh — one-shot governance hardening for the
# loxilb-inference-gateway repositories (maintainer release runbook,
# repository-hardening stage).
#
# Mirrors the loxilb-io/loxilb baseline (audited 2026-08-01): PRs only into
# main with 1 approving review + required status checks (strict), no force
# pushes/deletions, native secret scanning + push protection, Dependabot
# security updates, and least-privilege default workflow permissions.
#
# Requires: gh CLI authenticated with admin on the target repos.
#
# Usage:
#   scripts/apply-governance.sh                 # dry-run: print every change
#   scripts/apply-governance.sh --apply         # apply to both repos
#   scripts/apply-governance.sh --apply --repo loxilb-io/loxilb-inference-gateway
#
# IMPORTANT sequencing (why this is not run at repo creation):
#   - Required status-check contexts must exist (at least one CI run on main)
#     or GitHub rejects/ignores them → run after the R3 shake-out.
#   - The moment protection is applied, direct pushes to main stop working
#     for everyone (enforce_admins=false mirrors upstream, so org admins keep
#     an escape hatch, but the normal path becomes PRs).
#   - Flipping default workflow permissions to read requires every workflow
#     that pushes images/releases to declare its own `permissions:` block
#     (release.yml already does; verify docker-image*.yml before applying).

set -euo pipefail

GATEWAY_REPO="loxilb-io/loxilb-inference-gateway"
EBPF_REPO="loxilb-io/loxilb-ebpf-inference-gateway"

# Required status checks per repo — must match check names as they appear on
# commits (job names). Mirror of upstream's set, adapted to this fork's CI.
GATEWAY_CHECKS='["build-check", "basic-sanity-ubuntu-22", "ai-gateway-sanity", "hygiene", "gitleaks"]'
EBPF_CHECKS='[]'   # eBPF fork is consumed via submodule pin; gateway CI is the gate

APPLY=0
ONLY_REPO=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --repo)  ONLY_REPO="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

run() {
  echo "+ $*"
  if [ "$APPLY" = "1" ]; then "$@"; fi
}

protect_main() {
  local repo="$1" checks="$2"
  echo ""
  echo "── $repo: branch protection on main ──"
  # PRs only, 1 approving review (mirrors loxilb-io/loxilb), strict status
  # checks, no force pushes, no deletions. Linear history NOT required
  # (merge commits allowed for upstream sync — RELEASE-PLAN R4).
  run gh api -X PUT "repos/$repo/branches/main/protection" \
    --input - <<EOF
{
  "required_status_checks": { "strict": true, "contexts": $checks },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": false,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 1
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": false,
  "required_conversation_resolution": true
}
EOF
}

secure_repo() {
  local repo="$1"
  echo ""
  echo "── $repo: security & analysis ──"
  # Secret scanning needs Advanced Security while the repo is private; it is
  # included for free once public. Push protection blocks pushes containing
  # detected secrets.
  run gh api -X PATCH "repos/$repo" --input - <<'EOF'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
EOF
  run gh api -X PUT "repos/$repo/automated-security-fixes"
  echo ""
  echo "── $repo: actions default permissions → contents:read ──"
  run gh api -X PUT "repos/$repo/actions/permissions/workflow" \
    -f default_workflow_permissions=read \
    -F can_approve_pull_request_reviews=false
}

audit() {
  local repo="$1"
  echo ""
  echo "── $repo: current state ──"
  gh api "repos/$repo/branches/main" --jq '"  protected: \(.protected)"'
  gh api "repos/$repo" --jq '"  private: \(.private)  secret_scanning: \(.security_and_analysis.secret_scanning.status)  push_protection: \(.security_and_analysis.secret_scanning_push_protection.status)  dependabot_fixes: \(.security_and_analysis.dependabot_security_updates.status)"'
  gh api "repos/$repo/actions/permissions/workflow" --jq '"  default_workflow_permissions: \(.default_workflow_permissions)"'
}

for repo in $GATEWAY_REPO $EBPF_REPO; do
  if [ -n "$ONLY_REPO" ] && [ "$repo" != "$ONLY_REPO" ]; then continue; fi
  audit "$repo"
  if [ "$repo" = "$GATEWAY_REPO" ]; then
    protect_main "$repo" "$GATEWAY_CHECKS"
  else
    protect_main "$repo" "$EBPF_CHECKS"
  fi
  secure_repo "$repo"
done

echo ""
if [ "$APPLY" = "1" ]; then
  echo "Applied. Verify in repo Settings → Branches / Code security. Record the"
  echo "audit output in the release issue (RELEASE-PLAN R4 exit gate)."
else
  echo "Dry run only — re-run with --apply to make the changes."
fi
