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

# Required status checks per repo — must match check-run context names EXACTLY
# as they appear on a real PR head (verified against PR #26, 2026-08-04). These
# five mirror upstream loxilb-io/loxilb's required set one-for-one and all run on
# EVERY pull_request to main with no path filters, so they can never hang a
# docs-/monitoring-only PR.
#
# Deliberately NOT required:
#   - ai-gateway-sanity : path-filtered (cicd/vllm-**, pkg/**, api/**, ...), so it
#     is skipped on non-code PRs. Requiring it would block those PRs forever.
#     Promote it to a required check only behind a path-filter-safe shim job that
#     always reports (GitHub "skipped == success" pattern).
#   - hygiene gate / full-history secret scan / CodeQL / govulncheck : useful
#     signal but either flaky, advisory, or (CodeQL) gated on GHAS while private.
GATEWAY_CHECKS='["basic-sanity", "build-check-ci", "sctp-lb-sanity", "tcp-lb-sanity", "udp-lb-sanity"]'
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
  # Secret scanning + push protection need GitHub Advanced Security while the
  # repo is private (paid) — the PATCH errors without a GHAS license. They are
  # included for free once the repo is public, so only attempt them then. Run
  # this stage again at the public-flip step.
  local vis
  vis="$(gh api "repos/$repo" --jq '.visibility' 2>/dev/null || echo unknown)"
  if [ "$vis" = "public" ]; then
    run gh api -X PATCH "repos/$repo" --input - <<'EOF'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
EOF
  else
    echo "  (skip secret-scanning: repo is '$vis' — needs GHAS while private; re-run at public flip)"
  fi
  # Dependabot security fixes are free on private repos and safe to enable now.
  # Vulnerability alerts are a hard prerequisite (else automated-security-fixes
  # returns HTTP 422), so enable them first.
  run gh api -X PUT "repos/$repo/vulnerability-alerts"
  run gh api -X PUT "repos/$repo/automated-security-fixes"
  echo ""
  echo "── $repo: actions default workflow permissions ──"
  # Upstream loxilb-io/loxilb keeps this at 'write'; we match that (NOT read).
  # Downgrading to read is a valid future hardening, but only AFTER every
  # image/release workflow that needs write declares its own permissions: block.
  # As of 2026-08-04 these still lack one: docker-image.yml, docker-image-u24.yml,
  # docker-multiarch.yml, release.yml — flipping to read now would break publishing.
  echo "  (leaving default_workflow_permissions=write to match upstream; see note)"
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
