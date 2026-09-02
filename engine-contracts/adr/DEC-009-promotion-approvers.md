# DEC-009: Promotion Approvers

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

Promoting an engine identity tuple to validated status in the support catalog is a support commitment: it tells operators that strict features are safe against that exact build. An upstream release being observed by the automated watcher must never imply gateway support, so promotion needs a deliberate human decision — and no single person has both the framework-specific knowledge and the gateway-wide view.

## Decision

- Promotion of an identity tuple to `validated` in `support-catalog.yaml` must require two-stage human approval: the framework owner for the engine in question, and a gateway maintainer.
- Both approvals must be recorded on the change that edits the catalog entry; CODEOWNERS enforcement (DEC-001) must make the maintainer approval structurally unavoidable.
- The promotion change must reference the validation evidence for the exact tuple; a promotion without evidence references must be rejected in review.
- No automation, including the release watcher, may perform or pre-approve a promotion.

## Consequences

- Every validated tuple has a named framework expert and a named maintainer behind it, making support claims accountable.
- Promotions are slower than a one-click bot flow; this is accepted as the cost of a meaningful support statement.
- Framework-owner coverage must exist for each supported engine; gaps block promotions for that engine.
- Follow-up: document the framework-owner roster and the evidence checklist alongside the catalog.
