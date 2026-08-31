# DEC-006: Batch Error Policy

- Status: Accepted (2026-08-31)
- Deciders: Gateway maintainers

## Context

Engine KV events arrive in batches, and today's decoder silently skips any event it cannot parse, logging only at debug level. Under a wire-format mismatch this produces a healthy-looking pipeline feeding a permanently stale inventory — the most dangerous failure mode, because nothing alarms. A partial batch applied to inventory can also leave it internally inconsistent even when individual events parse.

## Decision

- If any event in a decoded batch is invalid, the entire batch must be rejected and the inventory must be left unchanged: decode and apply are atomic per batch.
- Batch rejection must be counted and surfaced through metrics and rule status; it must never be a debug-level-only event.
- This is a deliberate change from today's skip-and-continue behavior. Strict profiles must adopt atomic reject-on-error first.
- Legacy profiles must keep skip-and-continue semantics until the migration epic flips defaults; the effective policy per rule must be observable.

## Consequences

- Wire-format mismatches become loud and immediate instead of silently degrading routing quality over time.
- A single malformed event now costs a whole batch; engines emitting occasional garbage will show elevated rejection counters that operators must triage.
- Two policies coexist during the transition, so tests must cover both.
- Follow-up: the migration epic defines when legacy profiles flip to atomic semantics and what telemetry gates that flip (see DEC-010 for the gate pattern).
