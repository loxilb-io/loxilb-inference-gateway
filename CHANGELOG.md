# Changelog

All notable changes to loxilb-inference-gateway are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Because this is a fork of [loxilb](https://github.com/loxilb-io/loxilb), releases
follow upstream's version scheme — `vMAJOR.MINOR.PATCH` with an optional fourth
build component (e.g. `v0.9.8.7`), plus `-rc.N` for a release candidate — so the
upstream baseline is readable at a glance. The reported version is derived from
the release tag at build time, never pinned in source. Changes inherited from an
upstream loxilb sync are summarized here by their upstream version; only the
inference-gateway delta is enumerated in detail. See
[docs/UPSTREAM-SYNC.md](docs/UPSTREAM-SYNC.md) for the sync and tagging model.

## [Unreleased]

First inference-gateway release, forked from upstream loxilb `0.9.8.6-beta`.
Every AI capability is opt-in per load-balancer rule; with none enabled the
binary behaves exactly like upstream loxilb.

### Added

- **KV-cache-aware routing** for LLM serving fleets: cache-locality-aware
  endpoint selection driven by the serving engines' native contracts
  (vLLM `--kv-events-config` ZMQ events; SGLang radix-cache semantics).
- **Prefill/decode (P·D) disaggregation** routing, including KV-exact mode over
  a prefill/decode topology (`kvExactMode:1` + endpoint role, as shipped for
  vLLM) and single-role KV-exact over a role-less pool (`kvExactMode:3`, as
  shipped for SGLang). `kvExactMode` selects the topology; the serving engine
  and its block-hash contract are selected independently by `kvEngineType`.
- **Consistent-hash cache routing** (CHWBL) for aggregated vLLM pools.
- **MCP gateway** support: session-sticky routing for Model Context Protocol
  server pools.
- **AI gateway controls**: per-rule API-key auth and rate limiting, armed via
  `sse_mode` on L7 fullproxy rules.
- **AI control plane**: `loxilb-ai-controller` (TTFT-adaptive controller) and
  `loxilb-kv-agent` (DOCA) components, plus AI metrics export.
- **eBPF data-path extensions** for inference routing, tracked in the
  `loxilb-ebpf-inference-gateway` fork and pinned via the `loxilb-ebpf`
  submodule.
- **REST API / swagger** extensions for all AI fields (`api/swagger-extras.yml`
  and generated models).
- **Documentation** under `docs/load-balancing/` covering AI gateway L7, REST
  API reference, KV-cache-aware routing (incl. hierarchical and P·D deep dives),
  MCP gateway, and AI gateway controls.
- **CI**: `ai-gateway-sanity`, `mcp-sanity`, `l7-proxy-sanity`, and
  `vllm-proxy-sanity` workflows, plus the automated upstream-sync chain
  (`upstream-sync.yml`, `ebpf-pin-bump.yml`).
- **Token quotas (tokens-per-minute)** for AI gateway rules: per-tenant and
  per-tenant-and-model budgets enforced from the tokens the serving engine
  reports. Usage is read from the engine's own `usage` block, with
  `stream_options.include_usage` injected on streaming requests so a client
  cannot opt out of accounting. Requests are checked **before** dispatch —
  the prompt plus any declared completion ceiling is reserved up front and
  reconciled at completion — so an over-budget request is refused with `429`
  instead of being detected after the GPU has already been spent. Quota is a
  smooth token bucket, so a tenant recovers continuously rather than at a
  fixed window boundary, and idle per-tenant state is evicted. Configured via
  `tokens_per_min` on the tenant rate-limit API and optional `model_limits`
  for per-model budgets.
- **Traffic policing and shaping**, layered:
  - **Load-balancer-rule policers** (eBPF) — a bandwidth budget attached to a
    rule rather than a port, applied to both directions of the session.
  - **Egress-direction port policers** behind `--egr-hooks`, for
    host-originated egress.
  - **An L7 byte shaper** for full-proxy AI rules, which *paces* payload bytes
    to the configured rate in either direction instead of dropping them.
    Shaper-paused time is excluded from idle and stream-duration reaping, so
    pacing a long response or an SSE stream cannot manufacture a disconnect.
- **Observability for both of the above**: Prometheus series for token
  consumption (split by how the count was obtained), quota utilization and
  limits, quota denials, and per-service shaper counters — bytes passed and
  delayed, pause count and duration, currently-paused connections, and the
  configured rate and burst. The bundled AI dashboard gains a token-quota row
  and a byte-shaper row. `GET /metrics` is exempt from management-plane bearer
  auth so a scraper needs no credential.

### Changed

- Container image renamed to `ghcr.io/loxilb-io/loxilb-inference-gateway`.
- README rewritten around inference-gateway use cases; `loxilb-ebpf` submodule
  repointed to the `loxilb-ebpf-inference-gateway` fork.

### Notes

- This release preserves full upstream loxilb functionality; classic L4/L7
  load balancing is unchanged and documented upstream.

### Upgrade notes

- **Token-quota state does not interoperate across this change in an HA pair.**
  Quota is synchronized between peers over an unchanged wire format, and this
  release reuses one of its existing integer fields to carry a bucket
  drain-time timestamp instead of a consumed-token count. The two are merged
  by taking the larger value, which makes the incompatibility **one-way**:

  - **New peer → old peer is harmful.** The old build reads a millisecond
    timestamp as a token count, concludes the tenant is enormously over
    budget, and denies its traffic with `429` until the entry ages out.
  - **Old peer → new peer is harmless.** A token count interpreted as a
    timestamp lands far in the past, so it loses the merge to the new peer's
    own value and cannot deny anyone.

  So a **rolling upgrade of an HA pair is not supported while token quotas are
  enabled.** Prefer upgrading both peers together.

  If the peers must be upgraded one at a time, set `tokens_per_min` to `0`
  **before** upgrading the first one. Quota entries are only created when a
  limit is configured, so a peer that restarts into the new build with quotas
  disabled never creates quota state and therefore never sends any. Ordering
  matters: disabling quotas does not retract entries that already exist — the
  upgraded peer starts with an empty map, but a peer left running keeps its
  entries until they idle out (about 10 minutes by default, `LLB_AI_QUOTA_EVICT_WINDOWS`).
  Re-enable quotas once both peers run the same build.

  Request-rate limits, API-key authorization and model authorization are
  unaffected and may stay enabled throughout. This applies only to peers
  exchanging quota state — a standalone gateway upgrades normally.

<!--
Template for future releases:

## [vX.Y.Z.W] - YYYY-MM-DD
### Added
### Changed
### Fixed
### Upstream
- Synced loxilb <upstream-version> / loxilb-ebpf <pin>.
-->
