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

### Changed

- Container image renamed to `ghcr.io/loxilb-io/loxilb-inference-gateway`.
- README rewritten around inference-gateway use cases; `loxilb-ebpf` submodule
  repointed to the `loxilb-ebpf-inference-gateway` fork.

### Notes

- This release preserves full upstream loxilb functionality; classic L4/L7
  load balancing is unchanged and documented upstream.

<!--
Template for future releases:

## [vX.Y.Z.W] - YYYY-MM-DD
### Added
### Changed
### Fixed
### Upstream
- Synced loxilb <upstream-version> / loxilb-ebpf <pin>.
-->
