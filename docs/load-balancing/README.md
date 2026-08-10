# LoxiLB Inference Gateway — L7 / AI Load-Balancing Guide

> **Audience:** inference-gateway operators/users, QA engineers, and control-plane / data-plane
> developers.
> **Scope:** The inference-gateway capabilities — the AI-Gateway L7 proxy & HA, KV-cache-aware
> AI routing (vLLM & SGLang), MCP proxying, AI gateway controls (API keys, rate limits, model
> routing, SSE quotas), and L7 TLS.
> Classic **L4 load balancing** and the general **L7 policy engine** are inherited from
> [upstream loxilb](https://github.com/loxilb-io/loxilb) — see the
> [upstream documentation](https://loxilb-io.github.io/loxilbdocs/) for those.
> **Status:** All features documented here are **shipped and gate-verified** unless explicitly
> marked *Deferred*.

This guide is the single reference for *what the inference gateway supports*, *how to configure
it*, *how to test it*, and *how to extend it*.

---

## How to use this guide

| You are a… | Start here |
|---|---|
| **User / operator** configuring the gateway | [REST reference](05-rest-api-reference.md) → [L7 TLS](03-l7-tls.md); classic L4/L7 fundamentals: [upstream loxilb docs](https://loxilb-io.github.io/loxilbdocs/) |
| **AI / vLLM platform engineer** | [Hierarchical routing architecture](10-hierarchical-kv-routing-architecture.md) → [Configuration & tuning](11-hierarchical-kv-routing-config-tuning.md) → internals: [KV-exact deep dive](08-kv-cache-aware-routing.md), [AWS P/D deploy & debug](09-kv-cache-aware-routing-aws-pd-deep-dive.md), [AI-Gateway L7 proxy & HA](04-ai-gateway-l7.md); SGLang: [architecture](15-sglang-kv-cache-aware-routing.md) → [vs vLLM](16-sglang-vs-vllm-routing-differences.md) → [config & tuning](17-sglang-config-tuning.md) |
| **API platform operator** exposing OpenAI-compatible or MCP endpoints | [AI gateway controls](19-ai-gateway-controls.md) (API keys, rate limits, model routing, SSE quotas) → [MCP gateway](18-mcp-gateway.md) |
| **QA engineer** validating a feature | Each feature doc has a **CICD validation** section; consolidated runbook in [Troubleshooting](06-troubleshooting.md) and [Developer guide §CICD](07-developer-guide.md) |
| **Developer** adding/fixing a feature | [Developer guide](07-developer-guide.md) (code map, extension recipes, build gates) |
| Hitting a problem in the field | [Troubleshooting](06-troubleshooting.md) |

---

## Document set

| File | Covers |
|---|---|
| [`03-l7-tls.md`](03-l7-tls.md) | ALPN, TLS version/cipher pinning, HSTS, mTLS (client-cert + CRL + SAN/CN matching), `tls-hello` health probe, per-probe CA/verify, certId certificate management, backend re-encryption, VIP QoS |
| [`04-ai-gateway-l7.md`](04-ai-gateway-l7.md) | vLLM fullproxy L7, Prefill/Decode (P/D) disaggregation routing, CHWBL / cache-aware routing, circuit breaker, conversation stickiness, sockproxy HA state sync (xSync) |
| [`05-rest-api-reference.md`](05-rest-api-reference.md) | Consolidated REST endpoint + field reference: LB rules, AI gateway fields, TLS certificates |
| [`06-troubleshooting.md`](06-troubleshooting.md) | Symptom → cause → fix across L7/TLS/AI + CICD harness gotchas |
| [`07-developer-guide.md`](07-developer-guide.md) | Code map (Go control plane + C sockproxy data plane), extension recipes, build & test workflow |
| [`08-kv-cache-aware-routing.md`](08-kv-cache-aware-routing.md) | Engine-exact KV-cache-aware routing deep dive: architecture, end-to-end call flow, vLLM block-hash contract, guard ladder, metrics/log tracing, test & gate matrix, limitation analysis + enhancement roadmap |
| [`09-kv-cache-aware-routing-aws-pd-deep-dive.md`](09-kv-cache-aware-routing-aws-pd-deep-dive.md) | **Practical AWS deploy & debug** for P/D-disaggregated KV-aware routing: when it engages (P/D-only), 2P+1D topology, vLLM NIXL `kv_producer`/`kv_consumer` flags, loxilb container + LB rules, parity triad, request sequence diagram, the metrics that actually exist, and a failure-mode debugging playbook |
| [`10-hierarchical-kv-routing-architecture.md`](10-hierarchical-kv-routing-architecture.md) | **Hierarchical routing architecture & concepts**: the full P/D tier ladder (admission gate, Tier 0 stickiness, Tier 1 trie, Tier 1.5 KV-exact + unified CHWBL blend, Tier 2 min-load, decode selection), the single-pool prefix-hash CHWBL path, and the control loop (adaptive ε/λ, AI controller, Expected-TTFT) with formulas and code map |
| [`11-hierarchical-kv-routing-config-tuning.md`](11-hierarchical-kv-routing-config-tuning.md) | **Configuration & tuning**: complete REST field / env-var / controller-flag reference, per-layer enablement matrix, sweep-grounded tuning playbook (blend modes, ε/λ, admission, warmup), observability & silent-degradation alerts |
| [`14-kv-cache-observability-design.md`](14-kv-cache-observability-design.md) | **KV-cache observability design**: Prometheus metric export, Grafana dashboard, alert rules |
| [`15-sglang-kv-cache-aware-routing.md`](15-sglang-kv-cache-aware-routing.md) | **SGLang integration architecture deep dive**: single-role KV-exact routing (`kvExactMode=3`), the three gates, SGLang SHA-256 block-hash contract + parity vectors, KvEventSource multi-DP-rank fan-out, staleness fix, cross-VIP `kv_svc_id` isolation, zero-hit watchdog |
| [`16-sglang-vs-vllm-routing-differences.md`](16-sglang-vs-vllm-routing-differences.md) | **SGLang vs vLLM differences & optimization**: side-by-side hash contracts (CBOR/xxhash64 vs SHA-256 first-8-BE), P/D vs single-role topology, parity triads, event-stream/port planning, router ecosystem comparison, SGLang optimization guidance |
| [`17-sglang-config-tuning.md`](17-sglang-config-tuning.md) | **SGLang configuration, tuning & troubleshooting**: REST fields (`kvEngineType`, `kvDpRankCount`), validation guard table, env vars (`LOXILB_KV_ZERO_HIT_N`), SGLang server flags (`--kv-events-config`, `--page-size` parity), worked single-role + two-VIP coexistence examples, troubleshooting playbook, CICD scenario guide |
| [`18-mcp-gateway.md`](18-mcp-gateway.md) | **MCP gateway user guide**: load-balancing Model Context Protocol servers — session stickiness (`session_header_name: mcp-session-id`), the three deployment shapes (HTTP / TLS-terminating / end-to-end HTTPS), MCP trace tagging, troubleshooting |
| [`19-ai-gateway-controls.md`](19-ai-gateway-controls.md) | **AI gateway controls user guide**: API-key lifecycle & `X-Api-Key` enforcement (401/403/429), per-tenant rate limits, model-name routing (`model_name`/`path_prefix`), SSE stream quotas (`sse_mode`, `max_stream_duration_sec`) |

---

## Feature matrix (at a glance)

### L7 TLS

| Feature | Status |
|---|---|
| ALPN negotiation (h2 / http1.1 / both) | ✅ |
| TLS version range + cipher pinning (TLS 1.2 + 1.3, both legs) | ✅ |
| HSTS header injection (RFC 6797, H1 + H2) | ✅ |
| `tls-hello` handshake-only health probe | ✅ |
| mTLS client-cert CRL revocation (leaf) + SAN-DNS/CN matching | ✅ |
| Per-probe CA override + verify toggle | ✅ |
| certId certificate management (upload / rotate / delete) | ✅ |
| Backend re-encryption by certId (CA + client cert) | ✅ |
| `vip_qos_policy_id` QoS association | ✅ |

### AI-Gateway L7

| Feature | Status |
|---|---|
| vLLM fullproxy L7 (failover / error pass-through / concurrency / resilience) | ✅ |
| Mid-request / connect failover (retry across healthy EPs → `502 backend_unreachable`; pool down → `503 no_healthy_backend`; prefill death retried transparently; decode death → `502 pd_decode_backend_died`) | ✅ |
| Prefill/Decode (P/D) disaggregation routing + body rewriting | ✅ |
| Conversation stickiness (Tier 0) | ✅ |
| Cache-aware trie routing (Tier 1, CHWBL) | ✅ |
| Circuit breaker (per-endpoint) | ✅ |
| Sockproxy HA state sync — P/D sessions + rate limiter (xSync gRPC) | ✅ |
| Failover warmup (KV inventory + vLLM metrics snapshot) | ⏸ Deferred |
| Engine-exact KV routing from ZMQ KV-cache events (vLLM, P/D) | ✅ Live-validated on a real GPU fleet (NIXL P/D); see [doc 09](09-kv-cache-aware-routing-aws-pd-deep-dive.md) |
| Engine-exact KV routing, single pool (SGLang, `kvExactMode=3`) | ✅ See [doc 15](15-sglang-kv-cache-aware-routing.md) |
| MCP proxying with session stickiness | ✅ See [doc 18](18-mcp-gateway.md) |
| API keys / tenant rate limits / model routing / SSE quotas | ✅ See [doc 19](19-ai-gateway-controls.md) |

---

## Key conventions you must know

These apply across every feature below — read them once.

1. **API base path.** All REST examples use `http://<host>:11111/netlox/v1/...`. In CICD, auth is
   disabled; in production, LoxiLB's auth middleware applies (token / OAuth2 — see project auth docs).

2. **Fullproxy mode (`mode=4`) is required for L7.** L4 features work in all modes. *Every*
   L7 feature (TLS termination, AI proxy, MCP, gateway controls) runs in the **userspace
   sockproxy**, which only engages when the rule is `mode=4` (fullproxy).

3. **L7 gating is byte-for-byte safe.** Each L7 data-plane seam is gated so that rules which
   don't use it run the legacy path *unchanged* — plain L4 rules behave exactly like upstream
   loxilb. Preserve this guarantee when extending.

4. **Additive / optional fields.** All the advanced data-model fields are additive and
   default-off: omitting them preserves prior behavior. Pointer types (`*bool`) distinguish "absent"
   (default) from an explicit `false`.

5. **VIP must be local for fullproxy.** The sockproxy binds the VIP; a non-local VIP makes every L7
   attach silently report zero entries. CICD scenarios use the loxilb node's own address as the VIP.

6. **In-memory vs persisted.** `/stats` counters and circuit-breaker state are
   in-memory and reset on restart. Rule config (ids, members, TLS fields) is persisted —
   the primary artifact is `snapshot.json` under the gateway's config path (written by
   `POST /config/persist` and auto-persist); the legacy `lbconfig.txt` is still honored, with
   newest-wins arbitration between the two on boot. While the boot snapshot replay is settling
   after a restart, **all mutating REST calls return `503` with `Retry-After: 5`** — this is
   expected; retry through it rather than treating it as an outage.

7. **C/eBPF changes need a real Linux testbed.** macOS cannot build Go+eBPF+CGO. Build and run the
   scenarios under [`cicd/`](../../cicd/) on a real Linux host — each scenario brings up loxilb plus
   its backends in containers (`config.sh` → `validation.sh` → `rmconfig.sh`).
