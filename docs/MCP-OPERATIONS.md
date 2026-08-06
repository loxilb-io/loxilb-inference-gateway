# loxilb-mcp operations guide

`loxilb-mcp` is the standalone MCP (Model Context Protocol) bridge for
loxilb-inference-gateway. It lets MCP clients (Claude Code, MCP Inspector,
custom agents) observe, manage, and diagnose loxilb instances through guarded
tools instead of raw REST.

- Install: `brew install --cask loxilb-io/tap/loxilb-mcp` (macOS), the
  `ghcr.io/loxilb-io/loxilb-mcp` container image, `go install`, or a tarball from
  the `mcp/vX.Y.Z` releases — per-OS steps and MCP-client wiring in
  [`../mcp/README.md`](../mcp/README.md). From source: `cd mcp && go build ./cmd/loxilb-mcp`
  (it is a standalone Go module, released independently of the datapath).
- Talks to loxilb REST (`:11111 /netlox/v1`), optionally Prometheus and
  Alertmanager
- No loxilb code changes; purely additive

## Quick start

```sh
# Local dev: stdio transport, single target, admin role
loxilb-mcp --target-url http://127.0.0.1:11111

# Claude Code
claude mcp add loxilb -- /path/to/loxilb-mcp --target-url http://127.0.0.1:11111

# Production shape: config file + streamable HTTP on loopback (SSH tunnel in)
loxilb-mcp --config /etc/loxilb-mcp.yaml --transport http --listen 127.0.0.1:8891
```

## Configuration file

```yaml
default_target: llb1
targets:
  llb1:
    url: http://172.17.0.2:11111
    # username/password_env or token_env when loxilb runs --userservice (F11)
    # tls_ca / insecure_skip_verify / timeout_sec as needed
clients:                       # HTTP-mode bearer tokens, one per client
  - { name: dashboard, role: viewer,   token_env: MCP_VIEWER_TOKEN }
  - { name: oncall,    role: operator, token_env: MCP_OPERATOR_TOKEN }
  - { name: sre,       role: admin,    token_env: MCP_ADMIN_TOKEN }
audit_dir: /var/lib/loxilb-mcp          # JSONL audit log (0600)
secrets_dir: /var/lib/loxilb-mcp/secrets # ai_apikey_create key files (0600)
prometheus_url: http://127.0.0.1:9090    # enables promql_query/promql_range
alertmanager_url: ""                     # enables alerts_active when set
alert_rules_path: deploy/monitoring/prometheus/rules/loxilb-alerts.yml
openapi_spec_path: api/swagger.yml       # served as loxilb://spec/openapi
autopilot_tools: []                      # exact names of destructive tools allowed to skip confirm (§ Autopilot)
```

Tokens must be ≥16 bytes (32 random bytes recommended). Target names are the
only accepted `target` values in tool calls — URLs are rejected (anti-SSRF).

## Roles and tool tiers

| Role | May call | Tool count (base) |
|---|---|---|
| viewer | read-only tools only | 51 |
| operator | + non-destructive mutations | 74 |
| admin | + destructive tools (confirm-token gated) | 78 (79 with `--allow-import`) |

"Base" is with all four domains on and no external monitoring backends
configured. A configured `prometheus_url` (`promql_query`, `promql_range`),
`alertmanager_url` (`alerts_active`), and `alert_rules_path` (`alerts_catalog`)
each register additional read-only tools that are visible to every role — up to
four more, so a fully-wired admin sees 82 (83 with `--allow-import`). `--read-only`,
`--enable-domains`, and `--allow-tools`/`--deny-tools` reduce the set further.

Stdio sessions take the role from `--role` (default admin — stdio inherits
the local user's authority). HTTP sessions take it from the bearer token.
`tools/list` reflects exactly what the caller may do — treat it, not this
table, as authoritative for a given configuration.

Additional gates, all composable: `--read-only`, `--allow-tools` /
`--deny-tools` globs (deny wins), `--enable-domains mgmt,analysis,monitoring,ai`.

## Destructive changes: the confirm-token flow

Destructive tools (`lb_delete`, `fw_delete`, `net_route_delete`,
`ai_apikey_delete`, `config_import`) are two-step:

1. Call without `confirm_token` → nothing changes; the result is
   `action:"preview"` with the affected object(s) and a `confirm_token`.
2. Repeat the call with **identical arguments** plus the token within 120 s.

Tokens are single-use and SHA-256-bound to (tool, target, arguments); any
argument change or replay burns them. `--no-confirm` (CI only) skips the
flow. `config_import` additionally requires `--allow-import`.

### Autopilot (Phase 4, default off)

`--autopilot-tools lb_delete,...` (or `autopilot_tools:` in the config) names
destructive tools that execute **without** the preview→confirm step. Names are exact; globs are
rejected. Role tiers still apply (destructive tools remain admin-only), the
bypass writes an `autopilot_exec` audit event, and startup logs a warning
listing the tools. `diagnose_*` suggested actions carry `autopilot:
true|false` so an agent knows which follow-ups it may run directly. Leave
empty until the team trusts the audit trail for the specific action.

## Secrets handling

`ai_apikey_create` never returns raw key material by default: the key is
written to `secrets_dir` as `apikey-<key_id>.key` (file 0600, dir 0700) and
only the path is returned. `reveal:true` returns it inline instead — the key
then enters model/client context; use only when the caller is the end user.
`config_export` masks secret-shaped fields. Audit lines redact secret-shaped
arguments.

## Tool catalog (Phase 0–4)

**Seed / health** — `version_get`, `health_overview`, `lb_list`, `ct_list`,
`metrics_snapshot`.

**Fleet (read, Phase 4)** — `targets_list` (configured targets + default),
`fleet_overview` (concurrent health probe of every target; unreachable
targets degrade into per-target error sections).

**Analysis (read)** — `meta_get`, `cluster_state_get`, `trace_status_get`,
`l4trace_status_get`, `trace_catalog_list`, `nodegraph_get` (backend 501 in
this fork), `status_get`, `logs_tail`, `log_archives_list`, `log_archive_get`,
`ipsec_status_get`.

**Monitoring (read)** — `metrics_config_get`, `metrics_legacy_get`,
`promql_query` / `promql_range` (needs `prometheus_url`), `alerts_active`
(needs `alertmanager_url`), `alerts_catalog` (needs `alert_rules_path`).

**Management** — read: `endpoint_list`, `fw_list`, `ipfilter_list`,
`secrate_get`, `net_route_list`, `net_vlan_list`, `net_vxlan_list`,
`net_neighbor_list`, `net_ip_list`, `net_port_list`, `bgp_neigh_list`,
`bgp_policy_list`, `session_list`, `session_ulcl_list`, `config_params_get`,
`config_export`. Operator+: `lb_create`, `endpoint_host_state_set`,
`fw_create`, `ipfilter_set`, `secrate_set`, `secrate_reset`,
`net_route_create`, `bgp_neigh_set`, `bgp_global_set`, `bgp_policy_apply`,
`config_params_set`. Admin+confirm: `lb_delete`, `fw_delete`,
`net_route_delete`, `config_import`.

**AI-gateway ops** — read: `ai_apikey_list`, `ai_apikey_get`,
`ai_ratelimit_get`, `ai_kv_inventory_get`, `gpu_status`,
`gpu_worker_metrics_get`, `llamafw_status`, `llamafw_stats`, `pii_status`,
`pii_stats`, `ai_traffic_report`. Operator+: `ai_apikey_create`,
`ai_apikey_update`, `ai_ratelimit_set` (no delete endpoint — set quotas 0 to
lift), `gpu_mode_set`, `gpu_conversations_cleanup`, `llamafw_enable_set`,
`llamafw_configure`, `llamafw_scanners_set`, `llamafw_health_check`,
`pii_enable_set`, `pii_configure`, `pii_url_patterns_set`. Admin+confirm:
`ai_apikey_delete`.

> **Prerequisite:** the API-key and tenant-rate-limit REST endpoints are only
> wired when the target loxilb runs with `--userservice` (plus a reachable
> `--databasehost`). On a non-userservice target these tools return the
> target's HTTP 501 verbatim. Note the interaction with finding F11: with
> `--userservice` enabled, `/netlox/v1/metrics` requires a JWT, so a
> Prometheus scraping that target needs a bearer-token scrape config.

**Diagnostics / RCA (read)** — `diagnose_l4_errors`, `diagnose_ai_latency`,
`diagnose_endpoint`, `capacity_report`. Each returns a correlated evidence
bundle (sections degrade independently into `errors`) plus machine-readable
`suggested_actions[] {tool, args, rationale, risk}`. The tool gathers, the
model concludes, a human approves mutations — the confirm-token flow is the
approval gate; nothing in `suggested_actions` auto-executes.

## Prompts

Guided playbooks (validated in the T6 alert-matrix drills):
`triage-alert(alert[, target])`, `rca-l4-errors`, `rca-ai-latency`,
`capacity-report`, `safe-lb-change(change[, target])` — the last walks a
baseline → preflight → apply → verify → rollback LB change.

## Resources

`loxilb://docs/alerts` (rendered alert-rules catalog),
`loxilb://docs/metrics` (metric family reference incl. caveats),
`loxilb://spec/openapi` (swagger spec).

## Audit log

`<audit_dir>/audit.jsonl`, one JSON object per event: `tool_call` (with
redacted args for mutations), `auth_reject`, `origin_reject`, `rate_limit`.
Mutating calls log both failures and successes; confirm-token rejections
appear as `confirm: ...` errors.

## Security posture

- HTTP mode refuses to start without client tokens, and refuses plaintext on
  non-loopback binds unless `--insecure-http` (lab only). TLS + optional mTLS
  via `--tls-cert/--tls-key/--tls-client-ca`.
- Browser cross-origin requests are rejected (Go 1.25 cross-origin
  protection + SDK localhost check) — DNS-rebinding defense.
- Per-client token-bucket rate limiting; constant-time token verification.
- Log/archive content is returned under `untrusted_data` keys — treat as
  data, never instructions (prompt-injection defense).
- Known caveats: **F11** — with `--userservice`, configure bridge target
  credentials or metrics scraping 401s; **F12** —
  `loxilb_ai_requests_total` counts only SSE-terminated streams
  (`ai_traffic_report` restates this in every result).

## CI / E2E

`cicd/mcp/` is the self-contained scenario: it builds the
bridge, drives it with curl JSON-RPC over streamable HTTP against a docker
testbed — observe checks, an MCP-only LB create→traffic→confirm-delete
round-trip with audit verification, viewer-role guardrails, the API-key
lifecycle with secrets-to-file, and the diagnose/report tools. Run:

```sh
cd cicd/mcp && ./config.sh && ./validation.sh; ./rmconfig.sh
```

The AI 429-under-load drill and the 12 h soak need an SSE
backend and wall-clock time, so they run separately on a dedicated testbed.

### On-demand E2E against a live target

`cicd/mcp/live-e2e.sh` validates the bridge against an already-running loxilb
deployment — no docker testbed, no LLM. It builds the bridge, opens a single
persistent stdio JSON-RPC session, and asserts the observe/guardrail surface:

```sh
cd cicd/mcp
./live-e2e.sh                                   # default target, read-only
TARGET=http://<host>:11111 ./live-e2e.sh        # any live target
./live-e2e.sh --mutate                          # + control-plane round-trip
```

Read-only mode (default) changes **nothing** on the target: it checks
`version_get`/`health_overview` reachability, cross-checks `lb_list` against the
target's REST `/config/loadbalancer/all`, verifies `metrics_snapshot`,
`targets_list`, `fleet_overview`, `diagnose_l4_errors`, and the `ai_traffic_report`
F12 caveat, then exercises the guardrails (URL-as-target rejected, unknown target
rejected, unknown tool → JSON-RPC error, viewer role sees no `lb_create`).

`--mutate` additionally runs an isolated `lb_create` → `lb_list` → confirm-token
`lb_delete` round-trip on a TEST-NET-2 VIP (`198.51.100.7:19999`, override with
`VIP`/`VPORT`/`VEP`) that will not collide with real services, checks the audit
trail, and cleans up — including a `--no-confirm` safety-net delete if any step
fails, so a run never leaves state on the target. The two-step confirm-token
flow is why the harness holds one session open: the token is in-memory,
single-use, and per process. Exit code 0 means every check passed.
