# Configuration Snapshot Coverage

This document states exactly which configuration a loxilb-inference-gateway
snapshot captures, which configuration it deliberately does not, and the
rules that make snapshot documents verifiable and byte-stable. It describes
snapshot schema **1.13**, the version current builds emit.

The authoritative source for everything below is code, not prose:

- `pkg/snapshot/registry.go` — the ordered domain table (what is captured,
  and in which order it is applied and torn down).
- `pkg/snapshot/lifecycle.go` — the configuration-lifecycle registry: every
  mutating REST route is classified into exactly one lifecycle class, and a
  test fails the build when a route is missing. Adding a mutating route to
  the API forces an explicit persistence decision at review time.
- `pkg/snapshot/digest.go` and `pkg/snapshot/codec.go` — canonicalization
  and checksum rules.

## The snapshot document

A snapshot is one JSON document (`kind: loxilb-snapshot`). It is produced
in two ways:

| Operation | Route | Notes |
|---|---|---|
| Export | `GET /netlox/v1/config/snapshot` | On-demand download. Optional `components` query parameter selects a subset of domains; an unknown name is an error, never a silent omission. Response carries `X-Snapshot-Checksum`. |
| Persist | `POST /netlox/v1/config/persist` | Writes `snapshot.json` into the gateway's configuration directory. Replayed automatically at boot. |
| Restore | `POST /netlox/v1/config/restore` | Applies an uploaded document through a staged pipeline: parse and checksum-verify → validate and migrate → verify dependencies → plan → pre-restore snapshot → wipe and apply → verify → commit or roll back to the pre-restore state. |

`/config/export` and `/config/import` are deprecated legacy equivalents.

Every document describes its own coverage:

- `included_domains` — the domains the document actually carries. Restore
  selection derives from this, so a partial document never wipes domains it
  does not cover.
- `excluded_domains` — an honesty marker: every configuration area that has
  a desired-state mutating API but is **not** captured. It is derived from
  the lifecycle registry, not maintained by hand.
- `checksum` — see [Checksum and canonical form](#checksum-and-canonical-form).
- `generation` (schema 1.5) — a monotonic counter over the node's persisted
  snapshot lineage, stamped only by persist. Two persisted states can be
  ordered without trusting file timestamps. Plain exports carry no
  generation: an export is not a lineage point.

## Captured domains

Twenty-two domains, listed in apply order (dependencies first; teardown runs
in exact reverse). The `components` parameter and the `domains.*` JSON keys
use these names verbatim.

| # | Domain | Covers |
|---|---|---|
| 1 | `endpoint` | Endpoint hosts and probe configuration |
| 2 | `jwtauthprofile` | JWT auth profiles referenced by LB rules |
| 3 | `halfclose` | Half-close hold settings (singleton) |
| 4 | `netidentity` | Network-identity bindings: the tenant of requests by source network or ingress interface. Node-local: a binding names this node's addresses and interfaces |
| 5 | `loadbalancer` | LB rules and services, including AI/L7 service arguments |
| 6 | `kvexactbinding` | Per-rule KV-exact composed-binding identity |
| 7 | `l7policy` | Dedicated L7 policy resources, attached to rules by stable id |
| 8 | `firewall` | Firewall rules |
| 9 | `policy` | QoS policers / meters |
| 10 | `mirror` | Traffic mirrors |
| 11 | `session` | Subscriber sessions |
| 12 | `sessionulcl` | Subscriber UL-CL classifiers |
| 13 | `ipfilter` | IP allow/deny filter entries |
| 14 | `securityrate` | Security rate-limit configuration (singleton) |
| 15 | `bfd` | BFD sessions |
| 16 | `bgp` | BGP global config, neighbors, defined sets, policy definitions and applies |
| 17 | `bgppolicyassignment` | Operator BGP import/export policy bindings on neighbors |
| 18 | `ipsec` | IPsec config, tunnels, certificates and CA certificates |
| 19 | `cors` | CORS origin allowlist and wildcard opt-in (singleton) |
| 20 | `tracing` | OTLP trace-export product configuration (singleton) |
| 21 | `cert` | Managed TLS certificates, as `{id, digest}` metadata |
| 22 | `auditsink` | Audit sinks: receiver, certificate paths and, for a secondary sink, its selection |

The document additionally carries `recovery_dependencies` — not a domain
but a document-level manifest of the external stores the configuration
depends on (see below).

Singleton domains (`securityrate`, `cors`, `tracing`) capture the
configured state only; an unconfigured factory default is not configuration
and is captured as absent. Restoring such a document returns the gateway to
that default rather than to a synthetic value.

## What is deliberately not captured

Every mutating route outside the domains in the table above falls into one
of four classes. The classification is enforced by test — there is no
unclassified mutating route.

### External stores (referenced, never embedded)

Desired state owned by a store outside the document. The snapshot may
record the store's identity in `recovery_dependencies`, but never its
content:

- **User accounts** (`/auth/users*`) — management database.
- **AI API keys, rate limits and objectives** (`/config/ai/apikey*`,
  `/config/ai/tenant/ratelimit`, `/config/ai/user/ratelimit*`,
  `/config/ai/ratelimit/defaults*`, `/config/ai/objective*`) — key-store
  database. `aigw-lkg.json`, under the configuration directory, is a
  read-only last-known-good copy of the objectives, classes and limit rows,
  served while the store does not answer. It is not a write path: with no
  key store configured these routes answer 503 rather than hold a change
  in memory.
- **Legacy path-based SNI certificate registrations**
  (`/sni/certificates`) — these carry no certificate id, so the `cert`
  domain cannot capture them; `excluded_domains` keeps that honest.

### Runtime-rebuilt state

State the gateway relearns after boot from an authoritative source, or
state that is ephemeral by design and must be re-established by the
operator:

- **Kernel networking plumbing** — addresses, routes, neighbors, FDB
  entries, VLANs, VXLAN tunnels. The kernel owns this state; the gateway
  relearns it via netlink.
- **Endpoint host-state overrides** — endpoint health is rebuilt by
  probing, never replayed.
- **Auth sessions and tokens**, counter/statistics resets, validation
  probes, tunnel actions.
- **Runtime toggles** — metrics exporter, log level, trace and L4-trace
  enablement and sampling, GPU mode, cluster/HA instance state (driven by
  the HA manager).
- **Audit sealing/retention policy** — the audit root directory, the
  mandatory-audit mode and the instance identity are startup-only; the
  policy is changeable while running and held in memory, so a restart
  returns it to its startup values. The audit sinks are captured (the
  `auditsink` domain).

#### Environment-inherited defaults

Process-wide flow-control and admission defaults come from the
environment, for example `LLB_FC_WAKE_POLICY`, `LLB_FC_ADAPTIVE`,
`LLB_FC_MAX_QUEUE_DEPTH`, `LLB_FC_TENANT_MAX_SHARE_PCT`,
`LLB_FC_TENANT_SLOTS` and `LLB_AI_QUOTA_WARMUP_MS`. A snapshot stores what
a rule declares — `inherit` or an absent knob — never the value it resolves
to. Restoring onto a node with a different environment therefore yields
different effective settings; CI `ai-tenant` X12 pins this.

### Lifecycle operations

`/config/persist`, `/config/restore`, `/config/import` move configuration
owned by the other classes and carry no desired state of their own.

### Out of scope by product decision

Explicitly excluded from the persistence contract; their configuration is
not persisted and they must not become snapshot domains without separate
approval: **PII filtering**, **LlamaFirewall**, and the **OPA watcher**.

## Checksum and canonical form

The `checksum` field is `sha256:<hex>` over the document's canonical JSON
with the checksum field itself set to the empty string. Restore refuses a
document whose checksum does not verify.

Two captures of an unchanged gateway produce byte-identical domain
payloads. Canonicalization guarantees it:

- **Runtime fields are zeroed before encoding** — endpoint probe delays and
  current health, per-endpoint traffic counters, firewall counters, mirror
  datapath sync status, transient attach/detach opcodes. These are
  measurements, not desired configuration.
- **Every unordered list is sorted by its canonical JSON encoding**, so
  backend enumeration order can never change the payload.

The same normalized form backs the restore engine's verify stage: after
apply, a live re-capture must digest-equal the applied document
field-for-field, independent of enumeration order or runtime fields.

## Schema versioning

`schema_version` is `major.minor`: major on breaking changes, minor on
additive ones. A build refuses documents with a **newer minor** than it
understands — an additive domain the build would silently drop is treated
as a hard incompatibility, never a warning. Older documents are migrated
forward on read.

| Version | Added |
|---|---|
| 1.1 | `kvexactbinding` domain |
| 1.2 | `included_domains` (partial documents stop implying full wipe); BGP neighbor transport fidelity |
| 1.3 | `l7policy`, `cors`, `tracing`, `cert` domains |
| 1.4 | `recovery_dependencies` manifest |
| 1.5 | `generation` lineage counter |
| 1.6 | `jwtauthprofile` domain |
| 1.7 | `halfclose` domain |
| 1.8 | `auditsink` domain |
| 1.9 | `halfclose` gains `defaultMode` |
| 1.10 | a `loadbalancer` rule gains `ai_default_reservation` and `ai_default_max_tokens` |
| 1.11 | `netidentity` domain; a `jwtauthprofile` gains `priority_class` and a `loadbalancer` rule `ai_objective_strict` (both absent when unset) |
| 1.12 | `bgppolicyassignment` domain; a `loadbalancer` rule gains the priority-band knobs (`fc_wake_policy`, `fc_band_weights`, `fc_band_min_share_pct`, `fc_critical_reserve_pct`, `fc_band_wait_ms`, `fc_band_queue_pct`, `fc_shed_queue`, `fc_tenant_wake`, `fc_llmd_headers`), all absent when unset |
| 1.13 | Optional `bgp_api_adopted` marker; absent means static YAML owns the BGP group, which is not applied from snapshots until explicit adoption |

The resulting compatibility matrix, enforced by the version-gate and
golden-document test suites (a golden document of every prior schema must
decode, checksum-verify, migrate and pass a dry-run restore on the current
build):

| Document schema vs. build | Outcome |
|---|---|
| Same version | Restored as-is |
| Older (any prior 1.x) | Migrated forward on read, then restored |
| Newer minor | Refused — the build cannot know what it would silently drop |
| Newer major | Refused |

## Secrets and sensitive material

- **Tracing**: OTLP auth header *names* ride the document; header *values*
  stay in a node-local secret store and are re-joined on apply.
- **Managed TLS certificates** (`cert` domain): the document carries
  `{id, digest}` metadata only. PEM and keys stay in the node-local managed
  directory; restore verifies the digest before re-registering and fails
  loudly on missing or divergent material.
- **Audit sinks** (`auditsink` domain): the document carries the paths of
  the CA bundle and of the client certificate and key, never their
  contents. The files stay on the node; a restore that cannot read them
  refuses the sink, as the request that configures it would, and the
  restore rolls back. A sink's place in the trail and its export sequence
  are kept under the audit directory and are not in the document, so a
  restored sink continues both.
- **IPsec secret material rides the document encrypted, never in
  plaintext**: pre-shared keys, certificate private keys and passphrases
  are stored as `enc:v1:` values — AES-256-GCM under a node-local secret
  (`snapshot-node.secret` in the gateway's configuration directory, next to
  `snapshot.json`, so the pair persists or perishes together). A captured
  document is shippable without being a credential dump; failing to encrypt
  fails the capture, it never downgrades to plaintext. Public certificate
  bodies (certificates, CA certificates) ride as-is. Restoring a document
  on a *different* node requires transporting the node secret through an
  operator-controlled channel first — the snapshot file itself never
  carries the key that opens it, and the backup surface is therefore the
  configuration-directory pair, never `snapshot.json` alone.

## Recovery dependencies

Since schema 1.4 every document carries a manifest of the external stores
its configuration depends on for full recovery — type, stable id,
generation, digest and a required flag — for example the engine-contract
registry, the KV model-profile generation, the management and data-plane
databases, and the managed certificate directory. Identity only: the
stores' content stays external.

Restore verifies the manifest before anything is planned or wiped. A
missing or divergent **required** dependency fails the restore closed; a
non-required divergence is surfaced as a warning and tolerated.
