# Configuration Snapshot Coverage

This document states exactly which configuration a loxilb-inference-gateway
snapshot captures, which configuration it deliberately does not, and the
rules that make snapshot documents verifiable and byte-stable. It describes
snapshot schema **1.5**, the version current builds emit.

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

Seventeen domains, listed in apply order (dependencies first; teardown runs
in exact reverse). The `components` parameter and the `domains.*` JSON keys
use these names verbatim.

| # | Domain | Covers |
|---|---|---|
| 1 | `endpoint` | Endpoint hosts and probe configuration |
| 2 | `loadbalancer` | LB rules and services, including AI/L7 service arguments |
| 3 | `kvexactbinding` | Per-rule KV-exact composed-binding identity |
| 4 | `l7policy` | Dedicated L7 policy resources, attached to rules by stable id |
| 5 | `firewall` | Firewall rules |
| 6 | `policy` | QoS policers / meters |
| 7 | `mirror` | Traffic mirrors |
| 8 | `session` | Subscriber sessions |
| 9 | `sessionulcl` | Subscriber UL-CL classifiers |
| 10 | `ipfilter` | IP allow/deny filter entries |
| 11 | `securityrate` | Security rate-limit configuration (singleton) |
| 12 | `bfd` | BFD sessions |
| 13 | `bgp` | BGP global config, neighbors, defined sets, policy definitions and applies |
| 14 | `ipsec` | IPsec config, tunnels, certificates and CA certificates |
| 15 | `cors` | CORS origin allowlist and wildcard opt-in (singleton) |
| 16 | `tracing` | OTLP trace-export product configuration (singleton) |
| 17 | `cert` | Managed TLS certificates, as `{id, digest}` metadata |

The document additionally carries `recovery_dependencies` — not a domain
but a document-level manifest of the external stores the configuration
depends on (see below).

Singleton domains (`securityrate`, `cors`, `tracing`) capture the
configured state only; an unconfigured factory default is not configuration
and is captured as absent. Restoring such a document returns the gateway to
that default rather than to a synthetic value.

## What is deliberately not captured

Every mutating route outside the seventeen domains falls into one of four
classes. The classification is enforced by test — there is no unclassified
mutating route.

### External stores (referenced, never embedded)

Desired state owned by a store outside the document. The snapshot may
record the store's identity in `recovery_dependencies`, but never its
content:

- **User accounts** (`/auth/users*`) — management database.
- **AI API keys and tenant rate limits** (`/config/ai/apikey*`,
  `/config/ai/tenant/ratelimit`) — key-store database.
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

## Secrets and sensitive material

- **Tracing**: OTLP auth header *names* ride the document; header *values*
  stay in a node-local secret store and are re-joined on apply.
- **Managed TLS certificates** (`cert` domain): the document carries
  `{id, digest}` metadata only. PEM and keys stay in the node-local managed
  directory; restore verifies the digest before re-registering and fails
  loudly on missing or divergent material.
- **IPsec certificates are the exception**: the `ipsec` domain embeds
  certificate material so tunnels round-trip through a restore. A snapshot
  document must therefore be stored and transported as sensitive data.

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
