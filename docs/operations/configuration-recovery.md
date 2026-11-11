# Configuration recovery: operator commands and acceptance

UC-5 preserves configuration across process restart, container recreation,
replacement, and image changes. Verify actual request completion and backend
receipts after restore, alongside configuration readback. This guide covers
Gateway configuration; whole-appliance update/rollback/reset belongs to Product.

The Korean command manual and private evidence are delivered separately from
public source. Never commit tokens, plaintext API keys, private certificate keys,
DB dumps, packet captures, or raw host logs.

## Prepare the recovery set

Use a dedicated instance and persistent configuration directory. Keep its exact
image digest, startup options, DB endpoints and password-file paths. Also retain:

| Resource | Recovery authority |
|---|---|
| Gateway services, certificate IDs/digests, Audit sink configuration | Snapshot |
| API key hashes/policies, quotas, objectives and management users | Separate PostgreSQL backup |
| Management sessions | Do not restore; establish new sessions |
| Managed certificate material, sink CA file, frontend keys | Separate filesystem backup/mount |
| `snapshot-node.secret` | Separate recovery dependency for encrypted secrets |
| Local Audit records/cursors | Separate Audit volume |
| Binary/image identity and launch options | Deployment record |

Schema 1.12 adds the `bgppolicyassignment` domain for operator BGP import/export
bindings, including ordered policy names and the default action. Speaker-owned
policies remain runtime managed. Restore BGP definitions and assignments together.
A BGP-only replacement is refused before mutation if it would discard live
unselected assignments. Older snapshots never gain coverage of this new domain.
Changing a running speaker's ASN, router ID or listen port requires snapshot
replacement; ordinary BGP global POST rejects it. When live load balancers
advertise BGP routes, core replacement also requires `loadbalancer` coverage.

Schema 1.13 adds optional `bgp_api_adopted`. With a static GoBGP file and no
adoption marker, the snapshot BGP group is skipped at boot and after daemon
crashes. A successful BGP REST change or committed interactive BGP restore/import
adopts the supported projection. As with the 1.12 newer-minor boundary, older
binaries refuse 1.13 snapshots; keep a compatible pre-upgrade snapshot for a
planned downgrade. See [BGP ownership](ha-bgp-startup.md#bgp-configuration-after-a-daemon-crash).

A snapshot is not a complete system backup. Keep failed snapshots and original
resources when investigating a failure. Teardown only scenario-owned objects.

The examples below assume a running dedicated lab, an admin token file,
`admin.curl` containing its Bearer header, a data-plane `key.curl`, and explicit
request/CA files. Management Bearer and data-plane API keys are different
credentials. Paths passed to REST are on the Gateway; paths passed to CLI `-f`
are on the machine running the CLI.

```sh
API=http://172.30.89.10:11111/netlox/v1
loxicmd -s 172.30.89.10 --token-file ./admin.token get loadbalancer -o json
curl -sS --config ./admin.curl "$API/status/ready"
```

Expect HTTP 200 and `ready=true`. API listen can precede boot replay and DB
initialization. After a restart or image change, wait for actual readiness with a
finite deadline; stop and preserve logs if it never becomes ready. In a corrupt
snapshot test, wait for `boot.snapshot_found`, then assess the expected 503 and
quarantine instead of waiting for `ready=true`. Older images may have no readiness
endpoint; inspect their boot log, restored rule and service port together.

## Export, persist, preview and restore

```sh
curl -sS --config ./admin.curl "$API/config/snapshot" -o backup.private.json
curl -sS --config ./admin.curl -X POST "$API/config/persist"
loxicmd -s 172.30.89.10 --token-file ./admin.token get snapshot \
  -f cli-backup.private.json --strict -o json
loxicmd -s 172.30.89.10 --token-file ./admin.token create persist --strict -o json
loxicmd -s 172.30.89.10 --token-file ./admin.token save --api -o json
```

Read the returned checksum, schema, generation and included/excluded domains.
Manual persistence must return durable success, not merely an HTTP success code.
Auto-persistence has a quiet period; an unsaved change killed before that period
can return to the last disk state. Do not promise recovery of unsaved changes.

```sh
curl -sS --config ./admin.curl -X POST "$API/config/restore?mode=dry-run" \
  -H 'Content-Type: application/json' --data-binary @backup.private.json
loxicmd -s 172.30.89.10 --token-file ./admin.token create restore \
  -f cli-backup.private.json --strict -o json
curl -sS --config ./admin.curl -X POST \
  "$API/config/restore?mode=dry-run&components=loadbalancer" \
  -H 'Content-Type: application/json' --data-binary @backup.private.json
curl -sS --config ./admin.curl -X POST \
  "$API/config/restore?mode=commit&components=loadbalancer" \
  -H 'Content-Type: application/json' --data-binary @backup.private.json
loxicmd -s 172.30.89.10 --token-file ./admin.token create restore \
  -f cli-backup.private.json --commit --strict -o json
```

Default CLI restore is a preview. Compare live configuration before/after it and
require no mutation. A selected restore changes only its requested components.
For full restore, supply matching DB configuration, managed cert material,
engine-contract dependencies, sink CA, and node secret where required. A missing
or mismatched dependency must fail rather than silently restore a partial service;
verify unchanged configuration or compensating rollback after failure.

## Verify delivery after every recovery

### A BGP speaker that is late or unavailable

When a valid boot snapshot contains BGP configuration, the Gateway restores
independent domains first. Ordinary and BGP-enabled LB datapaths can serve
requests while the BGP group is pending. The BGP global, neighbor, defined-set,
policy-definition and policy-assignment group retries with bounded RPCs and a
backoff. Exceeding the former boot allowance does not quarantine the full
document or erase the independent LB rules. A partial boot skips legacy per-domain
replay in both `strict` and `compat`; old `*.txt` files cannot overwrite it.
Corrupt or incompatible documents still fail validation before independent apply.

Check `GET /netlox/v1/status/ready`. While pending it returns HTTP 503,
`ready=false`, and a `bgp_domain_pending` reason. Independent traffic success is
not whole-node recovery. Readiness returns to normal only after the BGP group
applies and verifies, subject to the other readiness reasons. Check an independent
BGP peer's RIB as well as actual HTTP completion before declaring route recovery.
The `loxilb_boot_bgp_pending` gauge is 1 during pending recovery and returns to 0
after recovery or full interactive replacement. It is independent of ordinary
LB traffic and of process liveness.

The BGP sections of the existing checksummed `snapshot.json` remain the durable
intent; there is no extra intent file or epoch. Explicit persist and auto-persist
capture live non-BGP configuration and merge the original BGP and
`bgppolicyassignment` JSON value bytes verbatim, including their formatting and
order. The surrounding live document receives a new valid checksum and generation.
Snapshot exports during pending also include that desired BGP state, rather than
the absent or partly applied speaker state. Use the speaker/peer RIB to inspect
actual BGP convergence. An unrelated LB change saved during pending survives a
restart together with the pending BGP configuration.

While pending, BGP mutation APIs return HTTP **409** with
`bgp_domain_pending`. This covers global settings, neighbors, defined sets,
definitions and assignments. Safe non-BGP management and explicit persist remain
available. Component restores and the deprecated import endpoint cannot replace
pending BGP state. The explicit operator replacement path is a **full interactive
restore**:

```sh
curl -sS --config ./admin.curl -X POST "$API/config/restore?mode=dry-run" \
  -H 'Content-Type: application/json' --data-binary @full-replacement.private.json
curl -sS --config ./admin.curl -X POST "$API/config/restore?mode=commit" \
  -H 'Content-Type: application/json' --data-binary @full-replacement.private.json
```

Use a complete current-schema snapshot covering every supported domain, with no
`components` filter, and the required external resources. Dry-run does not cancel
pending recovery. A failed commit preserves the original pending intent and the
transaction's rollback behavior. A committed replacement stops the old retry
before capturing its replacement state. Verify `result=ok`, `persisted=true`,
readback and traffic; `persisted=false` explicitly means the replacement is not
guaranteed to survive restart. Repair persistence and save before restarting.

The bundled Helm chart uses `/netlox/v1/version` for its Gateway readiness probe
and controller startup wait; its liveness probe is disabled by default.
The kube-loxilb integration client health check uses the API base path, rather
than `/status/ready`. The pending 503 therefore does not change these default
health inputs. Preserve this distinction if overriding probes: an EndpointSlice
whose `ready` condition becomes false is excluded by kube-loxilb discovery, and a
liveness probe pointed at `/status/ready` can restart a healthy process merely
because BGP is pending. Whole-node recovery status is not a process-liveness
check. Verify the effective chart values and controller image for your deployment.

Late advertisement reconciliation keeps the existing HA policy: MASTER to
BACKUP lowers advertisement priority, rather than withdrawing every route.
Deleting the LB withdraws its route. Role-decision advertisement barriers are a
separate HA startup change; reducing the existing 90-second sync wait is not part
of this boot-domain recovery change.

### Verify application delivery

```sh
curl -sS --max-time 5 --config ./key.curl -H 'Content-Type: application/json' \
  -H 'X-Test-Nonce: restored-normal' --data-binary @request-normal.json \
  -D normal.headers -o normal.body \
  http://172.30.89.10:2420/v1/chat/completions
curl -sS --max-time 10 --config ./key.curl -H 'Content-Type: application/json' \
  -H 'X-Test-Nonce: restored-sse' --data-binary @request-sse.json \
  -D sse.headers -o sse.body http://172.30.89.10:2421/v1/chat/completions
curl -sS --http1.1 --max-time 10 --cacert ./ca.pem --config ./key.curl \
  -H 'Content-Type: application/json' -H 'X-Test-Nonce: restored-tls' \
  --data-binary @request-normal.json -D tls.headers -o tls.body \
  https://172.30.89.10:2422/v1/chat/completions
```

Require 200, curl exit 0, complete JSON/SSE `[DONE]`, and exactly one corresponding
backend nonce receipt. Missing/disallowed keys or models must be denied without
backend delivery. A wrong backend CA must fail the actual handshake and leave
no inference receipt. Confirm Audit completion/settlement records at the receiver
and compare their MSG hashes against the local raw records. Readback alone is
not TLS, delivery or request-completion proof.

## Read, disable, delete and verify absence

Use the scenario's actual IDs. Generated IDs are not stable across environments.

```sh
loxicmd -s 172.30.89.10 --token-file ./admin.token get apikey "$KEY_ID" -o json
loxicmd -s 172.30.89.10 --token-file ./admin.token get apikey --tenant-id uc5t-cli -o json
loxicmd -s 172.30.89.10 --token-file ./admin.token set apikey "$KEY_ID" --enabled=false
loxicmd -s 172.30.89.10 --token-file ./admin.token set apikey "$KEY_ID" --enabled=true
curl -sS --config ./admin.curl -X PATCH "$API/config/ai/apikey/$KEY_ID" \
  -H 'Content-Type: application/json' -d '{"rate_limit_rps":0,"burst_size":0}'
loxicmd -s 172.30.89.10 --token-file ./admin.token delete apikey "$KEY_ID"
curl -sS --config ./admin.curl "$API/config/ai/apikey/$KEY_ID"
```

Run the RPS PATCH while the key still exists, before deletion. Verify enabled →
disabled → re-enabled → deleted as 200 → 401 → 200 → 401 with backend receipts
1 → 0 → 1 → 0. Deleted GET must return 404 (CLI exit 4); lists must omit the key.
Run the RPS-clear repetitions immediately after PATCH, while the key and service
rules still exist. Run disabled-key requests after disable and before delete;
write their HTTP status, curl exit and nonce receipt before consuming those files.
Keep the five-second bound. Test wrong backend CA before deleting the baseline
CA or service rules. For CLI traffic checks, create a separate live key and service,
then send a request at each state transition before deleting that service.

```sh
curl -sS --config ./admin.curl "$API/auth/users"
curl -sS --config ./admin.curl -X DELETE "$API/auth/users/$USER_ID"
loxicmd -s 172.30.89.10 --token-file ./admin.token get loadbalancer -o json
loxicmd -s 172.30.89.10 --token-file ./admin.token delete lb --name=uc5t-cli-http -o json
loxicmd -s 172.30.89.10 --token-file ./admin.token get cert "$CERT_ID" -o json
loxicmd -s 172.30.89.10 --token-file ./admin.token delete cert "$CERT_ID"
loxicmd -s 172.30.89.10 --token-file ./admin.token get audit-sink -o json
loxicmd -s 172.30.89.10 --token-file ./admin.token get audit-status -o json
loxicmd -s 172.30.89.10 --token-file ./admin.token set audit-sink --disable -o json
curl -sS --config ./admin.curl "$API/audit/sinks/$SINK_NAME"
curl -sS --config ./admin.curl -X DELETE "$API/audit/sinks/$SINK_NAME"
```

Confirm deleted user login is rejected, deleted rules do not deliver to a backend,
and deleted cert/named-sink GET returns 404. A listener may return 503 briefly
after its rule is deleted; connection refusal is not the only valid no-delivery
outcome. Remove rules referencing a certificate before deleting the certificate.
After disabling the default sink, its CLI readback is `{}`; new management events
stay local and receiver frames must not increase. Sink CLI set replaces the entire
configuration: read it first and supply all required fields when restoring it.

CLI parity limits at `28832f0c`: user read/delete, named Audit sinks, certificate
`usage=ca`, and API-key RPS/burst PATCH need REST. The current CLI does not provide
those matching flags/operations; do not invent a command or count REST fallback
as implementation of an absent CLI feature.

## Image changes and rollback

Record immutable old/new image digests. Export/persist configuration and copy the
old config, certificate material and external DB recovery set before changing the
image. In the isolated version instance:

1. Run old image and verify its exported snapshot and actual HTTP delivery.
2. Stop that instance; recreate it with the new image and the retained mount.
3. Wait for boot completion, then compare configuration and actual delivery.
4. Persist the new format and retain a separate new-format backup.
5. A new-format snapshot refused by old must stay quarantined; verify empty rules
   and zero backend receipt. Do not edit the snapshot to bypass the decoder.
6. Recreate old using the separately retained pre-change old-format config and
   wait for its restored service before verifying actual delivery.

Observed old `v0.9.8.9-rc.1-u24`: schema 1.0 → current 1.9 migrated; current persisted
snapshot → old was refused for unknown `generation`; pre-change backup restored
HTTP delivery. This is a bounded common-HTTP comparison, not universal reverse
migration, old-image key/TLS/Audit parity, or an appliance image-upgrade command.

CLI `28832f0c` with that old API: strict snapshot export and restore preview exit 0;
strict persist exits 6/`CONTRACT_MISMATCH` because durable schema/generation metadata
is absent. Old REST still writes the snapshot. Preserve that expected contract
failure and distinguish it from “nothing was saved.”

## Quality acceptance and defect handoff

Fresh latest-main mock-backed author verification covers 208 passing evidence assertions,
12 recovery phases, 74 matching received Audit MSG hashes, RPS-clear 30/30,
disabled key 20/20, burst 2 accepted/10 rejected, CRUD, effective wrong-CA rejection,
and image migration/refusal/backup rollback. Independent QA, release and
certification remain separate gates.

The eBPF component's `common/UC5-RECOVERY-REGRESSIONS.md` records the observed L2
reflection/FDB poisoning root cause, split-horizon fix, explicit denial framing,
C sanitizer regressions, and actual-kernel red/fixed replay. Original failed
captures are retained privately; later success does not erase failed evidence.

The fresh build used Gateway `865d99f9`, eBPF `36a01412` (including the merged
listener/model/path lookup change), CLI `28832f0c`, and libbpf `48989015`.
The original Gateway main gitlink was `33f52a12`; this update pins the reviewed
latest eBPF revision exercised by the new build. C sanitizer, Gateway recovery/auth
unit tests, listener routing sanitizer, and installed-kernel foreign-drop/routed-
hairpin checks passed. No additional product defect was observed in this scope.
The private manual's ordering, missing disabled-request evidence, CLI lifecycle,
startup waits and source identity were corrected; previous failures remain retained.
