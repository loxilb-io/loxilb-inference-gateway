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
| API keys, per-key RPS/burst, management users/sessions | Separate PostgreSQL backup |
| Managed certificate material, sink CA file, frontend keys | Separate filesystem backup/mount |
| `snapshot-node.secret` | Separate recovery dependency for encrypted secrets |
| Local Audit records/cursors | Separate Audit volume |
| Binary/image identity and launch options | Deployment record |

A snapshot is not a complete system backup. Keep failed snapshots and original
resources when investigating a failure. Teardown only scenario-owned objects.

The examples below assume a running dedicated lab, an admin token file,
`admin.curl` containing its Bearer header, a data-plane `key.curl`, and explicit
request/CA files. Management Bearer and data-plane API keys are different
credentials. Paths passed to REST are on the Gateway; paths passed to CLI `-f`
are on the machine running the CLI.

```sh
API=http://172.30.88.10:11111/netlox/v1
loxicmd -s 172.30.88.10 --token-file ./admin.token get loadbalancer -o json
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
loxicmd -s 172.30.88.10 --token-file ./admin.token get snapshot \
  -f cli-backup.private.json --strict -o json
loxicmd -s 172.30.88.10 --token-file ./admin.token create persist --strict -o json
loxicmd -s 172.30.88.10 --token-file ./admin.token save --api -o json
```

Read the returned checksum, schema, generation and included/excluded domains.
Manual persistence must return durable success, not merely an HTTP success code.
Auto-persistence has a quiet period; an unsaved change killed before that period
can return to the last disk state. Do not promise recovery of unsaved changes.

```sh
curl -sS --config ./admin.curl -X POST "$API/config/restore?mode=dry-run" \
  -H 'Content-Type: application/json' --data-binary @backup.private.json
loxicmd -s 172.30.88.10 --token-file ./admin.token create restore \
  -f cli-backup.private.json --strict -o json
curl -sS --config ./admin.curl -X POST \
  "$API/config/restore?mode=dry-run&components=loadbalancer" \
  -H 'Content-Type: application/json' --data-binary @backup.private.json
curl -sS --config ./admin.curl -X POST \
  "$API/config/restore?mode=commit&components=loadbalancer" \
  -H 'Content-Type: application/json' --data-binary @backup.private.json
loxicmd -s 172.30.88.10 --token-file ./admin.token create restore \
  -f cli-backup.private.json --commit --strict -o json
```

Default CLI restore is a preview. Compare live configuration before/after it and
require no mutation. A selected restore changes only its requested components.
For full restore, supply matching DB configuration, managed cert material,
engine-contract dependencies, sink CA, and node secret where required. A missing
or mismatched dependency must fail rather than silently restore a partial service;
verify unchanged configuration or compensating rollback after failure.

## Verify delivery after every recovery

```sh
curl -sS --max-time 5 --config ./key.curl -H 'Content-Type: application/json' \
  -H 'X-Test-Nonce: restored-normal' --data-binary @request-normal.json \
  -D normal.headers -o normal.body \
  http://172.30.88.10:2420/v1/chat/completions
curl -sS --max-time 10 --config ./key.curl -H 'Content-Type: application/json' \
  -H 'X-Test-Nonce: restored-sse' --data-binary @request-sse.json \
  -D sse.headers -o sse.body http://172.30.88.10:2421/v1/chat/completions
curl -sS --http1.1 --max-time 10 --cacert ./ca.pem --config ./key.curl \
  -H 'Content-Type: application/json' -H 'X-Test-Nonce: restored-tls' \
  --data-binary @request-normal.json -D tls.headers -o tls.body \
  https://172.30.88.10:2422/v1/chat/completions
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
loxicmd -s 172.30.88.10 --token-file ./admin.token get apikey "$KEY_ID" -o json
loxicmd -s 172.30.88.10 --token-file ./admin.token get apikey --tenant-id uc5s-cli -o json
loxicmd -s 172.30.88.10 --token-file ./admin.token set apikey "$KEY_ID" --enabled=false
loxicmd -s 172.30.88.10 --token-file ./admin.token set apikey "$KEY_ID" --enabled=true
curl -sS --config ./admin.curl -X PATCH "$API/config/ai/apikey/$KEY_ID" \
  -H 'Content-Type: application/json' -d '{"rate_limit_rps":0,"burst_size":0}'
loxicmd -s 172.30.88.10 --token-file ./admin.token delete apikey "$KEY_ID"
curl -sS --config ./admin.curl "$API/config/ai/apikey/$KEY_ID"
```

Run the RPS PATCH while the key still exists, before deletion. Verify enabled →
disabled → re-enabled → deleted as 200 → 401 → 200 → 401 with backend receipts
1 → 0 → 1 → 0. Deleted GET must return 404 (CLI exit 4); lists must omit the key.
Keep the five-second bound when repeating RPS-clear and denial requests.

```sh
curl -sS --config ./admin.curl "$API/auth/users"
curl -sS --config ./admin.curl -X DELETE "$API/auth/users/$USER_ID"
loxicmd -s 172.30.88.10 --token-file ./admin.token get loadbalancer -o json
loxicmd -s 172.30.88.10 --token-file ./admin.token delete lb --name=uc5s-cli-http -o json
loxicmd -s 172.30.88.10 --token-file ./admin.token get cert "$CERT_ID" -o json
loxicmd -s 172.30.88.10 --token-file ./admin.token delete cert "$CERT_ID"
loxicmd -s 172.30.88.10 --token-file ./admin.token get audit-sink -o json
loxicmd -s 172.30.88.10 --token-file ./admin.token get audit-status -o json
loxicmd -s 172.30.88.10 --token-file ./admin.token set audit-sink --disable -o json
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

Fresh mock-backed author verification covers 181 passing evidence assertions,
nine recovery phases, 56 matching received Audit MSG hashes, RPS-clear 30/30,
disabled key 20/20, burst 2 accepted/10 rejected, CRUD, effective wrong-CA rejection,
and image migration/refusal/backup rollback. Independent QA, release and
certification remain separate gates.

The eBPF component's `common/UC5-RECOVERY-REGRESSIONS.md` records the observed L2
reflection/FDB poisoning root cause, split-horizon fix, explicit denial framing,
C sanitizer regressions, and actual-kernel red/fixed replay. Original failed
captures are retained privately; later success does not erase failed evidence.
