# cfg-persist-negative

Failure semantics of the persistence pipeline. Every leg stages a hostile
condition and asserts the REFUSAL or quarantine behavior — never the
happy path.

## Legs

- **Partial document**: a capture covering only `loadbalancer`,
  committed with default selection, must leave firewall and session
  state untouched (the document's `included_domains` scopes the wipe).
  Explicitly requesting an uncovered component must be refused (400).
- **Hostile documents**: an unknown top-level field (strict decode) and
  a wrong `schema_version` are refused with 400 before anything is
  planned or wiped; state is proven unchanged afterwards.
- **Truncated `snapshot.json`**: boot must quarantine the file
  (`snapshot.json.failed-<ts>`), log loudly, and come up clean-empty —
  never boot silently on a file a later auto-persist would overwrite
  (that is how a failed boot becomes a durable config wipe).
- **Corrupted (bit-flipped checksum) `snapshot.json`**: same quarantine
  path via the checksum gate; the injection is verified to have taken
  before the restart, so the leg cannot green vacuously.
- **Recovery**: after each quarantine, the operator path (REST commit
  restore of the last good document) must fully recover, and the
  recovered VIP must serve traffic.
- **Cert digest gate**: the snapshot carries `{cert_id, digest}` only.
  Drifted on-disk material (appended bytes, PEM still parseable) must
  fail the commit restore at apply (500, rolled back, loud digest
  error); restoring the original bytes makes the same document apply.
- **Cross-node cert restore**: after an API delete (the one operation
  that removes managed material), the document must fail loudly with
  re-provision guidance — key material is never invented from a
  snapshot. Re-provisioning the same PEM makes the document apply again.
- **L7 policy conflicts**: the same policy id with different content and
  a second policy on an LB that already carries one are both 409 —
  restore-order winners are never decided by silent overwrite. (This leg
  adds an LB, so the count-sensitive legs above run before it.)
- **Missing required dependency (REST)**: a document whose
  `recovery_dependencies` manifest declares the data-plane API-key store
  REQUIRED (captured with `--aikey-db-host` wired; unreachable on
  purpose — the contract is configured-check, not reachability) must be
  refused on a store-less node with 400 BEFORE anything is planned or
  wiped, the error naming the dependency; dry-run preflights the same
  refusal, and the identical dry-run passes 200 while the store is
  wired, proving the refusal is dependency-driven.
- **KV-bound document onto a profile-less host**: a document carrying a
  `kvexactbinding` (captured against a published profile registry, which
  marks `kv-model-profiles` + `engine-contracts` REQUIRED) must fail
  closed once the registry is stripped — 400, dependency named, nothing
  mutated. Green counterpart: the same dry-run passes while the registry
  is published.
- **Missing dependency at boot**: the KV-bound document planted as
  `snapshot.json` must quarantine IMMEDIATELY at boot (dependency
  failures are not startup-class, so no retry loop), log the dependency
  by name, come up clean-empty, and recover via the operator path.
- **Concurrency storm**: three rounds of parallel persists, captures, a
  commit restore and six config mutations. Snapshot endpoints answer
  200 or 409 (gate held), every other mutating call answers 200/204 or
  503 (frozen while the gate is held); anything else — a 5xx above all —
  fails the leg. A round set that produced no rejection at all fails
  too, so the leg can never green without having contended the gate.
  Afterwards the gate must be free (a plain persist succeeds), the
  document must parse/checksum/plan cleanly, and the resulting state
  must round-trip a restart deep-equal.
- **SIGKILL inside the auto-persist debounce** (×10, one per offset
  across the 3s quiet window): the contract is integrity, not no-loss.
  `snapshot.json` must always be a valid document (proved by a dry-run
  restore of the file itself), boot must never quarantine it, and the
  pre-existing state must always come back. Each round may keep or lose
  its own mutation — documented behavior — but nothing else may move;
  the surviving count is reported for the record.

## Traps

- The gateway writes `snapshot.json` root-owned 0600 — host-side reads
  and mutations go through sudo.
- The canonical document is compact JSON (no spaces); corruption
  injections must match that form and then VERIFY they took.
- Evidence JSONs are scrubbed of the ipsec domain by
  `plib_collect_logs` before upload — snapshots embed live secrets.
- The concurrency and SIGKILL legs restart the gateway a dozen-plus
  extra times; on a hosted runner budget the job timeout accordingly (a
  timeout here is a workflow tune, not a code defect).
