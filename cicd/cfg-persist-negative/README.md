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

## Traps

- The gateway writes `snapshot.json` root-owned 0600 — host-side reads
  and mutations go through sudo.
- The canonical document is compact JSON (no spaces); corruption
  injections must match that form and then VERIFY they took.
- Evidence JSONs are scrubbed of the ipsec domain by
  `plib_collect_logs` before upload — snapshots embed live secrets.
