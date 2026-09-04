# cfg-persist-upgrade

The version matrix, live: one config volume, two gateway images, handed
back and forth. Dispatch and nightly only.

Both sides are explicit — `UP_OLD_IMAGE` (default the pinned released
tag) and `UP_NEW_IMAGE` (default `LOXILB_DOCKER_IMAGE`, else `:latest`).
If they resolve to the same reference the suite fails immediately rather
than running a matrix against itself.

## Cases

- **UP-04 — legacy-only volume**: the old image writes `*.txt` artifacts
  (`loxicmd save --all`) and no document; the new image must replay them,
  classify the boot as the legacy path (never as a snapshot recovery),
  and migrate the volume forward through the boot write-through. The
  migrated document must carry the running schema, and the next boot must
  come up through the snapshot path deep-equal.
- **UP-01 — forward migration**: a document persisted by the old image
  must restore deep-equal on the new one, with the boot surface reporting
  a successful replay.
- **UP-03 — idempotent migration**: booting the migrated volume a second
  time must change nothing byte-wise (modulo timestamp/generation/
  checksum).
- **UP-02 — downgrade fails closed**: a document persisted by the NEW
  image, handed back to the old one, must be quarantined and the node
  must boot empty — never a partial apply that leaves the gateway
  half-configured while looking healthy. An old image predating the
  schema gate must at least apply nothing and leave the document intact.
  Upgrading back must recover the node from its own document.

## Traps

- Volume surgery happens with **nothing running**: `teardown_llb1` first,
  then remove the document, then `spawn_llb1`. A live gateway's
  auto-persist will rewrite a file the moment a leg deletes it, and the
  next boot then classifies against an artifact the leg thought was gone.
- A respawned container has no `/tmp/loxilb.out` to grep — `spawn_docker_host`
  launches the gateway itself — so the boot **surface** is the receipt
  after an image swap, not the log line. `spawn_llb1` waits for the boot
  replay to settle before any leg measures anything; counting rules or
  probing the VIP before that reads a half-applied node.
- The cross-version deep-compare runs over a restricted domain set: the
  captured document (`snapshotdoc`) legitimately differs across a schema
  step, and the older API does not serve every domain the current one
  does. The fixture lives entirely inside the compared domains.
- A leg that wipes the volume must rebuild the fixture before persisting,
  or it proves empty equals empty.

- UP-01/02/03 need an old image that already speaks the snapshot API. The
  suite probes for it and SKIPS them **loudly**; set
  `UP_REQUIRE_SNAPSHOT_OLD=1` to turn that skip into a failure once a
  persistence-capable release exists. UP-04 always runs.
- Swapping images deletes and respawns the container: the veths die with
  it, so both pairs are rebuilt and re-addressed on every swap, and the
  config volume is the only thing that carries state across.
- `delete_docker_host` removes the container, not the config directory —
  that separation is what makes the matrix possible. `rmconfig.sh` is
  what finally removes the volume.
