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
