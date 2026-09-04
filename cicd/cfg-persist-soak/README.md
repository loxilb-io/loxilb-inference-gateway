# cfg-persist-soak

The drift and leak classes repetition finds and a single pass cannot.
Nightly and dispatch only — this is not a per-PR gate.

## Cases

- **SK-01 — cumulative drift** (`PLIB_SOAK_CYCLES`, default 20): each
  cycle adds a rule, waits out the auto-persist debounce, restarts in
  place and requires the post-restart dump to be identical to the
  pre-restart dump. A restore that re-applies one default or normalizes
  one empty list looks harmless on cycle 1 and obvious by cycle 20. The
  rule count is asserted every cycle too, so silent loss cannot hide
  behind a clean diff.
- **SK-02 — idle stability** (`PLIB_SOAK_IDLE_CYCLES`, default 20):
  restarts with no mutation at all. The persisted desired state must be
  byte-identical every cycle (only `created_at`, `generation` and
  `checksum` may move), and the gateway's open descriptor count must not
  creep across restarts — the historical restart fd-leak class.
- **SK-03 — config storm** (`PLIB_SOAK_MUTATIONS`, default 200): the
  debounce exists so a burst becomes a handful of disk writes; the leg
  asserts the persist counter collapsed the burst (fewer than a quarter
  of the mutations), that every accepted mutation is present, that
  descriptors and RSS stayed bounded through it, and that the final state
  survives a restart deep-equal.
- **SK-04 — concurrency rounds** (`PLIB_SOAK_CONC_ROUNDS`, default 10):
  persist ‖ dry-run restore ‖ capture ‖ mutation every round. Snapshot
  endpoints answer 200 or 409, mutations 200/204 or 503, the on-disk
  document stays valid after every round, and two back-to-back captures
  of the settled node must be identical — a torn capture differs.

## Traps

- Loop sizes are env-tunable so a dispatch run can shorten them; the
  defaults are what the nightly runs. Shortening them in CI config is a
  scheduling decision, not a coverage one — say so if you do it.
- The metrics endpoint is disabled until `POST /config/metrics`; the
  suite enables it before reading `loxilb_persist_total`.
- `restart_inplace_keep` relaunches the gateway without the `-p` flag, so
  metrics must be re-enabled after any restart that precedes a scrape.
- The gateway writes `snapshot.json` root-owned 0600 — host-side reads go
  through sudo, and the integrity oracle stages a copy rather than
  posting the live file that auto-persist replaces underneath it.
