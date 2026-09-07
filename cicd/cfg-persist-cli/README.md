# cfg-persist-cli

The configuration-lifecycle CLI as the subject under test, with REST and the
host-mounted config volume as the oracles.

## What this suite is for

`loxicmd create persist`, `create restore`, `get snapshot` and `save --api`
are how an operator and every wrapper script drive configuration durability.
Their failure behaviour is therefore part of the durability contract: a
command that prints an error and exits 0 turns a failed backup into a
recorded success.

The fine-grained matrices — every HTTP status, every malformed body, every
decode failure — live in the CLI repository's own tests against a fake
gateway, where a failure can be produced on demand. This suite covers only
what needs a real gateway:

- the identity a persist reports is the identity in the file on the host;
- the lineage generation advances through the CLI;
- a downloaded document independently hashes to the checksum it claims, and
  is stored 0600;
- a download that fails against a real dead gateway leaves the previous good
  copy byte-identical and no temporary file behind;
- a dry-run restore mutates nothing and a committed one round-trips a rule
  that was deleted in between, reporting its write-through;
- a corrupt document is refused with a stable reason code and no mutation;
- `save --api` is the same call as `create persist`, refuses the flag
  combinations it cannot honour, and still accepts `--ip`.

## Running it

```bash
cd cicd/cfg-persist-cli
sudo -E bash -c "./config.sh && ./validation.sh"; rc=$?
./rmconfig.sh; exit $rc
```

## Which CLI is measured

By default the `loxicmd` baked into the gateway image. To test a build of the
CLI instead:

```bash
LOXICMD_BIN=/path/to/loxicmd sudo -E bash -c "./config.sh && ./validation.sh"
```

The binary is copied over `/usr/local/sbin/loxicmd` inside `llb1` and the
substitution is announced by both scripts, so a run never leaves it ambiguous
which binary produced the result. Build it statically (`CGO_ENABLED=0`) so it
runs inside the image regardless of the host's libc.

`CLI_TESTS=required` is forced in `config.sh`: the CLI is the subject here, so
the usual auto-skip would turn the whole run green without testing anything.

## Traps

- **Drain the auto-persist debounce before pinning a generation.** Auto-persist
  is a legitimate concurrent writer; a leg that reads a generation immediately
  after a mutation may pin one the gateway is about to advance.
- **The config volume is host-mounted and root-owned 0600.** Read
  `llb1_config/snapshot.json` through `sudo`.
- **Files the CLI writes live inside the container.** Copy them out with
  `docker cp` before parsing them with host tools; check their mode inside the
  container, where it was set.
- **The gateway is killed deliberately in one leg.** It is brought back with
  the in-place restart trio and its replay receipt is polled before any later
  leg runs — probing inside the boot-restore retry window gives phantom
  verdicts.
