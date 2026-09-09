# appliance-dispatch

The `loxicmd appliance` dispatcher as the subject under test, with a contract-
conformant backend fixture as the oracle.

## What this suite is for

`loxicmd appliance` is a thin dispatcher over a host lifecycle backend
(`contracts/host-backend-contract.md` in the CLI repository). It implements no
lifecycle logic: it validates arguments, performs a version handshake, invokes
the backend, and maps the result onto the public exit-code and envelope
contracts. Everything worth testing on this side of the boundary is therefore
about *refusals and faithfulness* — what never reaches exec, what reaches it
unaltered, and what the caller is told afterwards.

That makes a fixture backend the right oracle, not a limitation. The suite
records the argv, environment and stdin of every invocation and asserts against
those, so "the CLI said it refused" is never the evidence — "the backend was
never spawned" is.

### Why this exists when the CLI repo already has unit tests

The CLI repository's `cmd/appliance` and `pkg/backend` tests are thorough, but
every one of them relocates the backend through
`-ldflags -X ...pkg/backend.executablePath=`. Nothing there exercises the path
the shipped binary actually compiles in. A typo'd or moved libexec layout would
pass the entire unit suite and fail on a real appliance.

Here the binary is unmodified and the fixture is installed at the real
`/usr/libexec/loxilb-appliance/loxilb-appliance-backend`. `config.sh` refuses to
proceed unless the shipped CLI reaches it, so a broken path fails loudly at
bring-up instead of turning every negative leg below into a pass-for-the-wrong-
reason.

## Topology

One container. The appliance family never opens a gateway API connection — that
is a contract clause, not an implementation detail — so there is no client, no
endpoint and no VIP. One leg stops the gateway process outright and requires the
family to keep working.

## What it covers

| Legs | Covers |
|---|---|
| AD-01…03 | dispatch through the real libexec path; envelope shape; correlation id joined to the backend's own argv |
| AD-04 | the family works with the gateway process stopped |
| AD-05 | absent backend → `5` / `BACKEND_UNAVAILABLE` |
| AD-06…08 | wrong contract major and unadvertised capability → `6`, no host state change; read-only needs no handshake |
| AD-09…10 | contract violation → `6`; backend refusal → `7` with its own exit preserved and stderr not flooded |
| AD-11…17 | every CLI-side refusal proven pre-spawn; shell metacharacters travel as one literal argv token |
| AD-18 | the child environment is fixed by the CLI, not inherited |
| AD-19…23, AD-28…29 | secret-file mode/symlink rules, stdin-only secrets, console-only bootstrap, key files never overwritten |
| AD-24 | capability stubs refused with `6`, never a successful stub |
| AD-25…26 | the two known-red legs below |
| AD-27 | `--timeout` bounds a forking backend (regression cover for a fixed defect) |

Out of scope, and deliberately so: installing the real package on a clean host,
finding the correlation id in the host journal, and injecting failures into the
surrounding components all need the real backend on a real appliance image. This
suite does not simulate those and does not claim them.

## Known-red legs

Two legs assert the published contract against behaviour that does not yet
implement it. They fail on purpose; that is the finding, not a harness bug.

- **AD-25** — `contracts/exit-codes.md` rule 5 names "timeout mid-mutation" as
  the `PARTIAL` case, and `host-backend-contract.md` requires exit `8` with the
  backend's operation id in `data.operationId`. Today every non-zero backend
  exit collapses to `7`, and `applianceData` has no `operationId` field. Exit
  `7` tells automation the operation is safe to retry; rule 4 forbids
  auto-retrying `8`. A half-written backup or a half-applied public address is
  exactly what must not be retried blindly.
- **AD-26** — `contracts/exit-codes.md` defines `3` (`AUTH`) as covering "OS
  privilege insufficient". `pkg/backend.run()` maps absent binary, permission
  denial and context death all to `5`. Exit `5` tells automation to retry with
  bounded backoff, which can never succeed for an under-privileged caller.

- **AD-27 — FIXED, now green; kept as regression cover.** `--timeout` did not
  bound an invocation whose backend forks a child. `exec.CommandContext` kills only the direct child; the grandchild
  inherits stdout/stderr, so `cmd.Run()` blocks until *that* exits. Measured at
  45s against `-t 2` (the leg's own backstop, not the CLI's). Every real backend
  forks the moment it shells out to `tar`, `pg_dump`, `systemctl` or
  `journalctl`, so this is the default shape, not an edge case. It also masks
  AD-25: the CLI frequently never reaches the classification at all.
  `cmd/appliance/appliance.go`'s `requestContext` comment claims the opposite —
  "so a wedged backend cannot hang automation forever". Minimal fix:
  `cmd.WaitDelay`, or `Setpgid` plus a process-group kill. Fixed in
  `pkg/backend/backend.go` (process group + group kill + `WaitDelay`); this leg
  stays so the bound cannot silently regress.

`APPL_TOLERATE_KNOWN_DEFECTS=1` downgrades the known-red legs to `[KNOWN-DEFECT]` warnings so
the suite can be wired into CI before the fixes land. Setting it is a scheduling
decision, not a coverage one — say so if you do it, and the legs still print
what they found.

## Running it

```bash
cd cicd/appliance-dispatch
sudo -E bash -c "./config.sh && ./validation.sh"; rc=$?
./rmconfig.sh; exit $rc
```

Testing a build of the CLI rather than the one baked into the image:

```bash
CGO_ENABLED=0 go build -o /tmp/loxicmd .      # static: runs inside the image
LOXICMD_BIN=/tmp/loxicmd sudo -E bash -c "./config.sh && ./validation.sh"
```

Full JSON-Schema validation of the envelope is opt-in, because the schema lives
in the CLI repository and a vendored copy here would only drift:

```bash
APPL_SCHEMA=~/go/src/loxicmd-inference-gateway/contracts/command-result.schema.json \
  sudo -E bash -c "./config.sh && ./validation.sh"
```

Without it the suite still checks the envelope structurally (required keys, no
nulls anywhere, `success` agreeing with `code`) and says the schema leg was
skipped.

## Red twin

The fixture's behaviour is selected by `/opt/appliance-fake/mode` inside the
container, so a class can be armed by hand:

```bash
# prove the pre-spawn oracle can fire: make a refusal reach exec
sudo docker exec -i llb1 sh -c 'echo ok > /opt/appliance-fake/mode'

# prove the libexec-path gate can fire: move the fixture aside, re-run config.sh
sudo docker exec -i llb1 mv /usr/libexec/loxilb-appliance/loxilb-appliance-backend /tmp/
# config.sh must abort with the "cannot reach the fixture" FATAL, not proceed
```

Run a red whenever the suite changes. A green suite whose oracles cannot fire
proves nothing.

## Traps

- **`docker exec` without `-t` is deliberate.** stdin and stdout are pipes, so
  the console-only guard on `credentials bootstrap` sees a non-terminal — which
  is the case under test. Adding `-t` inverts AD-23.
- **The spawn counter is the only proof of a pre-spawn refusal.** Asserting the
  exit code alone cannot distinguish "refused before exec" from "spawned, then
  the backend refused".
- **AD-17's archive path must be absolute**, or the CLI's own path check rejects
  it before exec, and the leg then measures argument validation instead of what
  it is for: how the token is handed to the process.
- **The two hang legs must bound themselves.** AD-25 and AD-27 wrap the CLI in a
  host-side `timeout 45`, because their subject is precisely that the CLI does
  not bound itself. Without the backstop a regression wedges the whole suite
  instead of reporting one red leg — which is exactly what the first run of this
  suite did.
- **`hang` and `hangfork` are different questions.** `hang` uses `exec sleep`, so
  the kill lands and the leg isolates *which exit code* is reported.
  `hangfork` forks, so the leg measures *whether the call returns at all*.
  Collapsing them into one mode loses the ability to tell "returned the wrong
  code" from "did not return at all".
- **AD-26 needs a genuinely unexecutable backend.** A file with no execute bits
  is refused even for root, which is why the leg checks for "permission denied"
  in the message and SKIPs loudly rather than passing if it could not produce
  the condition.
- **The fixture never implements lifecycle behaviour.** If a future leg needs
  the backend to actually do something, that leg belongs with the real backend
  on an appliance image, not here.
