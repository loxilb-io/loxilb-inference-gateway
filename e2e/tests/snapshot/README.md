# Snapshot / restore E2E suites

Live regression suites for the instance snapshot feature
(`docs/SNAPSHOT-DESIGN.md`). Both scripts run **on the gateway node itself**
(they target `http://127.0.0.1:11111` and drive the local `loxilb` docker
container), need `jq`, `curl`, `openssl`, and Go on `PATH` (one probe
re-encodes a tampered document with `go run` against `pkg/snapshot`).

```bash
bash snapshot-e2e.sh      # base suite: §9 scenarios (capture, dry-run, commit,
                          # restart survival, rollback injection, tamper,
                          # deprecated aliases, legacy import) — 26 checks
bash snapshot-probes.sh   # adversarial probes: IPsec PSK+PEM round-trip through
                          # restart, concurrent-restore gate, container-recreate
                          # upgrade survival (/etc/loxilb host volume) — 15 checks
```

Both print `PASS:`/`FAIL:` per check and a final `pass=/fail=` tally, restore
the gateway to the state they found it in (base suite) or to empty config
(probes cleanup), and leave artifacts under `/tmp/snap-e2e` / `/tmp/snap-probes`
for post-mortem.

⚠️ They **mutate live gateway configuration** (wipe/restore cycles). Never run
against a production instance.

The probes' upgrade scenario recreates the `loxilb` container with
`-v /opt/loxilb/config:/etc/loxilb` — the persistence prerequisite documented
in the top-level README ("Configuration persistence & snapshots").
