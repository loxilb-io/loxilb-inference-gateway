# `cicd/ai-authsep` — authentication plane separation

The data plane's key decision must not depend on the management plane. That is
the whole claim of the authentication-plane-separation work, and this scenario
is where it is asserted on live traffic.

Exercises the data plane across all four `{--userservice} × {key store}`
cells, in both TLS postures, and compares the two verdict vectors along the
`--userservice` axis for equality — a cell meeting its own expectations is not
the property; the two columns agreeing is.

```
l3h1 (10.10.10.1) ── llb1 (VIPs 10.10.10.254:2020 / :2021, mgmt :11111) ── l3ep1 (31.31.31.1:8080)
                       │
                       ├── aisep-pg      PostgreSQL 18.6, plaintext
                       ├── aisep-pg-tls  PostgreSQL 18.6, TLS required
                       └── mysql-ai      MariaDB — management plane only
```

## How it differs from `cicd/ai-apikey`

| | `ai-apikey` | `ai-authsep` |
|---|---|---|
| key store | MariaDB, via `--userservice` | PostgreSQL `aigw` schema, via `--aikey-db-*` |
| management plane | required | a **parameter** |
| backend | none — the suite never starts one | `count_server.py`, which records what actually arrived |
| TLS to the store | not covered | covered, both postures |

`ai-apikey` cannot ask the question this scenario exists for, because it can
only run with `--userservice on`.

## Running

```bash
./config.sh        # topology + both stores + certificates
./validation.sh    # all legs
./rmconfig.sh      # teardown, including the client key and the store password
```

`config.sh` accepts `USERSERVICE=on|off` and `AIKEYSTORE=configured|unconfigured`
for its initial posture. They exist so a cell can be pinned by hand;
`validation.sh` drives every combination itself, because comparing the cells is
the point.

Pin a specific gateway build with `LOXILB_DOCKER_IMAGE=<tag>`.

## What the legs prove

**Section 1 — the four-cell matrix.** Every data-plane leg runs in all four
`{--userservice on|off} × {store configured|not}` cells. Each cell is checked
against its own expected verdicts, and then the two vectors along the
`--userservice` axis are compared for *equality*. A cell passing its own
expectations is not the property under test; the two columns agreeing is.
Also POL-1 (the key lifecycle stands with no management plane), POL-1b (no
store configured is reported as `503 ai_key_store_unconfigured`, not `501` and
not `500`), POL-1c (management auth governs the caller), and POL-6 (the key
rows do not move when `--userservice` is toggled).

**Timing, not just verdicts.** Three legs sample the key API at moments the rest
of the suite deliberately waits past: the very first answer it gives after the
REST listener comes up, and again while the store dial is still in flight (that
precondition is itself asserted, so the leg cannot decay into one that waits
until the answer is easy). A configured store must never be described as
*unconfigured* at either moment — "you set no flag" and "your database is down"
are different situations and an operator acts on them differently. The storeless
cell is the control: there, the first answer must say `unconfigured`. These are
the regression legs for the configured-but-unreachable store reporting itself
as unconfigured, which the first version of this suite found.

**Section 2 — DP-18, DP-19.** Store role isolation, asserted at the database
rather than in the gateway. `public.users` and `public.api_tokens` are created
by the owner first, so `aigwuser`'s denial is about privilege and not about the
table being absent — otherwise the leg would pass for the wrong reason and stop
meaning anything the day those tables actually arrive. DP-19 asserts the
*known* state: `oamuser` is the initdb superuser and still reads
`aigw.api_keys`. It is written down so that it turns red if OAM ever moves to a
non-superuser role and nobody revisits the plan.

**Section 3 — DP-20.** The store password is in neither the gateway's `argv`
nor its log, checked against a run that actually had a store — a cell with no
store never builds a DSN, so grepping its log would pass for free.

**Section 4 — DP-16, DP-17.** Verified TLS to the store, and the absence of a
downgrade. The store certificate carries `DNS:aikey-store` and deliberately no
IP SAN, and `llb1`'s `/etc/hosts` entry for that name is what each leg moves:

* **DP-16a** — TLS-required server, correct CA and client keypair. The store
  connects; the *server* reports the session as TLS with `client_dn=CN=aigwuser`,
  which is the half a client-side assertion cannot give you; and a key written
  into that database with `psql` — never through the gateway — authenticates at
  the VIP, so the data plane demonstrably read that store over that connection.
* **DP-16b** — the same name, the same CA, the same keypair, pointed at a
  server that cannot speak TLS. That isolates the downgrade question from every
  other way a TLS connection can fail. The gateway must report
  `503 ai_key_store_unavailable`, and the plaintext server must log no
  authorized `aigwuser` session. A control leg immediately afterwards shows the
  same server *does* authorize one when TLS is not asked for, so the absence
  above is evidence rather than an empty log.
* **DP-17a** — the store certificate signed by a CA the gateway was not given.
* **DP-17b** — the store addressed by an identity its certificate does not
  carry.

Both DP-17 legs assert that nothing was authorized on the server, which is the
"no plaintext retry" clause stated where it can actually be observed.

## Verdicts that PR 3 changes

Three expectations in `validation.sh` encode the *current* behaviour of a
deliberately behaviour-preserving change, and PR 3 must edit them:

| leg | today | after PR 3 |
|---|---|---|
| keyless on `:2021` (`sse_mode=false`) | `200` — a plain full-proxy AI service never reaches the key check | `200`, because `api_key_auth=disabled` says so |
| keyless / unknown key with no store configured | `200` — the retained `nil → allow` | `503 policy_store_unavailable` (DP-13) |
| backend request counter on a denied request | reported, not asserted — denied requests can still reach the backend and the ratio is nondeterministic | asserted unchanged |

They are written down rather than left implicit so that flipping them is a
deliberate act with a diff, not a silent drift.

## Notes

* The gateway is restarted between cells because the flag set *is* the thing
  under test. A bare kill-and-start fails on `llb_xh_init: Assertion 0 failed`;
  `restart_gw` clears the four pieces of datapath state that outlive the
  process (the `llb0` TAP, the XDP programs, the clsact qdiscs, the bpffs pins).
* `validation.sh` refuses to start against a store that already holds keys.
  `key_hash` is `UNIQUE`, so a re-run would fail on the create and read as a
  code defect. `config.sh` recreates both stores.
* A red leg is a code defect until proven otherwise. Do not soften an assert.
