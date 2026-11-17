# ai-ha-failover-bfd

Two gateways peered by loxilb's own BFD (`--cluster --self --ka`), one shared
VIP that the client alone knows, one shared PostgreSQL API-key store, one
Keycloak. The scenario fails the pair over and reports what a client that
only addresses the VIP sees: same API key, same JWT, no management call.

This is a verification scenario. A failing case is a result. Nothing in it
repairs the product or weakens an oracle to reach PASS.

## Run

    ./config.sh && ./validation.sh ; ./rmconfig.sh

`validation.sh` exits 0 with no FAIL and no NOT_RUN, 1 with at least one
FAIL, 2 with at least one NOT_RUN. Evidence goes to `out/<timestamp>/`, or to
`$HAFO_OUT`; `verdicts.tsv` there has one line per verdict.

| Variable / option | Effect |
|---|---|
| `--cases FAILOVER-0,BED,FAILOVER-1,FAILOVER-2-4,FAILOVER-5-8,FAILOVER-6-7,FAILOVER-9,FAILOVER-10,FAILOVER-11,FAILOVER-11r,FAILOVER-12,FAILOVER-13,FAILOVER-FRONTEND` | select cases (default: all, in this order) |
| `HAFO_FO1_REPS` (5), `HAFO_FO1_CRASH_REPS` (3) | FAILOVER-1 repetitions per mode |
| `HAFO_LONE_WATCH_S` (300) | how long FAILOVER-12 watches a gateway on its own |
| `HAFO_MUTATE=<name>` | apply one deliberate break (see Mutations) |
| `LOXILB_DOCKER_IMAGE` | the gateway image (from `../common.sh`) |

A full run takes about 45 minutes with the default repetitions.

## Topology

    hfc1 10.10.10.1 ──┐                       ┌── hfe1 31.31.31.1 (echo :8080, witness :8081)
                      │ hfsw1 br0   hfsw2 br0 ├── hfe2 31.31.31.2
    llb1 10.10.10.11 ─┤ (client     (backend  ├── hfe3 31.31.31.3
    llb2 10.10.10.12 ─┘  segment)    segment) └── hfe4 31.31.31.4
         VIP 10.10.10.254

The client segment is one L2 broadcast domain. The VIP is an address in its
subnet that sits on no interface; the MASTER adds it to `lo` and announces it
with a gratuitous ARP. The harness never tells the client which node is
master and never changes the client's route, ARP entry or NAT.

BFD (UDP 3784) and the sync channel (TCP 22222/22223) run over the docker
bridge (`eth0`), which is where `spawn_docker_host --with-ka in` puts them.
PostgreSQL and Keycloak are on the docker bridge too.

| Port | Rule |
|---|---|
| 2020 | `api_key_auth: required` |
| 2021 | `jwt_auth_profile: kc` |
| 2022 | flow control `enforce`, ceiling 2, queue 4 (witness backend) |
| 2023 | `api_key_auth: required` (witness backend: paced streams, quota debt) |
| 2024 | `session_header_name: X-Conversation-Id`, four endpoints |

## Verdicts

| Verdict | Meaning |
|---|---|
| PASS / FAIL | an oracle with a threshold |
| RECORDED | a measurement with no threshold yet |
| NOT_RUN | the check could not run; never reported as PASS |

The scenario never downgrades a verdict. If the two REST APIs do not answer,
or the roles do not hold as one MASTER and one BACKUP for six consecutive
samples, every case is NOT_RUN and the exit status is 2. There are no fixed
sleeps before configuration: `config.sh` polls each REST API, then the roles,
and records both times.

## Backends

Four copies of `../ai-jwtauth/hdr_echo.py` answer on `:8080` with their own
label, a fixed 12-token usage object and a receipt count per `X-Test-Nonce`.
`hafo_backend.py` (the witness, on `hfe1:8081`) adds what the echo lacks: a
paced SSE stream, a held request, a usage figure the test chooses, its own
count of requests in flight with the peak, and a record of how each request
ended as the backend saw it. Receipts are always read inside the backend's
namespace, never through a gateway.

## What is per node and what is shared

| Configuration | Where it lives | How the scenario applies it |
|---|---|---|
| Load-balancer rules, JWT auth profiles | each node (saved by the node in `/etc/loxilb/snapshot.json` and restored when it starts) | the same list is sent to both nodes; read back from both and compared |
| Process flags and environment (`--cluster`, `--self`, `--ka`, key-store flags) | each node | recorded from `/proc/<pid>/cmdline`; a returning node is started with the same line |
| API keys, tenant limits | the shared PostgreSQL store | written once through one node, read back through the other |

Runtime state (token-quota buckets, conversation table, flow-control gate) is
process memory on each node; FAILOVER-0 records that the two containers share no
eBPF map.

## Cases

| Case | Question | Verdict kind |
|---|---|---|
| FAILOVER-0 | Is the pair healthy before any fault? Roles, a keyed 200 with one backend receipt, a 401 with none, a completed quota sync push, equal read-backs, store and JWKS usable on both. Records the standby's listener state, BFD lines, start-up times, bpffs layout. | PASS/FAIL + RECORDED |
| BED-1, BED-2 | Harness checks: docker does not restart a killed gateway; a dead node returns and the pair is healthy. | PASS/FAIL |
| FAILOVER-1 | How long is the service down? Open-loop probe (20/s, a new connection per request) through four ways of losing the MASTER: node death, container stop, SIGTERM to loxilb, crash and restart in place. Per repetition: survivor MASTER, VIP, listener, first 200, outcome histogram. | PASS/FAIL per repetition; telemetry and pre-fault settling recorded |
| FAILOVER-2 | Does the same API key keep working with no management call? Then 200 distinct keys at once. | PASS/FAIL + RECORDED |
| FAILOVER-3 | Does a JWT minted before the fault keep working, with the client unable to reach the IdP? Expired and garbage tokens are refused. | PASS/FAIL + RECORDED |
| FAILOVER-4 | Does a key deleted on the old master stay refused on the new one? Control: an undeleted key. | PASS/FAIL |
| FAILOVER-5 | Can a tenant in quota debt buy fresh quota by failing over? | PASS/FAIL (+ RPS RECORDED) |
| FAILOVER-6 | What happens to an SSE stream in flight, and does the same request complete when sent again? | PASS/FAIL (retry) + RECORDED |
| FAILOVER-7 | What happens to a saturated flow-control gate and its queue? | RECORDED |
| FAILOVER-8a / FAILOVER-8b | Do 100 pinned conversations land on the same endpoint afterwards? 8a records the share and the mechanism; 8b is PASS/FAIL at 0.90 when the peer held the entries. | RECORDED / PASS/FAIL |
| FAILOVER-9 | Failover while the key store is down; recovery when it returns, with no gateway restart. | PASS/FAIL (recovery) + RECORDED |
| FAILOVER-10 | Promotion of a standby that restarted a moment ago. | RECORDED |
| FAILOVER-11 | Failback: no second MASTER, the probe keeps answering, a tenant in debt stays refused. | PASS/FAIL + RECORDED |
| FAILOVER-11r | Repeat after restarting the standby before the fault. The survivor keeps MASTER and the returning node remains BACKUP. | PASS/FAIL + RECORDED |
| FAILOVER-12 | Does an isolated start serve the VIP, and does the peer rejoin without taking ownership or interrupting service? | PASS/FAIL |
| FAILOVER-13 | A node returns with an older configuration than its peer and is promoted. | RECORDED (+ harness restore check) |
| FAILOVER-FRONTEND | Restart both fixture nodes with frontend election enabled, then cut the customer link while BFD stays UP, cut both frontends, restore eligibility, and replace the elected node's frontend with a new ifindex. | PASS when there is no VIP with both frontends down and each handoff or recovery has the expected sole owner |

Every cross-node claim has three guards: a control identity that must be
admitted, backend receipts read out of band, and proof before the fault that
the sync channel carried a push made after the state existed.

### Quota debt

A debt tenant has a bound of 10 tokens per minute and is put in debt by one
answer that reports 60 tokens. The scenario does not assume how long the
refusal lasts. Each `429` carries `Retry-After`; a refusal at time *t* with
`Retry-After: r` says no request of that tenant can be admitted before
*t + r*. An admission earlier than the latest such moment (less 2 s) is the
failure, on whichever node it happens.

### Node death, return, and the other ways to lose a MASTER

| Name | What the harness does |
|---|---|
| node death | every link in the node's namespace down (t0), then SIGKILL of the container |
| container stop | `docker stop`; the gateway is not PID 1 here, so it serves through docker's grace period and is then killed |
| SIGTERM to loxilb | the signal to the gateway process only; the node stays up |
| crash | `kill -9` of the gateway process; nothing is cleared; restarted in place |
| return | reboot emulation: the old namespace is deleted, the container filesystem kept, links re-made, the gateway started with its recorded command line, the list re-applied (a write the node already holds answers 409 and is counted) |

### Before a fault

Every case waits for the roles to hold (one MASTER, one BACKUP, six samples
in a row). The cases that run the probe also require 3 s of nothing but 200s
before the fault, and wait up to 30 s for it. The requirement is not relaxed;
the wait is measured, and when the probe got anything else on the way the
repetition reports it as its own RECORDED line (`FAILOVER-1.<mode>.<n>.before`).
When 3 s of 200s are not reached within the 30 s, every verdict of that
repetition (`FAILOVER-1.<mode>.<n>` and `.before`) is NOT_RUN. A
pair whose roles hold is not always serving: a MASTER that has just taken the
role refuses quota-limited tenants while its quota state warms.

### B1 election limits

| Verdict | Required result | Source |
|---|---|---|
| FAILOVER-1 per repetition | MASTER promotion within 2 s. The stop clock starts at container exit after Docker's grace period. Other modes use fault injection. | Step 0 measured promotion in about 0.26–0.60 s. The 2 s gate includes runner and sample delay. |
| FAILOVER-12a and FAILOVER-12b | MASTER with the VIP within 120 s of gateway process creation, with ownership intact in the final three samples. The epoch comes from the gateway PID's kernel start time. | The 95 s XSync and cool-off gate plus 25 s for process initialization, ownership installation and sampling. This retains the 120 s threshold. |
| FAILOVER-12c and FAILOVER-12a.peer-up | The active node retains the VIP throughout the sampled return. At least 10 HTTP probes, all HTTP 200. | No pre-emption on peer return. The sample floor prevents a vacuous pass. |
| FAILOVER-12.bfd-only | Both nodes can become active when XSync is ready and only initial BFD is blocked. On reconnect only the higher-IP node owns the VIP. | The accepted split-brain policy and the fixed active-rank tie-break. |

The suite records promotion-to-sustained-HTTP time for campaign A, including
lone start. Three seconds of uninterrupted HTTP 200 define sustained service.
Returning-peer role stabilisation is recorded after six consistent samples.
The return observer has a 120 s collection limit and reports unobserved if
the roles have not stabilised. It does not set a role-stabilisation verdict.

The election gate also checks that a BFD BACKUP refuses a forced MASTER write to
`/config/cistate`. The failback checks require the survivor to keep the VIP
when the old MASTER returns.

## Mutations

Each PASS/FAIL oracle has a deliberate break that must turn it red (or
NOT_RUN where the oracle refuses to judge).

| `HAFO_MUTATE` | Break | Must give |
|---|---|---|
| `ka-peer` | llb2's `--ka` names a peer nobody holds | every case NOT_RUN |
| `drop-rule` | llb2 is not sent one rule | FAILOVER-0.readback FAIL |
| `fo1-skip-fault` | no fault is applied | FAILOVER-1 FAIL (no promotion) |
| `fo1-backend-down` | the backend is stopped first | FAILOVER-1 NOT_RUN (control) |
| `fo2-delete-key` | the key is deleted before the fault | FAILOVER-2 FAIL |
| `fo3-wrong-aud` | the JWT profile expects an audience no token has | FAILOVER-3 FAIL |
| `fo4-skip-delete` | the key is not deleted | FAILOVER-4 FAIL |
| `fo5-cut-xsync`, `fo8-cut-xsync` | the sync channel is cut before the state exists | FAILOVER-5 FAIL / FAILOVER-8b FAIL |
| `fo8-ep-order` | llb2 has the affinity rule's endpoints reversed | FAILOVER-0.readback FAIL; shows what FAILOVER-8 depends on |
| `fo6-backend-down` | the witness backend is stopped before the retry | FAILOVER-6 FAIL |
| `fo9-skip-pg-start` | PostgreSQL is not started again | FAILOVER-9 FAIL |
| `fo11-no-debt` | the tenant is never put in debt | FAILOVER-11.debt NOT_RUN |

`fo5-cut-xsync` cannot discriminate today: FAILOVER-5 already fails without it
(the new master admits the tenant in debt once whether or not the sync
channel carried the window). The mutation proves nothing about the FAILOVER-5
oracle until FAILOVER-5 passes unmutated; when it does, `fo5-cut-xsync` must be run
again and must turn FAILOVER-5 red before the FAILOVER-5 entry leaves `known-fail.tsv`.

`drop-limit` is kept as a probe, not a mutation: tenant limits are in the
shared store, so a node that was never sent one reads it back anyway.

## CI

The AI-HA-Failover-BFD workflow also runs the [L2 mixed-version regression](../ha-l2-mixed-version/README.md)
against a pinned released image. The same-version suite continues to cover
election and frontend loss, including both frontends down and same-name recreation.

Job `ai-ha-failover-bfd` on the schedule, on dispatch, and on same-repository
pull requests matching the workflow paths. `validation.sh` reports the product as it
is, and part of that is FAIL today. `known-fail.tsv` lists those verdicts;
`verdict_gate.py` makes the job green only when the run matches the list
exactly: an unlisted FAIL or NOT_RUN and a listed verdict that reports
something else each turn it red. An entry names the one verdict it expects:
`FAIL`, or `NOT_RUN` for an oracle whose precondition this product cannot
meet. Matching is exact. The single-MASTER verdict counts observed overlap
using the timestamps and sampling interval in the evidence.

| | CI runner | Testbed the numbers in the report come from |
|---|---|---|
| OS | ubuntu-22.04 | Ubuntu 24.04 |
| Image | `latest` | built from the same commit on the `latest-u24` base |
| FAILOVER-1 repetitions | 2 per mode, 2 crash | 5 per mode, 3 crash |

## Read-back comparison

Both nodes are configured from one list (`.cfg-list`) and read back
separately. These fields are dropped before the comparison because they
describe a node's runtime state, not its configuration (`readback_norm.py`):

| Read-back | Dropped field | Why |
|---|---|---|
| loadbalancer | `endpoints[].counter`, `endpoints[].state` | per-node traffic counter and probe result |
| loadbalancer | `serviceArguments.id` | a UUID each node mints for its own copy of the rule |
| loadbalancer | `serviceArguments.fc_effective` | the gate's live state; compared separately and RECORDED |
| apikey | `last_used_at` | set by the node that served the key |

## Limits of a single-host bed

- **Node death is emulated.** The harness bind-mounts each container's
  network namespace, so the namespace outlives a killed container with its
  addresses up. `node_death` therefore takes every link in the dead node's
  namespace down first (this instant is t0) and then sends SIGKILL. It acts on
  the dead node only: never on the client, a switch namespace or the survivor.
- **A returning node emulates a reboot.** Before the gateway starts again the
  old namespace is deleted, which clears every address (including a VIP left
  on `lo`), every neighbour entry, every route and both veths; the node's
  bpffs mount and its pins go with the container's processes. The container
  filesystem is kept, as a disk survives a reboot, so the gateway finds its
  saved configuration. The harness then re-wires the two links, starts the
  gateway with the command line it had, and re-applies the configuration
  list (a write the node already holds is answered 409 and counted).
- **A process crash clears nothing.** That variant kills only the gateway
  process; what the gateway does with a VIP still on `lo` is recorded.
- **eBPF state.** Each container mounts its own bpffs at `/opt/loxilb/dp`;
  FAILOVER-0 records the mount devices and the kernel ids of the pinned maps on
  both nodes so a run shows whether any map is visible to both.
- **Docker's restart policy** (`unless-stopped`) does not restart a killed
  container on this bed; BED-1 checks it on every run.

## Teardown

`rmconfig.sh` removes the containers, the two switch namespaces, the links
and the scenario's generated files, and empties `/etc/shared/llb{1,2}`. It
leaves images in place and lists the ones added since `config.sh` ran.
