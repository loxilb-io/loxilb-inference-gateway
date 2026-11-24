# radix-h1 — non-P/D prefix routing on HTTP/1.1

Scenario for the per-pool radix prefix routing of non-disaggregated pools on
the HTTP/1.1 path. It runs a gateway built with `-DHAVE_RADIX_TEST_SWITCH`
(the setting has no rule API yet; `LLB_RADIX_POOLS=1` turns it on for every
new pool that can use it) against three mock OpenAI-style backends.

## Topology

| Container | Role | Address |
|---|---|---|
| `rx4-llb1` | gateway (privileged, 3 CPUs, 8 GB) | `10.10.10.254` (VIP), `31.31.3{1,2,3}.254` |
| `rx4-h1` | client (`client.py`) | `10.10.10.1` |
| `rx4-ep1..3` | mock backends (`mock_backend.py`, port 8000) | `31.31.3{1,2,3}.1` |

All containers: `--network none --cgroupns private --restart no`; the client
and mocks with `--cap-drop ALL`, 0.5 CPU and 512 MB. Links are veth pairs
created between the container namespaces with `nsenter` (nothing under
`/var/run/netns`). The scenario folder is mounted read-only; each container
writes only to its own run folder.

Rules (VIP `10.10.10.254`, fullproxy, `sse_mode`, `fc_mode: observe`, three
endpoints): `:3001` round robin, `:3002` CHWBL, `:3003` round robin with a
session header, `:3004` round robin with the circuit breaker, `:3005`
persistence (`sel` 3, client-IP stickiness), `:3006` CHWBL with the breaker
and admission `enforce` at one request per endpoint.

## Running

    RX_IMG_GW=<gateway image> RX_IMG_MOCK=<image with python3> \
    RX_RUN_DIR=<writable folder> ./run.sh

`run.sh` runs `config.sh` (host snapshot, client and mocks), `validation.sh`
(two gateway arms: switch off, then on) and always `rmconfig.sh` (removal and
a host comparison); it exits non-zero when any leg fails. `mock.Dockerfile`
builds the image for the mocks and the client (CI: job `ai-radix-h1` in
`.github/workflows/ai-gateway-sanity.yml`). Results: `$RX_RUN_DIR/evidence/legs.txt`, one line per
leg (`LEG <id> PASS|FAIL|INFO <detail>`).

`hostcheck.sh` compares `sysctl -a`, `lsmod` and `bpftool prog / cgroup tree
/ net` with the snapshot taken before the first container, and checks after
the gateway starts that it loaded no host-wide program type and attached
cgroup programs only inside its own container. Two kinds of new cgroup
program elsewhere are accepted: the container runtime's cgroup_device filter
on the scenario's other containers, and the filters systemd attaches to its
own units (a cgroup_device or cgroup_skb program on a .service, .scope or
.socket unit under system.slice or user.slice, not a docker-*.scope, loaded
by systemd and named sd_* where bpftool reports either), counted per unit in
the "systemd unit filters accepted" notes line. Any other difference stops
the run. The comparison is `hostcheck.py`; `test_hostcheck.py` runs it on
snapshots recorded in `testdata/hostcheck` (a step of both radix jobs, before
the scenario).

## Legs

| Leg | Checks |
|---|---|
| E1a | the switch-on arm answers every request like the switch-off arm (status, endpoint, SSE) |
| E1b | the switch creates radix state for every pool (one per rule); none without it |
| M1 | client-side latency p50/p99, off and on (report only) |
| KA | endpoints seen per kept-alive connection (report) |
| E2 | turn 2 of a conversation goes to turn 1's endpoint (round robin alone: never) |
| E2-KA | on one kept-alive connection, turns of two conversations learned on different endpoints each go to their own endpoint (keep-alive rule) |
| GUARD-FALLBACK | balance guard: four requests of a prefix held on its endpoint X (in flight 0..3, each a HIT); the fifth sees 4 - 0 > 3 and counts `balance` |
| GUARD-RULES-APART | four requests held on Y; a prefix learned on idle X is a HIT on X (radix pick - least loaded = 0); the previous rule (max - min) fell back |
| GUARD-QUIESCE | after both guard legs the pool's admission in-flight is 0 and no underflow line appeared |
| KA-session | a session-header pool on a kept-alive connection behaves as before (leg kept) |
| E3-session | a session header keeps its endpoint and counts as a pin |
| E4 | short body and miss counted under their own names |
| E5 | 500 not learned; 100 Continue then 200 learned; SSE learned |
| E6 | CHWBL pool, keep-alive, client and backend close: no load-unit underflow |
| E6-move | CHWBL pool: a radix HIT on another endpoint than the CHWBL pick moves the bounded-load unit (fresh, kept-alive client close, backend close) and an admission move after a HIT; no underflow line, in-flight back to 0 |
| PIPE | HTTP/1.1 pipelining: a request that begins while an earlier answer is owed does not use radix (`pipelined`), and neither request learns |
| E3-cb/E7 | conversations learned on an endpoint; it goes down and its breaker opens (purge); after it returns, their next turns miss (no hit from old entries) and a new conversation learns on it again |
| STICKY | a persistence pool keeps its pick; radix counts the request as pinned and does not scan it |
| E8 | chunked and above-768 KiB bodies answered, bypass counted |
| TOKENS | a body above 8,192 JSON tokens is routed by radix |
| E9 | a marker string in a request is absent from the gateway log at debug level |

Counters come from the gateway's `[RADIX_STATS]` log line (names and counts
only). Legs that need radix decisions fail until the request path calls it.
