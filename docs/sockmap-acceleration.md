# sockmap acceleration (`--sockmapsupport`)

> **Read the [kernel requirement](#kernel-requirement) before enabling this.**
> On an unpatched kernel, sockmap acceleration corrupts response data.
> Most stock distribution kernels are unpatched.

## What it does

loxilb's FullProxy terminates the client connection and opens a separate
connection to the backend, then relays bytes between the two in userspace.
Every relayed chunk costs a wakeup, a `recv()`, and a `send()`.

sockmap acceleration removes that hop. Both sockets are registered in an eBPF
`sockhash`, and an `sk_skb/stream_verdict` program redirects bytes from one
socket to the other inside the kernel with `bpf_sk_redirect_hash()`. In steady
state the relay makes no syscalls at all.

This only replaces the relay. Connection setup, HTTP request parsing, backend
selection, and health checking still happen in userspace exactly as before —
acceleration is handed the connection pair only after the proxy has decided
where the traffic goes.

## Enabling it

Acceleration is opt-in at two levels. Both must be set.

**1. Daemon flag** — loads the sockmap BPF assets at boot:

```
loxilb --sockmapsupport
```

Without this flag no service can be accelerated. A request that sets
`sockMapMode` to anything but `off` is rejected with
`sockmap-accel requires loxilb started with --sockmapsupport`, so a service is
never shown as accelerated when it is not. A snapshot restore on a daemon
restarted without the flag is the one exception: the rule is restored with a
warning in the log and runs unaccelerated, rather than failing the restore.

**2. Per-service `sockMapMode`** — selects the direction to accelerate:

| value | accelerated direction |
|---|---|
| `off` (default) | none — plain userspace relay |
| `request` | client → backend only |
| `response` | backend → client only |
| `both` | both directions |

```json
{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2020,
    "protocol": "tcp",
    "mode": 4,
    "sockMapMode": "both"
  }
}
```

`response` is useful for workloads whose traffic is asymmetric — LLM token
streaming, for example, where the request is one small POST and the response is
a long stream.

The direction you do not accelerate stays on the ordinary TCP path: in
`response` mode the client socket never runs the sockmap verdict program, and
in `request` mode the backend socket never does. The requests of a `response`
service, or the responses of a `request` service, are relayed in userspace
exactly as with `off`.

### When a connection is accelerated

A connection is handed to the kernel only after the proxy has parsed its first
request and paired the client socket with a backend socket. From then on:

- **response direction** — from the first response on. The backend socket is
  registered when the pair is made, before the request is forwarded.
- **request direction** — once the proxy has forwarded every client byte it has
  read: after the first request, and for a streamed upload (a body above 64KB
  that needs no inspection) after the whole body. Registering earlier would let
  bytes the client sends next overtake the request still being forwarded.

HTTP/2 connections, including plaintext h2c, are never accelerated. The proxy
pairs no sockets for them, so none of their sockets runs the verdict program.

### Stopping it on connections that are already running

The verdict decides on the socket pairing installed when a connection was
accepted, so configuration alone cannot reach a connection that is already
accelerated — it keeps redirecting until it closes.

**Adding** a direction therefore applies to new connections only: a connection
that is already running is never accelerated retroactively, and is undisturbed.

**Taking a direction away closes the connections that had it accelerated.**
Lowering `sockMapMode`, switching to the other direction, and deleting the service
all do this. Connections of the same service that were never accelerated are not
touched — they drain as they always have, which includes every HTTP/2 connection
and any connection that has not yet sent a request.

To stop acceleration without changing the configuration, for example after finding
the kernel affected by the defect below:

```
curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer/\
externalipaddress/10.10.10.254/port/2020/protocol/tcp/sockmapreset
{"droppedConnections":12}
```

It closes rather than unmaps. Removing a socket from the map while traffic flows
races the kernel's own retry path and can drop bytes mid-connection; closing
cannot, because the connection is over either way. Clients reconnect, and the new
connections follow the service as it now stands. The call is idempotent: a service
with nothing accelerated answers `200` with `0`.

## How services are kept apart

Each service is accelerated or not on its own, even when services share ports.
The datapath recognizes a service's sockets by address **and** port:

- a client socket by the VIP address and port it was accepted on
- a backend socket by the endpoint address and port it connected to

So `10.0.0.1:80` with `sockMapMode: both` and `10.0.0.2:80` with `off` do not
affect each other, and neither do two services whose backends listen on the same
port on different hosts. A VIP of `0.0.0.0` matches any local address on its
port.

A shared address and port is shared at one level only. Two services that point
at the **same endpoint address and port** share its portset entry, because a
backend connection carries nothing that says which service opened it, and the
same holds for host-based services on one VIP address and port. If one of them
accelerates a direction, the matching sockets of the other are also registered
as possible redirect targets (`sock_proxy_map`). That is all they share: whether
a connection runs the verdict program is decided per connection by the service
that handled it, so a service with `off` still relays in userspace.

## Eligibility

A service is rejected at configuration time unless all of these hold:

| requirement | reason |
|---|---|
| `mode` = 4 (FullProxy) | acceleration operates on the proxy's socket pair |
| `protocol` = `tcp` | sockmap redirect is TCP-only |
| plaintext service (no TLS) | see below |
| IPv4 external IP | current implementation limit |
| daemon started with `--sockmapsupport` | the BPF assets must be loaded |
| the data plane changes no byte per request: no `sse_mode`, no `pd_disagg_mode`, no declared
`api_key_auth`, and no attached L7 policy | see below |

Setting `sockMapMode` on a service that does not qualify returns
`sockmap-accel requires plaintext tcp fullproxy ipv4 service`, or
`sockmap-accel requires loxilb started with --sockmapsupport` when only the
daemon flag is missing, or
`sockmap-accel is not allowed on a service whose data plane touches every request (sse_mode, pd_disagg_mode, a declared api_key_auth, or an attached L7 policy)`.

### Why only a service that rewrites nothing

Acceleration replaces the userspace relay. From the moment a direction is handed
to the kernel, userspace no longer sees those bytes and can neither inspect nor
rewrite them — so a service that does per-request work would lose it silently,
from the **second** request on a connection, which is exactly where it would be
hardest to notice.

Four declarations put work on that path:

| declaration | what an accelerated direction would skip |
|---|---|
| `sse_mode`, `pd_disagg_mode` | admission is re-run at each keep-alive request boundary, and each request is recorded from its response |
| `api_key_auth` = `required` / `jwt` / `apikey-or-jwt` | the credential check, and the strip that keeps the caller's `X-Api-Key` out of the backend |
| `api_key_auth` = an explicit `disabled` | the strip. This value enforces no credential, but it still declares `X-Api-Key` the **gateway's** namespace, so the header is removed before dispatch. Accelerated, the tenant's key would reach the backend from the second keep-alive request on |
| an attached L7 policy | `X-Forwarded-For` is overwritten with the real peer address, `X-Forwarded-Port` and `-Proto` are added, and the `insertHeaders` SET/ADD/REMOVE operations are applied — on every request. A `HTTP_COOKIE` route also injects a `Set-Cookie` on every response |

An **omitted** `api_key_auth` is the one credential value that stays accelerable:
it declares nothing, a backend-owned `X-Api-Key` passes through untouched, and no
header is rewritten.

The pairing is refused from both sides, because either can come second:

- setting a `sockMapMode` on a service that already carries an L7 policy is
  rejected with 400;
- attaching an L7 policy to a service that declares a `sockMapMode` is rejected
  with 400.

The credential check uses the `api_key_auth` the service keeps after an update, so
an update that omits `api_key_auth` on a protected service is refused as well.

A snapshot restore of an older configuration that combines the two does not fail.
A service is restored with `sockMapMode` off and a warning. A restored L7 policy
whose service declares a mode is attached with a warning and the service is left
unaccelerated — the loadbalancer domain is applied before the policy domain, so
refusing there would abort the whole restore, and dropping the policy instead would
silently relax a header or routing decision.

Independently of the configuration check, the data plane declines to pair a
connection whose service carries a policy or a declared `api_key_auth`. That covers
the window where a policy is attached while connections are already live.

A further check happens per connection in the datapath: **only plaintext
HTTP→HTTP is accelerated.** If TLS is in play on either side — TLS termination,
TLS transit, or TLS origination — the connection falls back to the userspace
relay. Those paths use kTLS offload (`--ktlssupport`) instead.

## Kernel requirement

**The Linux kernel has a defect that makes sockmap redirect duplicate
transmitted data.** It is not a loxilb bug and loxilb cannot work around it.

### The defect

`sk_psock_backlog()` retries sends that could not complete inline. It saves the
partial-send progress in `psock->work_state`, restores it at the top of the
function — and then unconditionally overwrites it inside the loop:

```c
mutex_lock(&psock->work_mutex);
if (unlikely(state->len)) {
        len = state->len;      /* restores saved progress */
        off = state->off;
}

while ((skb = skb_peek(&psock->ingress_skb))) {
        len = skb->len;        /* immediately overwritten */
        off = 0;               /* off reset to 0 */
```

The retry therefore resends the skb from offset 0, and the bytes already
delivered go out a second time.

Upstream fix: commit `3b4f14b7` — *"bpf, sockmap: fix duplicated data
transmission"*.

### What it looks like

The duplicated bytes land in the middle of an HTTP chunk rather than on a chunk
boundary, so the framing offset breaks. Clients see a parse error followed by a
reset — with Node's llhttp, `HPE_STRICT` paired 1:1 with `ECONNRESET`.

Measured on an SSE streaming workload, unpaced burst traffic (~240 MB/s):

| | completed streams | failed | failure rate |
|---|---|---|---|
| `sockMapMode: both` | 56 793 | 5 194 | **8.38 %** |
| `sockMapMode: off` | 66 700 | 0 | 0.00 % |

A smaller number of streams survive with **silently duplicated content** — no
error is raised and the client accepts the duplicated bytes. That makes this a
data-integrity defect, not only an availability one.

The defect was reproduced with a standalone sockmap relay containing no loxilb
code at all, and each corruption correlated 1:1 with a `sk_psock_backlog()`
entry resuming from a non-zero offset.

### Affected versions

| series | status |
|---|---|
| 5.4.y, 5.10.y | **not affected** (predates the change that introduced the defect) |
| 5.15.y | fixed in **5.15.186** and later |
| 6.1.y | fixed in **6.1.142** and later |
| 6.6.y | fixed in **6.6.94** and later |
| **6.8.y** | **affected, never fixed upstream** (EOL) |
| **6.11.y** | **affected, never fixed upstream** (EOL) |
| 6.12.y | fixed in **6.12.34** and later |
| **6.13.y, 6.14.y** | **affected, never fixed upstream** (EOL) |
| 6.15.y | fixed in **6.15.3** and later |
| 6.16 and later | fixed |

The backports all landed in the same stable cycle, so a live LTS line is safe as
long as the point release is recent enough. The lines that stay exposed are the
EOL non-LTS ones — and those are where most distribution kernels sit:

- Ubuntu 24.04 GA and 22.04 HWE → 6.8 — **affected**
- Ubuntu 24.04 HWE → 6.11, then 6.14 — **affected**
- Ubuntu 22.04 GA → 5.15 — safe once the upstream base reaches 5.15.186

Note the inversion: the HWE kernel is more exposed than the GA kernel it
replaces.

RHEL 9 (5.14 plus heavy backporting) cannot be judged from this table; test it
directly.

### Checking your kernel

On Debian and Ubuntu, compare the upstream base against the table:

```
$ cat /proc/version_signature
Ubuntu 6.11.0-29.29~24.04.1-generic 6.11.11
                                    ^^^^^^^ upstream base
```

Elsewhere use `uname -r`. A distribution may have backported the fix without
bumping the base version, so also check the vendor changelog for `3b4f14b7`
before concluding a kernel is affected.

### A second defect, avoided by design

Kernels from v6.14, and the stable backports in 6.1.130, 6.6.80 and 6.12.17, have
a separate defect in `tcp_bpf_strp_read_sock()` (still present on mainline). On a
socket in a stream-verdict map, data the verdict passes up to the socket
(`SK_PASS`) can move the socket's `copied_seq` past the received data, after
which a small incoming segment no longer wakes the reader. loxilb never lets the
verdict pass data up: a socket is added to `sock_verdict_map` only once it has a
peer to redirect to. Kernels with this defect need nothing extra for sockmap
acceleration.

## Should you enable it?

| situation | recommendation |
|---|---|
| kernel affected (see table) | **leave it off.** No throughput gain justifies silent data corruption |
| kernel patched | enable it, starting with `response` on streaming services |
| kernel affected, cannot be changed | leave it off, or apply a livepatch of `sk_psock_backlog()` |

Corruption was not observed under paced traffic — connections whose byte rate is
limited by the application, such as LLM token streaming at a fixed token rate.
**Treat that as an observation, not a guarantee.** The trigger is a partial send
followed by a full socket send buffer, and any burst — a long context dump, a
client that stalls and then drains, a retry storm — can produce it.

## What you gain

Measured on an OpenAI-compatible SSE workload (512 concurrent streams paced at
25 tokens/s each, ~12.7k tokens/s, 206 B per token), comparing the same build
with acceleration on and off:

| | loxilb CPU | per token |
|---|---|---|
| `sockMapMode: off` | 0.407 cores | 32.3 µs |
| `sockMapMode: both` | 0.097 cores | 7.6 µs |

Latency was unchanged at this load — the benefit appears entirely as CPU.

Two caveats on reading this:

- **Softirq cost is unchanged.** Packets still traverse the TCP stack twice
  either way; acceleration removes the userspace hop, nothing else.
- **The ratio depends on how efficient the userspace relay is.** Measurements
  taken before the relay CPU fixes in this tree showed a ~14x gap rather than
  ~4x, because the userspace arm was paying for work that has since been
  removed. Compare against a current build.

## Verifying it is engaged

Configuring `sockMapMode` does not guarantee the connection is accelerated — the
eligibility rules above are applied per connection. Check what the datapath
holds:

```
bpftool map dump name sockmap_vip_portset
bpftool map dump name sockmap_ep_portset
bpftool map dump name sock_proxy_map
bpftool map dump name sock_verdict_map
bpftool map dump name sockmap_stats
```

| map | what it holds |
|---|---|
| `sockmap_vip_portset` | one entry per accelerated service: VIP address and port |
| `sockmap_ep_portset` | one entry per endpoint address and port of accelerated services |
| `sock_proxy_map` | every live socket of an accelerated service (redirect targets) |
| `sock_verdict_map` | the sockets of accelerated connections whose incoming direction is accelerated, added once their pair is in `peer_map` |
| `sockmap_stats` | verdict counters: redirects (total, request, response), peer misses |

After a `sockmapreset`, or after lowering a mode, `sock_verdict_map` and
`peer_map` return to the size they had before those connections existed. A
residue there is a leak worth reporting.

A non-zero peer miss count means a socket ran the verdict without a pair. The
proxy removes a socket from `sock_verdict_map` before its pair, so the count
stays at zero; a growing count is a bug worth reporting. The ineligible counter
is retired and always reads zero.

Each portset entry carries `refs` (accelerated services using it) and
`verdict_refs` (how many of them accelerate the direction a matching socket
receives: requests for a VIP entry, responses for an endpoint entry). The
datapath no longer reads `verdict_refs`; it is the loader's bookkeeping.

An empty `sock_proxy_map` under load means acceleration is not engaging; the
traffic is being relayed in userspace and the configuration is having no effect.

## Testing

`cicd/sockmap-fullproxy/` holds the testbed and validation scenarios:

| script | covers |
|---|---|
| `validation.sh` | BPF assets attach, rules register, offload engages, AI gateway services refuse a `sockMapMode` |
| `validation_concurrent.sh` | concurrent connection handling |
| `validation_directional.sh` | `request` / `response` modes, the unaccelerated direction skipping the verdict, portset cleanup |
| `validation_refcount.sh` | portset refcounts across in-place updates, mode changes and shared endpoints |
| `validation_request_path.sh` | h2c through every mode, split and streamed and pipelined requests, half-closed clients, mode change and delete under a live connection, no verdict pass |
| `validation_equivalence.sh` | what the client and the backend observe on an accelerated rule is identical to `off`: one rule per mode over one endpoint, compared record by record, plus chunked, pipelined, streamed, truncated, 204/304/HEAD and half-closed shapes |
| `validation_control.sh` | stopping acceleration on live connections: the action drops one rule's accelerated connections and nothing else, a mode reduction and a delete do the same, and the maps return to their baseline |
| `validation_perf.sh` | throughput, acceleration on vs off, on a pair of services sharing every port |
| `validation-cpu.sh` | CPU comparison on the same pair |
| `validation-sse-cpu.sh` | CPU per token on SSE streaming, including `request` / `response` arms |

Some cases in `validation_equivalence.sh` and `validation_control.sh` describe
where the feature is going rather than where it is: those report `XFAIL` with the
defect they are waiting on, and they turn the suite red (`XPASS`) once it is
fixed, which is the signal to drop the registration. A run that ends `[OK]` names
how many cases were xfailed.

`cicd/sockmap-fullproxy/minrepro/` is a standalone reproducer for the kernel
defect. It uses no loxilb code and can be submitted upstream as-is.

## Status

`--sockmapsupport` is experimental. It is off by default, and every service must
opt in individually. Until the kernel requirement can be enforced automatically,
operators are responsible for confirming their kernel carries the fix.
