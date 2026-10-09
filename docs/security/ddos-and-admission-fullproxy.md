# DDoS protection and admission for fullproxy (L7 / AI) services — operator guide

A fullproxy service (`mode: 4`) terminates the client TCP connection in the kernel and
hands it to the userspace proxy, which parses the request and chooses the endpoint
(KV-cache-aware routing). Protection against unwanted traffic is layered so that each
layer stops what it is best placed to stop, and the routing layer only ever sees
requests that every layer admitted:

| Layer | Control | Configured by | What it stops |
|---|---|---|---|
| XDP (every ingress NIC) | ipfilter blacklist / whitelist | `POST /config/ipfilter` | packets from listed sources, before conntrack, routing, the socket and TLS |
| XDP | securityrate: per-source SYN rate, new-connection rate, UDP rate | `POST /config/securityrate` | floods from a single source |
| TC (ingress) | firewall rules; the `allowedSources` fence of a fullproxy rule | `POST /config/firewall`, `allowedSources` on the rule | sources not allowed to a specific VIP:port — the SYN is dropped before the kernel socket |
| Kernel socket | SYN cookies, listen backlog | `sysctl` (below) | SYN floods that pass the per-source limits (distributed) |
| Proxy (accept) | `connectionLimit` of the rule | `connectionLimit` on the rule | more concurrent client connections than the service should carry; the (N+1)th is reset at once |
| Proxy (request) | API-key / JWT policy, per-key rate limit and token quota, capacity admission (`fc_*`) | the rule's `api_key_auth`, the policy store, `fc_mode`/`fc_*` | unauthenticated, over-quota and over-capacity requests, with 401/403/429 before any endpoint is chosen |

Nothing on the fullproxy path bypasses XDP or TC: the proxy's own listener is reached
only after both. The routing tiers (Tier-0 session, Tier-1 prefix, Tier-1.5 KV-exact,
Tier-2 load) run after admission and are not mutated by a denial.

## Kernel socket settings (not set by loxilb)

The kernel, not loxilb, completes the TCP handshake of a fullproxy VIP, so the kernel's
own SYN defenses are what protect the listener once per-source limits are passed.
The securityrate `syn_cookies` counter reports how often the SYN threshold was exceeded;
it does not issue cookies. Set on the loxilb host (or the container's network namespace
with `--net=host`):

```
net.ipv4.tcp_syncookies = 1          # issue SYN cookies when the backlog overflows
net.ipv4.tcp_max_syn_backlog = 8192  # size to the expected new-connection burst
net.core.somaxconn = 8192            # the proxy listens with SOMAXCONN
net.ipv4.tcp_synack_retries = 2      # shorten half-open lifetimes under a flood
```

## securityrate for LLM clients

LLM clients open few connections and keep them (keep-alive, HTTP/2, long SSE streams).
Only SYNs count toward the SYN and new-connection limits, so steady traffic costs
nothing, but an agent fan-out or a pool of clients behind one NAT address can exceed the
per-source defaults (100 SYN/s, 50 new connections/s). Raise `synThreshold` and
`ratePerSec` to above the legitimate new-connection rate of your largest single source,
and whitelist only true client ranges:

```json
POST /config/securityrate
{"synEnabled":true,"synThreshold":500,"cookieThreshold":50,
 "connRateEnabled":true,"ratePerSec":200,
 "udpEnabled":false,"udpPktThreshold":1000,"udpBandwidthMB":100,
 "whitelistIps":["10.0.0.0/8"]}
```

## ipfilter: never fence the backend leg

ipfilter and securityrate run on every ingress interface and look only at the source
address. The proxy's own backend connections return on the same interfaces, as do the
KV-event streams from the engines, health-probe replies and cluster peers. A
`blacklist 0.0.0.0/0 + whitelist <clients>` default-deny therefore also drops the backend
replies and shows up as endpoints going down, not as a security event. Blacklist
offending ranges; put the VIP-scoped allow list on the rule instead:

```json
POST /config/loadbalancer
{"serviceArguments":{"externalIP":"10.10.10.254","port":8080,"protocol":"tcp","mode":4, ...},
 "allowedSources":[{"prefix":"10.0.0.0/8"},{"prefix":"192.0.2.0/24"}],
 "endpoints":[...]}
```

For a fullproxy rule this installs a per-VIP fence in the TC firewall (allow rules for the
listed sources at preference 65000 and a catch-all drop at 64999, both scoped to
`VIP/32:port`), so a SYN from any other source is dropped before the kernel socket. The
fence follows the rule's sources on replace, goes with the rule on delete, and is not
part of configuration snapshots. Like every rule the gateway installs for a source check,
it is hidden from `GET /config/firewall/all`; its install and delete are in the gateway
log (`fw-rule added ... dst-<VIP>/32,...,dport-<port>,-allow|-drop`) and its drops count
in `loxilb_fw_drop_packets_total`. User firewall rules at preference 64999 or above are
evaluated before the fence; keep operator rules below that band.

## connectionLimit on a fullproxy rule

`connectionLimit: N` on a fullproxy rule is enforced by the listener at accept: the
(N+1)th concurrent client connection is reset immediately (an LLM client sees a refused
connection in one round trip instead of a timeout) and counted in the loxilb log as
`[FE_CONN_LIMIT]`. `GET .../stats` reports `activeConnections` from the same gauge, with
or without a limit (the gauge is kept for every fullproxy listener; a NAT rule has
conntrack for this, a proxied flow has nothing else). `0` is unlimited: nothing is ever
refused. Pair it with `fc_max_outstanding` / `fc_max_queue_depth` for request-level
capacity, and with `LLB_PD_MAX_TOTAL_INFLIGHT` for the process-wide valve.

## timeoutTcpInspect (header-completion deadline)

A client that opens a connection and never completes its request headers (slowloris) is
dropped once `timeoutTcpInspect` (ms, default 10000) has elapsed since its first header
byte, whether it keeps trickling bytes or goes silent; the drop is counted in
`loxilb_proxy_header_deadline_drops_total`. The deadline measures the header block only:
it is keyed on the request's headers being complete, not on the `Host` header having been
seen, so sending `Host:` first does not disarm it. It never bounds a body upload.

## inactiveTimeOut (idle reap)

A fullproxy rule's `inactiveTimeOut` (seconds) reaps a client connection that has been
silent that long: the clock is armed at accept and restarted by every client byte and by
every backend byte relayed to the client, so an idle keep-alive connection that completed
its last request is closed by the gateway, not only by the client's own timer (log line
`[IDLE_TIMEOUT] fd=<n>: idle=<s>s >= timeout=<s>s`). It is independent of the sticky-
session / L7 member-data clock (`timeoutMemberData`), which only a routed request arms.
`activeConnections` reflects the reap at the next stats refresh (10 s). When an L7 policy
with `timeoutMemberData` is attached, that deadline governs the rule's connections instead
of `inactiveTimeOut`.

## KV-exact rules and `POST /config/restore`

A KV-exact rule restored without a `kvModelProfile` comes back `REQUIRES_MIGRATION`
(`GET .../kvexactstatus`): it is served through the normal routing tiers with the exact
tier fenced, by contract. Attach a profile, or re-create the rule (the hosturl `DELETE`
with `model_name`, then `POST`), to bring the exact tier back; a replace keeps the
restored identity. Security settings (`securityrate`, ipfilter, firewall rules, the
`allowedSources` fence) are re-applied to the datapath by the restore.

## Proxy-only mode

`--proxyonlymode` runs without the eBPF datapath. ipfilter, firewall rules, securityrate
and `allowedSources` are refused with HTTP 400 in that mode rather than accepted and not
enforced; `connectionLimit` and every proxy-level control still apply.

## Native XDP

By default the XDP program is attached in generic (skb) mode on every interface, which
needs no driver support; drops still happen before conntrack, routing, the socket and
TLS. `--xdp-native eth0,eth1` (or `all`) attaches in native (driver) mode on the listed
interfaces for drops before skb allocation; an interface whose driver refuses falls back
to generic with a warning, and the mode in force is logged per interface
(`xdp: ... attached in native (driver) mode on eth0`). `ip link show eth0` shows `xdp`
for native and `xdpgeneric` for generic.
