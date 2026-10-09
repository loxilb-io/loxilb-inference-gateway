# cicd/security-kv-coexist — security features × KV-cache-aware routing coexistence gate

Proves that the kernel-side security controls (XDP ipfilter, XDP securityrate, TC firewall
fence for `allowedSources`) and the sockproxy-side controls (`connectionLimit`, api-key
policy, capacity admission) can all be switched on **against one fullproxy KV-exact P/D
service** without disturbing its routing: the allowed client keeps landing on the published
prefill endpoint with a Tier-1.5 hit while the other client is dropped, reset or denied at the
layer that owns the control.

Design and layer ownership: `docs/security/ddos-and-admission-fullproxy.md`; the check matrix
is the table below.

## Topology

Reuses `cicd/vllm-kvcache-routing-cpu` (6 reflect-echo EPs, 3 prefill at indices 0/2/4, one
fullproxy P/D rule with `kvExactMode=1` fed by the synthetic ZMQ publisher), plus:

```
 l3h1 10.10.10.1  allowed client   ──┐
 l3h2 11.11.11.2  the other client ──┤── llb1 (VIP 10.10.10.254:8080, -p prometheus)
 l3ep1..6         serverP0/D0/P1/D1/P2/D2 (reflect-echo, port 80)
```

## Checks

| # | Control (layer) | Other client | Allowed client's routing |
|---|---|---|---|
| C1 | none | served | Tier-1.5 → serverP0 |
| C2 | ipfilter blacklist (XDP) | SYN never answered; `loxilb_ipfilter_blacklist_packets_total` moves | unchanged |
| C3 | securityrate SYN/conn-rate (XDP) | `loxilb_security_{syn,conn}_blocked_total` move | unchanged, during the flood |
| C4 | `allowedSources` on the fullproxy rule (TC fence) | SYN dropped, `loxilb_fw_drop_packets_total` moves; the gateway log shows the allow (pref 65000) + drop (pref 64999) install and, on a replace without sources, both deletes; the other client is served again right after (the delete reached the kernel table); `GET /config/firewall/all` hides the pair like every source-check rule; snapshot does not carry them | unchanged |
| C5 | `connectionLimit=2` (sockproxy gauge) | 3rd connection reset at accept, from either client; `/stats` `activeConnections` = 2 then 0 (holders = idle keep-alive connections that sent one complete routed request) | unchanged after the holders close |
| C6 | `api_key_auth=required`, no store (policy denial) | 401/403/503 before selection: no tier selection, no Tier-1.5 hit | unchanged after lift |
| C7 | fc role cap after selection (capacity 429) | no `[PD_LOAD] … never taken` canary (L-D1) | unchanged after lift |
| C8 | keep-alive user switch | second user on the same connection does not ride the first user's Tier-0 pin (L-D4) | — |
| C9 | proxy-only instance | ipfilter / firewall / allowedSources POST → 400, never a silent Success | — |
| C10 | XDP attach mode | every attach logs its mode; `XDP_NATIVE=<if|all>` asks for native and logs the fallback (on a veth bed such as llbigw-2 only `eth0` takes native; every veth refuses flags 0x4 and falls back to generic with a WARN line, counted as `fallback=`) | — |
| C11 | snapshot persist → restore | rule reads back `connectionLimit` + sources, fence re-installed; `kvexactstatus` reports `REQUIRES_MIGRATION` (the documented recovery contract for a profile-less KV-exact rule: served through the normal tiers, exact tier fenced); a fresh create (hosturl DELETE + POST) lifts it | flat while fenced (by contract), Tier-1.5 again after the fresh create |
| C12 | C unit layers | `make test_felimit test_fc test_kv` | — |

Hard asserts gate the sentinel `SCENARIO-security-kv-coexist [OK]`; timing-sensitive
observations are `soft`.

## DDoS option matrix — `validation-ddos.sh`

Same topology, every DDoS-protection option exercised one at a time (sentinel
`SCENARIO-security-kv-coexist-ddos [OK]`). Each row: the option bites l3h2 at its layer, its
own counters move, the counters of the OTHER options do not, l3h1's Tier-1.5 routing is
unchanged in the same window, and l3h2 is served again once the option is off.

| # | Option (layer) | Pass condition |
|---|---|---|
| D1 | securityrate SYN threshold alone (XDP) | `syn_blocked` moves, `conn_blocked` does not; `syn_cookies` moves above `cookieThreshold` (a counter — the real cookies are the kernel's) |
| D2 | connection rate alone (XDP) | `conn_blocked` moves, `syn_blocked` does not |
| D3 | threshold boundary (XDP) | 30-SYN burst under a 200/s threshold: nothing blocked, ≥30 counted passed |
| D4 | whitelist bypass (XDP) | whitelisted flooder never limited; a non-whitelisted source still is; entry visible in the shared ipfilter map (soft) and gone with the config |
| D5 | UDP flood protection (XDP) | `udp_blocked` moves; TCP counters untouched; KV routing unchanged during the UDP flood |
| D6 | stacked ipfilter + securityrate | blacklist counter moves, securityrate counters do not (XDP order ipfilter → securityrate) |
| D7 | securityrate durability | GET reflects; persist → restore keeps the thresholds AND re-applies them to XDP (`Security rate config updated` line); a burst above the restored `ratePerSec=5` is blocked (the sequential burst runs at ~10/s, so the rate must be one it exceeds); the restored LB rule reports `REQUIRES_MIGRATION` and a fresh create lifts it |
| D8 | header-completion deadline `timeoutTcpInspect=22000` (proxy, slowloris; sized to outlive two stats ticks) | 5 partial-header holders (`TOTAL_INFLIGHT`-2 in the valve arm) are counted by the listener gauge (`activeConnections` = 5 with no limit set) → `loxilb_proxy_header_deadline_drops_total` += 5 within the deadline, gauge back to 0 |
| D9 | process accept valve `LLB_PD_MAX_TOTAL_INFLIGHT` (proxy) | only with `TOTAL_INFLIGHT=4 sudo ./config.sh`: next connection held in the backlog, `loxilb_proxy_accept_blocked_total` moves |
| D10 | `inactiveTimeOut=22` (proxy) | a keep-alive connection that sent one complete routed request is counted, then reaped after 22 s of silence, proven by the gateway's own `[IDLE_TIMEOUT]` line (an unrouted `GET /v1/models` is answered 503 and closed, so it never idles; the timeout outlives two 10 s stats ticks so the gauge can count the connection first) |
| D11 | oversize 2 MB body (proxy) | answered 200 (stream fallback) or 413 — never held or reset |
| D12 | operator TC firewall drop rule to the VIP | `fw_rule_drop` moves; composes with the `allowedSources` fence; served after delete |
| D13 | XDP mode under a SYN flood | loxilb CPU sampled for the record in the generic and native arms (soft); on a veth bed the flood enters on a veth, generic in both arms, so the two samples are not a native-vs-generic delta — that needs a NIC-ingress bed |

Not covered here (needs an SSE-capable backend): `max_stream_duration_sec`; covered by
`cicd/qos-fullproxy`: the byte shaper; by `cicd/ai-authsep`: per-key rate limit / token quota.

## Run (Linux testbed, e.g. llbigw-2)

```bash
export LOXILB_DOCKER_IMAGE=loxilb-inference-gateway:<your-build>
cd cicd/security-kv-coexist
sudo ./config.sh            # XDP_NATIVE=all sudo ./config.sh  for the native-XDP arm (C10); config.sh records
                            # XDP_NATIVE / TOTAL_INFLIGHT in .arm-env for the validation scripts
sudo ./validation.sh
sudo ./validation-ddos.sh        # TOTAL_INFLIGHT=4 sudo ./config.sh first for the D9 arm
./rmconfig.sh
```

The publisher needs `pyzmq cbor2 xxhash transformers` on the host (config.sh installs them).
