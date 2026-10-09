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
| C4 | `allowedSources` on the fullproxy rule (TC fence) | SYN dropped, `loxilb_fw_drop_packets_total` moves; `GET /config/firewall/all` shows allow pref 65000 + drop pref 64999 on the VIP; replace without sources removes both; snapshot does not carry them | unchanged |
| C5 | `connectionLimit=2` (sockproxy gauge) | 3rd connection reset at accept, from either client; `/stats` `activeConnections` = 2 then 0 | unchanged after the holders close |
| C6 | `api_key_auth=required`, no store (policy denial) | 401/403/503 before selection: no tier selection, no Tier-1.5 hit | unchanged after lift |
| C7 | fc role cap after selection (capacity 429) | no `[PD_LOAD] … never taken` canary (L-D1) | unchanged after lift |
| C8 | keep-alive user switch | second user on the same connection does not ride the first user's Tier-0 pin (L-D4) | — |
| C9 | proxy-only instance | ipfilter / firewall / allowedSources POST → 400, never a silent Success | — |
| C10 | XDP attach mode | every attach logs its mode; `XDP_NATIVE=<if|all>` asks for native and logs the fallback | — |
| C11 | snapshot persist → restore | rule reads back `connectionLimit` + sources, fence re-installed | unchanged |
| C12 | C unit layers | `make test_felimit test_fc test_kv` | — |

Hard asserts gate the sentinel `SCENARIO-security-kv-coexist [OK]`; timing-sensitive
observations are `soft`.

## Run (Linux testbed, e.g. llbigw-2)

```bash
export LOXILB_DOCKER_IMAGE=loxilb-inference-gateway:<your-build>
cd cicd/security-kv-coexist
sudo ./config.sh            # XDP_NATIVE=all sudo ./config.sh  for the native-XDP arm (C10)
sudo ./validation.sh
./rmconfig.sh
```

The publisher needs `pyzmq cbor2 xxhash transformers` on the host (config.sh installs them).
