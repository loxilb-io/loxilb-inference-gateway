# Monitoring live-test guide — real traffic through the cicd topology into Grafana

How to stand up the reference monitoring stack against the
`cicd/vllm-kvcache-routing-cpu` topology, drive **real** traffic through the
datapath, and verify what you see in Grafana against data-plane ground truth.
This is the workflow used for the dashboard live-validation program; the
companion automation is `cicd/vllm-kvcache-routing-cpu/monitoring-redeploy.sh`.

Everything here runs **on the host that runs the cicd containers**.

---

## 1. One-time bring-up

```bash
# 1. topology: llb1 + client (l3h1) + 6 endpoints (l3ep1-6) + the KV :8080 rule
cd cicd/vllm-kvcache-routing-cpu && ./config.sh

# 2. monitoring stack (host network: prometheus :9090, grafana :3000,
#    credentials come from deploy/monitoring/.env)
cd ../../deploy/monitoring && docker compose up -d

# 3. metrics, extra rules, continuous traffic, prometheus target, verification
cd ../../cicd/vllm-kvcache-routing-cpu && ./monitoring-redeploy.sh up
```

If Grafana runs on a remote host, tunnel: `ssh -L 3000:localhost:3000 -L 9090:localhost:9090 <host>`.

`monitoring-redeploy.sh up` exists because `config.sh` alone is not enough for
monitoring work; it closes exactly these gaps:

| Gap after a bare `config.sh` | Consequence if skipped |
|---|---|
| loxilb starts **without** `-p` | `/netlox/v1/metrics` answers 503, every panel empty |
| only the KV `:8080` rule exists (unnamed) | no per-service panels (those need a **named** rule), no L4 echo target |
| no traffic generators | dashboards technically "work" but show flat zero |
| `prometheus.yml` targets llb1's **old** bridge IP | scrape target down after container re-creation |

## 2. The continuous generators (what feeds which panel)

Six transient systemd units run 24/7 (`systemctl status <unit>`; they do NOT
survive reboot or teardown — re-arm with `monitoring-redeploy.sh up`):

| Unit | Traffic | Feeds |
|---|---|---|
| `gen-traffic-loop` | KV completions to `:8080` (3 prompt classes → EP-A/B/C) + SSE streams to `:2020`, forever | AI Gateway dashboard (KV routing, PD, SSE), L7 proxy panels |
| `gen-traffic-l4` | one slow keepalive HTTP conn to `l4-echo :2222`, recycled ~60s | conntrack-derived L4 panels (active flows, top clients/endpoints) |
| `kvpub-epA/B/C` | KV-cache event publishers (ZMQ :5557) on endpoints A/B/C, republish every 30s | KV subscribers / ZMQ panels |
| `sse-mock` | SSE backend behind the `:2020` rule | makes SSE streams real |

Why both L4 generators matter: per-client/per-endpoint (sip/dip) breakdowns are
conntrack-sweep derived — **only flows alive across a 10s sweep boundary are
visible there**, so the keepalive generator is required for those panels. The
aggregate `processed_*` / `service_traffic_*` counters are fed from the exact
DP rule counters and count *all* flows, including sub-second ones.

## 3. Manual drills → expected panel effects

Wait ~20–30s after each drill (10s collector sweeps), view with a ≤30 min range.

```bash
cd cicd/vllm-kvcache-routing-cpu

# KV routing burst -> AI Gateway: requests/s, KV hit/route panels
./gen-traffic.sh kv 20

# SSE burst -> AI Gateway SSE panels + L7: responses by status, TTFB SLO shares
./gen-traffic.sh sse 20

# Short-connection storm -> L4 "Service throughput" (service=l4-echo) jumps;
# also proves exact aggregate accounting (see §4)
docker exec l3h1 sh -c 'for i in $(seq 1 200); do curl -s --max-time 2 -o /dev/null http://10.10.10.254:2222/; done'

# Firewall drill -> Security: "FW drops/s" spike + "Top dropping FW rules" row.
# The scoped rule below drops only TCP to the VIP's unused :2223.
docker exec llb1 curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/firewall \
  -H 'Content-Type: application/json' \
  -d '{"ruleArguments":{"destinationIP":"10.10.10.254/32","minDestinationPort":2223,"maxDestinationPort":2223,"protocol":6,"preference":400},"opts":{"drop":true}}'
docker exec l3h1 sh -c 'for i in $(seq 1 30); do curl -s --max-time 0.5 -o /dev/null http://10.10.10.254:2223/; done'
# expect fw_drop_packets_total delta == 30 (each --max-time 0.5 curl = exactly 1 SYN)
docker exec llb1 loxicmd delete firewall --destinationIP=10.10.10.254/32 2>/dev/null || \
docker exec llb1 curl -s -X DELETE "http://127.0.0.1:11111/netlox/v1/config/firewall?destinationIP=10.10.10.254%2F32&minDestinationPort=2223&maxDestinationPort=2223&protocol=6&preference=400"
```

Security-feature drills (SYN/UDP flood, conn-rate, ipfilter) with exact
expected counters are encoded in `cicd/secfilter/validation.sh` (enforcement
legs) — use those recipes verbatim. **Trap:** whitelisted sources are exempt
from ALL securityrate limiting by design; drive attack traffic from a
non-whitelisted source.

## 4. Verifying panels against ground truth

- **DP rule counters** (authoritative): `docker exec llb1 loxicmd get lb -o wide`
  — the COUNTERS column (`packets:bytes`, cumulative). A window delta there
  must match the same window's delta of `loxilb_service_traffic_*` /
  `loxilb_processed_*` within ±1 sweep.
- **Exporter truth** (before Prometheus/Grafana enter the picture):
  `docker exec llb1 curl -s http://127.0.0.1:11111/netlox/v1/metrics | grep <metric>`
- **PromQL spot checks**: `http://localhost:9090/graph`; alert states at `/alerts`.
- Regression to watch: unnamed-rule traffic must never produce `service=""` or
  `service="-"` series (placeholder rows on L4 panels).

## 5. Re-run after cicd cleanup

```bash
cd cicd/vllm-kvcache-routing-cpu
./monitoring-redeploy.sh stop      # stop generators BEFORE teardown (they exec into the containers)
./rmconfig.sh                      # tear down topology
./config.sh                        # rebuild topology
./monitoring-redeploy.sh up        # metrics + rules + generators + prometheus retarget + verify
```

The monitoring stack itself survives cicd teardown (separate compose, host
network) — `monitoring-redeploy.sh` only re-points its scrape target at llb1's
new bridge IP and reloads.

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Every panel empty, scrape target down | loxilb metrics disabled (503). `./monitoring-redeploy.sh up`, or `POST /netlox/v1/config/metrics` |
| Panels stuck "Loading plugin panel…" after a grafana container swap | stale cached bundle — hard-reload the browser (Cmd+Shift+R). Root cause (stale preinstalled plugins) is fixed by `GF_PLUGINS_PREINSTALL_DISABLED` + the 11.6.16 pin; existing grafana-data volumes need the old plugin dirs removed once |
| `up{job="loxilb"} == 0` after redeploy | llb1 bridge IP changed; `monitoring-redeploy.sh up` re-points `prometheus/prometheus.yml` |
| Per-service panels empty despite traffic | rule is unnamed — per-service series exist for **named** rules only (`--name=...`) |
| Top clients / endpoint breakdowns flat while throughput moves | breakdowns are persistent-flow views (conntrack sweep); short-lived conns don't register there — expected, use the keepalive generator |
| A `mode=fullproxy` rule POSTed right after loxilb start returns 200 but is absent from `get lb` | sockproxy init race — verify and re-POST (the script's `ensure_rule` does settle-verify-retry) |
| Re-POSTing an existing rule duplicates it | check `loxicmd get lb -o json` counts before replaying rule dumps |
| "stale eBPF generation: N sec_rate_cfg map instances" warning in the dp log | a previous container run leaked its BPF program/map generation; the *attached* programs still use the pinned live set, but stale map contents can mislead debugging. Inspect `bpftool map show name sec_rate_cfg`; remove stale non-attached pin dirs |
| dp log seems to miss startup lines | it rotates quickly under DEBUG — check `/var/log/loxilbdp-*.log.gz` archives |
