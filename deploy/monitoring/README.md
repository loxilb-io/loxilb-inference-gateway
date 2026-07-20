# LoxiLB Inference Gateway — Monitoring Stack (Prometheus + Grafana)

Operator monitoring for a loxilb-inference-gateway instance. Design and panel/alert
rationale: [`docs/MONITORING-DESIGN.md`](../../docs/MONITORING-DESIGN.md).

## Quick start

```bash
cd deploy/monitoring

# 1. Grafana admin credentials
cp .env.example .env            # then edit the password

# 2. mTLS certificates — SANs must cover the address Prometheus scrapes
./certs/gen-certs.sh <loxilb-ip> [more SANs...]
#    e.g. ./certs/gen-certs.sh 172.17.0.2 10.10.10.254 llb1

# 3. Install server cert + CA into the loxilb container and (re)start loxilb
docker cp certs/server.crt llb1:/opt/loxilb/cert/server.crt
docker cp certs/server.key llb1:/opt/loxilb/cert/server.key
docker cp certs/rootCA.crt llb1:/opt/loxilb/cert/rootCA.crt
docker exec llb1 pkill loxilb
docker exec -dt -e TLS_CA_CERTIFICATE=/opt/loxilb/cert/rootCA.crt \
  llb1 /root/loxilb-io/loxilb/loxilb --tls
#    NOTE: --tls-ca only exists on the API sub-parser; always pass the CA via
#    the TLS_CA_CERTIFICATE env var. With it set, the API requires a client
#    cert signed by our CA (mutual TLS).

# 4. Point prometheus/prometheus.yml `targets` at <loxilb-ip>:8091, then:
docker compose up -d

# 5. Enable metrics collection (endpoint answers 503 until enabled)
curl --cacert certs/rootCA.crt --cert certs/client.crt --key certs/client.key \
  -X POST https://<loxilb-ip>:8091/netlox/v1/config/metrics
```

- Prometheus: `http://<host>:9090` — Grafana: `http://<host>:3000` (credentials from `.env`).
- Dashboards are provisioned from `grafana/dashboards/` into the **LoxiLB** folder.

## Security notes

- **`--tls` keeps the plain HTTP listener (`:11111`) open.** mTLS on `:8091` protects
  nothing if `:11111` is reachable — in production bind it to localhost
  (`--host 127.0.0.1`) or firewall it. On the cicd testbed `:11111` stays open on
  purpose (cicd scripts use it).
- `certs/rootCA.key` signs everything: keep it out of images/repos (the whole certs
  dir is git-ignored except `gen-certs.sh`). In production, generate on a trusted
  host and distribute only the leaf certs + `rootCA.crt`.
- The Prometheus container runs as root solely to read the 0600 `client.key`
  bind-mount; alternatively `chown 65534 certs/client.key` and drop the
  `user: "0"` line in `docker-compose.yml`.
- Verify mTLS is actually enforced (T0 matrix): a curl **without** `--cert` must
  fail the handshake; with a foreign-CA cert it must be rejected.

## Operational notes

- Scrape interval is 10 s to match loxilb's internal stats sweep — don't lower it.
- `up == 0` has two meanings: process/network down, or metrics collection disabled
  (HTTP 503). The `LoxilbScrapeDown` alert runbook covers both.
- Conntrack-derived panels (active sessions, L4 traffic counters) only reflect
  **established** sessions; short-lived connections may never appear.
- On the cicd testbed, any scenario `config.sh` **recreates the llb1 container** —
  re-run step 3 (cert install + TLS restart) afterwards, or pass
  `--extra-opts "--tls"` where the scenario supports it. If the scenario dir has a
  `cert/` folder, common.sh bind-mounts it over `/opt/loxilb/cert/` — install the
  monitoring certs into that host dir instead of `docker cp`.
- **Name your LB rules** (`loxicmd create lb ... --name=<svc>`): unnamed rules produce
  empty `servName` in conntrack, so per-service metrics (`loxilb_service_*`, `service`
  labels) never appear for them.
- **Configure real endpoint probes** for health metrics/alerts: `--monitor` alone leaves
  endpoints unprobed (`ptype none`, state frozen at `ok`). Use
  `loxicmd create endpoint <ip> --name=<ip>_tcp_<port> --probetype=tcp
  --probeport=<port> --period=10 --retries=2`.
- Conntrack-derived panels (active sessions, `loxilb_requests_total`, traffic bytes)
  only see sessions that live past the 10 s sweep — short-lived request/response
  traffic legitimately reads 0 there (L7 proxy/AI metrics cover that traffic instead).
