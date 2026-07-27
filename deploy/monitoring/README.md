# LoxiLB Inference Gateway — Monitoring Stack (Prometheus + Grafana)

Operator monitoring for a loxilb-inference-gateway instance. Design and panel/alert
rationale: [`docs/MONITORING-DESIGN.md`](../../docs/MONITORING-DESIGN.md).

## Quick start (default — same-host, network-isolated scrape)

Run this stack **on the loxilb host** and scrape the plain REST listener over localhost.
The metrics endpoint is a control-plane REST route: loxilb's supported mTLS is the
**data-path / per-LB-rule** feature and does not apply here, so we don't use TLS as an auth
mechanism (see [`docs/MONITORING-DESIGN.md`](../../docs/MONITORING-DESIGN.md) §2 / F11).

```bash
cd deploy/monitoring

# 1. Grafana admin credentials
cp .env.example .env            # then edit the password

# 2. Keep loxilb's plain listener host-local (bind to localhost or firewall :11111).
#    prometheus.yml already targets 127.0.0.1:11111 over http.
docker compose up -d

# 3. Enable metrics collection (endpoint answers 503 until enabled)
curl -X POST http://127.0.0.1:11111/netlox/v1/config/metrics
```

- Prometheus: `http://<host>:9090` — Grafana: `http://<host>:3000` (credentials from `.env`).
- Dashboards are provisioned from `grafana/dashboards/` into the **LoxiLB** folder.

## Security notes

- **The metrics endpoint is control-plane and shares loxilb's API auth.** When an API auth
  mode is enabled (`--userservice`/`--oauth2`/manual-token), the go-swagger `Bearer` check
  runs in the handler on **every** listener — so `/metrics` returns 401 on both `:11111` and
  `:8091` without a token (finding F11). Our supported mTLS is data-path only and cannot
  protect this route.
- **Default posture = network isolation.** Bind loxilb's plain listener to localhost
  (`--host 127.0.0.1`) or firewall `:11111`, and run Prometheus on the same host. No certs,
  no tokens. (On the cicd testbed `:11111` stays open on purpose — cicd scripts use it.)
- **If API auth is enabled**, the scraper must send `Authorization: Bearer <token>`. loxilb
  user JWTs are short-lived (~24 h) and there is no long-lived service token today — rely on
  network isolation, accept token rotation, or track a future service-token/metrics-exempt
  feature. Do not enable auth and expect an unattended scrape to keep working.

## Optional: transport encryption across a network

Only if you must scrape loxilb across an untrusted network. This encrypts the channel; it
does **not** authenticate the scraper (auth still follows the rule above). The `--tls-ca`
client-cert path is stock go-swagger transport hardening, not a product auth boundary.

```bash
# 1. Certs — SANs must cover the address Prometheus scrapes
./certs/gen-certs.sh <loxilb-ip> [more SANs...]

# 2. Install server cert + CA and (re)start loxilb with --tls
docker cp certs/server.crt llb1:/opt/loxilb/cert/server.crt
docker cp certs/server.key llb1:/opt/loxilb/cert/server.key
docker cp certs/rootCA.crt llb1:/opt/loxilb/cert/rootCA.crt
docker exec llb1 pkill loxilb
docker exec -dt -e TLS_CA_CERTIFICATE=/opt/loxilb/cert/rootCA.crt \
  llb1 /root/loxilb-io/loxilb/loxilb --tls
#    (--tls-ca is only on the API sub-parser; pass the CA via TLS_CA_CERTIFICATE.)

# 3. In docker-compose.yml uncomment the cert bind-mounts + `user: "0"`, and in
#    prometheus.yml switch to the commented https/:8091 block. Then:
docker compose up -d
```

- `certs/rootCA.key` signs everything — keep it out of images/repos (the certs dir is
  git-ignored except `gen-certs.sh`). Generate on a trusted host; distribute only leaf
  certs + `rootCA.crt`.

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
