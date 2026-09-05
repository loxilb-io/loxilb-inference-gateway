#!/bin/bash
# CICD scenario: monitoring (Tier 1 of the internal monitoring CI plan)
# Stands up loxilb + the shipped Prometheus/Grafana stack and validates the
# three correctness surfaces (exporter, Prometheus, Grafana) against ground
# truth the driver controls.
#
# Topology:
#   l3h1 (10.10.10.1) ── llb1 (VIP 10.10.10.254) ── l3ep1 (31.31.31.1, SSE mock :8080)
#                                                 ── l3ep2 (32.32.32.1, plain HTTP :8080,
#                                                           RST server :8081)
# Rules:
#   VIP:2020 AI L7, sse_mode=true,  model sse-test   → l3ep1:8080  (SSE ground truth)
#   VIP:2021 AI L7, sse_mode=false, model nosse-test → l3ep2:8080  (non-SSE recording guard)
#   VIP:2023 plain L4 TCP                            → l3ep2:8080  (conntrack hold-driver)
#   VIP:2024 plain L4 TCP                            → l3ep2:8081  (server-RST error guard)
#
# Prometheus + Grafana run via docker-compose.ci.yml (host network) scraping
# llb1's docker bridge IP — the same layout deploy/monitoring documents for a
# host-local scrape. Config surface under test is deploy/monitoring/ verbatim
# (rules, dashboards, provisioning); only the scrape target is CI-generated.

source ../common.sh
echo SCENARIO-monitoring

## ── Spawn containers ────────────────────────────────────────────────────────
spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type host   --dock-name l3h1
spawn_docker_host --dock-type host   --dock-name l3ep1
spawn_docker_host --dock-type host   --dock-name l3ep2

## ── Connect hosts ───────────────────────────────────────────────────────────
connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1

sleep 5

## ── Configure IP addresses ──────────────────────────────────────────────────
config_docker_host --host1 l3h1  --host2 llb1  --ptype phy --addr 10.10.10.1/24   --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1  --ptype phy --addr 31.31.31.1/24   --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1  --ptype phy --addr 32.32.32.1/24   --gw 32.32.32.254
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1  --host2 l3ep2 --ptype phy --addr 32.32.32.254/24

## ── Routes ──────────────────────────────────────────────────────────────────
add_route l3h1  31.31.31.0/24 10.10.10.254
add_route l3h1  32.32.32.0/24 10.10.10.254
add_route l3ep1 10.10.10.0/24 31.31.31.254
add_route l3ep2 10.10.10.0/24 32.32.32.254

## ── Backends ────────────────────────────────────────────────────────────────
# SSE mock (shared with the ai-sse-quota scenario)
$hexec l3ep1 python3 $(pwd)/../ai-sse-quota/mock_sse_server.py &
# Plain HTTP backend
$hexec l3ep2 node ../common/tcp_server.js server-nosse &
# Abortive-close server (F7/F13 guard)
$hexec l3ep2 python3 $(pwd)/rst_server.py 8081 &
sleep 2

## ── Wait for loxilb REST API ────────────────────────────────────────────────
echo "Waiting for loxilb REST API..."
for i in $(seq 1 30); do
  if $hexec l3h1 curl -sf http://10.10.10.254:11111/netlox/v1/version >/dev/null 2>&1; then
    echo "loxilb REST API ready (${i})"
    break
  fi
  sleep 2
done

## ── LB rule 1: VIP:2020 → AI L7, SSE mode (l3ep1:8080) ─────────────────────
$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":      "10.10.10.254",
      "port":             2020,
      "protocol":        "tcp",
      "sel":              0,
      "mode":             4,
      "host":            "10.10.10.254",
      "path_prefix":     "/",
      "path_match_mode": "prefix",
      "model_name":      "sse-test",
      "sse_mode":         true,
      "inactiveTimeOut":  60
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}
    ]
  }'

## ── LB rule 2: VIP:2021 → AI L7, non-SSE (l3ep2:8080) ──────────────────────
# Regression guard: plain-JSON (non-SSE) AI responses must be recorded in
# loxilb_ai_requests_total.
$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":      "10.10.10.254",
      "port":             2021,
      "protocol":        "tcp",
      "sel":              0,
      "mode":             4,
      "host":            "10.10.10.254",
      "path_prefix":     "/",
      "path_match_mode": "prefix",
      "model_name":      "nosse-test",
      "sse_mode":         false,
      "inactiveTimeOut":  60
    },
    "endpoints": [
      {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
    ]
  }'

## ── LB rule 3: VIP:2023 → plain L4 (conntrack hold-driver) ─────────────────
## Named: only NAMED rules export the per-service L4 series
## (loxilb_service_requests_total etc.) that the "Requests/s per service"
## panel and the per-backend traffic panels consume — the T9 required-panel
## assertion depends on it.
create_lb_rule llb1 10.10.10.254 --tcp=2023:8080 --endpoints=32.32.32.1:1 --name=l4-echo

## ── LB rule 4: VIP:2024 → plain L4 (server-RST error guard) ────────────────
create_lb_rule llb1 10.10.10.254 --tcp=2024:8081 --endpoints=32.32.32.1:1 --name=l4-rst

## ── Enable the metrics endpoint ─────────────────────────────────────────────
$hexec l3h1 curl -s -X POST http://10.10.10.254:11111/netlox/v1/config/metrics >/dev/null

## ── Prometheus + Grafana (CI profile) ───────────────────────────────────────
LLB1_IP=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' llb1)
echo "llb1 bridge IP: $LLB1_IP"

# CI scrape config = the shipped one with the target repointed at llb1.
sed "s/127\.0\.0\.1:11111/${LLB1_IP}:11111/" \
  ../../deploy/monitoring/prometheus/prometheus.yml > prometheus-ci.yml

docker compose -f docker-compose.ci.yml up -d

echo "Waiting for Prometheus first successful scrape..."
scrape_ok=0
for i in $(seq 1 30); do
  v=$(curl -s "http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22loxilb%22%7D" \
      | python3 -c 'import sys,json;r=json.load(sys.stdin)["data"]["result"];print(r[0]["value"][1] if r else "")' 2>/dev/null)
  if [ "$v" = "1" ]; then
    echo "Prometheus scraping loxilb (up==1, ${i})"
    scrape_ok=1
    break
  fi
  sleep 3
done
if [ "$scrape_ok" != "1" ]; then
  echo "WARNING: Prometheus never reached up==1 during config — validation will fail T0"
fi

echo "Waiting for Grafana..."
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:3000/api/health >/dev/null 2>&1; then
    echo "Grafana ready (${i})"
    break
  fi
  sleep 3
done

echo "config.sh done"
