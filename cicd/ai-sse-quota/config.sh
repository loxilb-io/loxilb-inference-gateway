#!/bin/bash
# CICD scenario: ai-sse-quota
# Tests AI Gateway SSE connection tuning: stream survival past
# inactiveTimeOut, [DONE] terminator detection, MaxStreamDurationSec hard cap,
# and fragmentation safety.
#
# Topology:
#   l3h1 (10.10.10.1) ── llb1 (VIP 10.10.10.254) ── l3ep1 (31.31.31.1, SSE mock)
#                                                   ── l3ep2 (32.32.32.1, plain HTTP)
#
# NOTE: SSE-only scenario — no --userservice, no MariaDB (avoids auth/DB complexity).

source ../common.sh
echo SCENARIO-ai-sse-quota

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

## ── Start mock SSE backend on l3ep1 (port 8080) ────────────────────────────
$hexec l3ep1 python3 $(pwd)/mock_sse_server.py &
sleep 2

## ── Start simple HTTP backend on l3ep2 (port 8080) ─────────────────────────
$hexec l3ep2 node ../common/tcp_server.js server-nosse &
sleep 2

## ── Wait for loxilb REST API ────────────────────────────────────────────────
echo "Waiting for loxilb REST API..."
for i in $(seq 1 30); do
  if $hexec l3h1 curl -sf http://10.10.10.254:11111/netlox/v1/version >/dev/null 2>&1; then
    echo "loxilb REST API ready (${i}s)"
    break
  fi
  sleep 2
done

## ── LB rule 1: VIP:2020 → SSE mode (l3ep1:8080) ───────────────────────────
# sse_mode=true → suppresses inactiveTimeOut during active SSE stream
# max_stream_duration_sec=120 → hard cap for runaway streams
# backend_keepalive_interval_sec=30 → TCP keepalive towards backend
# Five required fields: mode=4, host, path_prefix, path_match_mode, model_name
$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":                    "10.10.10.254",
      "port":                           2020,
      "protocol":                      "tcp",
      "sel":                            0,
      "mode":                           4,
      "host":                          "10.10.10.254",
      "path_prefix":                   "/",
      "path_match_mode":               "prefix",
      "model_name":                    "sse-test",
      "sse_mode":                       true,
      "max_stream_duration_sec":        120,
      "backend_keepalive_interval_sec": 30,
      "inactiveTimeOut":                60
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}
    ]
  }'

## ── LB rule 2: VIP:2021 → non-SSE mode (l3ep2:8080) ───────────────────────
$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":     "10.10.10.254",
      "port":            2021,
      "protocol":       "tcp",
      "sel":             0,
      "mode":            4,
      "host":           "10.10.10.254",
      "path_prefix":    "/",
      "path_match_mode": "prefix",
      "model_name":     "nosse-test",
      "sse_mode":        false,
      "inactiveTimeOut": 60
    },
    "endpoints": [
      {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
    ]
  }'

## ── LB rule 3: VIP:2022 → SSE mode, short max_stream_duration_sec (l3ep1:8080)
$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":                    "10.10.10.254",
      "port":                           2022,
      "protocol":                      "tcp",
      "sel":                            0,
      "mode":                           4,
      "host":                          "10.10.10.254",
      "path_prefix":                   "/",
      "path_match_mode":               "prefix",
      "model_name":                    "cap-test",
      "sse_mode":                       true,
      "max_stream_duration_sec":        10,
      "backend_keepalive_interval_sec": 30,
      "inactiveTimeOut":                60
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}
    ]
  }'

sleep 2
echo "config.sh done"
