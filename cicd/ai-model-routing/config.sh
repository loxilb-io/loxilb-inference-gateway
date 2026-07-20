#!/bin/bash
# CICD scenario: ai-model-routing
# Tests AI Gateway model-name based routing (X-Model header / JSON body
# model field → per-model backend selection via find_endpoint_lpm in sockproxy.c).
#
# Topology:
#   l3h1 (10.10.10.1) ── llb1 (VIP 10.10.10.254) ── l3ep1 (31.31.31.1, llama-70b)
#                                                  ── l3ep2 (32.32.32.1, mistral-7b)
#                                                  ── l3ep3 (33.33.33.1, wildcard)
#
# NOTE: routing-only scenario — no --userservice, no MariaDB.

source ../common.sh
echo SCENARIO-ai-model-routing

## ── Spawn containers ─────────────────────────────────────────────────────────
spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type host   --dock-name l3h1
spawn_docker_host --dock-type host   --dock-name l3ep1
spawn_docker_host --dock-type host   --dock-name l3ep2
spawn_docker_host --dock-type host   --dock-name l3ep3

## ── Connect hosts ────────────────────────────────────────────────────────────
connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1
connect_docker_hosts l3ep3 llb1

sleep 5

## ── Configure IP addresses ──────────────────────────────────────────────────
config_docker_host --host1 l3h1  --host2 llb1  --ptype phy --addr 10.10.10.1/24   --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1  --ptype phy --addr 31.31.31.1/24   --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1  --ptype phy --addr 32.32.32.1/24   --gw 32.32.32.254
config_docker_host --host1 l3ep3 --host2 llb1  --ptype phy --addr 33.33.33.1/24   --gw 33.33.33.254
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1  --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1  --host2 l3ep3 --ptype phy --addr 33.33.33.254/24

## ── Routes ──────────────────────────────────────────────────────────────────
add_route l3h1  31.31.31.0/24 10.10.10.254
add_route l3h1  32.32.32.0/24 10.10.10.254
add_route l3h1  33.33.33.0/24 10.10.10.254
add_route l3ep1 10.10.10.0/24 31.31.31.254
add_route l3ep2 10.10.10.0/24 32.32.32.254
add_route l3ep3 10.10.10.0/24 33.33.33.254

## ── Wait for loxilb REST API ────────────────────────────────────────────────
echo "Waiting for loxilb REST API..."
for i in $(seq 1 30); do
  if $hexec l3h1 curl -sf http://10.10.10.254:11111/netlox/v1/version >/dev/null 2>&1; then
    echo "loxilb REST API ready (${i}s)"
    break
  fi
  sleep 2
done

## ── LB rule: port 2020 → llama-70b pool (l3ep1) ────────────────────────────
# Use $hexec l3h1 (not $dexec llb1) — loxilb image may not have curl at runtime
# mode=4 (LBModeFullProxy) enables userspace HTTP proxy with model-aware routing.
# host + path_prefix + path_match_mode ensure ephash key matches find_endpoint_lpm search key.
$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":     "10.10.10.254",
      "port":            2020,
      "protocol":       "tcp",
      "sel":             0,
      "mode":            4,
      "host":           "10.10.10.254",
      "path_prefix":    "/",
      "path_match_mode": "prefix",
      "model_name":     "llama-70b",
      "inactiveTimeOut": 30
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}
    ]
  }'

## ── LB rule: port 2021 → mistral-7b pool (l3ep2) ───────────────────────────
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
      "model_name":     "mistral-7b",
      "inactiveTimeOut": 30
    },
    "endpoints": [
      {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
    ]
  }'

## ── LB rule: port 2022 → wildcard pool (l3ep3) ─────────────────────────────
$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":     "10.10.10.254",
      "port":            2022,
      "protocol":       "tcp",
      "sel":             0,
      "mode":            4,
      "host":           "10.10.10.254",
      "path_prefix":    "/",
      "path_match_mode": "prefix",
      "model_name":     "",
      "inactiveTimeOut": 30
    },
    "endpoints": [
      {"endpointIP": "33.33.33.1", "targetPort": 8080, "weight": 1}
    ]
  }'

sleep 2
echo "config.sh done"
