#!/bin/bash
# CICD scenario: ai-ephealth
# The lightweight endpoint-health signal is keyed on the endpoint ADDRESS
# (proxy_update_ep_health_by_addr), so one probe transition must reach the
# endpoint's row in EVERY pool of its service — not the first pool the hash
# happens to yield, and not a pool-local index that means something different
# in every pool.
#
# Topology:
#   l3h1 (10.10.10.1) ── llb1 (VIP 10.10.10.254) ── l3ep1 (31.31.31.1, server-a)
#                                                 ── l3ep2 (32.32.32.1, server-b)
#
# Rules (all FullProxy):
#   :2050  single pool, monitor ON            → down/up logs "applied to 1 row"
#   :2060  model-alpha pool, monitor ON       → its probe is the only signal
#   :2060  model-beta pool,  monitor OFF      → its row can ONLY flip via the
#                                               address-keyed signal from the
#                                               alpha rule's probe. That is the
#                                               cross-pool property under test.
#
# NOTE: health-only scenario — no --userservice, no MariaDB.

source ../common.sh
echo SCENARIO-ai-ephealth

## ── Spawn containers ─────────────────────────────────────────────────────────
spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type host   --dock-name l3h1
spawn_docker_host --dock-type host   --dock-name l3ep1
spawn_docker_host --dock-type host   --dock-name l3ep2

## ── Connect hosts ────────────────────────────────────────────────────────────
connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1

sleep 5

## ── Configure IP addresses ──────────────────────────────────────────────────
config_docker_host --host1 l3h1  --host2 llb1  --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1  --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1  --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1  --host2 l3ep2 --ptype phy --addr 32.32.32.254/24

## ── Routes ──────────────────────────────────────────────────────────────────
add_route l3h1  31.31.31.0/24 10.10.10.254
add_route l3h1  32.32.32.0/24 10.10.10.254
add_route l3ep1 10.10.10.0/24 31.31.31.254
add_route l3ep2 10.10.10.0/24 32.32.32.254

# Start the mock listeners before installing the full-proxy rules. Creating a
# rule against a closed backend makes sockproxy take its 10-second reconnect
# path, and this scenario's whole subject is backend up/down transitions — a
# cold-start reconnect window mistaken for a probe transition would poison
# every oracle below. (Same ordering rule as ai-model-routing.)
start_mock_backend() { # <namespace> <response label>
  local ns=$1 label=$2
  $hexec "$ns" sh -c "nohup node ../common/tcp_server.js $label >/tmp/ai-ephealth-$label.log 2>&1 &"
  for i in $(seq 1 20); do
    if $hexec "$ns" curl -sf --max-time 1 http://127.0.0.1:8080/ | grep -q "$label"; then
      echo "  $label backend ready (${i})"
      return 0
    fi
    sleep 1
  done
  echo "  FATAL: $label backend did not become ready"
  return 1
}

start_mock_backend l3ep1 server-a || exit 1
start_mock_backend l3ep2 server-b || exit 1

## ── Wait for loxilb REST API ────────────────────────────────────────────────
echo "Waiting for loxilb REST API..."
for i in $(seq 1 30); do
  if $hexec l3h1 curl -sf http://10.10.10.254:11111/netlox/v1/version >/dev/null 2>&1; then
    echo "loxilb REST API ready (${i}s)"
    break
  fi
  sleep 2
done

# The REST listener answers before the boot config replay settles, and until
# it does the freeze middleware 503s every mutation — a fast runner's first
# write below lands inside that window and reads as a phantom product
# failure. Probe the freeze itself with a write that can never apply (empty
# body fails validation, so nothing is created); the middleware runs before
# auth, so the gate holds regardless of the auth flags in play.
for i in $(seq 1 40); do
  if ! $hexec l3h1 curl -s -m 3 -X POST http://10.10.10.254:11111/netlox/v1/config/loadbalancer -H 'Content-Type: application/json' -d '{}' | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
    echo "  boot config settled (${i})"; break
  fi
  if [ "$i" -eq 40 ]; then
    echo "  FATAL: boot config replay never settled; last probe answer:"
    $hexec l3h1 curl -s -m 3 -X POST http://10.10.10.254:11111/netlox/v1/config/loadbalancer -H 'Content-Type: application/json' -d '{}'
    exit 1
  fi
  sleep 1
done

## ── LB rule: port 2050 — single pool, monitor ON ────────────────────────────
# The control case: one pool, so a transition must log "applied to 1 endpoint
# row(s)". probeRetries=1 + probeTimeout=3 keep the nok/ok transitions inside
# the validation poll windows.
$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":   "10.10.10.254",
      "port":          2050,
      "protocol":     "tcp",
      "sel":           0,
      "mode":          4,
      "host":         "10.10.10.254",
      "monitor":       true,
      "probetype":    "tcp",
      "probeport":     8080,
      "probeTimeout":  3,
      "probeRetries":  1
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1},
      {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
    ]
  }'
echo ""

## ── LB rules: port 2060 — two model pools sharing both backends ─────────────
# model-alpha probes. model-beta deliberately does NOT: with its monitor off,
# nothing in the beta rule can mark its own rows, so the ONLY way its copy of
# 32.32.32.1:8080 flips is the address-keyed signal fanning out from alpha's
# probe. A first-pool-only or index-keyed regression leaves beta's row
# untouched and the validation oracles red.
$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":     "10.10.10.254",
      "port":            2060,
      "protocol":       "tcp",
      "sel":             0,
      "mode":            4,
      "host":           "10.10.10.254",
      "path_prefix":    "/",
      "path_match_mode": "prefix",
      "model_name":     "model-alpha",
      "monitor":         true,
      "probetype":      "tcp",
      "probeport":       8080,
      "probeTimeout":    3,
      "probeRetries":    1
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1},
      {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
    ]
  }'
echo ""

$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":     "10.10.10.254",
      "port":            2060,
      "protocol":       "tcp",
      "sel":             0,
      "mode":            4,
      "host":           "10.10.10.254",
      "path_prefix":    "/",
      "path_match_mode": "prefix",
      "model_name":     "model-beta"
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1},
      {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
    ]
  }'
echo ""

# Both 2060 rules must exist, or the "applied to 2 row(s)" oracle below tests
# a topology that was never built and every later failure points at the wrong
# suspect.
rules=$($hexec l3h1 curl -s http://10.10.10.254:11111/netlox/v1/config/loadbalancer/all)
for want in '"port":2050' 'model-alpha' 'model-beta'; do
  if ! echo "$rules" | grep -q "$want"; then
    echo "FATAL: LB rule with $want was not installed; got: $rules"
    exit 1
  fi
done
echo "all three LB rules installed"

echo "SCENARIO-ai-ephealth configured"
