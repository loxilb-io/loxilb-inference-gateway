#!/bin/bash
# CICD scenario: mgmt-profile-sanity — management-listener profile enforcement.
#
# --mgmt-profile decides which interfaces may serve the management API:
#
#   legacy           the historical behavior: plaintext API on every interface
#   appliance-local  plaintext API on loopback only
#   remote-tls       no plaintext listener at all; refuses to start unless TLS
#                    material and an authentication service are both present
#
# llb1 gets three non-loopback NICs, each with its own client host, so
# "loopback only" is judged against interfaces that demonstrably can serve the
# API: the legacy baseline leg proves every probe path reaches the API before
# any negative leg is allowed to claim a closed door.
#
# Topology:
#   c1 (10.10.10.1) ──┐
#   c2 (20.20.20.1) ──┼── llb1 (.254 in each net; mgmt :11111, TLS :8091)
#   c3 (30.30.30.1) ──┘
#
# config.sh brings the gateway up under the default (legacy) profile;
# validation.sh restarts it per leg — the flag set is the thing under test.
# No LB rules are configured anywhere: the management listener alone is the
# subject, so the datapath carries no VIP that could shadow a probe.
#
# No `set -e`: several common.sh helpers return non-zero benignly; the
# convention in this tree is that config.sh runs to completion and
# validation.sh decides the verdicts — except for bring-up itself, which
# fails loudly below rather than handing validation.sh a dead gateway.
cd "$(dirname "$0")"
source ../common.sh
echo SCENARIO-mgmt-profile-sanity

spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type host   --dock-name c1
spawn_docker_host --dock-type host   --dock-name c2
spawn_docker_host --dock-type host   --dock-name c3

connect_docker_hosts c1 llb1
connect_docker_hosts c2 llb1
connect_docker_hosts c3 llb1

sleep 5

config_docker_host --host1 c1   --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 c2   --host2 llb1 --ptype phy --addr 20.20.20.1/24 --gw 20.20.20.254
config_docker_host --host1 c3   --host2 llb1 --ptype phy --addr 30.30.30.1/24 --gw 30.30.30.254
config_docker_host --host1 llb1 --host2 c1   --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 c2   --ptype phy --addr 20.20.20.254/24
config_docker_host --host1 llb1 --host2 c3   --ptype phy --addr 30.30.30.254/24

echo "Waiting for loxilb REST API..."
for i in $(seq 1 30); do
  if $hexec c1 curl -sf -m 3 http://10.10.10.254:11111/netlox/v1/version >/dev/null 2>&1; then
    echo "loxilb REST API ready (${i})"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "FATAL: loxilb REST API never answered"
    exit 1
  fi
  sleep 2
done

# The REST listener answers before the boot config replay settles, and until
# it does the freeze middleware 503s every mutation — a fast runner's first
# write can land inside that window and read as a phantom product failure.
# Probe the freeze itself with a write that can never apply (empty body fails
# validation, so nothing is created); the middleware runs before auth, so the
# gate holds regardless of the auth flags in play. validation.sh repeats this
# gate after every restart it performs.
for i in $(seq 1 40); do
  if ! $hexec llb1 curl -s -m 3 -X POST http://localhost:11111/netlox/v1/config/loadbalancer -H 'Content-Type: application/json' -d '{}' | grep -q 'boot config replay settles'; then
    echo "  boot config settled (${i})"; break
  fi
  if [ "$i" -eq 40 ]; then
    echo "  FATAL: boot config replay never settled; last probe answer:"
    $hexec llb1 curl -s -m 3 -X POST http://localhost:11111/netlox/v1/config/loadbalancer -H 'Content-Type: application/json' -d '{}'
    exit 1
  fi
  sleep 2
done

echo "config.sh done"
