#!/bin/bash
# CICD scenario: ai-apikey
# Tests the AI Gateway control-plane API (create/list/get/delete API keys,
# set/get tenant rate limits). Starts loxilb with --userservice and a
# PostgreSQL backend so that the REST API at localhost:11111 is fully
# functional.
#
# Both planes reach the same server through different roles and different
# schemas: aigw/aigwuser for the data-plane keys, aigw_mgmt/aigw_mgmt_user for
# users and session tokens. Provisioned by the script the product ships, so
# the fixture and the deployment path are the same thing.
#
# Topology:
#   l3h1 (10.10.10.1) ---- llb1 (VIP 10.10.10.254) ---- l3ep1 (31.31.31.1)
#   pg-ai (docker bridge, reachable from llb1)

source ../common.sh

PG_NAME=pg-ai
PG_OWNER=oamuser
PG_OWNER_PW=oampass
PG_DB=loxilb
DP_PW=dp-secret-1
MGMT_PW=mgmt-secret-1

echo "#########################################"
echo "Spawning PostgreSQL for the two stores"
echo "#########################################"

docker rm -f "$PG_NAME" >/dev/null 2>&1
docker run --rm -d --name "$PG_NAME" \
  -e POSTGRES_USER="$PG_OWNER" \
  -e POSTGRES_PASSWORD="$PG_OWNER_PW" \
  -e POSTGRES_DB="$PG_DB" \
  postgres:18.6 >/dev/null

echo "Waiting for PostgreSQL to be ready..."
for i in $(seq 1 60); do
  # Over TCP, not the unix socket: pg_isready answers on the socket before the
  # server is listening on a port the gateway can reach.
  if docker exec "$PG_NAME" pg_isready -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" >/dev/null 2>&1; then
    echo "PostgreSQL ready (${i}s)"
    break
  fi
  sleep 1
done
docker exec "$PG_NAME" pg_isready -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" >/dev/null || {
  echo "PostgreSQL did not come up"; exit 1; }

docker cp ../../scripts/aigw-db-bootstrap.sql "$PG_NAME:/tmp/aigw-db-bootstrap.sql"
docker exec -e AIGW_DB_PASSWORD="$DP_PW" -e AIGW_MGMT_DB_PASSWORD="$MGMT_PW" \
  "$PG_NAME" psql -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" -q -f /tmp/aigw-db-bootstrap.sql || {
  echo "bootstrap script failed"; exit 1; }

PG_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PG_NAME")
echo "PostgreSQL IP: $PG_IP"

echo "#########################################"
echo "Preparing loxilb config directory"
echo "#########################################"

# pick_config=yes mounts $(pwd)/llb1_config as /etc/loxilb/ inside the container
pick_config=yes
mkdir -p llb1_config
# Both secrets arrive as mounted files, which is the deployment shape; neither
# ever becomes a command-line argument.
echo "$MGMT_PW" > llb1_config/mgmt_db_password
echo "$DP_PW"   > llb1_config/aikey_password

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1 \
  --extra-args "--userservice \
    --mgmt-db-host $PG_IP --mgmt-db-port 5432 --mgmt-db-user aigw_mgmt_user \
    --mgmt-db-name $PG_DB --mgmt-db-password-file /etc/loxilb/mgmt_db_password \
    --aikey-db-host $PG_IP --aikey-db-port 5432 --aikey-db-user aigwuser \
    --aikey-db-name $PG_DB --aikey-db-password-file /etc/loxilb/aikey_password"
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1

echo "#########################################"
echo "Connecting and configuring hosts"
echo "#########################################"

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1

sleep 5

# Reset pick_config so config_docker_host does NOT skip llb1 IP assignment.
# (The volume mount for /etc/loxilb/ already happened during spawn_docker_host.)
pick_config=""

config_docker_host --host1 l3h1  --host2 llb1  --ptype phy --addr 10.10.10.1/24   --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1  --ptype phy --addr 31.31.31.1/24   --gw 31.31.31.254
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24

add_route l3h1  31.31.31.0/24 10.10.10.254
add_route l3ep1 10.10.10.0/24 31.31.31.254

echo "#########################################"
echo "Waiting for loxilb REST API to be ready"
echo "#########################################"

for i in $(seq 1 30); do
  if $hexec llb1 curl -sf http://localhost:11111/netlox/v1/version >/dev/null 2>&1; then
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
  if ! $hexec llb1 curl -s -m 3 -X POST http://localhost:11111/netlox/v1/config/loadbalancer -H 'Content-Type: application/json' -d '{}' | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
    echo "  boot config settled (${i})"; break
  fi
  if [ "$i" -eq 40 ]; then
    echo "  FATAL: boot config replay never settled; last probe answer:"
    $hexec llb1 curl -s -m 3 -X POST http://localhost:11111/netlox/v1/config/loadbalancer -H 'Content-Type: application/json' -d '{}'
    exit 1
  fi
  sleep 2
done

# validation.sh extracts every JSON field with `jq`, and it runs jq on THIS
# host: its requests go out through `hexec` ("ip netns exec"), which swaps the
# network namespace but keeps the host filesystem. jq therefore has to be on
# the host PATH. Installing it into the llb1 container with `dexec` instead
# leaves the assertions with no extractor at all, and a missing extractor
# reads as the gateway omitting the field rather than as a broken bed.
#
# Neither half of this may be silent. Without `apt-get update` the package
# lists can be empty and the install answers "Unable to locate package jq"
# while still exiting 0, so the verdict comes from probing for the binary
# afterwards, never from the installer's own exit status.
if ! command -v jq >/dev/null 2>&1; then
  echo "Installing jq on the host (validation.sh extracts JSON fields with it)"
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq jq
fi
require_host_tools jq || exit 1

echo "#########################################"
echo "Creating admin user and authenticating"
echo "#########################################"

# Create admin user (POST /auth/users has security: [] — no auth required)
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/auth/users \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!","role":"admin"}'
echo ""

# Login to get JWT token
LOGIN_RESP=$($hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!"}')
TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
echo "Auth token obtained: ${TOKEN:0:20}..."

echo "#########################################"
echo "Creating LB rule (AI Gateway, VIP 10.10.10.254:2020)"
echo "#########################################"

# AI Gateway rule:
#   mode=4  (LBModeFullProxy)  — activates sockproxy HTTP userspace processing
#   sse_mode=true              — streaming shape (AI accounting)
#   api_key_auth="required"    — key enforcement is a per-service policy now,
#                                not a rider on the streaming flag; a rule that
#                                declares nothing deliberately does not enforce
#                                (and the gateway warns on every quota write).
#                                This suite exists to test enforcement, so it
#                                declares it.
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "serviceArguments": {
      "externalIP":      "10.10.10.254",
      "port":            2020,
      "protocol":        "tcp",
      "mode":            4,
      "sse_mode":        true,
      "api_key_auth":    "required",
      "inactiveTimeOut": 60,
      "host":            "10.10.10.254"
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}
    ]
  }'

echo ""

# F-P0-3. The boot-replay probe further up is sound for what it names, but it
# is not the whole freeze, and it runs in the wrong place for the other half.
# Auto-persist is a DEBOUNCED write-through fired BY a successful mutating
# call, so the rule POST immediately above can start a freeze that lands on
# validation.sh's FIRST write seconds later — which is exactly how this
# scenario once produced a phantom "503 Maintenance mode / configuration is
# frozen" in CI and was green on the re-run.
#
# The repair is a positive signal placed after the writes: /status/ready
# reports `ready` with the reasons behind it. The absence of a 503 before the
# writes means "not started yet", which is indistinguishable from "finished";
# `ready: true` after them is a verdict.
echo "Waiting for /status/ready after the config writes (F-P0-3)"
for i in $(seq 1 40); do
  rs=$($hexec llb1 curl -s -m 5 -H "Authorization: Bearer $TOKEN" \
    http://localhost:11111/netlox/v1/status/ready 2>/dev/null)
  if printf '%s' "$rs" | python3 -c \
      "import sys,json; sys.exit(0 if json.load(sys.stdin).get('ready') is True else 1)" 2>/dev/null; then
    echo "  configuration ready (${i})"
    break
  fi
  if [ "$i" -eq 40 ]; then
    echo "  FATAL: /status/ready never reported ready; last answer:"
    printf '%s\n' "$rs"
    exit 1
  fi
  sleep 2
done

echo "#########################################"
echo "ai-apikey testbed ready"
echo "#########################################"
echo "  VIP:               http://10.10.10.254:2020"
echo "  Control plane API: http://llb1:11111/netlox/v1/config/ai/..."
echo "  PostgreSQL:        $PG_IP:5432"
