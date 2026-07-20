#!/bin/bash
# CICD scenario: ai-apikey
# Tests the AI Gateway control-plane API (create/list/get/delete API keys,
# set/get tenant rate limits). Starts loxilb with --userservice and a MariaDB
# backend so that the REST API at localhost:11111 is fully functional.
#
# Topology:
#   l3h1 (10.10.10.1) ---- llb1 (VIP 10.10.10.254) ---- l3ep1 (31.31.31.1)
#   mysql-ai (docker bridge, reachable from llb1)

source ../common.sh

echo "#########################################"
echo "Spawning MariaDB for API key storage"
echo "#########################################"

# Start MariaDB on the Docker default bridge (accessible from all containers)
docker run --rm -d --name mysql-ai \
  -e MYSQL_ROOT_PASSWORD=loxilb123 \
  -e MYSQL_DATABASE=loxilb_db \
  mariadb:10.11

echo "Waiting for MariaDB to be ready..."
for i in $(seq 1 30); do
  if docker exec mysql-ai mysqladmin ping -h127.0.0.1 -uroot -ploxilb123 --silent 2>/dev/null; then
    echo "MariaDB ready (${i}s)"
    break
  fi
  sleep 2
done

MYSQL_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mysql-ai)
echo "MariaDB IP: $MYSQL_IP"

echo "#########################################"
echo "Preparing loxilb config directory"
echo "#########################################"

# pick_config=yes mounts $(pwd)/llb1_config as /etc/loxilb/ inside the container
pick_config=yes
mkdir -p llb1_config
echo "loxilb123" > llb1_config/mysql_password

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1 \
  --extra-args "--userservice --databasehost $MYSQL_IP"
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

# Ensure jq is available in the llb1 container (required for check_json() assertions in validation.sh)
$dexec llb1 bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y jq -qq 2>/dev/null" || true

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
#   mode=4  (LBModeFullProxy) — activates sockproxy HTTP userspace processing
#   sse_mode=true             — sets ai_gw_mode=1 inside sockproxy so that
#                               llb_ai_validate_key / llb_ai_ratelimit_check
#                               are invoked for every inbound request
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
      "inactiveTimeOut": 60,
      "host":            "10.10.10.254"
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}
    ]
  }'

echo ""
echo "#########################################"
echo "ai-apikey testbed ready"
echo "#########################################"
echo "  VIP:               http://10.10.10.254:2020"
echo "  Control plane API: http://llb1:11111/netlox/v1/config/ai/..."
echo "  MySQL:             $MYSQL_IP:3306"
