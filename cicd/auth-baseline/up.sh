#!/bin/bash
# Bring-up for the authentication-plane baselines and the management-auth
# smoke run.
#
# Deliberately asserts nothing: it only establishes the topology, and the probe
# scripts decide verdicts. The existing ai-apikey scenario is not reused as-is
# because it never starts a backend at all, so it cannot answer any question
# about what the backend received.
#
#   AUTHSEP_IMAGE=authsep-ci   the unmodified build, for the I-0 baselines
#   AUTHSEP_IMAGE=authsep-i1   the management-auth build, for the smoke run
#
# FROZEN at the pre-I-8 shape on purpose. It targets images from before the
# management store moved to PostgreSQL, which is why it still starts MariaDB
# and still passes --databasehost: those flags are the correct ones for the
# builds this script exists to run. Editing it to match the current flag family
# would leave the recorded I-0/I-1 evidence with no instrument that reproduces
# it. For a current build use up_i6.sh.
#   AUTHSEP_BOOTSTRAP=no       skip creating the admin, so a probe can drive the
#                              bootstrap itself against an empty users table
cd "$(dirname "$0")" || exit 1
export LOXILB_DOCKER_IMAGE=${AUTHSEP_IMAGE:-authsep-ci}
source ../common.sh

echo "### MariaDB"
docker rm -f mysql-ai 2>/dev/null
docker run --rm -d --name mysql-ai -e MYSQL_ROOT_PASSWORD=loxilb123 \
  -e MYSQL_DATABASE=loxilb_db mariadb:10.11 >/dev/null
for i in $(seq 1 30); do
  docker exec mysql-ai mysqladmin ping -h127.0.0.1 -uroot -ploxilb123 --silent 2>/dev/null && break
  sleep 2
done
MYSQL_IP=$(docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" mysql-ai)
echo "MariaDB IP: $MYSQL_IP"

pick_config=yes
mkdir -p llb1_config
echo "loxilb123" > llb1_config/mysql_password

echo "### spawn hosts (image=$LOXILB_DOCKER_IMAGE)"
spawn_docker_host --dock-type loxilb --dock-name llb1 \
  --extra-args "--userservice --databasehost $MYSQL_IP"
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1
sleep 5
pick_config=""
config_docker_host --host1 l3h1  --host2 llb1  --ptype phy --addr 10.10.10.1/24  --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1  --ptype phy --addr 31.31.31.1/24  --gw 31.31.31.254
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
add_route l3h1  31.31.31.0/24 10.10.10.254
add_route l3ep1 10.10.10.0/24 31.31.31.254

echo "### start the counting backend on l3ep1:8080"
docker cp count_server.py l3ep1:/count_server.py
docker exec -d l3ep1 python3 /count_server.py server1
sleep 2

echo "### wait for the loxilb REST API"
for i in $(seq 1 40); do
  $hexec llb1 curl -sf http://localhost:11111/netlox/v1/version >/dev/null 2>&1 && { echo "api ready ${i}"; break; }
  sleep 2
done

if [ "${AUTHSEP_BOOTSTRAP:-yes}" = "no" ]; then
  echo "### leaving the users table empty (AUTHSEP_BOOTSTRAP=no)"
  echo "### UP DONE"
  exit 0
fi

echo "### create admin + login"
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/auth/users \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"Admin123!\",\"role\":\"admin\"}"; echo
LOGIN=$($hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"Admin123!\"}")
TOKEN=$(echo "$LOGIN" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
echo "TOKEN=${TOKEN:0:16}..."

echo "### create the enforcing SSE VIP 10.10.10.254:2020 -> 31.31.31.1:8080"
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d "{\"serviceArguments\":{\"externalIP\":\"10.10.10.254\",\"port\":2020,\"protocol\":\"tcp\",\"mode\":4,\"sse_mode\":true,\"inactiveTimeOut\":60,\"host\":\"10.10.10.254\"},\"endpoints\":[{\"endpointIP\":\"31.31.31.1\",\"targetPort\":8080,\"weight\":1}]}"; echo

echo "### create a valid api key (tenant baseline-tenant, model test-model)"
KRESP=$($hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/ai/apikey \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d "{\"tenant_id\":\"baseline-tenant\",\"name\":\"baseline-key\",\"allowed_models\":[\"test-model\"],\"rate_limit_rps\":100,\"burst_size\":200,\"tokens_per_min\":1000000,\"enabled\":true}")
echo "KRESP=$KRESP"
RAW_KEY=$(echo "$KRESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("raw_key",""))' 2>/dev/null)
KEY_ID=$(echo "$KRESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("key_id",""))' 2>/dev/null)

{
  echo "TOKEN=$TOKEN"
  echo "RAW_KEY=$RAW_KEY"
  echo "KEY_ID=$KEY_ID"
} > /root/authsep-baseline.env
echo "### UP DONE"
