#!/bin/bash
# Bring-up for the PR 2 datapath repoint (step I-4).
#
# Differs from up.sh in one load-bearing way: the gateway is pointed at the
# PostgreSQL key store instead of MariaDB, and --userservice is OFF. That
# combination is the whole point of the change — a key store that exists, and
# a management plane that is not enabled — and it could not be expressed at all
# before this step.
#
# Asserts nothing. probe_i4.sh decides the verdicts.
#
#   AUTHSEP_IMAGE=authsep-i4   the PR 2 build
#
#   l3h1 (10.10.10.1) ── llb1 (VIP 10.10.10.254:2020, mgmt :11111) ── l3ep1 (31.31.31.1:8080)
#                          │
#                     aikey-pg (PostgreSQL 18.6, docker bridge)
cd "$(dirname "$0")" || exit 1
export LOXILB_DOCKER_IMAGE=${AUTHSEP_IMAGE:-authsep-i4}

echo "### PostgreSQL key store"
./pg-up.sh >/dev/null || { echo "pg-up.sh failed"; exit 1; }
PG_IP=$(docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" aikey-pg)
echo "key store IP: $PG_IP"

source ../common.sh

pick_config=yes
mkdir -p llb1_config
# The store password reaches the gateway as a file, which is the deployment
# shape (a mounted secret), not an exported variable.
echo "dp-secret-1" > llb1_config/aikey_password

AIKEY_ARGS="--aikey-db-host $PG_IP --aikey-db-port 5432 --aikey-db-user aigwuser --aikey-db-name loxilb --aikey-db-password-file /etc/loxilb/aikey_password"
echo "$AIKEY_ARGS" > /root/authsep-i4-aikey-args

echo "### spawn hosts (image=$LOXILB_DOCKER_IMAGE, no --userservice)"
spawn_docker_host --dock-type loxilb --dock-name llb1 --extra-args "$AIKEY_ARGS"
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

echo "### UP DONE"
