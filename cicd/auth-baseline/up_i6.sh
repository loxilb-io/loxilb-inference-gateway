#!/bin/bash
# Bring-up for the step I-6 baseline re-run (PR 2b, before any management fix).
#
# I-6 asks one question: are the I-0b management-plane reds still present now
# that PR 1 and PR 2 sit on top? So the topology has to be the I-0 one — the
# management store is MariaDB and does not move to PostgreSQL until I-8 — with
# exactly one difference, forced by the I-4 repoint: data-plane keys now live in
# `pkg/aikey`, so the gateway needs --aikey-db-* or POST /config/ai/apikey
# answers 503 ai_key_store_unconfigured and the B-5 leg has no key to present.
#
# That difference is deliberate and is the honest way to hold B-5 comparable.
# Everything B-2/B-3/B-4 touch is still MariaDB, exactly as at I-0.
#
# Asserts nothing. probe_i6.sh decides the verdicts.
#
#   AUTHSEP_IMAGE=authsep-i5b   the current tree's build (default)
#
#   l3h1 (10.10.10.1) ── llb1 (VIP 10.10.10.254:2020, mgmt :11111) ── l3ep1 (31.31.31.1:8080)
#                          │  management plane -> aikey-pg, schema aigw_mgmt
#                          └─ data plane       -> aikey-pg, schema aigw
cd "$(dirname "$0")" || exit 1
export LOXILB_DOCKER_IMAGE=${AUTHSEP_IMAGE:-authsep-i5b}

echo "### PostgreSQL key store (data plane)"
./pg-up.sh >/dev/null || { echo "pg-up.sh failed"; exit 1; }
PG_IP=$(docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" aikey-pg)
echo "key store IP: $PG_IP"

# The management plane moved to PostgreSQL at step I-8, so both planes now
# reach the same server through different roles and different schemas. MariaDB
# is gone from the topology because it is gone from the product.

source ../common.sh

pick_config=yes
mkdir -p llb1_config
# loxilb persists its configuration into the mounted config directory, so a
# second bring-up replays the first one's load-balancer rules and the create
# comes back 409. Start from nothing: "clean bring-up" has to mean the gateway
# too, not just the containers.
rm -f llb1_config/snapshot.json
echo "mgmt-secret-1" > llb1_config/mgmt_db_password
echo "dp-secret-1"   > llb1_config/aikey_password

MGMT_ARGS="--mgmt-db-host $PG_IP --mgmt-db-port 5432 --mgmt-db-user aigw_mgmt_user --mgmt-db-name loxilb --mgmt-db-password-file /etc/loxilb/mgmt_db_password"
AIKEY_ARGS="--aikey-db-host $PG_IP --aikey-db-port 5432 --aikey-db-user aigwuser --aikey-db-name loxilb --aikey-db-password-file /etc/loxilb/aikey_password"

echo "### spawn hosts (image=$LOXILB_DOCKER_IMAGE)"
spawn_docker_host --dock-type loxilb --dock-name llb1 \
  --extra-args "--userservice $MGMT_ARGS $AIKEY_ARGS"
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

# /version answering does not mean a subsystem is up: the REST listener serves
# before loxiNetInit has built either the user service or the key store, so a
# request issued the instant the API answers is issued during construction.
# Wait for each subsystem to say it is there rather than guessing a sleep.
echo "### bootstrap admin (retry while the user service is still being built)"
for i in $(seq 1 60); do
  RC=$($hexec llb1 curl -s -o /tmp/i6_bootstrap.out -w "%{http_code}" \
    -X POST http://localhost:11111/netlox/v1/auth/users \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin123!","role":"admin"}')
  [ "$RC" = "200" ] && { echo "bootstrap ok ${i}"; break; }
  sleep 2
done
echo "bootstrap status=$RC body=$(cat /tmp/i6_bootstrap.out)"

echo "### login"
for i in $(seq 1 30); do
  LOGIN=$($hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin123!"}')
  TOKEN=$(echo "$LOGIN" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
  [ -n "$TOKEN" ] && break
  sleep 2
done
echo "TOKEN=${TOKEN:0:16}..."

# Now the key store, asked with a credential that will not be rejected first.
# 503 here is the store talking (unconfigured while still being constructed, or
# unavailable while the dial retries); anything else means it answered.
echo "### wait for the key store"
KS_URL="http://localhost:11111/netlox/v1/config/ai/apikey?tenant_id=readiness-probe"
for i in $(seq 1 60); do
  KS=$($hexec llb1 curl -s -o /tmp/i6_ks.out -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" "$KS_URL")
  # A 404 means the route moved, not that the store is up. Without this the
  # loop would exit on the first iteration and the wait would be a no-op —
  # which is how a readiness check quietly stops checking anything.
  [ "$KS" = "404" ] && { echo "!!! $KS_URL is not a route on this build"; exit 1; }
  [ "$KS" != "503" ] && { echo "key store ready ${i} (status $KS)"; break; }
  sleep 2
done
if [ "$KS" = "503" ]; then
  echo "!!! key store never came up: $(cat /tmp/i6_ks.out)"; exit 1
fi

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
