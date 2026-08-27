#!/bin/bash
# CICD scenario: ai-authsep — authentication plane separation.
#
# Modelled on cicd/ai-apikey, with two differences that are the point of the
# scenario:
#
#   * the data-plane key store is PostgreSQL (the `aigw` schema provisioned by
#     the shipped bootstrap script), not MariaDB; and
#   * the management plane's presence is a *parameter*, not a precondition, so
#     the suite can assert that data-plane verdicts do not move when it is
#     toggled. That independence is the property under test.
#
# A second PostgreSQL runs with TLS required, so the verified-TLS store path is
# covered by live legs rather than only by unit tests.
#
# Topology:
#   l3h1 (10.10.10.1) ── llb1 (VIPs 10.10.10.254:2020/:2021, mgmt :11111) ── l3ep1 (31.31.31.1:8080)
#                          │
#                          ├── aisep-pg     PostgreSQL 18.6, plaintext
#                          │                (aigw = data plane, aigw_mgmt = management)
#                          └── aisep-pg-tls PostgreSQL 18.6, TLS required
#
# Parameters (initial posture only — validation.sh drives every combination
# itself, because comparing cells is what the matrix is for):
#   USERSERVICE=on|off              default off
#   AIKEYSTORE=configured|unconfigured   default configured
#
# l3ep1 runs count_server.py, which appends a line per arriving request. That
# log is the instrument for the legs that ask what the backend actually
# received, which the gateway's own counters cannot answer.
#
# No `set -e`: several common.sh helpers return non-zero benignly, and the
# convention in this tree is that config.sh runs to completion and
# validation.sh decides the verdicts.
cd "$(dirname "$0")"

USERSERVICE="${USERSERVICE:-off}"
AIKEYSTORE="${AIKEYSTORE:-configured}"

source ../common.sh

echo "#########################################"
echo "Certificates for the TLS store"
echo "#########################################"
./mkcerts.sh

echo "#########################################"
echo "PostgreSQL key stores (plaintext + TLS-required)"
echo "#########################################"
./pg.sh up plain || { echo "FATAL: plaintext store did not come up"; exit 1; }
./pg.sh up tls   || { echo "FATAL: TLS store did not come up"; exit 1; }
PG_IP=$(./pg.sh ip plain)
PG_TLS_IP=$(./pg.sh ip tls)
if [ -z "$PG_IP" ] || [ -z "$PG_TLS_IP" ]; then
  echo "FATAL: a store has no address (plain='$PG_IP' tls='$PG_TLS_IP')"
  exit 1
fi
echo "  plaintext store: $PG_IP"
echo "  TLS store:       $PG_TLS_IP"

# MariaDB is gone from this scenario. It was here only so --userservice could
# be switched on, and once the management plane moved to the aigw_mgmt schema
# nothing connected to it — while validation.sh went on querying it for the
# "no data-plane tables in the management store" leg, which then reported a
# clean separation for the trivial reason that the gateway had stopped writing
# to that database entirely. A fixture nothing uses does not sit inert; it
# answers questions with a stale yes.

echo "#########################################"
echo "loxilb config directory"
echo "#########################################"
# pick_config=yes mounts $(pwd)/llb1_config as /etc/loxilb/ inside llb1.
pick_config=yes
rm -rf llb1_config
mkdir -p llb1_config
# Both secrets arrive as mounted files, which is the deployment shape. The
# store password never becomes a command-line argument — DP-20 asserts that.
echo "dp-secret-1"   > llb1_config/aikey_password
echo "mgmt-secret-1" > llb1_config/mgmt_db_password
cp certs/ca.crt certs/rogue-ca.crt certs/client.crt certs/client.key llb1_config/
chmod 0600 llb1_config/client.key

AIKEY_ARGS="--aikey-db-host $PG_IP --aikey-db-port 5432 --aikey-db-user aigwuser --aikey-db-name loxilb --aikey-db-password-file /etc/loxilb/aikey_password"
# The management plane now reaches the same PostgreSQL server as the data
# plane, through its own role and its own schema. Same server, different
# credentials, different tables — which is the property the two-role bootstrap
# exists to give, and the reason MariaDB has left the bill of materials.
MGMT_ARGS="--userservice --mgmt-db-host $PG_IP --mgmt-db-port 5432 --mgmt-db-user aigw_mgmt_user --mgmt-db-name loxilb --mgmt-db-password-file /etc/loxilb/mgmt_db_password"

EXTRA=""
[ "$AIKEYSTORE" = "configured" ] && EXTRA="$AIKEY_ARGS"
[ "$USERSERVICE" = "on" ]        && EXTRA="$EXTRA $MGMT_ARGS"

echo "#########################################"
echo "Spawning hosts (USERSERVICE=$USERSERVICE AIKEYSTORE=$AIKEYSTORE)"
echo "#########################################"
spawn_docker_host --dock-type loxilb --dock-name llb1 --extra-args "$EXTRA"
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1
sleep 5

pick_config=""
config_docker_host --host1 l3h1  --host2 llb1  --ptype phy --addr 10.10.10.1/24   --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1  --ptype phy --addr 31.31.31.1/24   --gw 31.31.31.254
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
add_route l3h1  31.31.31.0/24 10.10.10.254
add_route l3ep1 10.10.10.0/24 31.31.31.254

# The store certificate carries DNS:aikey-store and no IP SAN, so the TLS legs
# address the store by name. Remapping this one name is also how the
# no-downgrade leg is isolated: same name, same CA, a server that cannot speak
# TLS.
# /etc/hosts is a bind mount, so `sed -i` cannot rename over it. Rewrite
# through the existing inode.
docker exec llb1 bash -c "grep -v ' aikey-store\$' /etc/hosts > /tmp/hosts.new; cat /tmp/hosts.new > /etc/hosts; echo '$PG_TLS_IP aikey-store' >> /etc/hosts"

echo "#########################################"
echo "Counting backend on l3ep1:8080"
echo "#########################################"
docker cp count_server.py l3ep1:/count_server.py
docker exec -d l3ep1 python3 /count_server.py server1
# Second instance on :8081 — the decode role of P/D rules needs a real,
# listening endpoint (an endpoint that exists only to satisfy create-time
# validation would be a fixture lying about the topology).
docker exec -d l3ep1 python3 /count_server.py server2 8081
sleep 2

echo "#########################################"
echo "Waiting for the loxilb REST API"
echo "#########################################"
for i in $(seq 1 40); do
  if $hexec llb1 curl -sf -m 3 http://localhost:11111/netlox/v1/version >/dev/null 2>&1; then
    echo "  REST API ready (${i})"; break
  fi
  sleep 2
done

# Quoted: AIKEY_ARGS and MGMT_ARGS contain spaces, and validation.sh sources
# this file.
cat > .state <<STATE
PG_IP="$PG_IP"
PG_TLS_IP="$PG_TLS_IP"
AIKEY_ARGS="$AIKEY_ARGS"
MGMT_ARGS="$MGMT_ARGS"
STATE

echo "#########################################"
echo "ai-authsep testbed ready"
echo "#########################################"
echo "  enforcing VIP:      http://10.10.10.254:2020"
echo "  non-enforcing VIP:  http://10.10.10.254:2021"
echo "  key store:          $PG_IP (plaintext) / aikey-store=$PG_TLS_IP (TLS)"
