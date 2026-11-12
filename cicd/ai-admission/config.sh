#!/bin/bash
# CICD scenario: ai-admission
#
# The capacity admission gate on a self-contained bed: a gateway booted with
# the gate enforcing (service ceiling 8, endpoint ceiling 5), three
# AI-gateway services over the same two backends, and a backend whose
# receipts say what actually arrived. validation.sh drives the gate past its
# ceilings over HTTP/1.1, HTTP/2 and TLS, reads the gauges and counters it
# exports, the refusals on the audit trail, and then reboots the gateway in
# observe mode to show the same load admitted and only counted.
#
# Topology:
#   l3h1 (10.10.10.1) ---- llb1 (VIP 10.10.10.254) ---- l3ep1 (31.31.31.1)
#
#   :2021  HTTP/1.1  -> l3ep1:8080, :8081   (mock_backend.py, one process)
#   :2022  HTTP/2    -> l3ep1:8090, :8091   (h2c_backend.py x2)
#   :2023  TLS       -> l3ep1:8080, :8081   with a 3 s SSE duration cap
#   :2024  HTTP/1.1  -> l3ep1:8080          one endpoint
#   :2025  HTTP/1.1  -> l3ep1:8080, :8081   queue depth 4, wait 30 s
#   :2026  HTTP/1.1  -> l3ep1:8080          queue depth 65536 (the warning)
#   :2028  HTTP/1.1  -> l3ep1:8080, :8081   the rule's own ceiling 4 under the env's 8
#   :2029  HTTP/1.1  -> l3ep1:8080, :8081   rule ceiling 2 and a queue, raised at runtime
#   :2030  HTTP/1.1  -> l3ep1:8084, :8085   adaptive ceiling 10 on the scraped queue depth
#   :2031  HTTP/1.1  -> l3ep1:8084, :8085   adaptive ceiling 8 on the time to first token
#   :2032  HTTP/1.1  -> l3ep1:8082, :8083   per-endpoint ceiling 8, 20 s warm-up
#   :2033  HTTP/1.1  -> l3ep1:8080, :8081   API keys required, ceiling 4, tenant share 50 %
#   :2034  HTTP/1.1  -> l3ep1:8080, :8081   API keys required, ceiling 2, tenant share 50 %, queue
#   :2035  HTTP/1.1  -> l3ep1:8080, :8081   ceiling 4, admission headers on admitted responses
#   :2036  HTTP/2    -> l3ep1:8090, :8091   ceiling 4, admission headers on admitted streams
#   :2037  HTTP/1.1  -> l3ep1:8099          nothing listens there: a failed connect (row OS)
#   :2038-:2040  the three rules row OBJ creates and deletes itself (gw.sh): keyed, admission
#                    headers on; :2039 strict, :2040 on the h2c backends
#   pg-ai-admission (docker bridge): the API-key store the two keyed pools need

source ../common.sh
source ./gw.sh

echo SCENARIO-ai-admission-config

require_host_tools jq curl python3 openssl || exit 1
if ! python3 -c 'import h2' 2>/dev/null; then
  echo "FATAL: python3 'h2' is not installed (the HTTP/2 driver and backend need it)"
  exit 1
fi

echo "#########################################"
echo "Certificate for the TLS listener"
echo "#########################################"
# common.sh mounts $(pwd)/cert as /opt/loxilb/cert/ in the gateway container,
# so the certificate survives the in-place restart validation.sh performs.
rm -rf cert; mkdir -p cert
openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
  -keyout cert/server.key -out cert/server.crt \
  -subj "/CN=$VIP" -addext "subjectAltName=IP:$VIP" >/dev/null 2>&1 || {
    echo "FATAL: could not issue the TLS test certificate"; exit 1; }

echo "#########################################"
echo "PostgreSQL for the API-key store"
echo "#########################################"
gw_pg_start || exit 1
echo "$MGMT_PW" > cert/mgmt_db_password
echo "$DP_PW" > cert/aikey_password

echo "#########################################"
echo "Spawning the topology (gate: enforce, service $FC_MAX_OUT, endpoint $FC_EP_CAP)"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1 \
  --docker-args "$(gw_env enforce | sed 's/\([A-Z_]*=[a-z0-9]*\)/-e \1/g')" \
  --extra-args "$GW_ARGS $(gw_db_args)"
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1

connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1

sleep 5

config_docker_host --host1 l3h1  --host2 llb1  --ptype phy --addr 10.10.10.1/24  --gw $VIP
config_docker_host --host1 l3ep1 --host2 llb1  --ptype phy --addr 31.31.31.1/24  --gw 31.31.31.254
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr $VIP/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24

add_route l3h1  31.31.31.0/24 $VIP
add_route l3ep1 10.10.10.0/24 31.31.31.254

echo "#########################################"
echo "Starting the backends"
echo "#########################################"

SDIR=$(pwd)
$hexec l3ep1 python3 "$SDIR/mock_backend.py" 8080 8081 8082 8083 8084 8085 > /tmp/ai-admission-mock.log 2>&1 &
track_helper
$hexec l3ep1 python3 "$SDIR/h2c_backend.py" server-h2a 8090 > /tmp/ai-admission-h2a.log 2>&1 &
track_helper
$hexec l3ep1 python3 "$SDIR/h2c_backend.py" server-h2b 8091 > /tmp/ai-admission-h2b.log 2>&1 &
track_helper

for p in 8080 8081 8082 8083 8084 8085; do
  for i in $(seq 1 20); do
    $hexec l3ep1 curl -sf --max-time 1 "http://127.0.0.1:$p/health" >/dev/null 2>&1 && break
    sleep 1
  done
  $hexec l3ep1 curl -sf --max-time 1 "http://127.0.0.1:$p/health" >/dev/null 2>&1 || {
    echo "FATAL: mock backend :$p did not become ready"; exit 1; }
done
for p in 8090 8091; do
  for i in $(seq 1 20); do
    $hexec l3ep1 curl -sf --max-time 1 --http2-prior-knowledge "http://127.0.0.1:$p/__receipts/probe" >/dev/null 2>&1 && break
    sleep 1
  done
  $hexec l3ep1 curl -sf --max-time 1 --http2-prior-knowledge "http://127.0.0.1:$p/__receipts/probe" >/dev/null 2>&1 || {
    echo "FATAL: h2c backend :$p did not become ready"; exit 1; }
done
echo "  four backends ready"

echo "#########################################"
echo "Waiting for the gateway"
echo "#########################################"
gw_wait_api   || exit 1
gw_wait_boot  || exit 1
gw_wait_audit || exit 1

echo "#########################################"
echo "Creating the AI services"
echo "#########################################"
gw_add_rules || exit 1

echo "config.sh done"
