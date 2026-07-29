#!/bin/bash

source ../common.sh

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type grpc-h2client --dock-name l3h1
spawn_docker_host --dock-type grpc-h2server --dock-name l3ep1
spawn_docker_host --dock-type grpc-h2server --dock-name l3ep2
spawn_docker_host --dock-type grpc-h2server --dock-name l3ep3


echo "#########################################"
echo "Connecting and configuring  hosts"
echo "#########################################"


connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1
connect_docker_hosts l3ep3 llb1

sleep 5

#L3 config
config_docker_host --host1 l3h1 --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24 --gw 33.33.33.254

config_docker_host --host1 llb1 --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1 --host2 l3ep3 --ptype phy --addr 33.33.33.254/24


$dexec llb1 ip addr add 10.10.10.3/32 dev lo

# Generate shared CA + LB frontend cert (10.10.10.254)
./generate-certs.sh 10.10.10.254 10.10.10.254
SHARED_CA_CERT=./10.10.10.254/certs/ca.crt
SHARED_CA_KEY=./10.10.10.254/certs/ca.key
sleep 5

# Generate per-endpoint certs signed by the same shared CA so loxilb's
# backend TLS verification (e2ehttps fullproxy) succeeds for each real backend IP.
./generate-certs.sh 31.31.31.1 31.31.31.1 $SHARED_CA_CERT $SHARED_CA_KEY
sleep 5
./generate-certs.sh 32.32.32.1 32.32.32.1 $SHARED_CA_CERT $SHARED_CA_KEY
sleep 5
./generate-certs.sh 33.33.33.1 33.33.33.1 $SHARED_CA_CERT $SHARED_CA_KEY
sleep 5

docker cp 31.31.31.1/certs/server.crt l3ep1:/certs/server.crt
docker cp 31.31.31.1/certs/server.key l3ep1:/certs/server.key
docker cp 32.32.32.1/certs/server.crt l3ep2:/certs/server.crt
docker cp 32.32.32.1/certs/server.key l3ep2:/certs/server.key
docker cp 33.33.33.1/certs/server.crt l3ep3:/certs/server.crt
docker cp 33.33.33.1/certs/server.key l3ep3:/certs/server.key

docker cp 10.10.10.254/certs/ca.crt l3h1:/certs/ca.crt
docker cp 10.10.10.254/certs/ca.crt llb1:/opt/loxilb/cert/rootCA.crt
docker cp 10.10.10.254/certs/server.crt llb1:/opt/loxilb/cert/server.crt
docker cp 10.10.10.254/certs/server.key llb1:/opt/loxilb/cert/server.key


sleep 5
cli_preflight llb1 && USE_CLI=1 || USE_CLI=0
if [[ "$USE_CLI" == "1" ]]; then
  create_lb_rule llb1 10.10.10.254 --tcp=2022:8082 --endpoints=31.31.31.1:1,32.32.32.1:1,33.33.33.1:1 --mode=fullproxy --security=e2ehttps --host=10.10.10.254 --backend-protocol=http2
else
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2022,
    "protocol": "tcp",
    "security": 2,
    "mode": 4,
    "host": "10.10.10.254",
    "backend_protocol": "http2"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8082, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8082, "weight": 1 },
    { "endpointIP": "33.33.33.1", "targetPort": 8082, "weight": 1 }
  ]
}'
fi
