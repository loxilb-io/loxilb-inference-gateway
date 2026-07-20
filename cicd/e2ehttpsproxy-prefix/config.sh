#!/bin/bash

source ../common.sh

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1
spawn_docker_host --dock-type host --dock-name l3ep2
spawn_docker_host --dock-type host --dock-name l3ep3


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

# Generate certificates with a single shared CA.
# The first call creates the CA; all subsequent calls reuse it so that
# the client can verify every server cert with the same minica.pem.
./generate-certs.sh 10.10.10.254 10.10.10.254
SHARED_CA_CERT=./10.10.10.254/certs/ca.crt
SHARED_CA_KEY=./10.10.10.254/certs/ca.key
sleep 10
./generate-certs.sh 10.10.10.1 10.10.10.1 $SHARED_CA_CERT $SHARED_CA_KEY
sleep 10
./generate-certs.sh 31.31.31.1 31.31.31.1 $SHARED_CA_CERT $SHARED_CA_KEY
sleep 10
./generate-certs.sh 32.32.32.1 32.32.32.1 $SHARED_CA_CERT $SHARED_CA_KEY
sleep 10
./generate-certs.sh 33.33.33.1 33.33.33.1 $SHARED_CA_CERT $SHARED_CA_KEY

# Copy certificates to the expected flat structure for validation scripts
# tcp_https_server.js expects server.crt and server.key in the IP directory
cp 10.10.10.254/certs/server.crt 10.10.10.254/server.crt
cp 10.10.10.254/certs/server.key 10.10.10.254/server.key
cp 31.31.31.1/certs/server.crt 31.31.31.1/server.crt
cp 31.31.31.1/certs/server.key 31.31.31.1/server.key
cp 32.32.32.1/certs/server.crt 32.32.32.1/server.crt
cp 32.32.32.1/certs/server.key 32.32.32.1/server.key
cp 33.33.33.1/certs/server.crt 33.33.33.1/server.crt
cp 33.33.33.1/certs/server.key 33.33.33.1/server.key

# Copy certificates to loxilb (load balancer)
docker cp 10.10.10.254/certs/ca.crt llb1:/opt/loxilb/cert/rootCA.crt
docker cp 10.10.10.254/certs/server.crt llb1:/opt/loxilb/cert/server.crt
docker cp 10.10.10.254/certs/server.key llb1:/opt/loxilb/cert/server.key

# Copy CA cert for minica.pem compatibility (used by validation scripts)
cp 10.10.10.254/certs/ca.crt minica.pem

# Copy certificates for HTTP/2 validation (expects cert.pem and key.pem)
cp 10.10.10.1/certs/client.crt 10.10.10.1/cert.pem
cp 10.10.10.1/certs/client.key 10.10.10.1/key.pem
cp 31.31.31.1/certs/server.crt 31.31.31.1/cert.pem
cp 31.31.31.1/certs/server.key 31.31.31.1/key.pem
cp 32.32.32.1/certs/server.crt 32.32.32.1/cert.pem
cp 32.32.32.1/certs/server.key 32.32.32.1/key.pem
cp 33.33.33.1/certs/server.crt 33.33.33.1/cert.pem
cp 33.33.33.1/certs/server.key 33.33.33.1/key.pem


sleep 5
# port 2020 -> /v1/users (endpoints 31/32)
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2020,
    "protocol": "tcp",
    "security": 2,
    "mode": 4,
    "host": "10.10.10.254",
    "path_prefix": "/v1/users",
    "path_match_mode": "prefix"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1 }
  ]
}'

# port 2020 -> /v1/orders (endpoint 33)
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2020,
    "protocol": "tcp",
    "security": 2,
    "mode": 4,
    "host": "10.10.10.254",
    "path_prefix": "/v1/orders",
    "path_match_mode": "prefix"
  },
  "endpoints": [
    { "endpointIP": "33.33.33.1", "targetPort": 8080, "weight": 1 }
  ]
}'

# port 2021 -> /v1/users (endpoints 31/32, backend http2)
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2021,
    "protocol": "tcp",
    "security": 2,
    "mode": 4,
    "host": "10.10.10.254",
    "backend_protocol": "http2",
    "path_prefix": "/v1/users",
    "path_match_mode": "prefix"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8081, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8081, "weight": 1 }
  ]
}'

# port 2021 -> /v1/orders (endpoint 33, backend http2)
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2021,
    "protocol": "tcp",
    "security": 2,
    "mode": 4,
    "host": "10.10.10.254",
    "backend_protocol": "http2",
    "path_prefix": "/v1/orders",
    "path_match_mode": "prefix"
  },
  "endpoints": [
    { "endpointIP": "33.33.33.1", "targetPort": 8081, "weight": 1 }
  ]
}'
