#!/bin/bash
# minica (github.com/jsha/minica) is fetched on demand — no binary is committed.
MINICA="$(command -v minica || echo "$(go env GOPATH)/bin/minica")"
[ -x "$MINICA" ] || { go install github.com/jsha/minica@latest; MINICA="$(go env GOPATH)/bin/minica"; }

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

#Prepare certificates
# minica issues every cert from the same CA (minica.pem), so the client
# can verify all server certs — and servers the client cert — with one root.
rm -fr 10.10.10.254 10.10.10.1 31.31.31.1 32.32.32.1 33.33.33.1
rm -fr minica*.pem
"$MINICA" -ip-addresses 10.10.10.254
"$MINICA" -ip-addresses 10.10.10.1
"$MINICA" -ip-addresses 31.31.31.1
"$MINICA" -ip-addresses 32.32.32.1
"$MINICA" -ip-addresses 33.33.33.1

# tcp_https_server.js expects server.crt and server.key in the IP directory
cp 10.10.10.254/cert.pem 10.10.10.254/server.crt
cp 10.10.10.254/key.pem 10.10.10.254/server.key

docker cp minica.pem llb1:/opt/loxilb/cert/rootCA.crt
docker cp 10.10.10.254/cert.pem llb1:/opt/loxilb/cert/server.crt
docker cp 10.10.10.254/key.pem llb1:/opt/loxilb/cert/server.key

sleep 5
create_lb_rule llb1 10.10.10.254 --tcp=2020:8080 --endpoints=31.31.31.1:1,32.32.32.1:1,33.33.33.1:1 --mode=fullproxy --security=e2ehttps --host=10.10.10.254
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
    "backend_protocol": "http2"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8081, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8081, "weight": 1 },
    { "endpointIP": "33.33.33.1", "targetPort": 8081, "weight": 1 }
  ]
}'
