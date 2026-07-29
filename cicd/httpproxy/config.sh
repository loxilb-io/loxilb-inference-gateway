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

sleep 5
# D-5 config path: drive the inference-gateway loxicmd as the load-bearing config
# path when present (subject-under-test); fall back to raw REST for old/absent CLI.
cli_preflight llb1 && USE_CLI=1 || USE_CLI=0
create_lb_rule llb1 10.10.10.254 --tcp=2020:8080 --endpoints=31.31.31.1:1,32.32.32.1:1,33.33.33.1:1 --mode=fullproxy --host=10.10.10.254
if [[ "$USE_CLI" == "1" ]]; then
  create_lb_rule llb1 10.10.10.254 --tcp=2021:8081 --endpoints=31.31.31.1:1,32.32.32.1:1,33.33.33.1:1 --mode=fullproxy --host=10.10.10.254 --backend-protocol=http2 --path-prefix=/ --path-match-mode=prefix
else
  $dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
    -H "Content-Type: application/json" \
    -d '{
    "serviceArguments": {
      "externalIP": "10.10.10.254",
      "port": 2021,
      "mode": 4,
      "protocol": "tcp",
      "host": "10.10.10.254",
      "backend_protocol": "http2",
      "path_prefix": "/",
      "path_match_mode": "prefix"
    },
    "endpoints": [
      { "endpointIP": "31.31.31.1", "targetPort": 8081, "weight": 1 },
      { "endpointIP": "32.32.32.1", "targetPort": 8081, "weight": 1 },
      { "endpointIP": "33.33.33.1", "targetPort": 8081, "weight": 1 }
    ]
  }'
fi
