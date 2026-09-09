#!/bin/bash
source ../common.sh

# loxicmd predates the snapshot auto-persist write gate and currently exposes
# its transient HTTP 503 as exit 5 without the response body. Keep this legacy
# scenario compatible by retrying only that exact status, with a small bound;
# all other failures are returned immediately.
run_loxicmd_mutation() { # <container> <loxicmd arguments...>
  local container=$1 out rc
  shift
  for _ in 1 2 3 4 5 6; do
    if out=$($dexec "$container" loxicmd "$@" 2>&1); then
      printf '%s\n' "$out"
      return 0
    else
      rc=$?
    fi
    case "$out" in
      *"gateway answered HTTP 503"*) sleep 2 ;;
      *) printf '%s\n' "$out"; return "$rc" ;;
    esac
  done
  printf '%s\n' "$out"
  return "$rc"
}

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1 --extra-args "--clusterinterface=eth0"
spawn_docker_host --dock-type loxilb --dock-name llb2 --extra-args "--clusterinterface=eth0"
spawn_docker_host --dock-type host --dock-name h1
spawn_docker_host --dock-type host --dock-name h2
spawn_docker_host --dock-type host --dock-name l3e1
spawn_docker_host --dock-type host --dock-name l3e2
spawn_docker_host --dock-type host --dock-name l3e3

echo "#########################################"
echo "Connecting and configuring  hosts"
echo "#########################################"


connect_docker_hosts h1 llb1
connect_docker_hosts h2 llb1
connect_docker_hosts llb1 llb2

config_docker_host --host1 h1 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 llb1 --host2 h1 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 h2 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 llb1 --host2 h2 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 llb2 --ptype phy --addr 10.10.10.59/24
config_docker_host --host1 llb2 --host2 llb1 --ptype phy --addr 10.10.10.56/24

#Endpoint Config
connect_docker_hosts l3e1 llb2
connect_docker_hosts l3e2 llb2
connect_docker_hosts l3e3 llb2

config_docker_host --host1 l3e1 --host2 llb2 --ptype phy --addr 25.25.25.1/24 --gw 25.25.25.254
config_docker_host --host1 llb2 --host2 l3e1 --ptype phy --addr 25.25.25.254/24
config_docker_host --host1 l3e2 --host2 llb2 --ptype phy --addr 26.26.26.1/24 --gw 26.26.26.254
config_docker_host --host1 llb2 --host2 l3e2 --ptype phy --addr 26.26.26.254/24
config_docker_host --host1 l3e3 --host2 llb2 --ptype phy --addr 27.27.27.1/24 --gw 27.27.27.254
config_docker_host --host1 llb2 --host2 l3e3 --ptype phy --addr 27.27.27.254/24

$dexec llb1 ip route add 25.25.25.0/24 via 10.10.10.56 dev ellb1llb2
$dexec llb1 ip route add 26.26.26.0/24 via 10.10.10.56 dev ellb1llb2
$dexec llb1 ip route add 27.27.27.0/24 via 10.10.10.56 dev ellb1llb2

#$dexec llb2 ip route add 31.31.31.0/24 via 10.10.10.59 dev ellb2llb1
$dexec llb2 ip route add 32.32.32.0/24 via 10.10.10.59 dev ellb2llb1

##Create LB rule
#$dexec llb2 loxicmd create lb 88.88.88.88 --tcp=2020:8080 --endpoints=25.25.25.1:1,26.26.26.1:1,27.27.27.1:1

sleep 5

$dexec llb1 bash -c "apt-get update && apt-get install -y curl iputils-ping"
$dexec llb2 bash -c "apt-get update && apt-get install -y curl iputils-ping"

$hexec llb1 curl -X 'POST' \
  'http:/127.0.0.1:11111/netlox/v1/config/cistate' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "instance": "default",
  "state": "BACKUP",
  "vip": "0.0.0.0"
}'

$hexec llb2 curl -X 'POST' \
  'http://127.0.0.1:11111/netlox/v1/config/cistate' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "instance": "default",
  "state": "MASTER",
  "vip": "0.0.0.0"
}'

run_loxicmd_mutation llb1 create lb 0.0.0.0 --tcp=9999:9999 --endpoints=172.17.0.3:1,172.17.0.4:1 --egress
run_loxicmd_mutation llb1 create firewall --firewallRule="sourceIP:32.32.32.1/32" --snat=172.17.0.41 --egress

run_loxicmd_mutation llb2 create lb 0.0.0.0 --tcp=9999:9999 --endpoints=172.17.0.3:1,172.17.0.4:1 --egress
run_loxicmd_mutation llb2 create firewall --firewallRule="sourceIP:32.32.32.1/32" --snat=172.17.0.41 --egress
