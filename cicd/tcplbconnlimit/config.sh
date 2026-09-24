#!/bin/bash

source ../common.sh

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1

echo "#########################################"
echo "Connecting and configuring  hosts"
echo "#########################################"

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1

sleep 5

#L3 config
config_docker_host --host1 l3h1 --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 llb1 --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24

sleep 5

# Both rules are created through the REST API rather than loxicmd, because the
# subject carries connectionLimit and the CLI inside the image may predate its
# flag. The subject holds the ceiling under test; the control is the same rule
# without one, so a connection the subject refuses is refused by the ceiling
# and not by the bed.
API=http://127.0.0.1:11111/netlox/v1/config/loadbalancer
post_rule() {   # <vip> <connectionLimit|"">
  local vip=$1 limit=$2 limit_field=""
  [[ -n "$limit" ]] && limit_field="\"connectionLimit\": $limit,"
  $dexec llb1 curl -sS -o /dev/null -w '%{http_code}' -X POST "$API" -H 'Content-Type: application/json' -d "{
    \"serviceArguments\": { \"externalIP\": \"$vip\", \"port\": 2020, \"protocol\": \"tcp\", \"sel\": 0, \"mode\": 0, $limit_field \"inactiveTimeOut\": 60 },
    \"endpoints\": [ { \"endpointIP\": \"31.31.31.1\", \"targetPort\": 8080, \"weight\": 1 } ]
  }"
}
echo "subject 20.20.20.1:2020 connectionLimit=2 -> HTTP $(post_rule 20.20.20.1 2)"
echo "control 20.20.20.2:2020 (no limit)        -> HTTP $(post_rule 20.20.20.2 "")"
$dexec llb1 loxicmd get lb -o wide
