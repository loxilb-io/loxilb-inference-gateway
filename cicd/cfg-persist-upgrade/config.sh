#!/bin/bash
# config.sh — cfg-persist-upgrade topology (GPU-free, no BGP).
#
# The version matrix suite: the SAME config volume is handed back and
# forth between two gateway images (UP_OLD_IMAGE / UP_NEW_IMAGE), so the
# topology here only brings up the hosts and a small fixture on the OLD
# side. validation.sh swaps the container's image around the volume.
# Dispatch and nightly only; it needs two distinct images to mean
# anything and says so loudly when it does not get them.

export LLB_HOST_PORTS=""
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"

"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true
sudo rm -rf "${CFGDIR}/artifacts" >/dev/null 2>&1 || true

echo "#########################################"
echo "Building the reflect-echo backend image"
echo "#########################################"
"${CFGDIR}/../common/reflect-echo/docker-build.sh"

echo "#########################################"
echo "Spawning hosts (llb1 + client + 1 echo EP)"
echo "#########################################"

UP_OLD_IMAGE="${UP_OLD_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:v0.9.8.9-rc.1-u24}"
[[ "$UP_OLD_IMAGE" != *"/"* && "$UP_OLD_IMAGE" != *":"* ]] && UP_OLD_IMAGE="ghcr.io/loxilb-io/loxilb-inference-gateway:$UP_OLD_IMAGE"
echo "  old side: $UP_OLD_IMAGE"

pick_config="yes"
mkdir -p "${CFGDIR}/llb1_config"
lxdocker="$UP_OLD_IMAGE"
spawn_docker_host --dock-type loxilb --dock-name llb1
pick_config=""
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type reflect-echo --dock-name l3ep1 --docker-args "-e ECHO_NAME=serverN"

connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1

sleep 5

config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 llb1 --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24

sleep 5

API="http://localhost:11111/netlox/v1"
echo "Waiting for loxilb REST API to be ready..."
api_ready=0
for _ in $(seq 1 60); do
    rc=$($hexec llb1 curl -s -m 3 -o /dev/null -w "%{http_code}" "${API}/config/loadbalancer/all" 2>/dev/null)
    if [[ "$rc" == "200" ]]; then api_ready=1; echo "  loxilb REST API ready"; break; fi
    sleep 1
done
[[ "$api_ready" == 1 ]] || { echo "FATAL: loxilb REST API not ready"; exit 1; }

post_json() {
    $hexec llb1 curl -s -m 10 -o /tmp/cfgup-post.json -w "%{http_code}" \
        -X POST "${API}$1" -H 'Content-Type: application/json' -d "$2"
}
must_200() {
    if [[ "$2" != "200" && "$2" != "204" ]]; then
        echo "FATAL: fixture $1 refused (HTTP $2):"
        cat /tmp/cfgup-post.json 2>/dev/null; echo
        exit 1
    fi
    echo "  fixture: $1 [OK]"
}

echo "#########################################"
echo "Building the fixture (LB + firewall)"
echo "#########################################"

rc=$(post_json /config/loadbalancer '{
  "serviceArguments": {
    "externalIP": "20.20.20.1", "port": 2020, "protocol": "tcp",
    "sel": 0, "mode": 2, "name": "up-l4"
  },
  "endpoints": [ { "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1 } ]
}')
must_200 "L4 LB rule (served VIP)" "$rc"

rc=$(post_json /config/firewall '{
  "ruleArguments": { "sourceIP": "77.77.77.7/32", "destinationIP": "20.20.20.1/32" },
  "opts": { "drop": true }
}')
must_200 "firewall drop rule" "$rc"

# The fixture above was built by the OLD image on purpose: the volume it
# leaves behind is what the new image has to take over.
echo "cfg-persist-upgrade config done (fixture built on $UP_OLD_IMAGE)"
