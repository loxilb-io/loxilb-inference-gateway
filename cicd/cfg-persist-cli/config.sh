#!/bin/bash
# config.sh — cfg-persist-cli topology (GPU-free, no BGP).
#
# The CLI is the SUBJECT here and the REST API is the oracle: every verdict
# validation.sh reaches about loxicmd is cross-checked against the same fact
# read through REST or off the host-mounted config volume. Fine-grained
# decode and status-code matrices belong to the CLI repository's own tests
# against a fake gateway; this suite covers only what needs a real one -
# exit statuses against real failure modes, the on-disk effects of a real
# download, and the alias/flag semantics as the packaged binary sees them.
#
# CLI under test: by default the loxicmd baked into the image. Set
# LOXICMD_BIN=/path/to/loxicmd to test a build of the CLI instead - it is
# copied over /usr/local/sbin/loxicmd inside llb1 and the substitution is
# reported, so a run never leaves it ambiguous which binary was measured.

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

# The config volume is host-mounted so the suite can read snapshot.json and
# its permissions directly, rather than trusting the CLI's own report of
# what it wrote.
pick_config="yes"
mkdir -p "${CFGDIR}/llb1_config"
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

echo "#########################################"
echo "Selecting the CLI under test"
echo "#########################################"
if [[ -n "$LOXICMD_BIN" ]]; then
    [[ -x "$LOXICMD_BIN" ]] || { echo "FATAL: LOXICMD_BIN=$LOXICMD_BIN is not an executable"; exit 1; }
    docker cp "$LOXICMD_BIN" llb1:/usr/local/sbin/loxicmd || { echo "FATAL: could not install the CLI under test"; exit 1; }
    $dexec llb1 chmod 0755 /usr/local/sbin/loxicmd
    echo "  CLI under test: $LOXICMD_BIN (copied into llb1, replacing the baked binary)"
    echo "$LOXICMD_BIN" > "${CFGDIR}/.cli-under-test"
else
    echo "  CLI under test: the loxicmd baked into the image"
    echo "image-baked" > "${CFGDIR}/.cli-under-test"
fi
$dexec llb1 loxicmd version || { echo "FATAL: the CLI does not run inside llb1"; exit 1; }

# The CLI is the subject of this suite, so an auto-skip would quietly turn
# the whole run green without testing anything.
CLI_TESTS=required cli_preflight llb1 || exit 1

post_json() {
    $hexec llb1 curl -s -m 10 -o /tmp/cfgcli-post.json -w "%{http_code}" \
        -X POST "${API}$1" -H 'Content-Type: application/json' -d "$2"
}
must_200() {
    if [[ "$2" != "200" && "$2" != "204" ]]; then
        echo "FATAL: fixture $1 refused (HTTP $2):"
        cat /tmp/cfgcli-post.json 2>/dev/null; echo
        exit 1
    fi
    echo "  fixture: $1 [OK]"
}

echo "#########################################"
echo "Building the fixture (LB + firewall + endpoint)"
echo "#########################################"

rc=$(post_json /config/loadbalancer '{
  "serviceArguments": {
    "externalIP": "20.20.20.1", "port": 2020, "protocol": "tcp",
    "sel": 0, "mode": 2, "name": "cli-l4"
  },
  "endpoints": [ { "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1 } ]
}')
must_200 "L4 LB rule (served VIP)" "$rc"

rc=$(post_json /config/firewall '{
  "ruleArguments": { "sourceIP": "77.77.77.7/32", "destinationIP": "20.20.20.1/32" },
  "opts": { "drop": true }
}')
must_200 "firewall drop rule" "$rc"

rc=$(post_json /config/endpoint '{
  "hostName": "31.31.31.1", "name": "31.31.31.1_tcp_80", "inactiveReTries": 2,
  "probeType": "ping", "probeDuration": 60
}')
must_200 "endpoint host state" "$rc"

echo "cfg-persist-cli config done"
