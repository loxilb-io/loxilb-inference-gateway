#!/bin/bash
#
# sockmap-fullproxy / crash-latest.sh
#
# Decides whether the rfd_ent[] data race (SIGSEGV) in handle_client_data is specific
# to the sockmap branch or is a product-wide defect.
#
# Method: apply the same load in a configuration where sockmap plays no part at all.
#   - image: ghcr.io/loxilb-io/loxilb-inference-gateway:latest (a main build)
#   - main's API has no sockMapAccel/sockMapMode field, so the rule is plain fullproxy
#   - loxilb is started WITHOUT --sockmapsupport, so no sockmap BPF is attached
# A death under these conditions confirms a pre-existing defect unrelated to sockmap.
#
# Prerequisite: sudo sh -c 'echo "/tmp/core.%e.%p.sig%s" > /proc/sys/kernel/core_pattern'
# Usage: ./crash-latest.sh [attempts]
# set -u is deliberately not used: spawn_docker_host in common.sh reads conditionally
# set variables, and an unset expansion would terminate the shell immediately.
source ../common.sh
source ./sockmap_common.sh
sockmap_init_artifacts

ATTEMPTS=${1:-3}
IMG=${IMG:-ghcr.io/loxilb-io/loxilb-inference-gateway:latest}
VIP=10.10.10.254; VP=2090; BP=9089
CONC=${CONC:-128}; PAR=${PAR:-4}
OUT=${OUT:-/tmp/latestrepro}; mkdir -p "$OUT"

lox_pid() { sudo docker exec -i llb1 sh -c 'pgrep -x loxilb' 2>/dev/null | head -1; }

# The :latest image has no curl (only :sockmap-test does), so the built-in loxicmd
# is used instead.
wait_api_loxicmd() {
  local i
  for ((i=0; i<60; i++)); do
    sudo docker exec -i llb1 loxicmd get lb >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

create_plain_lb() {
  # Plain fullproxy rule with no sockmap field - main's API has no sockMap* field.
  sudo docker exec -i llb1 loxicmd create lb "$VIP" --tcp="$VP:$BP" --mode=fullproxy \
    --endpoints="31.31.31.1:1,32.32.32.1:1" --name=latest-fp 2>&1 | tail -1
}

for ((a=1; a<=ATTEMPTS; a++)); do
  echo "############ latest attempt $a/$ATTEMPTS (no sockmap at all) ############"
  ./rmconfig.sh >/dev/null 2>&1 || true
  sleep 2

  lxdocker="$IMG"
  spawn_docker_host --dock-type loxilb --dock-name llb1 --extra-args "--loglevel info" >/dev/null 2>&1
  spawn_docker_host --dock-type host --dock-name l3h1  >/dev/null 2>&1
  spawn_docker_host --dock-type host --dock-name l3ep1 >/dev/null 2>&1
  spawn_docker_host --dock-type host --dock-name l3ep2 >/dev/null 2>&1
  connect_docker_hosts l3h1 llb1  >/dev/null 2>&1
  connect_docker_hosts l3ep1 llb1 >/dev/null 2>&1
  connect_docker_hosts l3ep2 llb1 >/dev/null 2>&1
  sleep 5
  config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254 >/dev/null 2>&1
  config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254 >/dev/null 2>&1
  config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254 >/dev/null 2>&1
  config_docker_host --host1 llb1 --host2 l3h1  --ptype phy --addr 10.10.10.254/24 >/dev/null 2>&1
  config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24 >/dev/null 2>&1
  config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24 >/dev/null 2>&1
  sleep 5
  wait_api_loxicmd || { echo "ERROR: API not ready (loxicmd)"; exit 1; }

  echo "loxilb pid=$(lox_pid)  image=$IMG  args='--loglevel info' (no sockmapsupport)"
  echo -n "rule create: "; create_plain_lb

  $hexec l3ep1 node ./sse_server.js s1 $BP 4000 0 >/dev/null 2>&1 &
  $hexec l3ep2 node ./sse_server.js s2 $BP 4000 0 >/dev/null 2>&1 &
  sleep 4
  code=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -X POST "http://$VIP:$VP/v1/chat/completions?tokens=3&rate=0" \
    -H 'Content-Type: application/json' -d '{"stream":true}')
  echo "VIP sanity: $code"
  [[ "$code" == "200" ]] || { echo "ERROR: VIP not serving"; exit 1; }

  # Same sequence that crashed: paced with 512 long-lived streams, then burst.
  for phase in paced burst; do
    if [[ $phase == paced ]]; then tk=250; rt=25; else tk=4000; rt=0; fi
    echo "  phase=$phase (tokens=$tk rate=$rt)"
    pids=()
    for i in $(seq 1 $PAR); do
      $hexec l3h1 node ./sse_client.js $VIP $VP $CONC 30000 512 10000 $tk $rt 8 1 \
        > "$OUT/a${a}_${phase}_$i.out" 2>/dev/null &
      pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
    if [[ -z "$(lox_pid)" ]]; then
      echo "*** loxilb DIED on :latest during phase=$phase (attempt $a) ***"
      sudo docker exec -i llb1 sh -c 'ls -la /tmp/core.* 2>/dev/null' || echo "(no core)"
      sudo docker logs llb1 2>&1 | tail -4 | cut -c1-140
      exit 0
    fi
  done
  sudo pkill -f "sse_server.js" >/dev/null 2>&1 || true
  echo "attempt $a: survived (pid=$(lox_pid))"
done
echo "### :latest $ATTEMPTS attempts, no death ###"
