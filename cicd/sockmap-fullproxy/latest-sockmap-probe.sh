#!/bin/bash
#
# sockmap-fullproxy / latest-sockmap-probe.sh
#
# Checks whether the segment duplication on the accelerated path also reproduces on
# :latest, which predates the sockmap work.
#
# :latest carries the older sockmap of a main build:
#   - userspace registers both FDs into the sockhash itself (sockmap_cb, non-HAVE_SOCKOPS)
#   - there is no per-service on/off flag: turning on --sockmapsupport applies it to
#     every eligible HTTP-to-HTTP plaintext connection (main sockproxy.c:7873 has no
#     sockmap_en condition)
#   - the verdict uses the same bpf_sk_redirect_hash(skb, map, &key, 0)
#
# So acceleration can be turned on and off purely by --sockmapsupport. Reproducing it
# here would mean the defect predates the directional/sockops work and is inherent to
# how loxilb uses sockmap, or to the kernel.
#
# Usage: ./latest-sockmap-probe.sh [streams]
source ../common.sh
source ./sockmap_common.sh
sockmap_init_artifacts

STREAMS=${1:-300}
IMG=${IMG:-ghcr.io/loxilb-io/loxilb-inference-gateway:latest}
VIP=10.10.10.254; VP=2130; BP=9130
CONC=${CONC:-32}; TOKENS=${TOKENS:-2000}

lox_pid() { sudo docker exec -i llb1 sh -c 'pgrep -x loxilb' 2>/dev/null | head -1; }
cpu_usec() { sudo docker exec -i llb1 sh -c 'awk "/usage_usec/{print \$2}" /sys/fs/cgroup/cpu.stat' 2>/dev/null; }
# Whether sockets actually got registered in the sockhash - the engage signal for
# the older path.
sockhash_n() {
  local id
  id=$(sudo docker exec -i llb1 bash -c 'bpftool map show 2>/dev/null | grep -m1 sock_proxy_map | cut -d: -f1')
  [[ -z "$id" ]] && { echo 0; return; }
  sudo docker exec -i llb1 bash -c "bpftool map dump id $id 2>/dev/null | grep -c '^key'" || echo 0
}

run_case() {   # $1 = with|without  (--sockmapsupport present or not)
  local mode=$1 extra=""
  [[ "$mode" == "with" ]] && extra="--sockmapsupport"
  echo "######## :latest  sockmapsupport=${mode} ########"
  ./rmconfig.sh >/dev/null 2>&1; sleep 2
  lxdocker="$IMG"
  spawn_docker_host --dock-type loxilb --dock-name llb1 --extra-args "$extra --loglevel info" >/dev/null 2>&1
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
  for i in $(seq 1 60); do sudo docker exec -i llb1 loxicmd get lb >/dev/null 2>&1 && break; sleep 1; done

  sudo docker exec -i llb1 loxicmd create lb "$VIP" --tcp="$VP:$BP" --mode=fullproxy \
    --endpoints="31.31.31.1:1,32.32.32.1:1" --name=lat-fp >/dev/null 2>&1
  $hexec l3ep1 node ./sse_server.js s1 $BP 4000 0 >/dev/null 2>&1 &
  $hexec l3ep2 node ./sse_server.js s2 $BP 4000 0 >/dev/null 2>&1 &
  sleep 4
  local code
  code=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -X POST "http://$VIP:$VP/v1/chat/completions?tokens=3&rate=0" \
    -H 'Content-Type: application/json' -d '{"stream":true}')
  echo "  VIP sanity: $code   loxilb pid=$(lox_pid)"
  [[ "$code" == "200" ]] || { echo "  ERROR: VIP not serving"; return 1; }

  local c0 c1 out
  c0=$(cpu_usec)
  out=$($hexec l3h1 node ./sse_raw_probe.js $VIP $VP $CONC 180000 $TOKENS 1 $STREAMS 2>&1)
  c1=$(cpu_usec)
  echo "  sockhash entries registered: $(sockhash_n)"
  echo "$out" | grep -E "streams=|RXBYTES|backward|forward|delta"
  local rx st
  rx=$(echo "$out" | grep RXBYTES | awk '{print $2}')
  st=$(echo "$out" | grep -o "streams=[0-9]*" | cut -d= -f2)
  python3 -c "
c=($c1-$c0)/1e6; rx=$rx; st=$st
print(f'  loxilb CPU: {c:.2f} core-s / {rx/1048576:.0f} MB  ->  {c*1e6/max(rx,1):.2f} us/MB' if rx else '')
"
  sudo pkill -f "sse_server.js" >/dev/null 2>&1 || true
}

run_case with
echo
run_case without
./rmconfig.sh >/dev/null 2>&1
