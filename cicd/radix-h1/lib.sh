#!/bin/bash
# lib.sh - shared helpers of the radix-h1 scenario (sourced).
#
# Self-contained on purpose: it does not use cicd/common.sh's spawn helpers,
# because this scenario runs on shared testbeds with its own isolation rules:
# containers with --network none, --cgroupns private and resource limits,
# links wired between container namespaces with nsenter (nothing registered
# under /var/run/netns), no restart policy, no host-path mounts beyond the
# scenario folder (read-only) and the run folder.
#
# Required environment:
#   RX_IMG_GW     gateway image built with -DHAVE_RADIX_TEST_SWITCH
#   RX_IMG_MOCK   an image with python3 (mock backends and the client)
#   RX_RUN_DIR    writable run folder on the host (receipts, logs, evidence)
# Optional: RX_PREFIX (container name prefix, default rx4-)

set -u
P=${RX_PREFIX:-rx4-}
IMG_GW=${RX_IMG_GW:?RX_IMG_GW is required}
IMG_MOCK=${RX_IMG_MOCK:?RX_IMG_MOCK is required}
RUN=${RX_RUN_DIR:?RX_RUN_DIR is required}
SCN_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
EVID=$RUN/evidence
VIP=10.10.10.254
API=http://127.0.0.1:11111/netlox/v1
MODEL=rx-model
EPS="ep1 ep2 ep3"
NAMES="${P}llb1 ${P}h1 ${P}ep1 ${P}ep2 ${P}ep3"

PORT_RR=3001      # round robin
PORT_CHWBL=3002   # consistent hash with bounded loads (sel 8)
PORT_SESS=3003    # round robin + session header x-session-id
PORT_CB=3004      # round robin + circuit breaker
PORT_STICKY=3005  # persistence (sel 3, client-IP stickiness)
PORT_MOVE=3006    # CHWBL + breaker + admission enforce, 1 per endpoint: radix moves the pick
POOL_PORTS="$PORT_RR $PORT_CHWBL $PORT_SESS $PORT_CB $PORT_STICKY $PORT_MOVE"   # one pool each (add_rules)

say() { echo "[radix-h1] $*"; }
pid_of() { docker inspect -f '{{.State.Pid}}' "$P$1"; }
nsx() { local pid; pid=$(pid_of "$1"); shift; nsenter -t "$pid" -n "$@"; }

# link <a> <if-a> <b> <if-b>: a veth pair straight between two containers
link() {
  nsx "$1" ip link add "$2" type veth peer name "$4" netns "$(pid_of "$3")" || return 1
  nsx "$1" ip link set "$2" up && nsx "$3" ip link set "$4" up
}

LIMITS_SMALL="--cpus 0.5 --memory 512m --memory-swap 512m"
LIMITS_GW="--cpus 3 --memory 8g --memory-swap 8g"
COMMON_RUN="--network none --cgroupns private --restart no"

# The client and the three mocks: unprivileged, no capabilities.
start_hosts() {
  local n i=1
  mkdir -p "$RUN/h1" "$EVID"
  docker run -d --name "${P}h1" $COMMON_RUN $LIMITS_SMALL --cap-drop ALL \
    --security-opt no-new-privileges -v "$SCN_DIR:/opt/rx4:ro" -v "$RUN/h1:/opt/out" \
    "$IMG_MOCK" sleep infinity >/dev/null || return 1
  for n in $EPS; do
    mkdir -p "$RUN/$n"
    : > "$RUN/$n/receipts.jsonl"
    docker run -d --name "$P$n" $COMMON_RUN $LIMITS_SMALL --cap-drop ALL \
      --security-opt no-new-privileges -v "$SCN_DIR:/opt/rx4:ro" -v "$RUN/$n:/opt/out" \
      "$IMG_MOCK" python3 /opt/rx4/mock_backend.py "$n" 8000 /opt/out/receipts.jsonl >/dev/null || return 1
    nsx "$n" ip link set lo up
    i=$((i + 1))
  done
  nsx h1 ip link set lo up
}

# The gateway container (privileged: eBPF load, bpffs and cgroup2 mounts inside).
start_gw_container() {
  mkdir -p "$RUN/llb1"
  docker run -d --name "${P}llb1" $COMMON_RUN $LIMITS_GW --privileged \
    --entrypoint /bin/bash -v "$RUN/llb1:/opt/radix-s4" "$IMG_GW" -c 'sleep infinity' >/dev/null || return 1
  nsx llb1 ip link set lo up
  link llb1 eh1 h1 rx0 || return 1
  nsx llb1 ip addr add 10.10.10.254/24 dev eh1
  nsx h1 ip addr add 10.10.10.1/24 dev rx0
  nsx h1 ip route add default via 10.10.10.254
  local i=1 n
  for n in $EPS; do
    link llb1 "e$i" "$n" rx0 || return 1
    nsx llb1 ip addr add "31.31.3$i.254/24" dev "e$i"
    nsx "$n" ip addr add "31.31.3$i.1/24" dev rx0
    nsx "$n" ip route add default via "31.31.3$i.254"
    i=$((i + 1))
  done
}

# start_gateway <arm> <switch:0|1>: the gateway process inside rx4-llb1
start_gateway() {
  local arm=$1 sw=$2 envarg="" i
  [ "$sw" = 1 ] && envarg="-e LLB_RADIX_POOLS=1"
  docker exec -d $envarg "${P}llb1" bash -c \
    "/root/loxilb-io/loxilb/loxilb --loglevel debug --prometheus > /opt/radix-s4/loxilb-$arm.out 2>&1"
  for i in $(seq 1 60); do
    docker exec "${P}llb1" curl -sf -m 3 "$API/version" >/dev/null 2>&1 && break
    sleep 2
  done
  docker exec "${P}llb1" curl -sf -m 3 "$API/version" >/dev/null 2>&1 || { say "FATAL: API never answered"; return 1; }
  for i in $(seq 1 40); do
    docker exec "${P}llb1" curl -s -m 3 -X POST "$API/config/loadbalancer" \
      -H 'Content-Type: application/json' -d '{}' \
      | grep -qE 'boot config replay settles|frozen while a snapshot restore' || return 0
    sleep 2
  done
  say "FATAL: boot config never settled"; return 1
}

# add_rule <port> <sel> <extra-json> [<fc-mode>]: three endpoints, fullproxy, AI gateway
add_rule() {
  local port=$1 sel=$2 extra=${3:-} fcm=${4:-observe} resp
  resp=$(docker exec "${P}llb1" curl -s -m 10 -X POST "$API/config/loadbalancer" \
    -H 'Content-Type: application/json' -d "{
      \"serviceArguments\": {
        \"externalIP\": \"$VIP\", \"port\": $port, \"protocol\": \"tcp\",
        \"sel\": $sel, \"mode\": 4, \"host\": \"$VIP\", \"path_prefix\": \"/\",
        \"path_match_mode\": \"prefix\", \"model_name\": \"$MODEL\",
        \"sse_mode\": true, \"fc_mode\": \"$fcm\", \"inactiveTimeOut\": 60$extra
      },
      \"endpoints\": [
        {\"endpointIP\": \"31.31.31.1\", \"targetPort\": 8000, \"weight\": 1},
        {\"endpointIP\": \"31.31.32.1\", \"targetPort\": 8000, \"weight\": 1},
        {\"endpointIP\": \"31.31.33.1\", \"targetPort\": 8000, \"weight\": 1}
      ]}")
  say "rule :$port sel $sel -> $(printf '%s' "$resp" | cut -c1-100)"
  case "$resp" in *Success*) return 0 ;; *) return 1 ;; esac
}

add_rules() {
  add_rule $PORT_RR 0 && add_rule $PORT_CHWBL 8 &&
    add_rule $PORT_SESS 0 ', "session_header_name": "x-session-id"' &&
    add_rule $PORT_CB 0 ', "cb_enable": true' &&
    add_rule $PORT_STICKY 3 &&
    add_rule $PORT_MOVE 8 ', "cb_enable": true, "fc_ep_max_inflight": 1' enforce
}
# inflight <port>: the admission in-flight units of that pool (all roles,
# Prometheus), or "n/a" when the metric cannot be read. The CHWBL bounded-load
# count itself has no read-out; its underflow log line is the check.
inflight() {
  docker exec "${P}llb1" curl -s -m 5 "$API/metrics" 2>/dev/null | python3 -c '
import sys, re
port = sys.argv[1]; tot = None
for l in sys.stdin:
    if l.startswith("loxilb_ai_admission_inflight{") and (":" + port) in l:
        tot = (tot or 0) + float(l.rsplit(None, 1)[1])
print("n/a" if tot is None else int(tot))' "$1"
}

# client <port> <args...>: run the driver in the client container
client() { local port=$1; shift; docker exec "${P}h1" python3 /opt/rx4/client.py "$VIP" "$port" "$@"; }
# plan <name> <json>: a plan file the client reads from its run folder
plan() { printf '%s\n' "$2" > "$RUN/h1/$1.json"; echo "/opt/out/$1.json"; }
mock_admin() { docker exec "$P$1" python3 -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000$2').read()"; }
receipts_count() { wc -l < "$RUN/$1/receipts.jsonl"; }
gw_log() { docker exec "${P}llb1" sh -c 'cat /var/log/loxilbdp.log /opt/radix-s4/loxilb-*.out 2>/dev/null'; }
stats_lines() { gw_log | grep -F '[RADIX_STATS]'; }

remove_containers() {
  local n
  say "removing: $NAMES"
  for n in $NAMES; do docker rm -f -v "$n" >/dev/null 2>&1; done
  for n in $NAMES; do docker inspect "$n" >/dev/null 2>&1 && say "STILL PRESENT: $n"; done
  return 0
}
