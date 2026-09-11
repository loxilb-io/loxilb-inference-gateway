#!/bin/bash
#
# sockmap-fullproxy / crash-offonly.sh
#
# Decides, using the same binary, whether sockmap raises the probability of hitting
# the rfd_ent race.
#
#   - image: :sockmap-dbgctl, the binary that took a SIGSEGV on the first attempt of
#     the 3-arm sequence with sockmap on
#   - rule: a single sockMapMode=off rule, so kernel redirect never engages
#   - load: the same paced (512 long-lived streams) to burst transition that crashed
#
# Surviving here supports the reading that the defect itself lives on the shared path,
# but the sockmap path creates the trigger - a storm of abrupt connection teardowns -
# and so raises the probability sharply.
source ../common.sh
source ./sockmap_common.sh
sockmap_init_artifacts

ATTEMPTS=${1:-3}
IMG=${IMG:-ghcr.io/loxilb-io/loxilb-inference-gateway:sockmap-dbgctl}
VIP=10.10.10.254; VP=2091; BP=9091
CONC=${CONC:-128}; PAR=${PAR:-4}
OUT=${OUT:-/tmp/offonly}; mkdir -p "$OUT"
lox_pid() { sudo docker exec -i llb1 sh -c 'pgrep -x loxilb' 2>/dev/null | head -1; }

for ((a=1; a<=ATTEMPTS; a++)); do
  echo "############ off-only attempt $a/$ATTEMPTS (same binary, sockmap not engaged) ############"
  ./rmconfig.sh >/dev/null 2>&1 || true
  sleep 2
  LOXILB_IMAGE="$IMG" ./config.sh >/dev/null 2>&1 || { echo "ERROR: config.sh failed"; exit 1; }
  echo "loxilb pid=$(lox_pid) image=$IMG"

  sockmap_create_lb_via_api llb1 $VIP $VP $BP "31.31.31.1,32.32.32.1" off "offonly" >/dev/null || exit 1
  $hexec l3ep1 node ./sse_server.js s1 $BP 4000 0 >/dev/null 2>&1 &
  $hexec l3ep2 node ./sse_server.js s2 $BP 4000 0 >/dev/null 2>&1 &
  sleep 4
  code=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -X POST "http://$VIP:$VP/v1/chat/completions?tokens=3&rate=0" \
    -H 'Content-Type: application/json' -d '{"stream":true}')
  echo "VIP sanity: $code"; [[ "$code" == "200" ]] || { echo "ERROR: VIP down"; exit 1; }

  for phase in paced burst; do
    if [[ $phase == paced ]]; then tk=250; rt=25; else tk=4000; rt=0; fi
    pids=()
    for i in $(seq 1 $PAR); do
      $hexec l3h1 node ./sse_client.js $VIP $VP $CONC 30000 512 10000 $tk $rt 8 1 \
        > "$OUT/a${a}_${phase}_$i.out" 2>/dev/null &
      pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
    er=$(awk '/^SSELINE/{e+=$3} END{print e+0}' "$OUT"/a${a}_${phase}_*.out)
    st=$(awk '/^SSELINE/{s+=$2} END{print s+0}' "$OUT"/a${a}_${phase}_*.out)
    echo "  phase=$phase streams=$st errors=$er"
    if [[ -z "$(lox_pid)" ]]; then
      echo "*** loxilb DIED (off-only!) attempt $a phase=$phase ***"
      sudo docker exec -i llb1 sh -c 'ls -la /tmp/core.* 2>/dev/null' || echo "(no core)"
      exit 0
    fi
  done
  sudo pkill -f "sse_server.js" >/dev/null 2>&1 || true
  echo "attempt $a: survived"
done
echo "### off-only $ATTEMPTS attempts, no death ###"
