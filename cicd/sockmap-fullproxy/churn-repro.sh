#!/bin/bash
#
# sockmap-fullproxy / churn-repro.sh
#
# Hypothesis: the loxilb process disappears not because of burst load itself, but
# when an LB rule is deleted and recreated while connections are still live.
#
# Basis: both observed deaths happened either (a) while a validation script switched
# regimes and arms, creating and deleting rules, or (b) right after a previous run
# cleaned its rules up. By contrast crash-repro.sh, which holds the rules fixed and
# only repeats burst load 40 times, never killed it.
#
# This script deletes and recreates the rule while load is flowing, which is also a
# realistic operational scenario: a config change arriving under load.
#
# Usage: ./churn-repro.sh [rounds]
set -u
source ../common.sh
source ./sockmap_common.sh
sockmap_init_artifacts

ROUNDS=${1:-8}
VIP=10.10.10.254
VP=${VP:-2080}; BP=${BP:-9088}
SMODE=${SMODE:-both}
CONC=${CONC:-128}; PAR=${PAR:-4}
DUR_MS=${DUR_MS:-20000}; WARM_MS=${WARM_MS:-3000}
TOKENS=${TOKENS:-4000}; RATE=${RATE:-0}
OUT=${OUT:-/tmp/churnrepro}; mkdir -p "$OUT"

lox_pid() { sudo docker exec -i llb1 sh -c 'pgrep -x loxilb' 2>/dev/null | head -1; }

echo "=== churn-repro: mode=$SMODE rate=$RATE tokens=$TOKENS ==="
sudo docker exec -i llb1 sh -c 'rm -f /tmp/loxilb-exit.txt /tmp/core.*' >/dev/null 2>&1 || true
for p in $BP; do
  $hexec l3ep1 node ./sse_server.js s1 $p 4000 0 >/dev/null 2>&1 &
  $hexec l3ep2 node ./sse_server.js s2 $p 4000 0 >/dev/null 2>&1 &
done
sleep 4

printf "%-6s %-9s %-9s %-9s %s\n" round pid streams errors status
for ((r=1; r<=ROUNDS; r++)); do
  PID=$(lox_pid)
  [[ -z "$PID" ]] && { echo "loxilb ALREADY DEAD before round $r"; break; }

  sockmap_create_lb_via_api llb1 $VIP $VP $BP "31.31.31.1,32.32.32.1" "$SMODE" "churn" >/dev/null 2>&1
  sleep 1

  pids=()
  for i in $(seq 1 $PAR); do
    $hexec l3h1 node ./sse_client.js $VIP $VP $CONC $DUR_MS 512 $WARM_MS $TOKENS $RATE 8 1 \
      > "$OUT/r${r}_$i.out" 2>/dev/null &
    pids+=($!)
  done

  # Once the load is in steady state, delete the rule with connections still live,
  # then recreate it shortly after.
  sleep 8
  sockmap_delete_lb_via_api llb1 $VIP $VP >/dev/null 2>&1
  sleep 3
  sockmap_create_lb_via_api llb1 $VIP $VP $BP "31.31.31.1,32.32.32.1" "$SMODE" "churn" >/dev/null 2>&1

  for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
  sockmap_delete_lb_via_api llb1 $VIP $VP >/dev/null 2>&1

  NPID=$(lox_pid)
  st=$(awk '/^SSELINE/{s+=$2} END{print s+0}' "$OUT"/r${r}_*.out)
  er=$(awk '/^SSELINE/{e+=$3} END{print e+0}' "$OUT"/r${r}_*.out)
  if [[ -z "$NPID" ]]; then
    printf "%-6s %-9s %-9s %-9s %s\n" "$r" "$PID" "$st" "$er" "*** DIED ***"
    break
  fi
  printf "%-6s %-9s %-9s %-9s %s\n" "$r" "$NPID" "$st" "$er" "alive"
done

echo
echo "=== post-mortem ==="
sudo docker exec -i llb1 sh -c '
  echo "--- exit status ---"; cat /tmp/loxilb-exit.txt 2>/dev/null || echo "(none - still alive)"
  echo "--- cores ---"; ls -la /tmp/core.* 2>/dev/null || echo "(no core)"'
sudo pkill -f "sse_server.js" >/dev/null 2>&1 || true
sockmap_delete_lb_via_api llb1 $VIP $VP >/dev/null 2>&1 || true
