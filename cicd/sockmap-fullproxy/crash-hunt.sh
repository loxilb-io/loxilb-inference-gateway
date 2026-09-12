#!/bin/bash
#
# sockmap-fullproxy / crash-hunt.sh
#
# Repeats the exact sequence under which the loxilb process actually died.
#
# Unlike the conditions that failed to reproduce it (40 rounds of burst load on fixed
# rules, 8 rounds of rule churn under load), both observed deaths came from the full
# validation-sse-cpu.sh sequence: the paced regime with 512 long-lived streams first,
# then a switch to burst. This runs that sequence as-is, but starts loxilb under a
# wrapper that records the exit status so the fatal signal is captured.
#
# The testbed's normal start (common.sh) uses `exec`, which discards the exit status,
# so loxilb is restarted for each attempt. The redirection is kept identical to the
# original (/proc/1/fd/*).
#
# Usage: ./crash-hunt.sh [attempts]
set -u
source ../common.sh
source ./sockmap_common.sh

ATTEMPTS=${1:-4}
lox_pid() { sudo docker exec -i llb1 sh -c 'pgrep -x loxilb' 2>/dev/null | head -1; }

for ((a=1; a<=ATTEMPTS; a++)); do
  echo "############ attempt $a/$ATTEMPTS ############"
  sudo docker exec -i llb1 sh -c 'pkill -x loxilb; rm -f /tmp/loxilb-exit.txt /tmp/core.*' >/dev/null 2>&1 || true
  sleep 3
  sudo docker exec -d llb1 bash -c '
    ulimit -c unlimited
    cd /tmp
    /root/loxilb-io/loxilb/loxilb --sockmapsupport --loglevel info >/proc/1/fd/1 2>/proc/1/fd/2
    echo "EXIT=$?" > /tmp/loxilb-exit.txt'
  if ! sockmap_wait_api_ready llb1; then echo "ERROR: API not ready"; exit 1; fi
  echo "loxilb pid=$(lox_pid)"

  MODES="on resp off" REGIMES="paced burst" CONC=128 PAR_CLIENTS=4 \
  PACED_RATE=25 PACED_TOKENS=250 BURST_TOKENS=4000 \
  DUR_MS=30000 WARM_MS=10000 IDLE_WIN_MS=8000 \
  ./validation-sse-cpu.sh >/tmp/crashhunt_a${a}.log 2>&1 || true

  NPID=$(lox_pid)
  if [[ -z "$NPID" ]]; then
    echo "*** loxilb DIED on attempt $a ***"
    sudo docker exec -i llb1 sh -c '
      echo "--- exit status (128+signal means killed by a signal) ---"; cat /tmp/loxilb-exit.txt 2>/dev/null || echo "(the wrapper died too)"
      echo "--- cores ---"; ls -la /tmp/core.* 2>/dev/null || echo "(no core)"'
    echo "--- where the validation log stops ---"
    grep -aE "^\[|Regime|engaged|errors" /tmp/crashhunt_a${a}.log | tail -12
    exit 0
  fi
  echo "attempt $a: survived (pid=$NPID)"
done
echo "### $ATTEMPTS attempts, no death ###"
