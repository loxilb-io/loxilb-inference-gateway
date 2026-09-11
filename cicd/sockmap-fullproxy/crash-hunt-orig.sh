#!/bin/bash
#
# sockmap-fullproxy / crash-hunt-orig.sh
#
# Runs the same load sequence as crash-hunt.sh, but starts loxilb exactly the way the
# testbed does: the `docker exec -dt ... bash -c "exec loxilb ..."` path from config.sh.
#
# Why separate them: both observed disappearances came from this original start, and
# 53 runs under the exit-status wrapper (which does not exec) never reproduced it.
# `exec` replaces bash with loxilb, making loxilb the pty session leader of the exec
# session - and the SIGHUP that arrives when that pty is torn down kills the process
# leaving neither core nor traceback. This checks whether that difference actually
# accounts for the deaths.
#
# Usage: ./crash-hunt-orig.sh [attempts]
set -u
source ../common.sh
source ./sockmap_common.sh

ATTEMPTS=${1:-3}
# HUNT_IMAGE selects the image. Both deaths happened on images compiled with
# HAVE_PROXY_EXTRA_DEBUG.
lox_pid() { sudo docker exec -i llb1 sh -c 'pgrep -x loxilb' 2>/dev/null | head -1; }

for ((a=1; a<=ATTEMPTS; a++)); do
  echo "############ orig attempt $a/$ATTEMPTS ############"
  ./rmconfig.sh >/dev/null 2>&1 || true
  sleep 2
  LOXILB_IMAGE=${HUNT_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:sockmap-nodebug} ./config.sh >/dev/null 2>&1 \
    || { echo "config.sh failed"; exit 1; }
  echo "loxilb pid=$(lox_pid) (testbed exec start)"

  MODES="on resp off" REGIMES="paced burst" CONC=128 PAR_CLIENTS=4 \
  PACED_RATE=25 PACED_TOKENS=250 BURST_TOKENS=4000 \
  DUR_MS=30000 WARM_MS=10000 IDLE_WIN_MS=8000 \
  ./validation-sse-cpu.sh >/tmp/hunt_orig_a${a}.log 2>&1 || true

  NPID=$(lox_pid)
  if [[ -z "$NPID" ]]; then
    echo "*** loxilb DIED on orig attempt $a ***"
    echo "--- container stdout/stderr tail (where it stops) ---"
    sudo docker logs llb1 2>&1 | tail -6 | cut -c1-160
    echo "--- cores ---"
    sudo docker exec -i llb1 sh -c 'ls -la /tmp/core.* /core.* 2>/dev/null' || echo "(no core)"
    echo "--- how far validation got ---"
    grep -aE "^\[|Regime|engaged|errors" /tmp/hunt_orig_a${a}.log | tail -12
    exit 0
  fi
  echo "orig attempt $a: survived (pid=$NPID)"
done
echo "### $ATTEMPTS orig attempts, no death ###"
