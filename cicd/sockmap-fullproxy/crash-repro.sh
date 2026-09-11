#!/bin/bash
#
# sockmap-fullproxy / crash-repro.sh
#
# Reproduces the loxilb process disappearing under burst SSE load and pins down why
# it exits.
#
# Why this is needed: the testbed starts loxilb detached with `docker exec -dt`
# (common.sh), so its exit status is thrown away. Until now nothing beyond "the
# process is gone" was observable. Here loxilb is restarted under a wrapper that
# records the exit status, stderr goes to a file, and core_pattern points inside the
# container so a core is captured too.
#
# Prerequisite: the testbed must be up via ./config.sh.
#   sudo sh -c 'echo "/tmp/core.%e.%p.sig%s" > /proc/sys/kernel/core_pattern'
# Usage: ./crash-repro.sh [rounds]
set -u
source ../common.sh
source ./sockmap_common.sh
sockmap_init_artifacts

ROUNDS=${1:-8}
VIP=10.10.10.254
ON_VP=2070;  ON_BP=9087
OFF_VP=2071; OFF_BP=9097
CONC=${CONC:-128}
PAR=${PAR:-4}
DUR_MS=${DUR_MS:-20000}
WARM_MS=${WARM_MS:-4000}
TOKENS=${TOKENS:-4000}
OUT=${OUT:-/tmp/crashrepro}
mkdir -p "$OUT"

lox_pid() { sudo docker exec -i llb1 sh -c 'pgrep -x loxilb' 2>/dev/null | head -1; }
lox_rss() { local p=$1; sudo docker exec -i llb1 sh -c "awk '/VmRSS/{print \$2}' /proc/$p/status" 2>/dev/null; }
lox_fds() { local p=$1; sudo docker exec -i llb1 sh -c "ls /proc/$p/fd 2>/dev/null | wc -l"; }

echo "=== [1] restart loxilb under a wrapper that records its exit status ==="
sudo docker exec -i llb1 sh -c 'pkill -x loxilb; rm -f /tmp/loxilb-exit.txt /tmp/loxilb-stderr.log /tmp/core.*' || true
sleep 3
# LAUNCH=file : stderr to a file inside the container, so the last message survives.
# LAUNCH=orig : stderr to /proc/1/fd/2 exactly like the testbed does, which is the
#   dockerd log pipe. Go exits immediately on SIGPIPE from a write to fd 1 or 2,
#   without going through a signal handler and leaving no traceback or core. This is
#   the control arm for whether that path explains the disappearance.
# Neither mode uses exec, so the exit status lands in a file (128+signal).
LAUNCH=${LAUNCH:-file}
if [[ "$LAUNCH" == "orig" ]]; then
  REDIR='>/proc/1/fd/1 2>/proc/1/fd/2'
else
  REDIR='>/proc/1/fd/1 2>/tmp/loxilb-stderr.log'
fi
echo "launch mode: $LAUNCH ($REDIR)"
sudo docker exec -d llb1 bash -c "
  ulimit -c unlimited
  cd /tmp
  /root/loxilb-io/loxilb/loxilb --sockmapsupport --loglevel info $REDIR
  echo \"EXIT=\$?\" > /tmp/loxilb-exit.txt"
if ! sockmap_wait_api_ready llb1; then echo "ERROR: API not ready after restart"; exit 1; fi
PID=$(lox_pid)
echo "loxilb restarted pid=$PID  (core ulimit: $(sudo docker exec -i llb1 sh -c "grep 'Max core' /proc/$PID/limits" | awk '{print $5}'))"

echo "=== [2] rules + backends ==="
sockmap_create_lb_via_api llb1 $VIP $ON_VP  $ON_BP  "31.31.31.1,32.32.32.1" both "crash-on"  >/dev/null
sockmap_create_lb_via_api llb1 $VIP $OFF_VP $OFF_BP "31.31.31.1,32.32.32.1" off  "crash-off" >/dev/null
sleep 2
for p in $ON_BP $OFF_BP; do
  $hexec l3ep1 node ./sse_server.js s1 $p 4000 0 >/dev/null 2>&1 &
  $hexec l3ep2 node ./sse_server.js s2 $p 4000 0 >/dev/null 2>&1 &
done
sleep 4
for ep in 31.31.31.1 32.32.32.1; do for p in $ON_BP $OFF_BP; do
  c=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$ep:$p/healthz")
  [[ "$c" == "200" ]] || { echo "ERROR: backend $ep:$p not ready ($c)"; exit 1; }
done; done
echo "backends ready"

echo "=== [3] repeat burst load (up to $ROUNDS rounds) ==="
printf "%-6s %-5s %-10s %-8s %-8s %-9s %s\n" round arm pid rss_MB fds streams status
for ((r=1; r<=ROUNDS; r++)); do
  for arm in on off; do
    [[ $arm == on ]] && vp=$ON_VP || vp=$OFF_VP
    PID=$(lox_pid)
    if [[ -z "$PID" ]]; then echo "loxilb ALREADY DEAD before round $r/$arm"; break 2; fi
    pids=()
    for i in $(seq 1 $PAR); do
      $hexec l3h1 node ./sse_client.js $VIP $vp $CONC $DUR_MS 512 $WARM_MS $TOKENS 0 8 1 \
        > "$OUT/r${r}_${arm}_$i.out" 2>/dev/null &
      pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
    NPID=$(lox_pid)
    st=$(awk '/^SSELINE/{s+=$2} END{print s+0}' "$OUT"/r${r}_${arm}_*.out)
    if [[ -z "$NPID" ]]; then
      printf "%-6s %-5s %-10s %-8s %-8s %-9s %s\n" "$r" "$arm" "$PID" "-" "-" "$st" "*** DIED ***"
      break 2
    fi
    printf "%-6s %-5s %-10s %-8s %-8s %-9s %s\n" "$r" "$arm" "$NPID" \
      "$(( $(lox_rss "$NPID") / 1024 ))" "$(lox_fds "$NPID")" "$st" "alive"
  done
done

echo
echo "=== [4] post-mortem ==="
sudo docker exec -i llb1 sh -c '
  echo "--- exit status ---"; cat /tmp/loxilb-exit.txt 2>/dev/null || echo "(none - still alive, or the wrapper died with it)"
  echo "--- stderr tail ---"; tail -40 /tmp/loxilb-stderr.log 2>/dev/null || echo "(empty)"
  echo "--- cores ---"; ls -la /tmp/core.* 2>/dev/null || echo "(no core)"'
sudo pkill -f "sse_server.js" >/dev/null 2>&1 || true
sockmap_delete_lb_via_api llb1 $VIP $ON_VP  >/dev/null 2>&1 || true
sockmap_delete_lb_via_api llb1 $VIP $OFF_VP >/dev/null 2>&1 || true
