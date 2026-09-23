#!/bin/bash
#
# sockmap-fullproxy / validation-cpu-dir.sh
#
# Splits the CPU gain of sockmap acceleration by DIRECTION.
#
# validation-cpu.sh compares both-directions-on against off. That cannot say what
# accelerating the request direction is worth on its own, and that number decides
# whether a fix which needs the request direction visible to userspace can afford
# to give it up. So this runs four arms - off, request, response, both - over
# three workloads chosen to load each direction:
#
#   response-heavy   GET  /?bytes=65536, no body       (what validation-cpu.sh runs)
#   request-heavy    POST 64KB body, 256 B answer      (the one a GET load never makes)
#   symmetric        POST 64KB body, 64KB answer
#
# Trials are ALTERNATED, not blocked by arm. Every round visits all four arms, and
# the order rotates from round to round, so a drift in the host over the run lands
# on every arm equally instead of on whichever arm happened to run last. That is
# the flaw a blocked design has, and this script exists because a blocked
# comparison was read as an image effect once already.
#
# Prerequisite: the testbed up via config.sh. Creates and removes its own four rules,
# addresses and backends; leaves config.sh's R1/R2 alone. Port 2031/9081 so it
# does not collide with validation-cpu.sh's 2030/9080 either.
#
#   ROUNDS (default 3)  CONC (32)  PAR_CLIENTS (4)  DUR_MS (8000)  WARM_MS (3000)
#   WORKLOADS (default "65536:0 256:65536 65536:65536", as down:up bytes)

source ../common.sh
source ./sockmap_common.sh
sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-cpu-dir"

declare -A VIP=([off]=10.10.10.253 [request]=10.10.10.252 [response]=10.10.10.251 [both]=10.10.10.254)
declare -A EPS=([off]="31.31.31.2,32.32.32.2" [request]="31.31.31.1,32.32.32.1"
                [response]="31.31.31.1,32.32.32.1" [both]="31.31.31.1,32.32.32.1")
ARMS="off request response both"
VPORT=2031; BPORT=9081

ROUNDS=${ROUNDS:-3}
CONC=${CONC:-32}
PAR_CLIENTS=${PAR_CLIENTS:-4}
DUR_MS=${DUR_MS:-8000}
WARM_MS=${WARM_MS:-3000}
SETTLE_MS=${SETTLE_MS:-1000}
GUARD_MS=${GUARD_MS:-1000}
WORKLOADS=${WORKLOADS:-"65536:0 256:65536 65536:65536"}
CPU_WIN_MS=$(( DUR_MS - SETTLE_MS - GUARD_MS ))

PERF_SRV_PIDS=()
cleanup() {
  sudo pkill -f "perf_server.js" >/dev/null 2>&1 || true
  sudo pkill -f "perf_client.js" >/dev/null 2>&1 || true
  local p a
  for p in "${PERF_SRV_PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  for a in $ARMS; do sockmap_delete_lb_via_api llb1 "${VIP[$a]}" "$VPORT" >/dev/null 2>&1 || true; done
  for ip in 10.10.10.251 10.10.10.252 10.10.10.253; do
    sudo ip -n llb1 addr del "$ip/24" dev ellb1l3h1 >/dev/null 2>&1 || true
  done
  sudo ip -n l3ep1 addr del 31.31.31.2/24 dev el3ep1llb1 >/dev/null 2>&1 || true
  sudo ip -n l3ep2 addr del 32.32.32.2/24 dev el3ep2llb1 >/dev/null 2>&1 || true
}
trap cleanup EXIT

ms_sleep() { sleep "$(awk -v m="$1" 'BEGIN{ printf "%.3f", m/1000 }')"; }
sockmap_cpu_stat_usec() {
  local raw
  raw=$(_sm_dexec "$1" sh -c \
    'if [ -r /sys/fs/cgroup/cpu.stat ]; then cat /sys/fs/cgroup/cpu.stat;
     elif [ -r /sys/fs/cgroup/cpuacct/cpuacct.usage ]; then echo "usage_usec $(( $(cat /sys/fs/cgroup/cpuacct/cpuacct.usage)/1000 ))";
     else echo "usage_usec 0"; fi')
  echo "$raw" | awk '/^usage_usec/{print $2; exit}'
}
host_busy_jiffies() {
  awk '/^cpu /{ print $2+$3+$4+$7+$8+$9; exit }' /proc/stat
}
HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)

echo "================ $SCENARIO ================"
echo "rounds=$ROUNDS conc=$CONC par_clients=$PAR_CLIENTS dur_ms=$DUR_MS warm_ms=$WARM_MS cpu_win_ms=$CPU_WIN_MS workloads='$WORKLOADS'"

sockmap_section 1 "Four arms on port $VPORT (off=${VIP[off]} request=${VIP[request]} response=${VIP[response]} both=${VIP[both]})"
for ip in 10.10.10.251 10.10.10.252 10.10.10.253; do sudo ip -n llb1 addr replace "$ip/24" dev ellb1l3h1; done
sudo ip -n l3ep1 addr replace 31.31.31.2/24 dev el3ep1llb1
sudo ip -n l3ep2 addr replace 32.32.32.2/24 dev el3ep2llb1
ok=1
for a in $ARMS; do
  sockmap_create_lb_via_api llb1 "${VIP[$a]}" "$VPORT" "$BPORT" "${EPS[$a]}" "$a" "cpudir-$a" >/dev/null || ok=0
done
if (( ok )); then sockmap_result "four rules created" "OK"; else sockmap_result "four rules created" "FAILED"; echo "RESULT: $SCENARIO [FAILED]"; exit 1; fi
$hexec l3ep1 node ./perf_server.js server1 "$BPORT" 256 & PERF_SRV_PIDS+=("$!")
$hexec l3ep2 node ./perf_server.js server2 "$BPORT" 256 & PERF_SRV_PIDS+=("$!")
sleep 3
ready=1
for a in $ARMS; do
  code=$($hexec l3h1 curl -s --max-time 3 -o /dev/null -w '%{http_code}' "http://${VIP[$a]}:$VPORT/?bytes=64")
  [[ "$code" == "200" ]] || { ready=0; echo "    arm $a: code=$code"; }
done
if (( ready )); then sockmap_result "all four arms serve" "OK"; else sockmap_result "all four arms serve" "FAILED"; echo "RESULT: $SCENARIO [FAILED]"; exit 1; fi

# measure <arm> <down> <up> <tag>  -> M_RPS M_MBPS M_CORES M_CPR M_HPR M_RREQ M_RRESP M_ERR
measure() {
  local arm=$1 down=$2 up=$3 tag=$4 vip=${VIP[$1]}
  local i out pids=() outs=()
  for i in $(seq 1 "$PAR_CLIENTS"); do
    out="$SOCKMAP_ARTIFACTS_DIR/cpudir_${tag}_c${i}.out"; : > "$out"
    $hexec l3h1 node ./perf_client.js "$vip" "$VPORT" "$CONC" "$DUR_MS" "$down" "$WARM_MS" "$up" >"$out" 2>/dev/null &
    pids+=("$!"); outs+=("$out")
  done
  ms_sleep "$(( WARM_MS + SETTLE_MS ))"
  local cb hb rqb rsb ca ha rqa rsa
  cb=$(sockmap_cpu_stat_usec llb1); hb=$(host_busy_jiffies)
  rqb=$(sockmap_redirect_req_count llb1); rsb=$(sockmap_redirect_resp_count llb1)
  ms_sleep "$CPU_WIN_MS"
  ca=$(sockmap_cpu_stat_usec llb1); ha=$(host_busy_jiffies)
  rqa=$(sockmap_redirect_req_count llb1); rsa=$(sockmap_redirect_resp_count llb1)
  for i in "${pids[@]}"; do wait "$i" 2>/dev/null || true; done
  local agg
  agg=$(cat "${outs[@]}" 2>/dev/null | awk '/^PERFLINE/ { req+=$2; err+=$3; rps+=$4; mbps+=$5 } END { printf "%d %d %.1f %.2f", req, err, rps, mbps }')
  read -r M_REQ M_ERR M_RPS M_MBPS <<< "$agg"
  M_RREQ=$(( rqa - rqb )); M_RRESP=$(( rsa - rsb ))
  read -r M_CORES M_CPR M_HPR < <(awk -v cpu="$(( ca - cb ))" -v hj="$(( ha - hb ))" -v hz="$HZ" \
      -v req="$M_REQ" -v win_ms="$CPU_WIN_MS" -v dur_ms="$DUR_MS" 'BEGIN{
        win_s=win_ms/1000.0; frac=win_ms/dur_ms; req_w=req*frac;
        cores=(win_s>0)? cpu/(win_s*1e6):0;
        cpr=(req_w>0)? cpu/req_w:0;
        hpr=(req_w>0)? (hj*1e6/hz)/req_w:0;
        printf "%.3f %.2f %.2f", cores, cpr, hpr }')
}

sockmap_section 2 "Measurements: $ROUNDS rounds, arm order rotated each round"
declare -A S_CPR S_HPR S_RPS S_CORES S_RREQ S_RRESP S_ERR   # key: "arm|down:up" -> space-separated samples
arms_arr=($ARMS)
for wl in $WORKLOADS; do
  down=${wl%%:*}; up=${wl##*:}
  for (( r=0; r<ROUNDS; r++ )); do
    # rotate by r, reverse on odd rounds: no arm keeps a fixed slot in the run
    order=()
    for (( k=0; k<4; k++ )); do order+=("${arms_arr[$(( (k + r) % 4 ))]}"); done
    (( r % 2 )) && order=("${order[3]}" "${order[2]}" "${order[1]}" "${order[0]}")
    for a in "${order[@]}"; do
      measure "$a" "$down" "$up" "${a}_${down}_${up}_r${r}"
      key="$a|$wl"
      S_CPR[$key]+="$M_CPR "; S_HPR[$key]+="$M_HPR "; S_RPS[$key]+="$M_RPS "; S_CORES[$key]+="$M_CORES "
      S_RREQ[$key]+="$M_RREQ "; S_RRESP[$key]+="$M_RRESP "; S_ERR[$key]+="$M_ERR "
      printf "    r%d %-8s down=%-6s up=%-6s rps=%-8s cores=%-6s lox_us/req=%-8s host_us/req=%-8s redir req=%-9s resp=%-9s err=%s\n" \
        "$r" "$a" "$down" "$up" "$M_RPS" "$M_CORES" "$M_CPR" "$M_HPR" "$M_RREQ" "$M_RRESP" "$M_ERR"
    done
  done
done

mean() { awk '{ s=0; for(i=1;i<=NF;i++) s+=$i; printf "%.2f", (NF? s/NF:0) }' <<< "$1"; }
spread() { awk '{ mn=$1; mx=$1; for(i=1;i<=NF;i++){ if($i<mn)mn=$i; if($i>mx)mx=$i } printf "%.2f", mx-mn }' <<< "$1"; }
sum() { awk '{ s=0; for(i=1;i<=NF;i++) s+=$i; print s }' <<< "$1"; }

sockmap_section 3 "Engagement (the comparison is meaningless without it)"
for wl in $WORKLOADS; do
  for a in $ARMS; do
    key="$a|$wl"; rq=$(sum "${S_RREQ[$key]}"); rs=$(sum "${S_RRESP[$key]}")
    case $a in
      off)      want="req==0 resp==0"; (( rq == 0 && rs == 0 )) && v=OK || v=FAILED ;;
      request)  want="req>0 resp==0";  (( rq > 0 && rs == 0 )) && v=OK || v=FAILED ;;
      response) want="req==0 resp>0";  (( rq == 0 && rs > 0 )) && v=OK || v=FAILED ;;
      both)     want="req>0 resp>0";   (( rq > 0 && rs > 0 )) && v=OK || v=FAILED ;;
    esac
    sockmap_result "$wl $a engaged as expected ($want)" "$v" "req=$rq resp=$rs"
  done
done

sockmap_section 4 "Per-direction CPU gain (mean over $ROUNDS rounds; lower us/req is better)"
printf "    %-14s %-9s %-9s %-13s %-13s %-9s\n" "workload" "arm" "rps" "lox_us/req" "host_us/req" "spread"
for wl in $WORKLOADS; do
  down=${wl%%:*}; up=${wl##*:}
  label="down=$down up=$up"
  declare -A M
  for a in $ARMS; do
    key="$a|$wl"; M[$a]=$(mean "${S_CPR[$key]}")
    printf "    %-14s %-9s %-9s %-13s %-13s %-9s\n" "$label" "$a" "$(mean "${S_RPS[$key]}")" "${M[$a]}" "$(mean "${S_HPR[$key]}")" "±$(spread "${S_CPR[$key]}")"
  done
  awk -v off="${M[off]}" -v rq="${M[request]}" -v rs="${M[response]}" -v bo="${M[both]}" -v l="$label" 'BEGIN{
    if (off<=0) { print "    (off arm has no CPU sample)"; exit }
    printf "    %-14s gain vs off (lox_us/req): request-only %+.1f%%   response-only %+.1f%%   both %+.1f%%\n",
      l, (off-rq)/off*100, (off-rs)/off*100, (off-bo)/off*100 }'
  echo
done
echo "    reading: a gain is what that direction's acceleration is worth on that workload."
echo "             request-only on the request-heavy row is the number that decides whether the"
echo "             request direction can be given up; compare its spread before trusting a sign."

{
  echo "# sockmap per-direction CPU ($(date -u +%FT%TZ)) rounds=$ROUNDS conc=$CONC par=$PAR_CLIENTS dur_ms=$DUR_MS"
  echo "workload arm lox_us_per_req_samples | host_us_per_req_samples | rps_samples"
  for wl in $WORKLOADS; do for a in $ARMS; do key="$a|$wl"; echo "$wl $a ${S_CPR[$key]}| ${S_HPR[$key]}| ${S_RPS[$key]}"; done; done
} > "$SOCKMAP_ARTIFACTS_DIR/cpu_dir.txt"
echo "    [saved] $SOCKMAP_ARTIFACTS_DIR/cpu_dir.txt"

echo
if (( SOCKMAP_FAIL_COUNT == 0 )); then echo "RESULT: $SCENARIO [OK]  (CPU numbers are informational)"; exit 0
else echo "RESULT: $SCENARIO [FAILED] ($SOCKMAP_FAIL_COUNT check(s) failed)"; exit 1; fi
