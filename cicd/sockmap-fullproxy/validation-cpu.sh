#!/bin/bash
#
# sockmap-fullproxy / validation-cpu.sh
#
# Compares loxilb CPU efficiency with sockmap acceleration on vs off.
#
# Why this is a separate script
# -----------------------------
# validation_perf.sh only looks at RPS, MB/s and latency. But the real benefit of
# sockmap (sk_skb stream_verdict + bpf_sk_redirect_hash, HAVE_SOCKOPS build) is that
# once a connection engages splice, the kernel takes over the data relay and loxilb
# userspace drops out of the per-byte recv()/send() and user<->kernel copies. The
# primary effect is therefore not throughput but CPU consumed per unit of work. With a
# single-host, single-Node closed loop the client becomes the bottleneck first (see
# Caveat #2 in the perf document), so loxilb never gets loaded enough for the CPU
# difference to show up in validation_perf.sh's scenario.
#
# Measurement strategy
# --------------------
#   1) Amplify load: run PAR_CLIENTS copies of perf_client.js in parallel, each with its
#      own event loop, to get past the single-Node bottleneck and actually CPU-load
#      loxilb.
#   2) Attributable CPU: snapshot the loxilb container cgroup's cpu.stat (usage/user/
#      system usec) before and after the window, giving exactly the microseconds loxilb
#      consumed in it - loxilb only, not the whole host, so client and backend Node CPU
#      never mix in.
#   3) Normalize: RPS differs between on and off, so raw CPU% cannot be compared.
#      Normalizing to CPU per request (us/req) and CPU per MB (us/MB) answers whether
#      the same work is done with less CPU.
#   4) Engagement check: within the window the on arm's redirect counter must rise
#      (splice really happening) and the off arm's must not (control). A CPU comparison
#      without engagement is meaningless, so this is a gate.
#
# Payloads: the large one (64 KB) is where per-byte datapath CPU dominates, so the
# splice effect - or the sk_skb per-segment penalty - shows most clearly. The small one
# (256 B) is dominated by connection and parsing overhead and serves as a control.
#
# Prerequisite: the testbed (containers/network) must be up via config.sh. This script
#       creates and cleans up its own cpu-on/cpu-off rules and backends, leaving
#       config.sh's R1/R2 alone.
# Run: ./config.sh && ./validation-cpu.sh && ./rmconfig.sh
#
# Tuning (environment variables):
#   CONC (connections per client, default 32)  PAR_CLIENTS (parallel clients, default 4)
#   DUR_MS (client window, default 12000)  WARM_MS (warm-up, default 3000)
#   SETTLE_MS/GUARD_MS (margin inside the CPU window, default 1000/1000)
#   SIZES (default "65536 256")
#   If loxilb does not get loaded (avg cores < MIN_CORES_WARN, default 0.2) it warns and
#   suggests raising PAR_CLIENTS/CONC.

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-cpu"
PERF_VIP="10.10.10.254"
ON_VPORT=2030;  ON_BPORT=9080
OFF_VPORT=2031; OFF_BPORT=9090
EPS="31.31.31.1,32.32.32.1"

CONC=${CONC:-32}              # concurrent keep-alive connections per client
PAR_CLIENTS=${PAR_CLIENTS:-4} # parallel clients, each its own Node process
DUR_MS=${DUR_MS:-12000}       # client measurement window (ms)
WARM_MS=${WARM_MS:-3000}      # warm-up (excluded); absorbs connection setup and the
                              # first-request splice engage
SETTLE_MS=${SETTLE_MS:-1000}  # margin from end of warm-up to the CPU 'before' snapshot,
                              # absorbing client launch skew
GUARD_MS=${GUARD_MS:-1000}    # takes the CPU 'after' snapshot before the clients stop,
                              # trimming the idle tail
SIZES=${SIZES:-"65536 256"}   # payload sizes in bytes, largest first
MIN_CORES_WARN=${MIN_CORES_WARN:-0.2}

# CPU window length (ms): a sub-interval of the client window [WARM, WARM+DUR]
CPU_WIN_MS=$(( DUR_MS - SETTLE_MS - GUARD_MS ))
if (( CPU_WIN_MS < 2000 )); then
  echo "ERROR: CPU_WIN_MS=$CPU_WIN_MS too small; raise DUR_MS or lower SETTLE_MS/GUARD_MS"
  exit 1
fi

PERF_SRV_PIDS=()

cleanup() {
  sudo pkill -f "perf_server.js" >/dev/null 2>&1 || true
  sudo pkill -f "perf_client.js" >/dev/null 2>&1 || true
  local p
  for p in "${PERF_SRV_PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  sockmap_delete_lb_via_api llb1 "$PERF_VIP" "$ON_VPORT"  >/dev/null 2>&1 || true
  sockmap_delete_lb_via_api llb1 "$PERF_VIP" "$OFF_VPORT" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Millisecond sleep, using coreutils sleep's fractional-second support.
ms_sleep() { sleep "$(awk -v m="$1" 'BEGIN{ printf "%.3f", m/1000 }')"; }

# Snapshot of the loxilb container cgroup's cumulative CPU in microseconds.
# Returns "usage_usec user_usec system_usec", monotonically increasing. cgroup v2 is
# preferred with v1 as a fallback. The cgroup is loxilb's alone, so client and backend
# CPU never mix in.
sockmap_cpu_stat_usec() {
  local llb=$1 raw usage user sys
  raw=$(_sm_dexec "$llb" sh -c \
    'if [ -r /sys/fs/cgroup/cpu.stat ]; then cat /sys/fs/cgroup/cpu.stat;
     elif [ -r /sys/fs/cgroup/cpuacct/cpuacct.usage ]; then echo "usage_usec $(( $(cat /sys/fs/cgroup/cpuacct/cpuacct.usage)/1000 ))";
     elif [ -r /sys/fs/cgroup/cpu,cpuacct/cpuacct.usage ]; then echo "usage_usec $(( $(cat /sys/fs/cgroup/cpu,cpuacct/cpuacct.usage)/1000 ))";
     else echo "usage_usec 0"; fi')
  usage=$(echo "$raw" | awk '/^usage_usec/{print $2; exit}')
  user=$(echo "$raw"  | awk '/^user_usec/{print $2; exit}')
  sys=$(echo "$raw"   | awk '/^system_usec/{print $2; exit}')
  echo "${usage:-0} ${user:-0} ${sys:-0}"
}

# Host-wide CPU snapshot (/proc/stat, USER_HZ jiffies). Returns "busy softirq system".
# The loxilb cgroup only captures userspace process CPU, while the kernel work of
# sk_skb redirect runs in softirq context and can be accounted outside the cgroup,
# mostly to ksoftirqd/root. Telling whether splice removed the work or merely moved it
# into the kernel therefore requires the host-wide numbers, softirq in particular.
#   busy = user+nice+system+irq+softirq+steal (idle/iowait excluded)
HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)
host_cpu_jiffies() {
  awk '/^cpu /{
        user=$2; nice=$3; sys=$4; irq=$7; softirq=$8; steal=$9;
        busy=user+nice+sys+irq+softirq+steal;
        printf "%d %d %d", busy, softirq, sys+irq+softirq;
        exit }' /proc/stat
}

echo "================ $SCENARIO ================"
echo "conc=$CONC par_clients=$PAR_CLIENTS dur_ms=$DUR_MS warm_ms=$WARM_MS cpu_win_ms=$CPU_WIN_MS sizes='$SIZES'"

# ---------- [1] boot assets ----------
sockmap_section 1 "Daemon boot assets"
if sockmap_assert_bpf_assets llb1; then
  sockmap_result "sockops prog + 5 sockmap maps attached" "OK"
else
  sockmap_result "sockops prog + 5 sockmap maps attached" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (bootstrap)"; exit 1
fi

# ---------- [2] create on/off rules (separate backend ports) ----------
sockmap_section 2 "Create CPU rules (on=$ON_VPORT->$ON_BPORT, off=$OFF_VPORT->$OFF_BPORT)"
if sockmap_create_lb_via_api llb1 "$PERF_VIP" "$ON_VPORT"  "$ON_BPORT"  "$EPS" true  "cpu-on" \
   && sockmap_create_lb_via_api llb1 "$PERF_VIP" "$OFF_VPORT" "$OFF_BPORT" "$EPS" false "cpu-off"; then
  sockmap_result "cpu-on / cpu-off rules created" "OK"
else
  sockmap_result "cpu-on / cpu-off rules created" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (rule create)"; exit 1
fi
sleep 2

if sockmap_portset_has llb1 "$SOCKMAP_VIP_NAME" "$ON_VPORT" \
   && sockmap_portset_has llb1 "$SOCKMAP_EP_NAME" "$ON_BPORT"; then
  sockmap_result "cpu-on vip $ON_VPORT + ep $ON_BPORT in portsets" "OK"
else
  sockmap_result "cpu-on vip $ON_VPORT + ep $ON_BPORT in portsets" "FAILED"
fi

# ---------- [3] start backend servers (9080 + 9090) ----------
sockmap_section 3 "Start backend HTTP servers on $ON_BPORT and $OFF_BPORT"
$hexec l3ep1 node ./perf_server.js server1 "$ON_BPORT"  256 & PERF_SRV_PIDS+=("$!")
$hexec l3ep1 node ./perf_server.js server1 "$OFF_BPORT" 256 & PERF_SRV_PIDS+=("$!")
$hexec l3ep2 node ./perf_server.js server2 "$ON_BPORT"  256 & PERF_SRV_PIDS+=("$!")
$hexec l3ep2 node ./perf_server.js server2 "$OFF_BPORT" 256 & PERF_SRV_PIDS+=("$!")

sleep 3
ready=0
for i in $(seq 1 20); do
  ok=1
  for ep in 31.31.31.1 32.32.32.1; do
    for pp in "$ON_BPORT" "$OFF_BPORT"; do
      code=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$ep:$pp/?bytes=16" 2>/dev/null || echo 000)
      [[ "$code" == "200" ]] || ok=0
    done
  done
  (( ok == 1 )) && { ready=1; break; }
  sleep 1
done
if (( ready == 1 )); then
  sockmap_result "backends ready on $ON_BPORT/$OFF_BPORT (both eps)" "OK"
else
  sockmap_result "backends ready on $ON_BPORT/$OFF_BPORT (both eps)" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (backend not ready)"; exit 1
fi

# ---------- [4] sanity via VIPs ----------
sockmap_section 4 "Sanity: both VIPs serve via fullproxy"
on_code=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$PERF_VIP:$ON_VPORT/?bytes=256" 2>/dev/null || echo 000)
off_code=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$PERF_VIP:$OFF_VPORT/?bytes=256" 2>/dev/null || echo 000)
[[ "$on_code"  == "200" ]] && sockmap_result "cpu-on VIP $ON_VPORT serves (200)"  "OK" || sockmap_result "cpu-on VIP $ON_VPORT serves (200)"  "FAILED" "code=$on_code"
[[ "$off_code" == "200" ]] && sockmap_result "cpu-off VIP $OFF_VPORT serves (200)" "OK" || sockmap_result "cpu-off VIP $OFF_VPORT serves (200)" "FAILED" "code=$off_code"

# ---------- CPU measure helper ----------
# $1 vip $2 vport $3 bytes $4 tag
# Globals produced here: CPU per request, per MB, and so on
M_RPS=0; M_MBPS=0; M_REQ=0; M_ERR=0; M_NCLI=0; M_MEAN=0
M_CPU_US=0; M_USER_US=0; M_SYS_US=0; M_CORES=0
M_CPU_PER_REQ=0; M_CPU_PER_MB=0; M_USER_PER_REQ=0; M_SYS_PER_REQ=0
M_REDIR_DELTA=0
M_HOST_CORES=0; M_SI_CORES=0; M_HOST_PER_REQ=0; M_SI_PER_REQ=0
measure_cpu() {
  local vip=$1 vport=$2 bytes=$3 tag=$4
  local i out pids=() outs=()

  # Launch the parallel clients (each warm=WARM_MS, dur=DUR_MS), one output file each.
  for i in $(seq 1 "$PAR_CLIENTS"); do
    out="$SOCKMAP_ARTIFACTS_DIR/cpu_${tag}_${bytes}_c${i}.out"
    : > "$out"
    $hexec l3h1 node ./perf_client.js "$vip" "$vport" "$CONC" "$DUR_MS" "$bytes" "$WARM_MS" \
      >"$out" 2>/dev/null &
    pids+=("$!"); outs+=("$out")
  done

  # Take the CPU/redirect 'before' snapshot once warm-up and launch skew are past.
  ms_sleep "$(( WARM_MS + SETTLE_MS ))"
  local cb ub sb rdb hbb hsib hsyb
  read -r cb ub sb < <(sockmap_cpu_stat_usec llb1)
  read -r hbb hsib hsyb < <(host_cpu_jiffies)
  rdb=$(sockmap_redirect_count llb1)

  # Wait out the CPU window, which sits inside the client window.
  ms_sleep "$CPU_WIN_MS"
  local ca ua sa rda hba hsia hsya
  read -r ca ua sa < <(sockmap_cpu_stat_usec llb1)
  read -r hba hsia hsya < <(host_cpu_jiffies)
  rda=$(sockmap_redirect_count llb1)

  # Wait for the clients to finish, then aggregate their output.
  for i in "${pids[@]}"; do wait "$i" 2>/dev/null || true; done

  local agg
  agg=$(cat "${outs[@]}" 2>/dev/null | awk '
    /^PERFLINE/ { req+=$2; err+=$3; rps+=$4; mbps+=$5; meansum+=$6; n++ }
    END { printf "%d %d %.1f %.2f %.3f %d", req, err, rps, mbps, (n? meansum/n : 0), n }')
  read -r M_REQ M_ERR M_RPS M_MBPS M_MEAN M_NCLI <<< "$agg"

  M_CPU_US=$(( ca - cb ))
  M_USER_US=$(( ua - ub ))
  M_SYS_US=$(( sa - sb ))
  M_REDIR_DELTA=$(( rda - rdb ))

  # Normalization: the CPU window is a sub-interval of the client window, of relative
  # length CPU_WIN_MS/DUR_MS. Assuming steady state, requests and bytes within the CPU
  # window are the full measurement scaled by that fraction.
  read -r M_CORES M_CPU_PER_REQ M_CPU_PER_MB M_USER_PER_REQ M_SYS_PER_REQ < <(awk \
    -v cpu="$M_CPU_US" -v usr="$M_USER_US" -v sys="$M_SYS_US" \
    -v req="$M_REQ" -v mbps="$M_MBPS" -v win_ms="$CPU_WIN_MS" -v dur_ms="$DUR_MS" '
    BEGIN {
      win_s   = win_ms/1000.0;
      frac    = win_ms/dur_ms;       # fraction of the client window covered by the CPU window
      req_w   = req * frac;          # requests within the CPU window
      mb_w    = mbps * win_s;        # MB transferred within the CPU window (mbps is summed MB/s)
      cores   = (win_s>0)? cpu/(win_s*1e6) : 0;
      cpr     = (req_w>0)? cpu/req_w : 0;
      cpm     = (mb_w >0)? cpu/mb_w  : 0;
      upr     = (req_w>0)? usr/req_w : 0;
      spr     = (req_w>0)? sys/req_w : 0;
      printf "%.3f %.2f %.1f %.2f %.2f", cores, cpr, cpm, upr, spr;
    }')

  # Host-wide CPU delta.
  # The loxilb cgroup only captures userspace process CPU. sk_skb redirect runs in
  # kernel softirq context and can land outside the cgroup, so reading host-wide and
  # softirq together is what distinguishes work splice removed from work it moved into
  # the kernel.
  local hb_delta si_delta
  hb_delta=$(( hba - hbb ))
  si_delta=$(( hsia - hsib ))
  read -r M_HOST_CORES M_SI_CORES M_HOST_PER_REQ M_SI_PER_REQ < <(awk \
    -v hb="$hb_delta" -v si="$si_delta" \
    -v req="$M_REQ" -v win_ms="$CPU_WIN_MS" -v dur_ms="$DUR_MS" -v hz="$HZ" '
    BEGIN {
      win_s  = win_ms/1000.0;
      frac   = win_ms/dur_ms;
      req_w  = req * frac;
      hb_us  = (hz>0)? hb/hz*1e6 : 0;
      si_us  = (hz>0)? si/hz*1e6 : 0;
      hcores = (win_s>0)? hb_us/(win_s*1e6) : 0;
      scores = (win_s>0)? si_us/(win_s*1e6) : 0;
      hpr    = (req_w>0)? hb_us/req_w : 0;
      spr    = (req_w>0)? si_us/req_w : 0;
      printf "%.3f %.3f %.1f %.1f", hcores, scores, hpr, spr;
    }')
}

# ---------- [5] CPU benchmark on vs off ----------
sockmap_section 5 "CPU benchmark (loxilb cgroup cpu.stat over ${CPU_WIN_MS}ms steady window)"

declare -A ON_RPS ON_MBPS ON_CORES ON_CPR ON_CPM ON_UPR ON_SPR ON_REDIR ON_ERR ON_NCLI ON_HCORES ON_SICORES ON_HPR ON_SIPR
declare -A OFF_RPS OFF_MBPS OFF_CORES OFF_CPR OFF_CPM OFF_UPR OFF_SPR OFF_REDIR OFF_ERR OFF_NCLI OFF_HCORES OFF_SICORES OFF_HPR OFF_SIPR

for bytes in $SIZES; do
  # --- ON ---
  measure_cpu "$PERF_VIP" "$ON_VPORT" "$bytes" "on"
  ON_RPS[$bytes]=$M_RPS;   ON_MBPS[$bytes]=$M_MBPS; ON_CORES[$bytes]=$M_CORES
  ON_CPR[$bytes]=$M_CPU_PER_REQ; ON_CPM[$bytes]=$M_CPU_PER_MB
  ON_UPR[$bytes]=$M_USER_PER_REQ; ON_SPR[$bytes]=$M_SYS_PER_REQ
  ON_REDIR[$bytes]=$M_REDIR_DELTA; ON_ERR[$bytes]=$M_ERR; ON_NCLI[$bytes]=$M_NCLI
  ON_HCORES[$bytes]=$M_HOST_CORES; ON_SICORES[$bytes]=$M_SI_CORES
  ON_HPR[$bytes]=$M_HOST_PER_REQ;  ON_SIPR[$bytes]=$M_SI_PER_REQ
  on_cores=$M_CORES

  # --- OFF ---
  measure_cpu "$PERF_VIP" "$OFF_VPORT" "$bytes" "off"
  OFF_RPS[$bytes]=$M_RPS;   OFF_MBPS[$bytes]=$M_MBPS; OFF_CORES[$bytes]=$M_CORES
  OFF_CPR[$bytes]=$M_CPU_PER_REQ; OFF_CPM[$bytes]=$M_CPU_PER_MB
  OFF_UPR[$bytes]=$M_USER_PER_REQ; OFF_SPR[$bytes]=$M_SYS_PER_REQ
  OFF_REDIR[$bytes]=$M_REDIR_DELTA; OFF_ERR[$bytes]=$M_ERR; OFF_NCLI[$bytes]=$M_NCLI
  OFF_HCORES[$bytes]=$M_HOST_CORES; OFF_SICORES[$bytes]=$M_SI_CORES
  OFF_HPR[$bytes]=$M_HOST_PER_REQ;  OFF_SIPR[$bytes]=$M_SI_PER_REQ

  # Required engagement check: on redirect>0, off redirect==0.
  if (( ${ON_REDIR[$bytes]} > 0 )); then
    sockmap_result "bytes=$bytes ON sockmap engaged (redirect>0)" "OK" "delta=${ON_REDIR[$bytes]}"
  else
    sockmap_result "bytes=$bytes ON sockmap engaged (redirect>0)" "FAILED" "delta=${ON_REDIR[$bytes]}; CPU comparison is meaningless"
  fi
  if (( ${OFF_REDIR[$bytes]} == 0 )); then
    sockmap_result "bytes=$bytes OFF not engaged (redirect==0)" "OK"
  else
    sockmap_result "bytes=$bytes OFF not engaged (redirect==0)" "FAILED" "delta=${OFF_REDIR[$bytes]}"
  fi

  # Warn if loxilb did not get enough load.
  awk -v on="$on_cores" -v off="${OFF_CORES[$bytes]}" -v thr="$MIN_CORES_WARN" 'BEGIN{
    m = (on>off)? on : off;
    if (m < thr) exit 1; else exit 0;
  }' || sockmap_result "bytes=$bytes loxilb CPU-loaded (>=$MIN_CORES_WARN cores)" "FAILED" \
        "on=${on_cores} off=${OFF_CORES[$bytes]} cores; consider raising PAR_CLIENTS/CONC"
done

# ---------- [6] comparison table ----------
sockmap_section 6 "Comparison: loxilb cgroup CPU + host-wide CPU (ON vs OFF)"
fmt_size() { local b=$1; if (( b >= 1024 )); then echo "$((b/1024))KB"; else echo "${b}B"; fi; }

# Columns:
#   lox_cores  = loxilb container cgroup CPU (userspace work only)
#   host_cores = host-wide busy CPU (loxilb userspace plus kernel softirq/redirect)
#   si_cores   = host softirq CPU (where the kernel work of sk_skb redirect lands)
#   lox/req    = loxilb cgroup CPU (us) per request
#   host/req   = host-wide CPU (us) per request, the real system efficiency measure
printf "    %-8s %-5s %-9s %-9s %-11s %-11s %-11s %-10s %-10s\n" \
  "payload" "mode" "rps" "MB/s" "lox_cores" "host_cores" "si_cores" "lox_us/req" "host_us/req"
printf "    %-8s %-5s %-9s %-9s %-11s %-11s %-11s %-10s %-10s\n" \
  "-------" "----" "---" "----" "---------" "----------" "--------" "----------" "-----------"

for bytes in $SIZES; do
  ps=$(fmt_size "$bytes")
  printf "    %-8s %-5s %-9s %-9s %-11s %-11s %-11s %-10s %-10s\n" "$ps" "ON" \
    "${ON_RPS[$bytes]}" "${ON_MBPS[$bytes]}" \
    "${ON_CORES[$bytes]}" "${ON_HCORES[$bytes]}" "${ON_SICORES[$bytes]}" \
    "${ON_CPR[$bytes]}" "${ON_HPR[$bytes]}"
  printf "    %-8s %-5s %-9s %-9s %-11s %-11s %-11s %-10s %-10s\n" "$ps" "OFF" \
    "${OFF_RPS[$bytes]}" "${OFF_MBPS[$bytes]}" \
    "${OFF_CORES[$bytes]}" "${OFF_HCORES[$bytes]}" "${OFF_SICORES[$bytes]}" \
    "${OFF_CPR[$bytes]}" "${OFF_HPR[$bytes]}"
  awk -v cpr_on="${ON_CPR[$bytes]}"  -v cpr_off="${OFF_CPR[$bytes]}" \
      -v hpr_on="${ON_HPR[$bytes]}"  -v hpr_off="${OFF_HPR[$bytes]}" \
      -v rps_on="${ON_RPS[$bytes]}"  -v rps_off="${OFF_RPS[$bytes]}" \
      -v hc_on="${ON_HCORES[$bytes]}" -v hc_off="${OFF_HCORES[$bytes]}" \
      -v si_on="${ON_SICORES[$bytes]}" -v ps="$ps" '
    BEGIN {
      lox_x  = (cpr_off>0)? cpr_on/cpr_off : 0;
      host_x = (hpr_off>0)? hpr_on/hpr_off : 0;
      rps_x  = (rps_off>0)? rps_on/rps_off : 0;
      printf "    %-8s %-5s lox_cpu/req x%.2f, host_cpu/req x%.2f (ON vs OFF), rps x%.2f\n",
             ps, "delta", lox_x, host_x, rps_x;
      printf "    %8s       [si_cores ON=%-6s OFF=%-6s -> the softirq increase is splice kernel work]\n",
             "", si_on, ((hc_off-hc_on)>0 ? sprintf("%.3f",hc_off-hc_on) : "~0");
    }'
  echo
done

# save artifacts
{
  echo "# sockmap CPU comparison ($(date -u +%FT%TZ))"
  echo "# conc=$CONC par_clients=$PAR_CLIENTS dur_ms=$DUR_MS warm_ms=$WARM_MS cpu_win_ms=$CPU_WIN_MS"
  echo "# lox_cores=cgroup, host_cores=host-wide busy, si_cores=host softirq"
  echo "payload mode rps mbps lox_cores host_cores si_cores lox_us/req host_us/req cpu_us/MB redirect_delta"
  for bytes in $SIZES; do
    echo "$bytes ON  ${ON_RPS[$bytes]}  ${ON_MBPS[$bytes]}  ${ON_CORES[$bytes]}  ${ON_HCORES[$bytes]}  ${ON_SICORES[$bytes]}  ${ON_CPR[$bytes]}  ${ON_HPR[$bytes]}  ${ON_CPM[$bytes]}  ${ON_REDIR[$bytes]}"
    echo "$bytes OFF ${OFF_RPS[$bytes]} ${OFF_MBPS[$bytes]} ${OFF_CORES[$bytes]} ${OFF_HCORES[$bytes]} ${OFF_SICORES[$bytes]} ${OFF_CPR[$bytes]} ${OFF_HPR[$bytes]} ${OFF_CPM[$bytes]} ${OFF_REDIR[$bytes]}"
  done
} > "$SOCKMAP_ARTIFACTS_DIR/cpu_comparison.txt"
echo "    [saved] $SOCKMAP_ARTIFACTS_DIR/cpu_comparison.txt"
echo "    note: a lower host_us/req on the ON arm means overall system efficiency improved even after the work moved into the kernel."

# ---------- finalize ----------
echo
if (( SOCKMAP_FAIL_COUNT == 0 )); then
  echo "RESULT: $SCENARIO [OK]  (CPU numbers above are informational)"
  exit 0
else
  echo "RESULT: $SCENARIO [FAILED] ($SOCKMAP_FAIL_COUNT check(s) failed)"
  echo "Artifacts: $SOCKMAP_ARTIFACTS_DIR/"
  exit 1
fi
