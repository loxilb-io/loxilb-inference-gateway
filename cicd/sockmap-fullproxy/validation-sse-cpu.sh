#!/bin/bash
#
# sockmap-fullproxy / validation-sse-cpu.sh
#
# Compares CPU efficiency and latency of sockmap acceleration on vs off under
# OpenAI-compatible SSE (Server-Sent Events) streaming traffic.
#
# Why this is separate from validation-cpu.sh
# -------------------------------------------
# validation-cpu.sh drives keep-alive GETs, one request to one response. In that model:
#   - the fixed cost of "the first request on a connection goes through userspace
#     because peer_map is not installed yet" is mixed into every request, and
#   - the response ends in one large write, so per-byte cost dominates.
#
# Real LLM / AI gateway traffic has a different shape:
#   - one request (POST /v1/chat/completions) is answered by hundreds of small chunks
#     over tens of seconds, one token being a 200-300 B write
#   - the connection stays alive until the stream ends, and the number of concurrent
#     streams is the load
#
# That shape structurally favours sockmap. peer_map is installed when the backend
# connection is established (the HAVE_SOCKOPS block in sockproxy.c), which is right
# after request parsing and therefore before the response stream begins. So the entire
# SSE response, hundreds of chunks, is eligible for kernel redirect. With acceleration
# off, every single token costs an epoll wakeup -> recv() -> copy -> send().
# CPU per token is therefore the central metric of this experiment.
#
# The measurement strategy follows validation-cpu.sh, with the same dual accounting:
#   - loxilb container cgroup cpu.stat: userspace process CPU only, not mixed with the
#     client or backend
#   - host /proc/stat busy + softirq: where the kernel work of sk_skb redirect lands
#   Both are needed to tell work that disappeared from work that moved into the kernel.
#
# Two load regimes
# ----------------
#   paced (default, rate>0) - fixes the per-stream token rate (25 tok/s for example) and
#     varies load by the number of concurrent streams. Both arms do the same amount of
#     work, so CPU compares directly with no normalization error. This is closest to
#     real LLM serving, and it is the only regime where TTFT/ITL comparison is meaningful.
#   burst (rate=0) - the backend pushes as fast as it can, for a saturation throughput
#     comparison in the spirit of the earlier CPU document. Chunks coalesce at the TCP
#     level here, so ITL carries no meaning.
#
# Prerequisite: the testbed must be up via config.sh. This script creates and cleans up
# only its own rules and backends.
# Run: ./config.sh && ./validation-sse-cpu.sh && ./rmconfig.sh
#
# Tuning (environment variables):
#   MODES        arms to compare (default "on off"; "on resp off" adds response-only)
#   REGIMES      any of "paced burst" (default "paced burst")
#   CONC         concurrent streams per client (default 128)
#   PAR_CLIENTS  parallel client processes (default 4); total streams = CONC*PAR_CLIENTS
#   PACED_RATE   tokens/s per stream in the paced regime (default 25)
#   PACED_TOKENS tokens per stream in the paced regime (default 250, a 10s stream)
#   BURST_TOKENS tokens per stream in the burst regime (default 4000)
#   TOK_CHARS    content length of one token (default 8, a ~205 B chunk, close to real
#                OpenAI)
#   PROMPT_BYTES request prompt size (default 512)
#   DUR_MS/WARM_MS/SETTLE_MS/GUARD_MS  measurement windows (default 30000/10000/1000/1000)

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-sse-cpu"
SSE_VIP="10.10.10.254"
EPS="31.31.31.1,32.32.32.1"

# Arm definitions: mode -> vport, bport, sockMapMode
declare -A ARM_VPORT=( [on]=2040  [off]=2041  [resp]=2042 )
declare -A ARM_BPORT=( [on]=9081  [off]=9091  [resp]=9082 )
declare -A ARM_SMODE=( [on]=both  [off]=off   [resp]=response )

MODES=${MODES:-"on off"}
REGIMES=${REGIMES:-"paced burst"}
CONC=${CONC:-128}
PAR_CLIENTS=${PAR_CLIENTS:-4}
PACED_RATE=${PACED_RATE:-25}
PACED_TOKENS=${PACED_TOKENS:-250}
BURST_TOKENS=${BURST_TOKENS:-4000}
TOK_CHARS=${TOK_CHARS:-8}
PROMPT_BYTES=${PROMPT_BYTES:-512}
DUR_MS=${DUR_MS:-30000}
WARM_MS=${WARM_MS:-10000}
SETTLE_MS=${SETTLE_MS:-1000}
GUARD_MS=${GUARD_MS:-1000}
MIN_CORES_WARN=${MIN_CORES_WARN:-0.1}

CPU_WIN_MS=$(( DUR_MS - SETTLE_MS - GUARD_MS ))
if (( CPU_WIN_MS < 2000 )); then
  echo "ERROR: CPU_WIN_MS=$CPU_WIN_MS too small; raise DUR_MS or lower SETTLE_MS/GUARD_MS"
  exit 1
fi

SSE_SRV_PIDS=()
ACTIVE_MODES=()

cleanup() {
  sudo pkill -f "sse_server.js" >/dev/null 2>&1 || true
  sudo pkill -f "sse_client.js" >/dev/null 2>&1 || true
  local p m
  for p in "${SSE_SRV_PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  for m in "${!ARM_VPORT[@]}"; do
    sockmap_delete_lb_via_api llb1 "$SSE_VIP" "${ARM_VPORT[$m]}" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

ms_sleep() { sleep "$(awk -v m="$1" 'BEGIN{ printf "%.3f", m/1000 }')"; }

# Cumulative loxilb container cgroup CPU in microseconds: "usage user system".
# cgroup v2 preferred, v1 as fallback.
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

# Host-wide CPU in jiffies: "busy softirq sys+irq+softirq".
HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)
host_cpu_jiffies() {
  awk '/^cpu /{
        user=$2; nice=$3; sys=$4; irq=$7; softirq=$8; steal=$9;
        printf "%d %d %d", user+nice+sys+irq+softirq+steal, softirq, sys+irq+softirq;
        exit }' /proc/stat
}

echo "================ $SCENARIO ================"
echo "modes='$MODES' regimes='$REGIMES' streams=$(( CONC * PAR_CLIENTS )) (conc=$CONC x par=$PAR_CLIENTS)"
echo "paced: rate=${PACED_RATE}tok/s tokens=$PACED_TOKENS | burst: tokens=$BURST_TOKENS | tok_chars=$TOK_CHARS prompt=${PROMPT_BYTES}B"
echo "dur_ms=$DUR_MS warm_ms=$WARM_MS cpu_win_ms=$CPU_WIN_MS"

# ---------- [1] boot assets ----------
sockmap_section 1 "Daemon boot assets"
if sockmap_assert_bpf_assets llb1; then
  sockmap_result "sockops prog + sockmap maps attached" "OK"
else
  sockmap_result "sockops prog + sockmap maps attached" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (bootstrap)"; exit 1
fi

# ---------- [2] create rules per arm ----------
sockmap_section 2 "Create SSE rules per arm"
for m in $MODES; do
  if [[ -z "${ARM_VPORT[$m]:-}" ]]; then
    echo "    ERROR: unknown mode '$m' (on|off|resp)"; exit 1
  fi
  if sockmap_create_lb_via_api llb1 "$SSE_VIP" "${ARM_VPORT[$m]}" "${ARM_BPORT[$m]}" \
       "$EPS" "${ARM_SMODE[$m]}" "sse-$m"; then
    sockmap_result "rule sse-$m (vip ${ARM_VPORT[$m]} -> ep ${ARM_BPORT[$m]}, sockMapMode=${ARM_SMODE[$m]})" "OK"
    ACTIVE_MODES+=("$m")
  else
    # If the image predates the response mode (older API), skip just that arm.
    sockmap_result "rule sse-$m (sockMapMode=${ARM_SMODE[$m]})" "FAILED" "arm skipped — image may predate sockMapMode"
  fi
done
if (( ${#ACTIVE_MODES[@]} < 2 )); then
  echo "RESULT: $SCENARIO [FAILED] (need at least 2 arms to compare)"; exit 1
fi
sleep 2

# ---------- [3] start SSE backends ----------
sockmap_section 3 "Start OpenAI-compatible SSE backends"
for m in "${ACTIVE_MODES[@]}"; do
  bp=${ARM_BPORT[$m]}
  $hexec l3ep1 node ./sse_server.js "server1-$m" "$bp" "$PACED_TOKENS" "$PACED_RATE" \
    >"$SOCKMAP_ARTIFACTS_DIR/sse_srv_ep1_${bp}.log" 2>&1 & SSE_SRV_PIDS+=("$!")
  $hexec l3ep2 node ./sse_server.js "server2-$m" "$bp" "$PACED_TOKENS" "$PACED_RATE" \
    >"$SOCKMAP_ARTIFACTS_DIR/sse_srv_ep2_${bp}.log" 2>&1 & SSE_SRV_PIDS+=("$!")
done

sleep 3
ready=0
for i in $(seq 1 20); do
  ok=1
  for ep in 31.31.31.1 32.32.32.1; do
    for m in "${ACTIVE_MODES[@]}"; do
      code=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$ep:${ARM_BPORT[$m]}/healthz" 2>/dev/null || echo 000)
      [[ "$code" == "200" ]] || ok=0
    done
  done
  (( ok == 1 )) && { ready=1; break; }
  sleep 1
done
if (( ready == 1 )); then
  sockmap_result "SSE backends ready on both eps" "OK"
else
  sockmap_result "SSE backends ready on both eps" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (backend not ready)"; exit 1
fi

# ---------- [4] sanity: SSE through each VIP ----------
sockmap_section 4 "Sanity: each VIP streams SSE through fullproxy"
for m in "${ACTIVE_MODES[@]}"; do
  out=$($hexec l3h1 curl -s -N --max-time 8 \
        -X POST "http://$SSE_VIP:${ARM_VPORT[$m]}/v1/chat/completions?tokens=3&rate=0&tok=$TOK_CHARS" \
        -H 'Content-Type: application/json' -H 'Accept: text/event-stream' \
        -d '{"model":"gpt-4o-mini","stream":true}' 2>/dev/null)
  ndata=$(grep -c '^data: ' <<< "$out")
  if grep -q 'data: \[DONE\]' <<< "$out" && (( ndata >= 5 )); then
    sockmap_result "arm=$m VIP ${ARM_VPORT[$m]} streams SSE ($ndata events, [DONE] seen)" "OK"
  else
    sockmap_result "arm=$m VIP ${ARM_VPORT[$m]} streams SSE" "FAILED" "events=$ndata"
  fi
done

# ---------- measurement helper ----------
M_STREAMS=0; M_ERR=0; M_EVENTS=0; M_TOKENS=0; M_BYTES=0
M_SPS=0; M_TPS=0; M_MBPS=0
M_TTFT_MEAN=0; M_TTFT_P50=0; M_TTFT_P99=0
M_ITL_MEAN=0;  M_ITL_P50=0;  M_ITL_P99=0
M_CORES=0; M_HOST_CORES=0; M_SI_CORES=0
M_CPU_PER_TOK=0; M_HOST_PER_TOK=0; M_CPU_PER_STREAM=0; M_CPU_PER_MB=0; M_CPU_PER_TOK_NET=0
M_REDIR_DELTA=0; M_REDIR_RESP_DELTA=0; M_PEERMISS_DELTA=0
measure_sse() {
  local vport=$1 tokens=$2 rate=$3 tag=$4
  local i out pids=() outs=()

  for i in $(seq 1 "$PAR_CLIENTS"); do
    out="$SOCKMAP_ARTIFACTS_DIR/sse_${tag}_c${i}.out"
    : > "$out"
    $hexec l3h1 node ./sse_client.js "$SSE_VIP" "$vport" "$CONC" "$DUR_MS" "$PROMPT_BYTES" \
      "$WARM_MS" "$tokens" "$rate" "$TOK_CHARS" 1 >"$out" 2>/dev/null &
    pids+=("$!"); outs+=("$out")
  done

  ms_sleep "$(( WARM_MS + SETTLE_MS ))"
  local cb ub sb hbb hsib hsyb rdb rrb pmb
  read -r cb ub sb < <(sockmap_cpu_stat_usec llb1)
  read -r hbb hsib hsyb < <(host_cpu_jiffies)
  rdb=$(sockmap_redirect_count llb1)
  rrb=$(sockmap_redirect_resp_count llb1)
  pmb=$(sockmap_peer_miss_count llb1)

  ms_sleep "$CPU_WIN_MS"
  local ca ua sa hba hsia hsya rda rra pma
  read -r ca ua sa < <(sockmap_cpu_stat_usec llb1)
  read -r hba hsia hsya < <(host_cpu_jiffies)
  rda=$(sockmap_redirect_count llb1)
  rra=$(sockmap_redirect_resp_count llb1)
  pma=$(sockmap_peer_miss_count llb1)

  for i in "${pids[@]}"; do wait "$i" 2>/dev/null || true; done

  # Aggregate the per-client SSELINE: sum throughput and counts, average the latencies.
  local agg
  agg=$(cat "${outs[@]}" 2>/dev/null | awk '
    /^SSELINE/ { st+=$2; er+=$3; ev+=$4; tk+=$5; by+=$6; sps+=$7; tps+=$8; mb+=$9;
                 tm+=$10; t50+=$11; t99+=$12; im+=$13; i50+=$14; i99+=$15; n++ }
    END { if(!n) n=1;
          printf "%d %d %d %d %d %.2f %.1f %.3f %.2f %.2f %.2f %.2f %.2f %.2f",
                 st, er, ev, tk, by, sps, tps, mb,
                 tm/n, t50/n, t99/n, im/n, i50/n, i99/n }')
  read -r M_STREAMS M_ERR M_EVENTS M_TOKENS M_BYTES M_SPS M_TPS M_MBPS \
          M_TTFT_MEAN M_TTFT_P50 M_TTFT_P99 M_ITL_MEAN M_ITL_P50 M_ITL_P99 <<< "$agg"

  M_REDIR_DELTA=$(( rda - rdb ))
  M_REDIR_RESP_DELTA=$(( rra - rrb ))
  M_PEERMISS_DELTA=$(( pma - pmb ))

  # Normalization: the CPU window is a sub-interval of the client's measurement window.
  # Assuming steady state, scale tokens/streams/MB into that window.
  read -r M_CORES M_CPU_PER_TOK M_CPU_PER_STREAM M_CPU_PER_MB < <(awk \
    -v cpu="$(( ca - cb ))" -v tps="$M_TPS" -v sps="$M_SPS" -v mbps="$M_MBPS" \
    -v win_ms="$CPU_WIN_MS" '
    BEGIN {
      w = win_ms/1000.0;
      cores = (w>0)? cpu/(w*1e6) : 0;
      tok_w = tps*w; str_w = sps*w; mb_w = mbps*w;
      printf "%.3f %.3f %.1f %.1f", cores,
             (tok_w>0)? cpu/tok_w : 0,
             (str_w>0)? cpu/str_w : 0,
             (mb_w >0)? cpu/mb_w  : 0;
    }')
  # net = (measured CPU - idle CPU) / tokens: the marginal cost of relaying one token.
  M_CPU_PER_TOK_NET=$(awk -v cpu="$(( ca - cb ))" -v idle="$IDLE_CORES" -v tps="$M_TPS" \
    -v win_ms="$CPU_WIN_MS" 'BEGIN{
      w = win_ms/1000.0; net = cpu - idle*w*1e6; if (net < 0) net = 0;
      tok_w = tps*w; printf "%.3f", (tok_w>0)? net/tok_w : 0 }')

  read -r M_HOST_CORES M_SI_CORES M_HOST_PER_TOK < <(awk \
    -v hb="$(( hba - hbb ))" -v si="$(( hsia - hsib ))" -v tps="$M_TPS" \
    -v win_ms="$CPU_WIN_MS" -v hz="$HZ" '
    BEGIN {
      w = win_ms/1000.0;
      hb_us = (hz>0)? hb/hz*1e6 : 0;
      si_us = (hz>0)? si/hz*1e6 : 0;
      tok_w = tps*w;
      printf "%.3f %.3f %.2f", (w>0)? hb_us/(w*1e6):0, (w>0)? si_us/(w*1e6):0,
             (tok_w>0)? hb_us/tok_w : 0;
    }')
}

# ---------- [4b] idle baseline ----------
# The paced regime holds load fixed, so loxilb's idle CPU - background threads, health
# checks, BGP timers - sits on top of every measurement as a constant. The lower the
# load, the more that constant dominates CPU per token and hides the on/off difference.
# So idle cgroup CPU is measured separately and the marginal relay cost (net) reported
# alongside.
sockmap_section 4 "Idle baseline (no load) for net CPU attribution"
IDLE_WIN_MS=${IDLE_WIN_MS:-6000}
read -r _ib _ _ < <(sockmap_cpu_stat_usec llb1)
ms_sleep "$IDLE_WIN_MS"
read -r _ia _ _ < <(sockmap_cpu_stat_usec llb1)
IDLE_CORES=$(awk -v d="$(( _ia - _ib ))" -v w="$IDLE_WIN_MS" 'BEGIN{ printf "%.4f", (w>0)? d/(w*1000.0) : 0 }')
sockmap_result "loxilb idle CPU measured" "OK" "idle=${IDLE_CORES} cores over ${IDLE_WIN_MS}ms"

# ---------- [5] run regimes x arms ----------
declare -A R_TPS R_SPS R_MBPS R_CORES R_HCORES R_SICORES R_CPTOK R_HPTOK R_CPTOK_NET R_CPS R_CPMB
declare -A R_TTFT50 R_TTFT99 R_ITL50 R_ITL99 R_REDIR R_RRESP R_PMISS R_ERR

for regime in $REGIMES; do
  case "$regime" in
    paced) rtokens=$PACED_TOKENS; rrate=$PACED_RATE ;;
    burst) rtokens=$BURST_TOKENS; rrate=0 ;;
    *) echo "    ERROR: unknown regime '$regime'"; exit 1 ;;
  esac

  sockmap_section 5 "Regime '$regime' (tokens/stream=$rtokens rate=${rrate}tok/s) over ${CPU_WIN_MS}ms window"

  for m in "${ACTIVE_MODES[@]}"; do
    measure_sse "${ARM_VPORT[$m]}" "$rtokens" "$rrate" "${regime}_${m}"
    k="${regime}_${m}"
    R_TPS[$k]=$M_TPS;         R_SPS[$k]=$M_SPS;        R_MBPS[$k]=$M_MBPS
    R_CORES[$k]=$M_CORES;     R_HCORES[$k]=$M_HOST_CORES; R_SICORES[$k]=$M_SI_CORES
    R_CPTOK[$k]=$M_CPU_PER_TOK; R_HPTOK[$k]=$M_HOST_PER_TOK; R_CPTOK_NET[$k]=$M_CPU_PER_TOK_NET
    R_CPS[$k]=$M_CPU_PER_STREAM; R_CPMB[$k]=$M_CPU_PER_MB
    R_TTFT50[$k]=$M_TTFT_P50; R_TTFT99[$k]=$M_TTFT_P99
    R_ITL50[$k]=$M_ITL_P50;   R_ITL99[$k]=$M_ITL_P99
    R_REDIR[$k]=$M_REDIR_DELTA; R_RRESP[$k]=$M_REDIR_RESP_DELTA
    R_PMISS[$k]=$M_PEERMISS_DELTA; R_ERR[$k]=$M_ERR

    # Engagement gate: the on/resp arms must show redirects, the off arm must not.
    if [[ "$m" == "off" ]]; then
      if (( M_REDIR_DELTA == 0 )); then
        sockmap_result "$regime/$m not engaged (redirect==0)" "OK"
      else
        sockmap_result "$regime/$m not engaged (redirect==0)" "FAILED" "delta=$M_REDIR_DELTA"
      fi
    else
      if (( M_REDIR_DELTA > 0 )); then
        sockmap_result "$regime/$m sockmap engaged (redirect>0)" "OK" \
          "delta=$M_REDIR_DELTA (resp=$M_REDIR_RESP_DELTA)"
      else
        sockmap_result "$regime/$m sockmap engaged (redirect>0)" "FAILED" \
          "delta=0 peer_miss=$M_PEERMISS_DELTA; CPU comparison is meaningless"
      fi
    fi
    (( M_ERR > 0 )) && sockmap_result "$regime/$m stream errors" "FAILED" "errors=$M_ERR"
  done
done

# ---------- [6] comparison tables ----------
sockmap_section 6 "Comparison: CPU per token / latency (ON vs OFF)"
for regime in $REGIMES; do
  echo "    --- regime: $regime ---"
  printf "    %-6s %-9s %-9s %-8s %-10s %-10s %-9s %-10s %-10s %-11s %-9s %-8s\n" \
    "arm" "tok/s" "stream/s" "MB/s" "lox_cores" "host_cores" "si_cores" "lox_us/tok" "net_us/tok" "host_us/tok" "ttft_p99" "itl_p99"
  printf "    %-6s %-9s %-9s %-8s %-10s %-10s %-9s %-10s %-10s %-11s %-9s %-8s\n" \
    "-----" "-----" "--------" "----" "---------" "----------" "--------" "----------" "----------" "-----------" "--------" "-------"
  for m in "${ACTIVE_MODES[@]}"; do
    k="${regime}_${m}"
    printf "    %-6s %-9s %-9s %-8s %-10s %-10s %-9s %-10s %-10s %-11s %-9s %-8s\n" \
      "$m" "${R_TPS[$k]}" "${R_SPS[$k]}" "${R_MBPS[$k]}" \
      "${R_CORES[$k]}" "${R_HCORES[$k]}" "${R_SICORES[$k]}" \
      "${R_CPTOK[$k]}" "${R_CPTOK_NET[$k]}" "${R_HPTOK[$k]}" "${R_TTFT99[$k]}" "${R_ITL99[$k]}"
  done
  # ratios against the off arm
  ko="${regime}_off"
  if [[ -n "${R_CPTOK[$ko]:-}" ]]; then
    for m in "${ACTIVE_MODES[@]}"; do
      [[ "$m" == "off" ]] && continue
      k="${regime}_${m}"
      awk -v a="${R_CPTOK[$k]}" -v b="${R_CPTOK[$ko]}" \
          -v c="${R_CPTOK_NET[$k]}" -v d="${R_CPTOK_NET[$ko]}" \
          -v e="${R_TPS[$k]}"  -v f="${R_TPS[$ko]}" \
          -v g="${R_TTFT99[$k]}" -v h="${R_TTFT99[$ko]}" -v m="$m" '
        BEGIN { printf "    delta %-5s lox_cpu/tok x%.3f (net of idle x%.3f), tok/s x%.2f, ttft_p99 x%.2f (vs off)\n",
                       m, (b>0? a/b:0), (d>0? c/d:0), (f>0? e/f:0), (h>0? g/h:0) }'
    done
  fi
  echo
done

# ---------- artifacts ----------
{
  echo "# sockmap SSE CPU comparison ($(date -u +%FT%TZ))"
  echo "# streams=$(( CONC * PAR_CLIENTS )) conc=$CONC par=$PAR_CLIENTS dur_ms=$DUR_MS warm_ms=$WARM_MS cpu_win_ms=$CPU_WIN_MS"
  echo "# paced_rate=$PACED_RATE paced_tokens=$PACED_TOKENS burst_tokens=$BURST_TOKENS tok_chars=$TOK_CHARS prompt=$PROMPT_BYTES"
  echo "regime arm tok_s stream_s MB_s lox_cores host_cores si_cores lox_us_tok net_us_tok host_us_tok lox_us_stream lox_us_MB ttft_p50 ttft_p99 itl_p50 itl_p99 redirect_delta redirect_resp_delta peer_miss_delta errors"
  for regime in $REGIMES; do
    for m in "${ACTIVE_MODES[@]}"; do
      k="${regime}_${m}"
      echo "$regime $m ${R_TPS[$k]} ${R_SPS[$k]} ${R_MBPS[$k]} ${R_CORES[$k]} ${R_HCORES[$k]} ${R_SICORES[$k]} ${R_CPTOK[$k]} ${R_CPTOK_NET[$k]} ${R_HPTOK[$k]} ${R_CPS[$k]} ${R_CPMB[$k]} ${R_TTFT50[$k]} ${R_TTFT99[$k]} ${R_ITL50[$k]} ${R_ITL99[$k]} ${R_REDIR[$k]} ${R_RRESP[$k]} ${R_PMISS[$k]} ${R_ERR[$k]}"
    done
  done
} > "$SOCKMAP_ARTIFACTS_DIR/sse_cpu_comparison.txt"
echo "    [saved] $SOCKMAP_ARTIFACTS_DIR/sse_cpu_comparison.txt"

echo
if (( SOCKMAP_FAIL_COUNT == 0 )); then
  echo "RESULT: $SCENARIO [OK]  (numbers above are informational)"
  exit 0
else
  echo "RESULT: $SCENARIO [FAILED] ($SOCKMAP_FAIL_COUNT check(s) failed)"
  echo "Artifacts: $SOCKMAP_ARTIFACTS_DIR/"
  exit 1
fi
