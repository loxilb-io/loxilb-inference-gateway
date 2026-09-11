#!/bin/bash
#
# sockmap-fullproxy / validation_perf.sh
#
# Performance comparison of sockmap acceleration on vs off.
#
#   - The two rules use separate backend ports so they cannot overlap:
#       perf-on  : VIP 10.10.10.254:2030 -> tcp/9080, sockMapAccel=true
#       perf-off : VIP 10.10.10.254:2031 -> tcp/9090, sockMapAccel=false
#     Both the VIP ports (2030/2031) and the backend ports (9080/9090) differ, so there
#     is no shared sockmap_ep_portset contamination - the off service cannot slip into
#     the sockhash through the on service's port.
#   - Measures throughput (rps), bandwidth (MB/s) and latency (mean, p99) under a
#     keep-alive closed loop.
#   - Two payload sizes, small (256 B) and large (64 KB): the datapath difference grows
#     with payload size.
#
# Prerequisite: the testbed (containers/network) must be up via config.sh. This script
#       creates and cleans up its own perf rules and backends, leaving config.sh's
#       R1/R2 untouched.
# Run: ./config.sh && ./validation_perf.sh && ./rmconfig.sh

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-perf"
PERF_VIP="10.10.10.254"
ON_VPORT=2030;  ON_BPORT=9080
OFF_VPORT=2031; OFF_BPORT=9090
EPS="31.31.31.1,32.32.32.1"

CONC=16          # concurrent keep-alive connections
DUR_MS=6000      # measurement window (ms)
WARM_MS=2000     # warm-up (excluded, ms); absorbs first-request peer_map setup and
                 # connection establishment
SIZES="256 65536"  # payload sizes in bytes: small / large (64 KB)

PERF_SRV_PIDS=()

cleanup() {
  sudo pkill -f "perf_server.js" >/dev/null 2>&1 || true
  local p
  for p in "${PERF_SRV_PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  sockmap_delete_lb_via_api llb1 "$PERF_VIP" "$ON_VPORT"  >/dev/null 2>&1 || true
  sockmap_delete_lb_via_api llb1 "$PERF_VIP" "$OFF_VPORT" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "================ $SCENARIO ================"

# ---------- [1] boot assets ----------
sockmap_section 1 "Daemon boot assets"
if sockmap_assert_bpf_assets llb1; then
  sockmap_result "sockops prog + 5 sockmap maps attached" "OK"
else
  sockmap_result "sockops prog + 5 sockmap maps attached" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (bootstrap)"; exit 1
fi

# ---------- [2] create perf rules (separate backend ports) ----------
sockmap_section 2 "Create perf rules (on=$ON_VPORT->$ON_BPORT, off=$OFF_VPORT->$OFF_BPORT)"
if sockmap_create_lb_via_api llb1 "$PERF_VIP" "$ON_VPORT"  "$ON_BPORT"  "$EPS" true  "perf-on" \
   && sockmap_create_lb_via_api llb1 "$PERF_VIP" "$OFF_VPORT" "$OFF_BPORT" "$EPS" false "perf-off"; then
  sockmap_result "perf-on / perf-off rules created" "OK"
else
  sockmap_result "perf-on / perf-off rules created" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (rule create)"; exit 1
fi
sleep 2

if sockmap_portset_has llb1 "$SOCKMAP_VIP_NAME" "$ON_VPORT" \
   && sockmap_portset_has llb1 "$SOCKMAP_EP_NAME" "$ON_BPORT"; then
  sockmap_result "perf-on vip $ON_VPORT + ep $ON_BPORT in portsets" "OK"
else
  sockmap_result "perf-on vip $ON_VPORT + ep $ON_BPORT in portsets" "FAILED"
fi
if sockmap_portset_has llb1 "$SOCKMAP_EP_NAME" "$OFF_BPORT"; then
  sockmap_result "perf-off ep $OFF_BPORT NOT in ep_portset" "FAILED" "leaked"
else
  sockmap_result "perf-off ep $OFF_BPORT NOT in ep_portset" "OK"
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
if [[ "$on_code" == "200" ]]; then
  sockmap_result "perf-on VIP $ON_VPORT serves (200)" "OK"
else
  sockmap_result "perf-on VIP $ON_VPORT serves (200)" "FAILED" "code=$on_code"
fi
if [[ "$off_code" == "200" ]]; then
  sockmap_result "perf-off VIP $OFF_VPORT serves (200)" "OK"
else
  sockmap_result "perf-off VIP $OFF_VPORT serves (200)" "FAILED" "code=$off_code"
fi

# ---------- measure helper ----------
# $1 vip $2 vport $3 bytes -> M_REQ M_ERR M_RPS M_MBPS M_MEAN M_P50 M_P99 (globals)
M_REQ=0; M_ERR=0; M_RPS=0; M_MBPS=0; M_MEAN=0; M_P50=0; M_P99=0
measure() {
  local vip=$1 vport=$2 bytes=$3 line
  M_REQ=0; M_ERR=0; M_RPS=0; M_MBPS=0; M_MEAN=0; M_P50=0; M_P99=0
  line=$($hexec l3h1 node ./perf_client.js "$vip" "$vport" "$CONC" "$DUR_MS" "$bytes" "$WARM_MS" 2>/dev/null \
           | grep '^PERFLINE' | tail -1)
  [[ -z "$line" ]] && return 1
  read -r _ M_REQ M_ERR M_RPS M_MBPS M_MEAN M_P50 M_P99 <<< "$line"
  return 0
}

# ---------- [5] benchmark on vs off ----------
sockmap_section 5 "Benchmark (conc=$CONC, ${DUR_MS}ms measure, ${WARM_MS}ms warmup)"

declare -A R_ON_RPS R_ON_MBPS R_ON_MEAN R_ON_P99 R_ON_REQ R_ON_ERR R_ON_DELTA
declare -A R_OFF_RPS R_OFF_MBPS R_OFF_MEAN R_OFF_P99 R_OFF_REQ R_OFF_ERR R_OFF_DELTA

for bytes in $SIZES; do
  # --- ON ---
  rb=$(sockmap_redirect_count llb1)
  if ! measure "$PERF_VIP" "$ON_VPORT" "$bytes"; then
    sockmap_result "measure ON  bytes=$bytes" "FAILED" "no PERFLINE"
    continue
  fi
  ra=$(sockmap_redirect_count llb1)
  R_ON_DELTA[$bytes]=$(( ra - rb ))
  R_ON_RPS[$bytes]=$M_RPS;  R_ON_MBPS[$bytes]=$M_MBPS; R_ON_MEAN[$bytes]=$M_MEAN
  R_ON_P99[$bytes]=$M_P99;  R_ON_REQ[$bytes]=$M_REQ;   R_ON_ERR[$bytes]=$M_ERR

  # --- OFF ---
  rb=$(sockmap_redirect_count llb1)
  if ! measure "$PERF_VIP" "$OFF_VPORT" "$bytes"; then
    sockmap_result "measure OFF bytes=$bytes" "FAILED" "no PERFLINE"
    continue
  fi
  ra=$(sockmap_redirect_count llb1)
  R_OFF_DELTA[$bytes]=$(( ra - rb ))
  R_OFF_RPS[$bytes]=$M_RPS;  R_OFF_MBPS[$bytes]=$M_MBPS; R_OFF_MEAN[$bytes]=$M_MEAN
  R_OFF_P99[$bytes]=$M_P99;  R_OFF_REQ[$bytes]=$M_REQ;   R_OFF_ERR[$bytes]=$M_ERR

  # Engagement check: the on arm must show redirects (accelerated), the off arm must
  # never (control).
  if (( ${R_ON_DELTA[$bytes]} > 0 )); then
    sockmap_result "bytes=$bytes ON sockmap engaged (redirect>0)" "OK" "delta=${R_ON_DELTA[$bytes]}"
  else
    sockmap_result "bytes=$bytes ON sockmap engaged (redirect>0)" "FAILED" "delta=${R_ON_DELTA[$bytes]}"
  fi
  if (( ${R_OFF_DELTA[$bytes]} == 0 )); then
    sockmap_result "bytes=$bytes OFF not engaged (redirect==0)" "OK"
  else
    sockmap_result "bytes=$bytes OFF not engaged (redirect==0)" "FAILED" "delta=${R_OFF_DELTA[$bytes]}"
  fi
done

# ---------- [6] comparison table ----------
sockmap_section 6 "Comparison (sockmap ON vs OFF)"
fmt_size() { local b=$1; if (( b >= 1024 )); then echo "$((b/1024))KB"; else echo "${b}B"; fi; }

printf "    %-10s %-6s %-12s %-12s %-12s %-12s\n" "payload" "mode" "rps" "MB/s" "lat_mean(ms)" "lat_p99(ms)"
printf "    %-10s %-6s %-12s %-12s %-12s %-12s\n" "-------" "----" "---" "----" "------------" "-----------"
for bytes in $SIZES; do
  ps=$(fmt_size "$bytes")
  printf "    %-10s %-6s %-12s %-12s %-12s %-12s\n" "$ps" "ON"  "${R_ON_RPS[$bytes]:-NA}"  "${R_ON_MBPS[$bytes]:-NA}"  "${R_ON_MEAN[$bytes]:-NA}"  "${R_ON_P99[$bytes]:-NA}"
  printf "    %-10s %-6s %-12s %-12s %-12s %-12s\n" "$ps" "OFF" "${R_OFF_RPS[$bytes]:-NA}" "${R_OFF_MBPS[$bytes]:-NA}" "${R_OFF_MEAN[$bytes]:-NA}" "${R_OFF_P99[$bytes]:-NA}"
  # ratios (awk, float)
  if [[ -n "${R_ON_RPS[$bytes]}" && -n "${R_OFF_RPS[$bytes]}" ]]; then
    awk -v on="${R_ON_RPS[$bytes]}" -v off="${R_OFF_RPS[$bytes]}" \
        -v lon="${R_ON_MEAN[$bytes]}" -v loff="${R_OFF_MEAN[$bytes]}" -v ps="$ps" '
      BEGIN {
        rps_x = (off>0)? on/off : 0;
        lat_d = (loff>0)? (lon-loff)/loff*100 : 0;
        printf "    %-10s %-6s rps x%.2f, lat_mean %+.1f%% (ON vs OFF)\n", ps, "delta", rps_x, lat_d;
      }'
  fi
  echo
done

# save artifacts
{
  echo "# sockmap perf comparison ($(date -u +%FT%TZ))"
  echo "# conc=$CONC dur_ms=$DUR_MS warm_ms=$WARM_MS"
  echo "payload mode rps mbps lat_mean_ms lat_p99_ms requests errors redirect_delta"
  for bytes in $SIZES; do
    echo "$bytes ON  ${R_ON_RPS[$bytes]:-NA} ${R_ON_MBPS[$bytes]:-NA} ${R_ON_MEAN[$bytes]:-NA} ${R_ON_P99[$bytes]:-NA} ${R_ON_REQ[$bytes]:-NA} ${R_ON_ERR[$bytes]:-NA} ${R_ON_DELTA[$bytes]:-NA}"
    echo "$bytes OFF ${R_OFF_RPS[$bytes]:-NA} ${R_OFF_MBPS[$bytes]:-NA} ${R_OFF_MEAN[$bytes]:-NA} ${R_OFF_P99[$bytes]:-NA} ${R_OFF_REQ[$bytes]:-NA} ${R_OFF_ERR[$bytes]:-NA} ${R_OFF_DELTA[$bytes]:-NA}"
  done
} > "$SOCKMAP_ARTIFACTS_DIR/perf_comparison.txt"
echo "    [saved] $SOCKMAP_ARTIFACTS_DIR/perf_comparison.txt"

# ---------- finalize ----------
echo
if (( SOCKMAP_FAIL_COUNT == 0 )); then
  echo "RESULT: $SCENARIO [OK]  (perf numbers above are informational)"
  exit 0
else
  echo "RESULT: $SCENARIO [FAILED] ($SOCKMAP_FAIL_COUNT check(s) failed)"
  echo "Artifacts: $SOCKMAP_ARTIFACTS_DIR/"
  exit 1
fi
