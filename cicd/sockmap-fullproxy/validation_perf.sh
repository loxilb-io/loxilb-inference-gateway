#!/bin/bash
#
# sockmap-fullproxy / validation_perf.sh
#
# Performance comparison of sockmap acceleration on vs off.
#
#   - The two rules share every port and differ only in address:
#       perf-on  : VIP 10.10.10.254:2030 -> 31.31.31.1,32.32.32.1 :9080, sockMapMode=both
#       perf-off : VIP 10.10.10.253:2030 -> 31.31.31.2,32.32.32.2 :9080, sockMapMode=off
#     sockmap portsets are keyed by (address, port), so the off service must stay out
#     of the sockhash even though it uses the on service's ports. The script checks
#     that the portsets hold only the on service's entries and that the off arm's
#     traffic never reaches the sk_skb verdict. The .253 VIP and the .2 endpoint
#     addresses are added for the run and removed afterwards.
#     Both arms keep two backend processes each: with a single Node backend the on arm
#     is capped by that backend (about 5k rps at 256 B on this testbed) while the off
#     arm is not, and the comparison stops measuring the datapath.
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
# Each arm gets both backend hosts, on addresses of its own: .1 for on, .2 for off.
ON_VIP="10.10.10.254";  ON_EPS="31.31.31.1,32.32.32.1"
OFF_VIP="10.10.10.253"; OFF_EPS="31.31.31.2,32.32.32.2"
VPORT=2030; BPORT=9080

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
  sockmap_delete_lb_via_api llb1 "$ON_VIP"  "$VPORT" >/dev/null 2>&1 || true
  sockmap_delete_lb_via_api llb1 "$OFF_VIP" "$VPORT" >/dev/null 2>&1 || true
  sudo ip -n llb1 addr del "$OFF_VIP/24" dev ellb1l3h1 >/dev/null 2>&1 || true
  sudo ip -n l3ep1 addr del 31.31.31.2/24 dev el3ep1llb1 >/dev/null 2>&1 || true
  sudo ip -n l3ep2 addr del 32.32.32.2/24 dev el3ep2llb1 >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "================ $SCENARIO ================"

# ---------- [1] boot assets ----------
sockmap_section 1 "Daemon boot assets"
if sockmap_assert_bpf_assets llb1; then
  sockmap_result "sockops prog + 6 sockmap maps attached" "OK"
else
  sockmap_result "sockops prog + 6 sockmap maps attached" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (bootstrap)"; exit 1
fi

# ---------- [2] create perf rules (same ports, different addresses) ----------
sockmap_section 2 "Create perf rules (on=$ON_VIP:$VPORT->$ON_EPS:$BPORT, off=$OFF_VIP:$VPORT->$OFF_EPS:$BPORT)"
# The off VIP must exist before its rule is created: the proxy listener binds to it.
sudo ip -n llb1 addr replace "$OFF_VIP/24" dev ellb1l3h1
sudo ip -n l3ep1 addr replace 31.31.31.2/24 dev el3ep1llb1
sudo ip -n l3ep2 addr replace 32.32.32.2/24 dev el3ep2llb1
if sockmap_create_lb_via_api llb1 "$ON_VIP"  "$VPORT" "$BPORT" "$ON_EPS"  both "perf-on" \
   && sockmap_create_lb_via_api llb1 "$OFF_VIP" "$VPORT" "$BPORT" "$OFF_EPS" off  "perf-off"; then
  sockmap_result "perf-on / perf-off rules created" "OK"
else
  sockmap_result "perf-on / perf-off rules created" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (rule create)"; exit 1
fi

if sockmap_portset_wait llb1 "$SOCKMAP_VIP_NAME" "$VPORT" present 16 "$ON_VIP" \
   && sockmap_portset_wait llb1 "$SOCKMAP_EP_NAME" "$BPORT" present 16 "${ON_EPS%%,*}" \
   && sockmap_portset_wait llb1 "$SOCKMAP_EP_NAME" "$BPORT" present 16 "${ON_EPS##*,}"; then
  sockmap_result "perf-on $ON_VIP:$VPORT + $ON_EPS:$BPORT in portsets" "OK"
else
  sockmap_result "perf-on $ON_VIP:$VPORT + $ON_EPS:$BPORT in portsets" "FAILED"
fi
# Isolation: the off rule shares both ports, but neither of its addresses may appear.
if sockmap_portset_has llb1 "$SOCKMAP_VIP_NAME" "$VPORT" "$OFF_VIP" \
   || sockmap_portset_has llb1 "$SOCKMAP_VIP_NAME" "$VPORT" "0.0.0.0"; then
  sockmap_result "perf-off $OFF_VIP:$VPORT NOT in vip_portset" "FAILED" "leaked"
else
  sockmap_result "perf-off $OFF_VIP:$VPORT NOT in vip_portset" "OK"
fi
if sockmap_portset_has llb1 "$SOCKMAP_EP_NAME" "$BPORT" "${OFF_EPS%%,*}" \
   || sockmap_portset_has llb1 "$SOCKMAP_EP_NAME" "$BPORT" "${OFF_EPS##*,}"; then
  sockmap_result "perf-off $OFF_EPS:$BPORT NOT in ep_portset" "FAILED" "leaked"
else
  sockmap_result "perf-off $OFF_EPS:$BPORT NOT in ep_portset" "OK"
fi

# ---------- [3] start backend servers ----------
sockmap_section 3 "Start backend HTTP servers on $ON_EPS:$BPORT and $OFF_EPS:$BPORT"
$hexec l3ep1 node ./perf_server.js server1 "$BPORT" 256 & PERF_SRV_PIDS+=("$!")
$hexec l3ep2 node ./perf_server.js server2 "$BPORT" 256 & PERF_SRV_PIDS+=("$!")

sleep 3
ready=0
for i in $(seq 1 20); do
  ok=1
  for ep in ${ON_EPS//,/ } ${OFF_EPS//,/ }; do
    code=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$ep:$BPORT/?bytes=16" 2>/dev/null || echo 000)
    [[ "$code" == "200" ]] || ok=0
  done
  (( ok == 1 )) && { ready=1; break; }
  sleep 1
done
if (( ready == 1 )); then
  sockmap_result "backends ready on $ON_EPS/$OFF_EPS:$BPORT" "OK"
else
  sockmap_result "backends ready on $ON_EPS/$OFF_EPS:$BPORT" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (backend not ready)"; exit 1
fi

# ---------- [4] sanity via VIPs ----------
sockmap_section 4 "Sanity: both VIPs serve via fullproxy"
on_code=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$ON_VIP:$VPORT/?bytes=256" 2>/dev/null || echo 000)
off_code=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$OFF_VIP:$VPORT/?bytes=256" 2>/dev/null || echo 000)
if [[ "$on_code" == "200" ]]; then
  sockmap_result "perf-on VIP $ON_VIP:$VPORT serves (200)" "OK"
else
  sockmap_result "perf-on VIP $ON_VIP:$VPORT serves (200)" "FAILED" "code=$on_code"
fi
if [[ "$off_code" == "200" ]]; then
  sockmap_result "perf-off VIP $OFF_VIP:$VPORT serves (200)" "OK"
else
  sockmap_result "perf-off VIP $OFF_VIP:$VPORT serves (200)" "FAILED" "code=$off_code"
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
declare -A R_OFF_RPS R_OFF_MBPS R_OFF_MEAN R_OFF_P99 R_OFF_REQ R_OFF_ERR R_OFF_DELTA R_OFF_VERDICT

for bytes in $SIZES; do
  # --- ON ---
  rb=$(sockmap_redirect_count llb1)
  if ! measure "$ON_VIP" "$VPORT" "$bytes"; then
    sockmap_result "measure ON  bytes=$bytes" "FAILED" "no PERFLINE"
    continue
  fi
  ra=$(sockmap_redirect_count llb1)
  R_ON_DELTA[$bytes]=$(( ra - rb ))
  R_ON_RPS[$bytes]=$M_RPS;  R_ON_MBPS[$bytes]=$M_MBPS; R_ON_MEAN[$bytes]=$M_MEAN
  R_ON_P99[$bytes]=$M_P99;  R_ON_REQ[$bytes]=$M_REQ;   R_ON_ERR[$bytes]=$M_ERR

  # --- OFF ---
  # Every verdict outcome is counted: redirect, peer miss and ineligible. The off
  # arm's sockets must never be in sock_verdict_map, so all three stay flat.
  rb=$(sockmap_redirect_count llb1)
  vb=$(( $(sockmap_peer_miss_count llb1) + $(sockmap_ineligible_count llb1) ))
  if ! measure "$OFF_VIP" "$VPORT" "$bytes"; then
    sockmap_result "measure OFF bytes=$bytes" "FAILED" "no PERFLINE"
    continue
  fi
  ra=$(sockmap_redirect_count llb1)
  va=$(( $(sockmap_peer_miss_count llb1) + $(sockmap_ineligible_count llb1) ))
  R_OFF_DELTA[$bytes]=$(( ra - rb ))
  R_OFF_VERDICT[$bytes]=$(( va - vb ))
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
  if (( ${R_OFF_VERDICT[$bytes]} == 0 )); then
    sockmap_result "bytes=$bytes OFF never reaches verdict (miss+inelig==0)" "OK"
  else
    sockmap_result "bytes=$bytes OFF never reaches verdict (miss+inelig==0)" "FAILED" "delta=${R_OFF_VERDICT[$bytes]}; shared ports leak into sockmap"
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
