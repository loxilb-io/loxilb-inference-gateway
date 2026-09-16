#!/bin/bash
#
# sockmap-fullproxy / validation_integrity.sh
#
# Byte-level integrity of the relayed stream, accelerated arm vs userspace control.
#
# Why this exists
# ---------------
# validation.sh proves the right backend answered; validation_perf.sh counts HTTP
# errors. Neither compares the bytes that came back against the bytes the backend
# must have sent, so neither can see the failure mode that matters most on the
# accelerated path: the kernel's sk_psock_backlog partial-send defect, which
# re-sends an skb from offset 0 and duplicates bytes mid-stream. A client can accept
# such a response silently. That is a data-integrity defect, not an availability one,
# so it needs its own oracle.
#
# Oracle
# ------
# sse_server.js in ?seq=1 mode emits a fully predictable body (role chunk, then
# fixed-width tokens carrying a monotonic sequence number, then stop and [DONE]).
# sse_raw_probe.js reads the response over a raw socket, walks HTTP/1.1 chunked
# framing itself, and compares the de-chunked body against that sequence, so a
# duplicate, a loss and a reorder are distinguishable rather than all showing up as
# "parse error".
#
# Gates (these fail the run)
#   1. the OFF arm is byte-clean          - if the userspace relay corrupts a stream,
#                                           that is a loxilb defect and the oracle
#                                           would otherwise be blamed on the kernel
#   2. the ON arm engages  (REDIRECT_OK delta > 0)
#   3. the OFF arm does not engage (delta == 0) - control really is the control
#   4. the ON arm actually carried the response through the kernel
#      (RESP_BYTES / bytes received >= ENGAGE_FLOOR, default 80%). Without this a
#      barely-engaged run reports "clean" and looks like evidence of correctness
#      when it is only evidence that the accelerated path was not used.
#
# Reported, not gated
#   the ON arm's anomaly count. On a kernel without the sk_psock_backlog fix
#   (6.8, 6.11, 6.13, 6.14 and older LTS point releases) corruption here is expected
#   and is exactly why sockMapMode ships off by default; see
#   docs/sockmap-acceleration.md. Failing the suite for it would make this scenario
#   unrunnable on the very kernels it is meant to warn about.
#
# Prerequisite: the testbed is up via config.sh. This script creates and removes its
# own rules and backends (VIPs 2060/2061, backend ports 9160/9161) and leaves
# config.sh's R1/R2 alone.
# Run: ./config.sh && ./validation_integrity.sh && ./rmconfig.sh

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-integrity"
VIP=10.10.10.254
EPS="31.31.31.1,32.32.32.1"

declare -A ARM_VPORT=( [on]=2060  [off]=2061 )
declare -A ARM_BPORT=( [on]=9160  [off]=9161 )
declare -A ARM_SMODE=( [on]=both  [off]=off  )

# Defaults are the regime the defect is documented to need. A first run at
# conc=16 / 1500 tokens reported every stream clean while the redirect counter showed
# only ~4 redirects per stream: the acceleration had barely engaged, so "clean" meant
# "mostly not accelerated", not "accelerated and correct". The engagement share below
# is what tells those two apart, and these defaults keep it near 100%.
CONC=${CONC:-32}            # concurrent streams
STREAMS=${STREAMS:-200}     # total streams per arm (fixed, so counts compare exactly)
TOKENS=${TOKENS:-4000}      # tokens (chunks) per stream
DUR_MS=${DUR_MS:-300000}    # ceiling; the stream limit normally ends the run first
MAX_REPORTS=${MAX_REPORTS:-3}

# sockmap_stats index for bytes handed to bpf_sk_redirect_hash in the response
# direction (llb_sockmap.h: SOCKMAP_STAT_RESP_BYTES).
SOCKMAP_STAT_RESP_BYTES=5

SRV_PIDS=()

cleanup() {
  sudo pkill -f "sse_server.js" >/dev/null 2>&1 || true
  sudo pkill -f "sse_raw_probe.js" >/dev/null 2>&1 || true
  local m p
  for m in "${!ARM_VPORT[@]}"; do
    sockmap_delete_lb_via_api llb1 "$VIP" "${ARM_VPORT[$m]}" >/dev/null 2>&1 || true
  done
  for p in "${SRV_PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

echo "================ $SCENARIO ================"
echo "conc=$CONC streams=$STREAMS tokens=$TOKENS  kernel=$(uname -r)"

# ---------- [1] boot assets ----------
sockmap_section 1 "Daemon boot assets"
if sockmap_assert_bpf_assets llb1; then
  sockmap_result "sockops prog + 5 sockmap maps attached" "OK"
else
  sockmap_result "sockops prog + 5 sockmap maps attached" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (bootstrap)"; exit 1
fi

# ---------- [2] rules ----------
sockmap_section 2 "Create integrity rules"
for m in on off; do
  if sockmap_create_lb_via_api llb1 "$VIP" "${ARM_VPORT[$m]}" "${ARM_BPORT[$m]}" \
        "$EPS" "${ARM_SMODE[$m]}" "integ-$m"; then
    sockmap_result "rule integ-$m (vip ${ARM_VPORT[$m]} -> ep ${ARM_BPORT[$m]}, mode=${ARM_SMODE[$m]})" "OK"
  else
    sockmap_result "rule integ-$m created" "FAILED"
    echo "RESULT: $SCENARIO [FAILED] (rule create)"; exit 1
  fi
done

if sockmap_portset_wait llb1 "$SOCKMAP_VIP_NAME" "${ARM_VPORT[on]}" present \
   && sockmap_portset_wait llb1 "$SOCKMAP_EP_NAME" "${ARM_BPORT[on]}" present; then
  sockmap_result "on arm in portsets" "OK"
else
  sockmap_result "on arm in portsets" "FAILED"
fi
if sockmap_portset_has llb1 "$SOCKMAP_VIP_NAME" "${ARM_VPORT[off]}"; then
  sockmap_result "off arm NOT in vip portset" "FAILED" "leaked"
else
  sockmap_result "off arm NOT in vip portset" "OK"
fi

# ---------- [3] backends ----------
sockmap_section 3 "Start SSE backends on ${ARM_BPORT[on]} and ${ARM_BPORT[off]}"
for m in on off; do
  bp=${ARM_BPORT[$m]}
  $hexec l3ep1 node ./sse_server.js "server1-$m" "$bp" "$TOKENS" 0 >/dev/null 2>&1 & SRV_PIDS+=("$!")
  $hexec l3ep2 node ./sse_server.js "server2-$m" "$bp" "$TOKENS" 0 >/dev/null 2>&1 & SRV_PIDS+=("$!")
done

sleep 3
ready=0
for i in $(seq 1 20); do
  ok=1
  for ep in 31.31.31.1 32.32.32.1; do
    for m in on off; do
      code=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
               "http://$ep:${ARM_BPORT[$m]}/healthz" 2>/dev/null || echo 000)
      [[ "$code" == "200" ]] || ok=0
    done
  done
  (( ok == 1 )) && { ready=1; break; }
  sleep 1
done
if (( ready == 1 )); then
  sockmap_result "backends ready on both ports" "OK"
else
  sockmap_result "backends ready on both ports" "FAILED"
  echo "RESULT: $SCENARIO [FAILED] (backend not ready)"; exit 1
fi

# ---------- [4] probe each arm ----------
declare -A A_STREAMS A_CLEAN A_ANOM A_REDIR A_RX A_RESPB A_SHARE

probe_arm() {
  local m=$1
  local vport=${ARM_VPORT[$m]}
  local out="$SOCKMAP_ARTIFACTS_DIR/integrity_${m}.txt"

  local before after rb_before rb_after
  before=$(sockmap_redirect_count llb1)
  rb_before=$(sockmap_stat_sum llb1 "$SOCKMAP_STAT_RESP_BYTES")

  $hexec l3h1 node ./sse_raw_probe.js "$VIP" "$vport" "$CONC" "$DUR_MS" \
      "$TOKENS" "$MAX_REPORTS" "$STREAMS" > "$out" 2>&1 || true

  after=$(sockmap_redirect_count llb1)
  rb_after=$(sockmap_stat_sum llb1 "$SOCKMAP_STAT_RESP_BYTES")
  A_REDIR[$m]=$(( after - before ))
  A_RESPB[$m]=$(( rb_after - rb_before ))
  A_RX[$m]=$(grep -oE 'RXBYTES [0-9]+' "$out" | tail -1 | awk '{print $2}')
  : "${A_RX[$m]:=0}"
  A_SHARE[$m]=$(awk -v r="${A_RESPB[$m]}" -v x="${A_RX[$m]}" \
                    'BEGIN{printf "%.1f", (x>0)? r*100/x : 0}')

  # "  streams=64 clean=64 anomalous=0"
  local line
  line=$(grep -oE 'streams=[0-9]+ clean=[0-9]+ anomalous=[0-9]+' "$out" | tail -1)
  A_STREAMS[$m]=$(sed -n 's/.*streams=\([0-9]*\).*/\1/p' <<<"$line")
  A_CLEAN[$m]=$(sed -n 's/.*clean=\([0-9]*\).*/\1/p' <<<"$line")
  A_ANOM[$m]=$(sed -n 's/.*anomalous=\([0-9]*\).*/\1/p' <<<"$line")
  : "${A_STREAMS[$m]:=0}" "${A_CLEAN[$m]:=0}" "${A_ANOM[$m]:=0}"
}

# The ON arm is probed FIRST, before anything else has touched the proxy.
#
# KNOWN LIMITATION - this scenario does not reliably reproduce the kernel defect.
# On kernel 6.11.0-29 a standalone probe (ONE accelerated rule, TWO backend
# processes) corrupted 183-187 of 200 streams in five consecutive rounds at ~61 MB/s
# and ~99.5% engagement. This scenario, at identical conc/streams/tokens and 99.7%
# engagement, reported 0 of 200 in three runs - probing the ON arm first did not
# change that. The fingerprint that differs is the redirect count: 6000 here versus
# 5200 standalone for the same bytes, i.e. smaller average skb per redirect. This
# scenario runs four backend node processes (two ports x two endpoints) against the
# standalone harness's two, and that extra contention appears to pace the backend
# into smaller writes, which keeps sk_psock_backlog off the partial-send path the
# defect needs. So a clean result here is NOT evidence that a kernel is safe.
#
# To actually exercise the defect, drive one accelerated rule with two backends:
#   sockmap_create_lb_via_api llb1 <vip> 2070 9170 "31.31.31.1,32.32.32.1" both x
#   ip netns exec l3ep1 node ./sse_server.js r1 9170 4000 0   # and l3ep2
#   ip netns exec l3h1  node ./sse_raw_probe.js <vip> 2070 32 300000 4000 1 200
# The standalone kernel-only reproducer in minrepro/ (run inside the netns, not on
# loopback - loopback's 64KB MTU hides it) is the other half of the answer: it
# corrupted 193/200 with no loxilb code in the path at all.
sockmap_section 4 "Probe the ON arm (sockmap accelerated)"
probe_arm on
sockmap_result "on streams completed" \
  "$([[ ${A_STREAMS[on]} -eq $STREAMS ]] && echo OK || echo FAILED)" \
  "streams=${A_STREAMS[on]}/$STREAMS"
if (( ${A_REDIR[on]} > 0 )); then
  sockmap_result "on arm engaged (gate)" "OK" "redirect delta=${A_REDIR[on]}"
else
  sockmap_result "on arm engaged (gate)" "FAILED" "redirect delta=0 - not accelerated"
fi

# A clean verdict is only meaningful if the kernel actually carried the stream.
# RESP_BYTES counts what the verdict handed to bpf_sk_redirect_hash; compared with
# what the client received it gives the share of the response that took the
# accelerated path. Below the floor, "clean" says nothing about the accelerated path.
ENGAGE_FLOOR=${ENGAGE_FLOOR:-80}
if awk -v s="${A_SHARE[on]}" -v f="$ENGAGE_FLOOR" 'BEGIN{exit !(s>=f)}'; then
  sockmap_result "on arm carried the response (gate)" "OK" \
    "RESP_BYTES/received=${A_SHARE[on]}% (floor ${ENGAGE_FLOOR}%)"
else
  sockmap_result "on arm carried the response (gate)" "FAILED" \
    "RESP_BYTES/received=${A_SHARE[on]}% below ${ENGAGE_FLOOR}% - a clean result here would not be evidence"
fi

# ---------- [6] verdict ----------
sleep 3

sockmap_section 5 "Probe the OFF arm (userspace relay, control)"
probe_arm off
sockmap_result "off streams completed" \
  "$([[ ${A_STREAMS[off]} -eq $STREAMS ]] && echo OK || echo FAILED)" \
  "streams=${A_STREAMS[off]}/$STREAMS"
if (( ${A_ANOM[off]} == 0 )); then
  sockmap_result "off arm byte-clean (gate)" "OK" "clean=${A_CLEAN[off]}/${A_STREAMS[off]}"
else
  sockmap_result "off arm byte-clean (gate)" "FAILED" \
    "anomalous=${A_ANOM[off]} - userspace relay corrupted a stream"
fi
if (( ${A_REDIR[off]} == 0 )); then
  sockmap_result "off arm did not engage (gate)" "OK"
else
  sockmap_result "off arm did not engage (gate)" "FAILED" "redirect delta=${A_REDIR[off]}"
fi

sockmap_section 6 "Integrity comparison"
printf "    %-5s %-8s %-7s %-10s %-15s %s\n" arm streams clean anomalous redirect_delta kernel_relayed
printf "    %-5s %-8s %-7s %-10s %-15s %s\n" ----- ------- ----- --------- -------------- --------------
for m in off on; do
  printf "    %-5s %-8s %-7s %-10s %-15s %s\n" \
    "$m" "${A_STREAMS[$m]}" "${A_CLEAN[$m]}" "${A_ANOM[$m]}" "${A_REDIR[$m]}" "${A_SHARE[$m]}%"
done

{
  echo "# sockmap integrity comparison ($(date -u +%FT%TZ))"
  echo "# kernel=$(uname -r) conc=$CONC streams=$STREAMS tokens=$TOKENS"
  echo "arm streams clean anomalous redirect_delta resp_bytes rxbytes kernel_relayed_pct"
  for m in off on; do
    echo "$m ${A_STREAMS[$m]} ${A_CLEAN[$m]} ${A_ANOM[$m]} ${A_REDIR[$m]} ${A_RESPB[$m]} ${A_RX[$m]} ${A_SHARE[$m]}"
  done
} > "$SOCKMAP_ARTIFACTS_DIR/integrity_comparison.txt"
echo "    [saved] $SOCKMAP_ARTIFACTS_DIR/integrity_comparison.txt"

echo
if (( ${A_ANOM[on]} == 0 )); then
  echo "    on arm: no corruption in ${A_STREAMS[on]} streams on $(uname -r) with"
  echo "    ${A_SHARE[on]}% of the response relayed by the kernel."
  echo "    One clean run is not proof the kernel carries the sk_psock_backlog fix:"
  echo "    the defect scales with concurrency and byte rate. Check the version against"
  echo "    docs/sockmap-acceleration.md, and raise CONC/STREAMS/TOKENS before trusting it."
else
  pct=$(awk -v a="${A_ANOM[on]}" -v s="${A_STREAMS[on]}" 'BEGIN{printf "%.1f", s? a*100/s : 0}')
  echo "    on arm: ${A_ANOM[on]}/${A_STREAMS[on]} streams corrupted (${pct}%) while the"
  echo "    off arm stayed clean. This is the kernel sk_psock_backlog partial-send"
  echo "    defect, not a loxilb defect: it is reached only through"
  echo "    bpf_sk_redirect_hash, so sockMapMode=off avoids it entirely."
  echo "    Kernel $(uname -r) - see docs/sockmap-acceleration.md for the fixed versions."
  echo "    First anomaly reports: $SOCKMAP_ARTIFACTS_DIR/integrity_on.txt"
fi

echo
if (( SOCKMAP_FAIL_COUNT == 0 )); then
  echo "RESULT: $SCENARIO [OK]  (on-arm corruption above is a kernel property, reported not gated)"
  exit 0
else
  echo "RESULT: $SCENARIO [FAILED] ($SOCKMAP_FAIL_COUNT gate(s) failed)"
  echo "Artifacts: $SOCKMAP_ARTIFACTS_DIR/"
  exit 1
fi
