#!/bin/bash
#
# sockmap-fullproxy / seq-diag.sh
#
# Determines what exactly breaks in the HTTP framing corruption on the accelerated
# path.
#
# The server stamps a monotonic seq into every token (?seq=1) and the client checks
# continuity:
#   seq jumps forward -> data loss       (the redirect-drops-under-pressure theory)
#   seq goes backward -> reordering      (userspace/kernel mix at the engage boundary)
#   previous value again -> duplication  (delivered twice)
# The raw byte tail at the point of the parse failure is also dumped for inspection.
#
# Usage: ./seq-diag.sh [rounds]
source ../common.sh
source ./sockmap_common.sh
sockmap_init_artifacts

ROUNDS=${1:-2}
VIP=10.10.10.254
ON_VP=2100;  ON_BP=9100
OFF_VP=2101; OFF_BP=9101
CONC=${CONC:-128}; PAR=${PAR:-4}
DUR_MS=${DUR_MS:-20000}; WARM_MS=${WARM_MS:-4000}
TOKENS=${TOKENS:-4000}; RATE=${RATE:-0}
OUT=${OUT:-/tmp/seqdiag}; DUMP=$OUT/dumps
rm -rf "$OUT"; mkdir -p "$DUMP"

sockmap_create_lb_via_api llb1 $VIP $ON_VP  $ON_BP  "31.31.31.1,32.32.32.1" both "seq-on"  >/dev/null
sockmap_create_lb_via_api llb1 $VIP $OFF_VP $OFF_BP "31.31.31.1,32.32.32.1" off  "seq-off" >/dev/null
sleep 2
for p in $ON_BP $OFF_BP; do
  $hexec l3ep1 node ./sse_server.js s1 $p 4000 0 >/dev/null 2>&1 &
  $hexec l3ep2 node ./sse_server.js s2 $p 4000 0 >/dev/null 2>&1 &
done
sleep 4

for ((r=1; r<=ROUNDS; r++)); do
  for arm in on off; do
    [[ $arm == on ]] && vp=$ON_VP || vp=$OFF_VP
    pids=()
    for i in $(seq 1 $PAR); do
      $hexec l3h1 env SSE_SEQ_CHECK=1 SSE_DEBUG_ERR=1 SSE_DUMP_DIR="$DUMP/$arm" \
        node ./sse_client.js $VIP $vp $CONC $DUR_MS 512 $WARM_MS $TOKENS $RATE 8 1 \
        > "$OUT/r${r}_${arm}_$i.out" 2> "$OUT/r${r}_${arm}_$i.err" &
      pids+=($!)
    done
    mkdir -p "$DUMP/$arm"
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
  done
done

echo "======== findings ========"
for arm in on off; do
  echo "--- arm=$arm ---"
  awk '/^SSELINE/{s+=$2; e+=$3} END{printf "  streams=%-7d errors=%-6d\n", s, e}' "$OUT"/r*_${arm}_*.out
  grep -h SEQSUM "$OUT"/r*_${arm}_*.err 2>/dev/null | awk '
    { for(i=2;i<=NF;i++){split($i,kv,"="); a[kv[1]]+=kv[2]} }
    END { printf "  ok_tokens=%-10d gap_events=%-6d gap_tokens=%-8d dup=%-6d reorder=%d\n",
                 a["ok"], a["gap_events"], a["gap_tokens"], a["dup"], a["reorder"] }'
  grep -h ERRSUM "$OUT"/r*_${arm}_*.err 2>/dev/null | awk '{a[$2]+=$3} END{for(k in a) printf "  errkind %-22s %d\n", k, a[k]}'
  echo "  dump files: $(ls "$DUMP/$arm" 2>/dev/null | wc -l)"
done
sudo pkill -f "sse_server.js" >/dev/null 2>&1 || true
sockmap_delete_lb_via_api llb1 $VIP $ON_VP  >/dev/null 2>&1 || true
sockmap_delete_lb_via_api llb1 $VIP $OFF_VP >/dev/null 2>&1 || true
