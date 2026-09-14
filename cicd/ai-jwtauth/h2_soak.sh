#!/bin/bash
# HTTP/2 connection-lifecycle soak.
#
# Measures the gateway's resident set across a long run of HTTP/2
# connection open/teardown cycles. The session freed by the lifecycle fix
# is per connection, so a leak shows up as RSS that climbs with the
# connection count and never comes back down; a fixed build settles onto
# a flat line after the allocator's own warm-up.
#
# Run it against a topology that config.sh already brought up. It reads
# only — it configures nothing and tears nothing down.
#
# Usage: h2_soak.sh <rounds> <conns-per-round> [port]

set -u
# common.sh is written to be sourced by a full scenario driver and exits when
# it is not; this reader only needs the namespace helper it would have set.
hexec="sudo ip netns exec"

ROUNDS=${1:-6}
PER=${2:-500}
PORT=${3:-2048}
VIP=10.10.10.254

rss_kb() {
  # The gateway is the container's entrypoint; take its RSS from the
  # kernel rather than from any reporting the binary does itself.
  local pid
  pid=$(sudo docker exec llb1 sh -c \
        'for p in /proc/[0-9]*; do
           case "$(cat $p/comm 2>/dev/null)" in loxilb) echo ${p#/proc/}; break;; esac
         done' 2>/dev/null | head -1)
  if [ -z "$pid" ]; then
    echo "ERR"
    return 1
  fi
  sudo docker exec llb1 sh -c "awk '/VmRSS/{print \$2}' /proc/$pid/status" 2>/dev/null
}

echo "== HTTP/2 connection-lifecycle soak =="
echo "   $ROUNDS rounds x $PER connections to $VIP:$PORT"
echo ""

base=$(rss_kb)
if [ "$base" = "ERR" ] || [ -z "$base" ]; then
  echo "FAIL: could not read the gateway's RSS — is llb1 up?"
  exit 2
fi
echo "round 0 (baseline): RSS ${base} kB"

prev=$base
for r in $(seq 1 "$ROUNDS"); do
  $hexec l3h1 python3 ./h2_churn.py "$VIP" "$PORT" "$PER" 0 || {
    echo "FAIL: churn round $r could not drive the connections"
    exit 2
  }
  sleep 2          # let the teardown path drain before sampling
  now=$(rss_kb)
  delta=$(( now - prev ))
  tot=$(( now - base ))
  per=$(awk -v d="$tot" -v n="$(( r * PER ))" 'BEGIN{printf "%.0f", d*1024/n}')
  echo "round $r: RSS ${now} kB  (+${delta} kB this round, +${tot} kB total, ${per} B/conn)"
  prev=$now
done

echo ""
echo "final: baseline ${base} kB -> ${prev} kB over $(( ROUNDS * PER )) connections"
