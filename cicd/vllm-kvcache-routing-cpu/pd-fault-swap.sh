#!/bin/bash
# pd-fault-swap.sh <ep-netns> hang|ok|refuse|zerobyte|slowok|off
#
# Puts one endpoint netns behind a chosen fault backend, or restores it.
#
# `slowok` takes STUB_DELAY (seconds, default 8): the stub reads the whole
# request, stays silent for that long, then answers exactly as `ok` does. It is
# the only mode here that holds a connection OPEN without failing it, which is
# what an arm needs when the thing under test is per-endpoint in-flight load
# (pd_ep_loads[].active_conns) rather than a fault. `hang` cannot serve that
# purpose: it ends in a zero-byte close and moves the death counters.
#
# Mechanism: each EP netns already runs reflect-echo on :80. A fault mode
# starts pd-fault-backend.py on $STUB_PORT and REDIRECTs :80 to it; `off`
# removes the redirect and kills the stub, which restores reflect-echo.
# `off` is therefore the DEFAULT shape of the bed and is idempotent -- running
# it on an EP that was never switched is a successful no-op, not an error.
#
# Never kill by process-name pattern here. `ip netns exec` is a NETWORK
# namespace, not a pid namespace, so the hosts share the runner's pid
# namespace and a pattern kill would reap other scenarios' backends -- and can
# match this script's own shell. Teardown goes by pidfile AND then PROVES,
# netns-scoped and by PORT, that nothing still listens. A pidfile alone is not
# enough: the recorded pid can die while the real listener survives, and
# because `off` removes the REDIRECT first, probes read correctly and the
# orphan only surfaces one run later as EADDRINUSE. A teardown that cannot
# fail is not a teardown.
set -u

EP="${1:?usage: pd-fault-swap.sh <ep-netns> hang|ok|refuse|zerobyte|slowok|off}"
STATE="${2:?usage: pd-fault-swap.sh <ep-netns> hang|ok|refuse|zerobyte|slowok|off}"
STUB_PORT="${STUB_PORT:-8099}"
STUB_DELAY="${STUB_DELAY:-8}"
DIR="${PD_FAULT_DIR:-/tmp/pd-fault}"
PIDFILE="$DIR/$EP.pid"
LOGFILE="$DIR/$EP.log"
FAULT_STUB="$(cd "$(dirname "$0")" && pwd)/pd-fault-backend.py"

mkdir -p "$DIR"

if ! ip netns list 2>/dev/null | grep -qw "$EP"; then
  echo "FATAL: netns $EP does not exist" >&2
  exit 2
fi

nse() { ip netns exec "$EP" "$@"; }

redirect_del() {
  # Delete EVERY copy of the rule, so a double switch cannot leave one behind.
  while nse iptables -t nat -C PREROUTING -p tcp --dport 80 \
          -j REDIRECT --to-port "$STUB_PORT" 2>/dev/null; do
    nse iptables -t nat -D PREROUTING -p tcp --dport 80 \
        -j REDIRECT --to-port "$STUB_PORT" 2>/dev/null || break
  done
  while nse iptables -t nat -C OUTPUT -p tcp --dport 80 \
          -j REDIRECT --to-port "$STUB_PORT" 2>/dev/null; do
    nse iptables -t nat -D OUTPUT -p tcp --dport 80 \
        -j REDIRECT --to-port "$STUB_PORT" 2>/dev/null || break
  done
}

port_kill() {
  # Free $STUB_PORT inside this netns, then PROVE it is free.
  #
  # Tool availability differs per runner and the difference is SILENT: on some
  # hosts `ss`/`pgrep` are disabled, so an ss-based check finds nothing and
  # reports success while the orphan still holds the port. A verification that
  # cannot fail is worse than none. `fuser` is netns-scoped here and is the
  # primary. Matching by PORT, never by process name, is what keeps this from
  # reaping other scenarios' backends in the shared pid namespace.
  local i
  nse fuser -k -n tcp "$STUB_PORT" >/dev/null 2>&1
  for i in 1 2 3 4 5 6 7 8 9 10; do
    nse fuser -s -n tcp "$STUB_PORT" 2>/dev/null || return 0
    sleep 0.3
  done
  nse fuser -k -KILL -n tcp "$STUB_PORT" >/dev/null 2>&1
  sleep 1
  if nse fuser -s -n tcp "$STUB_PORT" 2>/dev/null; then
    echo "FATAL: $EP still holds :$STUB_PORT after teardown — refusing to" \
         "report a clean state that is not clean" >&2
    return 1
  fi
  return 0
}

stub_kill() {
  local pid
  if [ -f "$PIDFILE" ]; then
    pid="$(cat "$PIDFILE" 2>/dev/null)"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.2
      done
      kill -9 "$pid" 2>/dev/null
    fi
    rm -f "$PIDFILE"
  fi
  port_kill || return 1
  return 0
}

case "$STATE" in
  hang|ok|refuse|zerobyte|slowok)
    # `refuse` deliberately does NOT listen: the REDIRECT then points traffic
    # at a closed port and connect() gets ECONNREFUSED. That is the event the
    # caller asked for, not a failure of this script, so the usual "did the
    # stub come up" check below is satisfied by the process being alive rather
    # than by the port being bound.
    [ -f "$FAULT_STUB" ] || { echo "FATAL: missing $FAULT_STUB" >&2; exit 2; }
    stub_kill || exit 1
    redirect_del
    # --delay is only read by slowok; passing it unconditionally would still be
    # inert, but keeping it off the other modes' argv keeps their invocation
    # byte-identical to what they were proven with.
    if [ "$STATE" = slowok ]; then
      nse python3 "$FAULT_STUB" --mode "$STATE" --port "$STUB_PORT" \
          --delay "$STUB_DELAY" >"$LOGFILE" 2>&1 &
    else
      nse python3 "$FAULT_STUB" --mode "$STATE" --port "$STUB_PORT" \
          >"$LOGFILE" 2>&1 &
    fi
    echo $! > "$PIDFILE"
    sleep 1
    if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "FATAL: fault stub ($STATE) died on $EP; see $LOGFILE" >&2
      tail -5 "$LOGFILE" >&2
      exit 1
    fi
    nse iptables -t nat -A PREROUTING -p tcp --dport 80 \
        -j REDIRECT --to-port "$STUB_PORT" || exit 1
    nse iptables -t nat -A OUTPUT -p tcp --dport 80 \
        -j REDIRECT --to-port "$STUB_PORT" || exit 1
    echo "$EP fault-mode=$STATE (pid $(cat "$PIDFILE") port $STUB_PORT$([ "$STATE" = slowok ] && echo " delay ${STUB_DELAY}s"))"
    ;;
  off)
    redirect_del
    stub_kill || exit 1
    echo "$EP fault-mode=off (reflect-echo restored)"
    ;;
  *)
    echo "FATAL: unknown state '$STATE' (hang|ok|refuse|zerobyte|slowok|off)" >&2
    exit 2
    ;;
esac
