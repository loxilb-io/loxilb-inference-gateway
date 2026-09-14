#!/bin/bash
# Validates that the lightweight endpoint-health signal reaches the endpoint's
# row in EVERY pool of its service (proxy_update_ep_health_by_addr).
#
# The load-bearing oracles are the datapath's own log lines, because they name
# the mechanism directly:
#
#   EP health - <ep>:<port> -> inactive=<x> applied to <N> endpoint row(s)
#   EP health updated - <ep>:<port> pool='<key>' ep[i] <old>-><new>
#   EP health - <ep>:<port> not found in service <vip>:<port>
#
# "applied to 2" can only be printed by the address-keyed walk visiting both
# model pools; the per-pool 'model-beta' line can only appear via cross-pool
# fan-out (the beta rule has no monitor of its own); and "not found in
# service" firing at all means the Go->C key conversion regressed. Traffic
# checks ride along as product-level confirmation, but sockproxy's own
# connect-failure retry can mask a dead row, so they are supporting evidence,
# not the verdict.

source ../common.sh
echo SCENARIO-ai-ephealth
code=0

check() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == *"$want"* ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAILED] — expected '$want', got: '$got'"
    code=1
  fi
}

DPLOG=/var/log/loxilbdp.log

dp_count() { # <grep pattern> -> count on stdout
  # grep -c prints the count itself even when it is 0 (rc 1), so a `|| echo 0`
  # here would emit a second line and corrupt every numeric compare. The
  # fallback is only for the file not existing yet (grep prints nothing).
  local c
  c=$($dexec llb1 sh -c "grep -c -- \"$1\" $DPLOG 2>/dev/null")
  echo "${c:-0}"
}

# Poll until the datapath log holds at least <want> occurrences of <pattern>,
# or <budget> seconds pass. Probe cadence bounds the wait, so the budget is
# generous; a healthy run exits the loop in a fraction of it.
wait_dp_log() { # <label> <pattern> <want> <budget-seconds>
  local label="$1" pattern="$2" want="$3" budget="$4" n=0
  for i in $(seq 1 "$budget"); do
    n=$(dp_count "$pattern")
    if [ "$n" -ge "$want" ] 2>/dev/null; then
      echo "  $label [OK] (${i}s, count=$n)"
      return 0
    fi
    sleep 1
  done
  echo "  $label [FAILED] — wanted >=$want of '$pattern' within ${budget}s, got $n"
  code=1
  return 1
}

# A short ledger is a lost measurement: every burst below writes one line per
# request and then fails hard if the line count is not the request count, so
# a burst that silently sent nothing cannot satisfy an "all lines match"
# assert vacuously.
burst() { # <label> <count> <outfile> <curl args...>
  local label="$1" n="$2" out="$3"; shift 3
  : > "$out"
  for i in $(seq 1 "$n"); do
    r=$($hexec l3h1 curl -s --max-time 8 "$@")
    rc=$?
    echo "rc=$rc body=$r" >> "$out"
  done
  local lines
  lines=$(wc -l < "$out")
  if [ "$lines" -ne "$n" ]; then
    echo "  $label [FATAL] — sent $n requests but ledger holds $lines lines"
    code=1
    return 1
  fi
  return 0
}

## ── T1: baseline — both backends serve through every rule ───────────────────
echo ""
echo "T1: baseline traffic reaches both backends"
burst "t1 burst :2050" 8 /tmp/ephealth_t1 http://10.10.10.254:2050/
check "baseline :2050 hits server-a" "server-a" "$(cat /tmp/ephealth_t1)"
check "baseline :2050 hits server-b" "server-b" "$(cat /tmp/ephealth_t1)"

burst "t1 burst alpha" 2 /tmp/ephealth_t1a -H "X-Model: model-alpha" http://10.10.10.254:2060/
check "baseline alpha answers" "server-" "$(cat /tmp/ephealth_t1a)"
burst "t1 burst beta" 2 /tmp/ephealth_t1b -H "X-Model: model-beta" http://10.10.10.254:2060/
check "baseline beta answers" "server-" "$(cat /tmp/ephealth_t1b)"

## ── T2: kill server-b — the down signal must reach every pool ───────────────
echo ""
echo "T2: server-b dies; one probe transition fans out to every pool"
# Kill server-b ONLY, by its argv. The [t] bracket keeps the pattern from
# matching pkill's OWN command line (a plain -f pattern reaps the caller).
# hexec is "ip netns exec", so the mocks share
# the HOST pid namespace and differ only in their network namespace: a
# `killall node` here reaps server-a too, and the scenario then measures a
# two-backend outage while believing it measured one. Kill by the label, then
# prove the survivor is still serving before trusting anything that follows.
sudo pkill -9 -f "[t]cp_server.js server-b" 2>/dev/null
sleep 1
if ! $hexec l3ep1 curl -sf --max-time 2 http://127.0.0.1:8080/ | grep -q "server-a"; then
  echo "  [FATAL] server-a died with server-b — the kill was not surgical, so"
  echo "          every oracle below would describe a two-backend outage"
  code=1
  echo "SCENARIO-ai-ephealth [FAILED]"
  exit 1
fi
echo "  server-b killed, server-a still serving [OK]"
if $hexec l3ep2 curl -sf --max-time 2 http://127.0.0.1:8080/ 2>/dev/null | grep -q "server-b"; then
  echo "  [FATAL] server-b still answering after the kill"
  code=1
  echo "SCENARIO-ai-ephealth [FAILED]"
  exit 1
fi

# :2050 is single-pool → its transition applies to exactly 1 row.
wait_dp_log "down applied to 1 row (:2050, single pool)" \
  "inactive=1 applied to 1 endpoint row(s)" 1 180
# :2060 holds two pools sharing the backend → 2 rows from ONE signal.
wait_dp_log "down applied to 2 rows (:2060, alpha+beta pools)" \
  "inactive=1 applied to 2 endpoint row(s)" 1 180

# The per-pool receipts. model-beta has no monitor, so its 0->1 line can ONLY
# be the cross-pool fan-out — this is the property the datapath fix exists for.
check_at_least() { # <label> <want-min> <got>
  if [ "$3" -ge "$2" ] 2>/dev/null; then
    echo "  $1 [OK] (count=$3)"
  else
    echo "  $1 [FAILED] — wanted >=$2, got '$3'"
    code=1
  fi
}
check_at_least "alpha pool row marked down" 1 \
  "$(dp_count "pool='10.10.10.254|/|model-alpha'.*0->1")"
check_at_least "beta pool row marked down via cross-pool signal" 1 \
  "$(dp_count "pool='10.10.10.254|/|model-beta'.*0->1")"

## ── T3: traffic while down — the dead backend takes nothing ─────────────────
echo ""
echo "T3: while server-b is down, every request lands on server-a"
burst "t3 burst :2050" 6 /tmp/ephealth_t3 http://10.10.10.254:2050/
got_a=$(grep -c "server-a" /tmp/ephealth_t3)
got_b=$(grep -c "server-b" /tmp/ephealth_t3)
check ":2050 all 6 on server-a" "6" "$got_a"
check ":2050 none on server-b" "0" "$got_b"

burst "t3 burst beta" 4 /tmp/ephealth_t3b -H "X-Model: model-beta" http://10.10.10.254:2060/
got_a=$(grep -c "server-a" /tmp/ephealth_t3b)
got_b=$(grep -c "server-b" /tmp/ephealth_t3b)
check "beta pool all 4 on server-a" "4" "$got_a"
check "beta pool none on server-b" "0" "$got_b"

## ── T4: server-b recovers — the up signal fans out the same way ─────────────
echo ""
echo "T4: server-b recovers; the up signal reaches every pool"
$hexec l3ep2 sh -c "nohup node ../common/tcp_server.js server-b >/tmp/ai-ephealth-server-b2.log 2>&1 &"
for i in $(seq 1 20); do
  if $hexec l3ep2 curl -sf --max-time 1 http://127.0.0.1:8080/ | grep -q "server-b"; then
    echo "  server-b restarted (${i}s)"
    break
  fi
  if [ "$i" -eq 20 ]; then echo "  FATAL: server-b did not restart"; code=1; fi
  sleep 1
done

wait_dp_log "up applied to 1 row (:2050)" \
  "inactive=0 applied to 1 endpoint row(s)" 1 180
wait_dp_log "up applied to 2 rows (:2060)" \
  "inactive=0 applied to 2 endpoint row(s)" 1 180
check_at_least "beta pool row recovered via cross-pool signal" 1 \
  "$(dp_count "pool='10.10.10.254|/|model-beta'.*1->0")"

# Product-level: server-b rejoins the beta rotation. Poll rather than burst:
# round-robin position after the flap is not deterministic.
seen_b=0
for i in $(seq 1 60); do
  r=$($hexec l3h1 curl -s --max-time 8 -H "X-Model: model-beta" http://10.10.10.254:2060/)
  if [[ "$r" == *"server-b"* ]]; then seen_b=1; echo "  server-b back in beta rotation (${i} tries) [OK]"; break; fi
  sleep 1
done
if [ "$seen_b" -ne 1 ]; then
  echo "  server-b never rejoined beta rotation [FAILED]"
  code=1
fi

## ── T5: the address key never missed ────────────────────────────────────────
# "not found in service" means the C side could not match the address the Go
# side sent — the byte-order / keying regression this suite exists to catch.
# It must be zero across the WHOLE run, not merely rare.
echo ""
echo "T5: zero address-key misses across the run"
n=$(dp_count "not found in service")
if [ "$n" = "0" ]; then
  echo "  no 'not found in service' lines [OK]"
else
  echo "  no 'not found in service' lines [FAILED] — $n misses"
  code=1
fi

## ── Verdict ──────────────────────────────────────────────────────────────────
echo ""
if [ "$code" -ne 0 ]; then
  echo "---- EP-health lines in $DPLOG (diagnostic) ----"
  $dexec llb1 sh -c "grep -n 'EP health' $DPLOG | tail -40" || true
  echo "SCENARIO-ai-ephealth [FAILED]"
  exit 1
fi
echo "SCENARIO-ai-ephealth [OK]"
exit 0
