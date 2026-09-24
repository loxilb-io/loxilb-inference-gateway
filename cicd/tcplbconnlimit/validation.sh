#!/bin/bash
#
# tcplbconnlimit / validation.sh
#
# connectionLimit, end to end through the REST API: a rule created with a
# ceiling of 2 admits two connections and drops the third SYN, a PATCH to 3
# admits it, a PATCH back to 2 while three are held drops the next one, and
# the readback reports the stored value at every step. A control rule with the
# same endpoint and no ceiling admits three, so the drop is the ceiling's
# doing. Every admission is proven by a one-byte echo through the backend and
# counted on the backend with ss, never inferred from the client alone.
source ../common.sh

SCENARIO=SCENARIO-tcplbconnlimit
SUBJECT=20.20.20.1
CONTROL=20.20.20.2
PORT=2020
EP_PORT=8080
API=http://127.0.0.1:11111/netlox/v1/config/loadbalancer
CONNECT_TIMEOUT=3
FAILS=0
HOLDERS=()

echo "$SCENARIO"

result() {   # <label> <OK|FAILED> [detail]
  if [[ "$2" == "OK" ]]; then
    printf "    %-52s : OK%s\n" "$1" "${3:+ ($3)}"
  else
    printf "    %-52s : FAILED%s\n" "$1" "${3:+ ($3)}"
    FAILS=$((FAILS + 1))
  fi
}

readback() {   # prints the subject's connectionLimit as GET reports it ("" = absent)
  $dexec llb1 curl -s "$API/all" | python3 -c '
import json, sys
vip = sys.argv[1]
for r in json.load(sys.stdin).get("lbAttr", []):
    s = r.get("serviceArguments", {})
    if s.get("externalIP") == vip and s.get("port") == 2020:
        print(s.get("connectionLimit", ""))
        break' "$1"
}

patch_limit() {   # <limit> -> HTTP code
  $dexec llb1 curl -sS -o /dev/null -w '%{http_code}' -X PATCH \
    "$API/externalipaddress/$SUBJECT/port/$PORT/protocol/tcp" \
    -H 'Content-Type: application/json' -d "{\"serviceArguments\":{\"connectionLimit\":$1}}"
}

# Established connections the backend holds on its port, counted where they
# terminate.
backend_established() {
  $hexec l3ep1 ss -Htn state established "( sport = :$EP_PORT )" | wc -l
}

# Runs the holder in the background and waits until it has reported every
# attempt; prints its output file.
hold() {   # <host> <port> <count> <hold-seconds>
  local out
  out=$(mktemp /tmp/connlimit.XXXXXX)
  $hexec l3h1 python3 ./hold_client.py "$1" "$2" "$3" "$CONNECT_TIMEOUT" "$4" > "$out" 2>&1 &
  HOLDERS+=($!)
  for _ in $(seq 1 $(( (CONNECT_TIMEOUT + 2) * $3 * 2 ))); do
    grep -q '"attempted"' "$out" && break
    sleep 0.5
  done
  echo "$out"
}
attempts() { grep -c "\"result\": \"$2\"" "$1"; }
connected() { python3 -c 'import json,sys
for l in open(sys.argv[1]):
    d = json.loads(l)
    if "connected" in d: print(d["connected"])' "$1"; }

cleanup() {
  for p in "${HOLDERS[@]}"; do sudo kill "$p" 2>/dev/null; done
  sudo pkill -f "hold_client.py" 2>/dev/null
  sudo pkill -f "hold_server.py" 2>/dev/null
}
trap cleanup EXIT

echo "  -- Step 0: backend"
$hexec l3ep1 python3 ./hold_server.py $EP_PORT > /tmp/connlimit-server.log 2>&1 &
HOLDERS+=($!)
# The backend and the bed's routes come up on their own clocks, as every
# scenario's server wait allows for: wait for the listen socket, then retry
# the direct probe a few times before declaring the backend absent.
for _ in $(seq 1 20); do
  $hexec l3ep1 ss -Hltn "( sport = :$EP_PORT )" | grep -q LISTEN && break
  sleep 0.5
done
probe=""
for _ in $(seq 1 10); do
  direct=$(hold 31.31.31.1 $EP_PORT 1 0)
  probe=$(cat "$direct" | tr '\n' ' ')
  [[ "$(attempts "$direct" connected)" == "1" ]] && break
  sleep 1
done
if [[ "$(attempts "$direct" connected)" == "1" ]]; then
  result "backend answers a direct connection" "OK"
else
  result "backend answers a direct connection" "FAILED" "$probe"
  echo "FATAL: no backend, nothing below can run"
  echo "$SCENARIO [FAILED]"
  exit 1
fi

echo "  -- Step 1: the readback reports the stored ceiling"
got=$(readback $SUBJECT)
[[ "$got" == "2" ]] && result "subject reads back connectionLimit 2" "OK" || result "subject reads back connectionLimit 2" "FAILED" "got '${got:-absent}'"
got=$(readback $CONTROL)
[[ -z "$got" ]] && result "control reads back no ceiling" "OK" || result "control reads back no ceiling" "FAILED" "got '$got'"

echo "  -- Step 2: two connections admitted, the third SYN dropped"
before=$(backend_established)
held=$(hold $SUBJECT $PORT 2 90)
n=$(attempts "$held" connected)
[[ "$n" == "2" ]] && result "first two connections admitted and echoed" "OK" || result "first two connections admitted and echoed" "FAILED" "$(cat "$held" | tr '\n' ' ')"
sleep 1
now=$(( $(backend_established) - before ))
[[ "$now" == "2" ]] && result "backend holds exactly two of them" "OK" "ss" || result "backend holds exactly two of them" "FAILED" "backend +$now"
third=$(hold $SUBJECT $PORT 1 0)
if [[ "$(attempts "$third" timeout)" == "1" ]]; then
  result "third connection: SYN dropped, no reset" "OK" "${CONNECT_TIMEOUT}s timeout"
elif [[ "$(attempts "$third" refused)" == "1" ]]; then
  result "third connection: SYN dropped, no reset" "FAILED" "reset instead of a drop"
else
  result "third connection: SYN dropped, no reset" "FAILED" "$(cat "$third" | tr '\n' ' ')"
fi
now=$(( $(backend_established) - before ))
[[ "$now" == "2" ]] && result "backend still holds two" "OK" || result "backend still holds two" "FAILED" "backend +$now"

echo "  -- Step 3: control without a ceiling admits three"
cbefore=$(backend_established)
ctrl=$(hold $CONTROL $PORT 3 5)
n=$(attempts "$ctrl" connected)
[[ "$n" == "3" ]] && result "control: three connections admitted" "OK" || result "control: three connections admitted" "FAILED" "$(cat "$ctrl" | tr '\n' ' ')"
sleep 1
now=$(( $(backend_established) - cbefore ))
[[ "$now" == "3" ]] && result "control: backend holds all three" "OK" "ss" || result "control: backend holds all three" "FAILED" "backend +$now"
sleep 6

echo "  -- Step 4: PATCH raises the ceiling to 3 and the next connection is admitted"
code=$(patch_limit 3)
[[ "$code" == "200" ]] && result "PATCH connectionLimit 3 accepted" "OK" || result "PATCH connectionLimit 3 accepted" "FAILED" "HTTP $code"
got=$(readback $SUBJECT)
[[ "$got" == "3" ]] && result "subject reads back connectionLimit 3" "OK" || result "subject reads back connectionLimit 3" "FAILED" "got '${got:-absent}'"
sleep 1
fourth=$(hold $SUBJECT $PORT 1 60)
[[ "$(attempts "$fourth" connected)" == "1" ]] && result "a third connection is now admitted" "OK" || result "a third connection is now admitted" "FAILED" "$(cat "$fourth" | tr '\n' ' ')"
sleep 1
now=$(( $(backend_established) - before ))
[[ "$now" == "3" ]] && result "backend holds three" "OK" "ss" || result "backend holds three" "FAILED" "backend +$now"

echo "  -- Step 5: PATCH lowers the ceiling to 2 under three held connections"
code=$(patch_limit 2)
[[ "$code" == "200" ]] && result "PATCH connectionLimit 2 accepted" "OK" || result "PATCH connectionLimit 2 accepted" "FAILED" "HTTP $code"
got=$(readback $SUBJECT)
[[ "$got" == "2" ]] && result "subject reads back connectionLimit 2 again" "OK" || result "subject reads back connectionLimit 2 again" "FAILED" "got '${got:-absent}'"
sleep 1
fifth=$(hold $SUBJECT $PORT 1 0)
[[ "$(attempts "$fifth" timeout)" == "1" ]] && result "a fourth connection is dropped again" "OK" || result "a fourth connection is dropped again" "FAILED" "$(cat "$fifth" | tr '\n' ' ')"

echo "  -- Step 6: released slots admit again"
for p in "${HOLDERS[@]:1}"; do sudo kill "$p" 2>/dev/null; done
sudo pkill -f "hold_client.py" 2>/dev/null
for _ in $(seq 1 20); do
  [[ "$(( $(backend_established) - before ))" == "0" ]] && break
  sleep 0.5
done
now=$(( $(backend_established) - before ))
[[ "$now" == "0" ]] && result "backend released every held connection" "OK" || result "backend released every held connection" "FAILED" "backend +$now"
sleep 2
fresh=$(hold $SUBJECT $PORT 2 0)
[[ "$(attempts "$fresh" connected)" == "2" ]] && result "two fresh connections admitted after release" "OK" || result "two fresh connections admitted after release" "FAILED" "$(cat "$fresh" | tr '\n' ' ')"

echo
if [[ "$FAILS" -eq 0 ]]; then
  echo "$SCENARIO [OK]"
  exit 0
fi
echo "$SCENARIO [FAILED] ($FAILS check(s) failed)"
exit 1
