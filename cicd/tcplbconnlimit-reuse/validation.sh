#!/bin/bash
#
# tcplbconnlimit-reuse / validation.sh
#
# connectionLimit counts only connections that exist. Every way a NAT
# connection can leave the gateway other than its own close must give its slot
# back: deleting the rule under live connections, the idle timeout, an endpoint
# taken out of selection, and a SYN that is counted and then dropped because
# its reverse tuple is taken. Each arm ends with the same two checks: the
# datapath counts exactly the connections that are really open, and a rule
# with connectionLimit 2 admits exactly two connections and drops the third
# SYN. The delete arm runs once per NAT mode (default, onearm, fullnat). Arm E
# overwrites the counter and expects the gateway to correct it. Arm F is the
# same rule for the per-endpoint counts least-connections selection reads:
# connections removed by the idle timeout must leave them. Arm G is the other
# side: a rule that is applied again, changed in place or given another
# endpoint while it has connections keeps every count. Arm H overwrites a
# per-endpoint count and expects the gateway to correct that too. Arm I: a SYN
# the limit refuses is not a connection and takes no per-endpoint count.
source ../common.sh

SCENARIO=SCENARIO-tcplbconnlimit-reuse
PORT=2020
EP=31.31.31.1
EP_PORT=8080
EP2=32.32.32.1
LIMIT=2
API=http://127.0.0.1:11111/netlox/v1/config/loadbalancer
CONNECT_TIMEOUT=3
FAILS=0
# hold() runs inside $( ), so the holders it starts are recorded in a file.
HOLDERS=$(mktemp /tmp/connlimit-reuse-pids.XXXXXX)
# Arms to run, for reproducing one path alone: ARMS="B" ./validation.sh
ARMS=${ARMS:-A B C D E F G H I}

echo "$SCENARIO"

result() {   # <label> <OK|FAILED> [detail]
  if [[ "$2" == "OK" ]]; then
    printf "    %-58s : OK%s\n" "$1" "${3:+ ($3)}"
  else
    printf "    %-58s : FAILED%s\n" "$1" "${3:+ ($3)}"
    FAILS=$((FAILS + 1))
  fi
}

post_rule() {   # <vip> <mode> <inactiveTimeOut> -> HTTP code
  $dexec llb1 curl -sS -o /dev/null -w '%{http_code}' -X POST "$API" -H 'Content-Type: application/json' -d "{
    \"serviceArguments\": { \"externalIP\": \"$1\", \"port\": $PORT, \"protocol\": \"tcp\", \"sel\": 0, \"mode\": $2, \"connectionLimit\": $LIMIT, \"inactiveTimeOut\": $3 },
    \"endpoints\": [ { \"endpointIP\": \"$EP\", \"targetPort\": $EP_PORT, \"weight\": 1 } ]
  }"
}

# A least-connections rule over the given endpoints.
post_lc_rule() {   # <vip> <connectionLimit> <inactiveTimeOut> <endpoint-ip>... -> HTTP code
  local vip=$1 limit=$2 ito=$3 eps="" ip
  shift 3
  for ip in "$@"; do
    eps="$eps${eps:+, }{ \"endpointIP\": \"$ip\", \"targetPort\": $EP_PORT, \"weight\": 1 }"
  done
  $dexec llb1 curl -sS -o /dev/null -w '%{http_code}' -X POST "$API" -H 'Content-Type: application/json' -d "{
    \"serviceArguments\": { \"externalIP\": \"$vip\", \"port\": $PORT, \"protocol\": \"tcp\", \"sel\": 4, \"mode\": 0, \"connectionLimit\": $limit, \"inactiveTimeOut\": $ito },
    \"endpoints\": [ $eps ]
  }"
}

delete_rule() {   # <vip> -> HTTP code
  $dexec llb1 curl -sS -o /dev/null -w '%{http_code}' -X DELETE \
    "$API/externalipaddress/$1/port/$PORT/protocol/tcp"
}

patch_rule() {   # <vip> <serviceArguments-json> -> HTTP code
  $dexec llb1 curl -sS -o /dev/null -w '%{http_code}' -X PATCH \
    "$API/externalipaddress/$1/port/$PORT/protocol/tcp" \
    -H 'Content-Type: application/json' -d "{\"serviceArguments\":$2}"
}

# The datapath's live connection count, summed over every rule index. Each arm
# has exactly one rule at a time, so the sum is that rule's count plus whatever
# deleted rules left behind, and it must equal the connections really open.
counted() {
  $dexec llb1 bpftool map dump name nat_ep_map -j | python3 -c '
import json, sys
print(sum(e["formatted"]["value"]["conc_conns"] for e in json.load(sys.stdin)))'
}

# Everything the datapath counts for the rules that have counted anything:
# live and cumulative connections, cumulative bytes, per-endpoint sessions.
counts() {
  $dexec llb1 bpftool map dump name nat_ep_map -j | python3 ./rule_counts.py
}
sessions() {
  local c
  # No session counted prints nothing, so a dump that cannot be read must not.
  c=$(counts) || { echo "unreadable"; return; }
  echo "$c" | sed -n 's/.* sess=//p' | tr '\n' ' ' | sed 's/ $//'
}

expect_sessions() {   # <label> <want>
  local got=""
  for _ in $(seq 1 10); do
    got=$(sessions)
    [[ "$got" == "$2" ]] && break
    sleep 0.5
  done
  [[ "$got" == "$2" ]] && result "$1" "OK" "sessions [$got]" || result "$1" "FAILED" "sessions [$got], want [$2]"
}

# Connections a backend holds established.
established() {   # <backend-host>
  $hexec "$1" ss -Htn state established "( sport = :$EP_PORT )" | wc -l
}

# Corrections of a rule's counts the gateway reports as a metric.
corrections() {
  $dexec llb1 curl -s --max-time 5 http://127.0.0.1:11111/netlox/v1/metrics |
    awk '$1 == "loxilb_lb_conn_count_corrections_total" { print $2 }'
}

# Every correction the datapath has logged, for the report of a failed check.
correction_log() {
  echo "    corrections in the datapath log:"
  $dexec llb1 grep "count corrected" /var/log/loxilbdp.log | sed 's/^/      /'
  echo "    (end of corrections)"
}

# A close reaches the counter a moment after the client returns, so the check
# polls for the expected value and fails with the last value seen.
expect_counted() {   # <label> <want>
  local got=""
  for _ in $(seq 1 10); do
    got=$(counted)
    [[ "$got" == "$2" ]] && break
    sleep 0.5
  done
  [[ "$got" == "$2" ]] && result "$1" "OK" "counted $got" || result "$1" "FAILED" "counted $got, want $2"
}

# Conntrack entries the gateway holds towards a service address.
ct_entries() {   # <vip>
  $dexec llb1 loxicmd get ct -o wide 2>/dev/null | grep -c "$1"
}

# The gateway lists entries towards the address and then, within 180 s, none.
# Without the first half a listing that fails would read as "aged out".
expect_aged_out() {   # <label> <vip>
  local had=0 left=""
  for _ in $(seq 1 20); do
    had=$(ct_entries "$2")
    [[ "$had" -gt 0 ]] && break
    sleep 0.5
  done
  if [[ "$had" -eq 0 ]]; then
    result "$1" "FAILED" "no conntrack entry listed while the connections were open"
    return
  fi
  for _ in $(seq 1 180); do
    left=$(ct_entries "$2")
    [[ "$left" == "0" ]] && break
    sleep 1
  done
  [[ "$left" == "0" ]] && result "$1" "OK" "$had entries gone" || result "$1" "FAILED" "$left conntrack entries left after 180 s"
}

# Runs the holder in the background and waits until it has reported every
# attempt; prints its output file.
hold() {   # <host> <vip> <count> <hold-seconds> [source-port]
  local out
  out=$(mktemp /tmp/connlimit-reuse.XXXXXX)
  $hexec "$1" python3 ./hold_client.py "$2" "$PORT" "$3" "$CONNECT_TIMEOUT" "$4" ${5:+"$5"} > "$out" 2>&1 &
  echo $! >> "$HOLDERS"
  for _ in $(seq 1 $(( (CONNECT_TIMEOUT + 2) * $3 * 2 ))); do
    grep -q '"attempted"' "$out" && break
    sleep 0.5
  done
  echo "$out"
}
attempts() { grep -c "\"result\": \"$2\"" "$1"; }

release() {   # stop every holder started so far
  local p
  while read -r p; do
    sudo pkill -9 -P "$p" 2>/dev/null
    sudo kill -9 "$p" 2>/dev/null
  done < "$HOLDERS"
  : > "$HOLDERS"
}

# Three attempts against a rule with nothing held: exactly LIMIT are admitted
# and echoed, the next SYN is dropped. Leaves the admitted ones held.
expect_exactly_limit() {   # <label> <vip>
  local out
  out=$(hold l3h1 "$2" $((LIMIT + 1)) 120)
  if [[ "$(attempts "$out" connected)" == "$LIMIT" && "$(attempts "$out" timeout)" == "1" ]]; then
    result "$1" "OK" "$LIMIT admitted, next SYN dropped"
  else
    result "$1" "FAILED" "$(tr '\n' ' ' < "$out")"
  fi
}

release_only() {   # <holder-pid>...
  local p
  for p in "$@"; do
    sudo pkill -9 -P "$p" 2>/dev/null
    sudo kill -9 "$p" 2>/dev/null
    sed -i "/^$p\$/d" "$HOLDERS"
  done
}
last_holder() { tail -n 1 "$HOLDERS"; }

cleanup() {
  release
  stop_helpers
  rm -f "$HOLDERS" /tmp/connlimit-reuse.??????
}
trap cleanup EXIT

echo "  -- Step 0: backend"
$hexec l3ep1 python3 ../tcplbconnlimit/hold_server.py $EP_PORT > /tmp/connlimit-reuse-server.log 2>&1 &
track_helper
$hexec l3ep2 python3 ../tcplbconnlimit/hold_server.py $EP_PORT > /tmp/connlimit-reuse-server2.log 2>&1 &
track_helper
for _ in $(seq 1 20); do
  $hexec l3ep1 ss -Hltn "( sport = :$EP_PORT )" | grep -q LISTEN &&
    $hexec l3ep2 ss -Hltn "( sport = :$EP_PORT )" | grep -q LISTEN && break
  sleep 0.5
done
probe=""
for _ in $(seq 1 10); do
  direct=$(mktemp /tmp/connlimit-reuse.XXXXXX)
  $hexec l3h1 python3 ./hold_client.py $EP $EP_PORT 1 $CONNECT_TIMEOUT 0 > "$direct" 2>&1
  [[ "$(attempts "$direct" connected)" == "1" ]] && break
  sleep 1
done
if [[ "$(attempts "$direct" connected)" == "1" ]]; then
  result "backend answers a direct connection" "OK"
else
  result "backend answers a direct connection" "FAILED" "$(tr '\n' ' ' < "$direct")"
  echo "FATAL: no backend, nothing below can run"
  echo "$SCENARIO [FAILED]"
  exit 1
fi

# ---------------------------------------------------------------------------
# Arm A: the rule is deleted while its connections are open, then created
# again. The new rule starts from zero in every NAT mode.
# ---------------------------------------------------------------------------
arm_delete() {   # <mode> <mode-name> <vip>
  local mode=$1 name=$2 vip=$3 code
  echo "  -- Arm A ($name): rule deleted under live connections, then re-created"
  code=$(post_rule "$vip" "$mode" 60)
  [[ "$code" == "200" ]] && result "$name: rule created" "OK" || result "$name: rule created" "FAILED" "HTTP $code"
  sleep 2
  expect_exactly_limit "$name: fresh rule admits exactly $LIMIT" "$vip"
  expect_counted "$name: counter matches the held connections" "$LIMIT"
  code=$(delete_rule "$vip")
  [[ "$code" == "200" ]] && result "$name: rule deleted with $LIMIT connections open" "OK" || result "$name: rule deleted with $LIMIT connections open" "FAILED" "HTTP $code"
  sleep 2
  release
  code=$(post_rule "$vip" "$mode" 60)
  [[ "$code" == "200" ]] && result "$name: rule re-created" "OK" || result "$name: rule re-created" "FAILED" "HTTP $code"
  sleep 2
  expect_counted "$name: re-created rule starts from zero" 0
  expect_exactly_limit "$name: re-created rule admits exactly $LIMIT" "$vip"
  release
  expect_counted "$name: closed connections give their slots back" 0
  delete_rule "$vip" > /dev/null
  sleep 1
}
if [[ " $ARMS " == *" A "* ]]; then
arm_delete 0 default 20.20.20.1
arm_delete 1 onearm  20.20.20.2
arm_delete 2 fullnat 20.20.20.3
fi

# ---------------------------------------------------------------------------
# Arm B: idle connections are removed by the inactivity timeout, not by a
# close the gateway sees.
# ---------------------------------------------------------------------------
if [[ " $ARMS " == *" B "* ]]; then
echo "  -- Arm B: connections removed by the idle timeout"
VIP=20.20.20.4
code=$(post_rule $VIP 0 5)
[[ "$code" == "200" ]] && result "idle: rule created with a 5 s idle timeout" "OK" || result "idle: rule created with a 5 s idle timeout" "FAILED" "HTTP $code"
sleep 2
expect_exactly_limit "idle: fresh rule admits exactly $LIMIT" $VIP
expect_aged_out "idle: gateway aged out the idle connections" $VIP
release
expect_counted "idle: aged-out connections give their slots back" 0
expect_exactly_limit "idle: rule admits exactly $LIMIT again" $VIP
release
delete_rule $VIP > /dev/null
sleep 1

fi

# ---------------------------------------------------------------------------
# Arm C: the rule's only endpoint is taken out of selection (service paused)
# while connections are open, then put back.
# ---------------------------------------------------------------------------
if [[ " $ARMS " == *" C "* ]]; then
echo "  -- Arm C: endpoint taken out of selection and put back"
VIP=20.20.20.5
code=$(post_rule $VIP 0 60)
[[ "$code" == "200" ]] && result "pause: rule created" "OK" || result "pause: rule created" "FAILED" "HTTP $code"
sleep 2
expect_exactly_limit "pause: fresh rule admits exactly $LIMIT" $VIP
code=$(patch_rule $VIP '{"adminStateUp":false}')
[[ "$code" == "200" ]] && result "pause: PATCH adminStateUp false accepted" "OK" || result "pause: PATCH adminStateUp false accepted" "FAILED" "HTTP $code"
sleep 2
release
code=$(patch_rule $VIP '{"adminStateUp":true}')
[[ "$code" == "200" ]] && result "pause: PATCH adminStateUp true accepted" "OK" || result "pause: PATCH adminStateUp true accepted" "FAILED" "HTTP $code"
sleep 2
expect_counted "pause: counter matches the open connections (none)" 0
expect_exactly_limit "pause: resumed rule admits exactly $LIMIT" $VIP
release
delete_rule $VIP > /dev/null
sleep 1

fi

# ---------------------------------------------------------------------------
# Arm D: a SYN whose reverse tuple is already taken. Under fullnat a second
# client address using the same source port is such a SYN today. Whether that
# connection succeeds is not this scenario's subject; the counter must equal
# the connections that exist either way.
# ---------------------------------------------------------------------------
if [[ " $ARMS " == *" D "* ]]; then
echo "  -- Arm D: SYN refused after it was counted"
VIP=20.20.20.6
code=$(post_rule $VIP 2 60)
[[ "$code" == "200" ]] && result "dup-port: fullnat rule created" "OK" || result "dup-port: fullnat rule created" "FAILED" "HTTP $code"
sleep 2
first=$(hold l3h1 $VIP 1 120 40000)
[[ "$(attempts "$first" connected)" == "1" ]] && result "dup-port: first client connected from port 40000" "OK" || result "dup-port: first client connected from port 40000" "FAILED" "$(tr '\n' ' ' < "$first")"
second=$(hold l3h2 $VIP 1 0 40000)
echo "    second client, same source port: $(tr '\n' ' ' < "$second")"
sleep 2
expect_counted "dup-port: counter matches the one open connection" 1
rest=$(hold l3h1 $VIP 2 120)
if [[ "$(attempts "$rest" connected)" == "1" && "$(attempts "$rest" timeout)" == "1" ]]; then
  result "dup-port: one more admitted, the next SYN dropped" "OK"
else
  result "dup-port: one more admitted, the next SYN dropped" "FAILED" "$(tr '\n' ' ' < "$rest")"
fi
release
delete_rule $VIP > /dev/null

fi

# ---------------------------------------------------------------------------
# Arm E: the counter is made wrong from outside while two connections are
# open. The gateway compares it with the connections that exist after every
# ageing run and corrects it, says so in its datapath log and counts the
# correction in loxilb_lb_conn_count_corrections_total.
# ---------------------------------------------------------------------------
if [[ " $ARMS " == *" E "* ]]; then
echo "  -- Arm E: a wrong counter is corrected"
VIP=20.20.20.7
WRONG=7
fails_before=$FAILS
code=$(post_rule $VIP 0 60)
[[ "$code" == "200" ]] && result "inject: rule created" "OK" || result "inject: rule created" "FAILED" "HTTP $code"
sleep 2
expect_exactly_limit "inject: fresh rule admits exactly $LIMIT" $VIP
expect_counted "inject: counter matches the held connections" "$LIMIT"
reported=$(corrections)
[[ "$reported" == "0" ]] && result "inject: no correction reported before" "OK" || result "inject: no correction reported before" "FAILED" "metric reads '$reported'"
args=$($dexec llb1 bpftool map dump name nat_ep_map -j | python3 ./inject_count.py "$LIMIT" "$WRONG")
if [[ -n "$args" ]] && $dexec llb1 bpftool map update name nat_ep_map $args; then
  got=$(counted)
  [[ "$got" == "$WRONG" ]] && result "inject: counter overwritten with $WRONG" "OK" || result "inject: counter overwritten with $WRONG" "FAILED" "counted $got"
else
  result "inject: counter overwritten with $WRONG" "FAILED" "could not rewrite the entry"
fi
got=""
for _ in $(seq 1 90); do
  got=$(counted)
  [[ "$got" == "$LIMIT" ]] && break
  sleep 1
done
[[ "$got" == "$LIMIT" ]] && result "inject: counter corrected to the open connections" "OK" "counted $got" || result "inject: counter corrected to the open connections" "FAILED" "counted $got after 90 s, want $LIMIT"
logged=$($dexec llb1 grep -c "live connection count corrected $WRONG -> $LIMIT" /var/log/loxilbdp.log)
[[ "$logged" == "1" ]] && result "inject: the correction is logged once" "OK" || result "inject: the correction is logged once" "FAILED" "$logged log lines"
reported=$(corrections)
[[ "$reported" == "1" ]] && result "inject: the correction is reported as a metric" "OK" || result "inject: the correction is reported as a metric" "FAILED" "metric reads '$reported'"
release
expect_counted "inject: closed connections give their slots back" 0
delete_rule $VIP > /dev/null
[[ "$FAILS" -gt "$fails_before" ]] && correction_log
sleep 1
fi

# ---------------------------------------------------------------------------
# Arm F: least-connections selection reads a per-endpoint session count. Three
# idle connections on the first endpoint are removed by the idle timeout while
# the three on the second are closed by their clients. Both ways must leave
# the counts, so the next connections are spread evenly again.
# ---------------------------------------------------------------------------
if [[ " $ARMS " == *" F "* ]]; then
echo "  -- Arm F: least-connections after connections age out"
VIP=20.20.20.8
code=$(post_lc_rule $VIP 0 20 $EP $EP2)
[[ "$code" == "200" ]] && result "lc-idle: least-connections rule, 20 s idle timeout" "OK" || result "lc-idle: least-connections rule, 20 s idle timeout" "FAILED" "HTTP $code"
sleep 2
second=()
# A backend still holds the connections of earlier arms that the gateway
# removed without the backend seeing a close, so new ones are counted from here.
b1=$(established l3ep1); b2=$(established l3ep2)
for n in 1 2 3 4 5 6; do
  hold l3h1 $VIP 1 300 > /dev/null
  (( n % 2 == 0 )) && second+=("$(last_holder)")
done
n1=$(( $(established l3ep1) - b1 )); n2=$(( $(established l3ep2) - b2 ))
[[ "$n1" == "3" && "$n2" == "3" ]] && result "lc-idle: six connections alternate between the endpoints" "OK" || result "lc-idle: six connections alternate between the endpoints" "FAILED" "$n1 on the first endpoint, $n2 on the second"
expect_sessions "lc-idle: three sessions counted on each endpoint" "3,3"
release_only "${second[@]}"
expect_sessions "lc-idle: closed connections leave the second endpoint" "3"
expect_aged_out "lc-idle: gateway aged out the idle connections" $VIP
expect_sessions "lc-idle: aged-out connections leave the first endpoint" ""
b1=$(established l3ep1); b2=$(established l3ep2)
hold l3h2 $VIP 4 120 > /dev/null
n1=$(( $(established l3ep1) - b1 )); n2=$(( $(established l3ep2) - b2 ))
[[ "$n1" == "2" && "$n2" == "2" ]] && result "lc-idle: four new connections are spread two and two" "OK" || result "lc-idle: four new connections are spread two and two" "FAILED" "$n1 on the first endpoint, $n2 on the second"
release
expect_sessions "lc-idle: closed connections leave both endpoints" ""
delete_rule $VIP > /dev/null
sleep 1

fi

# ---------------------------------------------------------------------------
# Arm G: a rule that already exists is applied again while it has connections:
# the identical rule, the rule with another connectionLimit, the rule with one
# endpoint more and with that endpoint removed again. None of these is a new
# rule, so the live count, the per-endpoint sessions and the cumulative
# statistics stay as they are, and the limit goes on counting the connections
# that were open before.
# ---------------------------------------------------------------------------
if [[ " $ARMS " == *" G "* ]]; then
echo "  -- Arm G: rule applied again under live connections"
VIP=20.20.20.9
EP3=31.31.31.2
code=$(post_lc_rule $VIP 3 60 $EP $EP2)
[[ "$code" == "200" ]] && result "re-apply: least-connections rule, connectionLimit 3" "OK" || result "re-apply: least-connections rule, connectionLimit 3" "FAILED" "HTTP $code"
sleep 2
hold l3h1 $VIP 1 0 > /dev/null
expect_counted "re-apply: one connection opened and closed" 0
hold l3h1 $VIP 2 120 > /dev/null
expect_counted "re-apply: two connections held" 2
before=$(counts)
if [[ "$before" =~ ^conc=2\ total=3\ in=[1-9][0-9]*\ out=[1-9][0-9]*\ sess=1,1$ ]]; then
  result "re-apply: counters before" "OK" "$before"
else
  result "re-apply: counters before" "FAILED" "$before"
fi
same() {   # <label> <want-http> <got-http>
  local now
  sleep 1
  now=$(counts)
  if [[ "$3" == "$2" && "$now" == "$before" ]]; then
    result "$1" "OK" "HTTP $3, counters unchanged"
  else
    result "$1" "FAILED" "HTTP $3 (want $2), counters $now"
  fi
}
same "re-apply: identical rule posted again" 409 "$(post_lc_rule $VIP 3 60 $EP $EP2)"
same "re-apply: connectionLimit changed in place" 200 "$(post_lc_rule $VIP 5 60 $EP $EP2)"
same "re-apply: endpoint attached" 200 "$(post_lc_rule $VIP 5 60 $EP $EP2 $EP3)"
same "re-apply: endpoint detached" 200 "$(post_lc_rule $VIP 5 60 $EP $EP2)"
same "re-apply: connectionLimit changed back" 200 "$(post_lc_rule $VIP 3 60 $EP $EP2)"
rest=$(hold l3h2 $VIP 2 120)
if [[ "$(attempts "$rest" connected)" == "1" && "$(attempts "$rest" timeout)" == "1" ]]; then
  result "re-apply: the limit still counts the two held connections" "OK" "one more admitted, the next SYN dropped"
else
  result "re-apply: the limit still counts the two held connections" "FAILED" "$(tr '\n' ' ' < "$rest")"
fi
release
expect_counted "re-apply: closed connections give their slots back" 0
delete_rule $VIP > /dev/null
sleep 1
fi

# ---------------------------------------------------------------------------
# Arm H: a per-endpoint session count is made wrong from outside while two
# connections are open on each endpoint. The gateway compares the counts of a
# least-connections rule with the connections that exist after every ageing
# run and corrects them, says so in its datapath log and counts the
# correction. With the count left wrong, the next connections would all go to
# the other endpoint.
# ---------------------------------------------------------------------------
if [[ " $ARMS " == *" H "* ]]; then
echo "  -- Arm H: a wrong per-endpoint session count is corrected"
VIP=20.20.20.10
WRONG=9
fails_before=$FAILS
code=$(post_lc_rule $VIP 0 240 $EP $EP2)
[[ "$code" == "200" ]] && result "lc-inject: least-connections rule created" "OK" || result "lc-inject: least-connections rule created" "FAILED" "HTTP $code"
sleep 2
hold l3h1 $VIP 4 300 > /dev/null
expect_sessions "lc-inject: two sessions counted on each endpoint" "2,2"
reported=$(corrections)
args=$($dexec llb1 bpftool map dump name nat_ep_map -j | python3 ./inject_sessions.py 0 2 "$WRONG")
if [[ -n "$args" ]] && $dexec llb1 bpftool map update name nat_ep_map $args; then
  got=$(sessions)
  [[ "$got" == "$WRONG,2" ]] && result "lc-inject: first endpoint's count overwritten with $WRONG" "OK" || result "lc-inject: first endpoint's count overwritten with $WRONG" "FAILED" "sessions [$got]"
else
  result "lc-inject: first endpoint's count overwritten with $WRONG" "FAILED" "could not rewrite the entry"
fi
got=""
for _ in $(seq 1 90); do
  got=$(sessions)
  [[ "$got" == "2,2" ]] && break
  sleep 1
done
[[ "$got" == "2,2" ]] && result "lc-inject: count corrected to the open connections" "OK" "sessions [$got]" || result "lc-inject: count corrected to the open connections" "FAILED" "sessions [$got] after 90 s, want [2,2]"
logged=$($dexec llb1 grep -c "endpoint 0: session count corrected $WRONG -> 2" /var/log/loxilbdp.log)
[[ "$logged" == "1" ]] && result "lc-inject: the correction is logged once" "OK" || result "lc-inject: the correction is logged once" "FAILED" "$logged log lines"
now=$(corrections)
[[ "$reported" =~ ^[0-9]+$ && "$now" == "$((reported + 1))" ]] && result "lc-inject: the correction is reported as a metric" "OK" "$reported -> $now" || result "lc-inject: the correction is reported as a metric" "FAILED" "metric reads '$reported' before, '$now' after"
b1=$(established l3ep1); b2=$(established l3ep2)
hold l3h2 $VIP 2 120 > /dev/null
n1=$(( $(established l3ep1) - b1 )); n2=$(( $(established l3ep2) - b2 ))
[[ "$n1" == "1" && "$n2" == "1" ]] && result "lc-inject: two new connections are spread one and one" "OK" || result "lc-inject: two new connections are spread one and one" "FAILED" "$n1 on the first endpoint, $n2 on the second"
release
expect_sessions "lc-inject: closed connections leave both endpoints" ""
expect_counted "lc-inject: closed connections give their slots back" 0
delete_rule $VIP > /dev/null
[[ "$FAILS" -gt "$fails_before" ]] && correction_log
sleep 1
fi

# ---------------------------------------------------------------------------
# Arm I: a least-connections rule at its connectionLimit refuses SYNs. A
# refused SYN is not a connection: it takes no per-endpoint session, so when
# the limit is raised the next connections are still spread evenly.
# ---------------------------------------------------------------------------
if [[ " $ARMS " == *" I "* ]]; then
echo "  -- Arm I: refused SYNs take no per-endpoint session"
VIP=20.20.20.11
code=$(post_lc_rule $VIP 2 240 $EP $EP2)
[[ "$code" == "200" ]] && result "lc-refuse: least-connections rule, connectionLimit 2" "OK" || result "lc-refuse: least-connections rule, connectionLimit 2" "FAILED" "HTTP $code"
sleep 2
hold l3h1 $VIP 2 300 > /dev/null
expect_sessions "lc-refuse: one session counted on each endpoint" "1,1"
refused=$(hold l3h2 $VIP 3 0)
[[ "$(attempts "$refused" timeout)" == "3" ]] && result "lc-refuse: three more SYNs dropped by the limit" "OK" || result "lc-refuse: three more SYNs dropped by the limit" "FAILED" "$(tr '\n' ' ' < "$refused")"
got=$(sessions)
[[ "$got" == "1,1" ]] && result "lc-refuse: refused SYNs took no session" "OK" "sessions [$got]" || result "lc-refuse: refused SYNs took no session" "FAILED" "sessions [$got], want [1,1]"
code=$(post_lc_rule $VIP 6 240 $EP $EP2)
[[ "$code" == "200" ]] && result "lc-refuse: connectionLimit raised to 6 in place" "OK" || result "lc-refuse: connectionLimit raised to 6 in place" "FAILED" "HTTP $code"
sleep 1
b1=$(established l3ep1); b2=$(established l3ep2)
hold l3h2 $VIP 4 120 > /dev/null
n1=$(( $(established l3ep1) - b1 )); n2=$(( $(established l3ep2) - b2 ))
[[ "$n1" == "2" && "$n2" == "2" ]] && result "lc-refuse: four new connections are spread two and two" "OK" || result "lc-refuse: four new connections are spread two and two" "FAILED" "$n1 on the first endpoint, $n2 on the second"
expect_sessions "lc-refuse: three sessions counted on each endpoint" "3,3"
release
expect_sessions "lc-refuse: closed connections leave both endpoints" ""
delete_rule $VIP > /dev/null
fi

# A correction means some path lost count. Only the ones arms E and H
# provoked may appear in the datapath log, one line each.
want=0
[[ " $ARMS " == *" E "* ]] && want=$((want + 1))
[[ " $ARMS " == *" H "* ]] && want=$((want + 1))
logged=$($dexec llb1 grep -c "count corrected" /var/log/loxilbdp.log)
if [[ "$logged" == "$want" ]]; then
  result "no counter correction except the provoked ones" "OK" "$logged logged"
else
  result "no counter correction except the provoked ones" "FAILED" "$logged logged, want $want"
  correction_log
fi

echo
if [[ "$FAILS" -eq 0 ]]; then
  echo "$SCENARIO [OK]"
  exit 0
fi
echo "$SCENARIO [FAILED] ($FAILS check(s) failed)"
exit 1
