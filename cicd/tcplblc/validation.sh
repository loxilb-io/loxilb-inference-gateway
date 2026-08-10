#!/bin/bash
source ../common.sh
echo SCENARIO-tcplb-lc
$hexec l3ep1 node ../common/tcp_server.js server1 &
$hexec l3ep2 node ../common/tcp_server.js server2 &
$hexec l3ep3 node ../common/tcp_server.js server3 &

sleep 5
code=0
servIP="20.20.20.1"
servArr=( "server1" "server2" "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )
# Seconds to let a short-lived probe drain before the next least-conn decision.
# Overridable for slow runners: SETTLE=3 ./validation.sh
SETTLE=${SETTLE:-2}
holdPids=()

# probe(): one short-lived HTTP request to the VIP; prints the backend id it hit.
probe() { $hexec l3h1 curl --max-time 10 -s ${servIP}:2020; }

# add_hold(): open a long-lived idle TCP connection to the VIP (held open by the
# backend's http server). least-conn routes it to the currently least-loaded
# endpoint. TCP established conntrack has a long timeout, so the hold stays
# counted for the whole test.
add_hold() {
    $hexec l3h1 nohup nc -d ${servIP} 2020 >/dev/null 2>&1 &
    holdPids+=( $! )
}

# --- wait for backends to be reachable directly ---
j=0
waitCount=0
while [ $j -le 2 ]
do
    res=$($hexec l3h1 curl --max-time 10 -s ${ep[j]}:8080)
    if [[ $res == "${servArr[j]}" ]]
    then
        echo "$res UP"
        j=$(( $j + 1 ))
    else
        echo "Waiting for ${servArr[j]}(${ep[j]})"
        waitCount=$(( $waitCount + 1 ))
        if [[ $waitCount == 10 ]];
        then
            echo "All Servers are not UP"
            echo SCENARIO-tcplb-lc [FAILED]
            sudo killall -9 node 2>&1 > /dev/null
            exit 1
        fi
    fi
    sleep 1
done

# -- (informational): on a fully idle fleet, least-conn tie-breaks
# deterministically to the same endpoint every time. Reported but NOT fatal. ---
echo -e "\nPhase 1: idle-fleet stability (informational)"
idleEp=""
for i in {1..3}
do
    res=$(probe)
    echo -e "$res"
    [ -z "$idleEp" ] && idleEp="$res"
    if [[ "$res" != "$idleEp" ]]; then
        echo "  [warn] idle pick not stable (got $res, first was $idleEp)"
    fi
    sleep $SETTLE
done
if [[ -z "$idleEp" ]]; then
    echo "  [fail] no response from VIP $servIP"
    code=1
fi

# -- (authoritative): build a load gradient one hold at a time and
# verify least-conn at every step. Each hold lands on whatever endpoint the
# preceding probe reported as least-loaded, so we can track the exact active
# count per endpoint and assert that every NEW connection is routed to a
# genuinely minimum-loaded endpoint. No hard-coded backend names, no assumption
# about how the holds happen to distribute. ---
echo -e "\nPhase 2: least-conn load-gradient (authoritative)"
declare -A load
for e in "${servArr[@]}"; do load[$e]=0; done

# helper: is $1 one of the known backends?
known() { for e in "${servArr[@]}"; do [ "$e" == "$1" ] && return 0; done; return 1; }

least=$(probe)                      # current least-loaded endpoint (idle => first)
if ! known "$least"; then
    echo "  [fail] unexpected VIP response '$least'"
    code=1
fi

STEPS=5
for step in $(seq 1 $STEPS)
do
    add_hold                        # least-conn routes this hold to $least
    load[$least]=$(( load[$least] + 1 ))
    sleep $SETTLE                   # let the handshake settle / probe drain

    newLeast=$(probe)               # where does a fresh connection go now?
    if ! known "$newLeast"; then
        echo "  [fail] unexpected VIP response '$newLeast'"
        code=1
        break
    fi

    # compute the true minimum active count across endpoints
    minv=999999
    for e in "${servArr[@]}"; do
        (( ${load[$e]} < minv )) && minv=${load[$e]}
    done

    printf "  step %d: holds{%s=%d %s=%d %s=%d} -> new conn hit %s\n" \
        "$step" \
        "${servArr[0]}" "${load[${servArr[0]}]}" \
        "${servArr[1]}" "${load[${servArr[1]}]}" \
        "${servArr[2]}" "${load[${servArr[2]}]}" \
        "$newLeast"

    if (( ${load[$newLeast]} != minv )); then
        echo "  [fail] least-conn routed to '$newLeast' (load ${load[$newLeast]}) but min load is $minv"
        code=1
    fi
    least=$newLeast
    sleep $SETTLE
done

# --- cleanup ---
for p in "${holdPids[@]}"; do kill $p >/dev/null 2>&1; done
sudo killall -9 nc 2>&1 > /dev/null
sudo killall -9 node 2>&1 > /dev/null
rm -f nohup.out

if [[ $code == 0 ]]
then
    echo SCENARIO-tcplb-lc with least-connection [OK]
else
    echo SCENARIO-tcplb-lc with least-connection [FAILED]
fi
exit $code
