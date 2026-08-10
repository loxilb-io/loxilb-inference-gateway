#!/bin/bash
source ../common.sh
echo SCENARIO-sctplb-lc

servArr=( "server1" "server2" "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )
vip="20.20.20.1"
sport=2020
# Seconds to let a short-lived SCTP association drain from conntrack before the
# next least-conn decision. Overridable for slow runners: SETTLE=3 ./validation.sh
SETTLE=${SETTLE:-2}

# --- start backends ---
$hexec l3ep1 ../common/sctp_server ${ep[0]} 8080 server1 >/dev/null 2>&1 &
$hexec l3ep2 ../common/sctp_server ${ep[1]} 8080 server2 >/dev/null 2>&1 &
$hexec l3ep3 ../common/sctp_server ${ep[2]} 8080 server3 >/dev/null 2>&1 &

sleep 5
code=0

# probe(): one short-lived SCTP request to the VIP; prints the backend id it hit.
probe() {
    $hexec l3h1 timeout 10 ../common/sctp_client 10.10.10.1 0 $vip $sport
}

# --- wait for backends to be reachable directly ---
j=0
waitCount=0
while [ $j -le 2 ]
do
    res=$($hexec l3h1 timeout 10 ../common/sctp_client 10.10.10.1 0 ${ep[j]} 8080)
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
            echo SCENARIO-sctplb-lc [FAILED]
            sudo pkill sctp_server >/dev/null 2>&1
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
    echo "  [fail] no response from VIP $vip"
    code=1
fi
sleep $SETTLE

# -- (authoritative): hold ONE long-lived, ACTIVE connection (1 pps so
# loxilb keeps its conntrack/least-conn count fresh -- an idle hold gets aged out
# of the active count and defeats the test). Whatever endpoint it lands on now
# carries the most active connections, so under least-conn EVERY new connection
# must AVOID that endpoint. This invariant does not depend on endpoint ordering
# or hard-coded backend names. The 1pps hold runs long enough to outlast every
# probe below. ---
echo -e "\nHolding an active connection at"
heldOut=$(mktemp)
$hexec l3h1 ../common/sctp_client 10.10.10.1 0 $vip $sport 0 40 >"$heldOut" 2>/dev/null &
heldPid=$!
sleep 2
heldEp=$(head -n1 "$heldOut" | tr -d '[:space:]')
echo "$heldEp"
if [[ -z "$heldEp" ]]; then
    echo "  [fail] could not determine held endpoint"
    code=1
fi

echo -e "\n\nTesting Service IP: $vip  (least-conn must avoid held endpoint '$heldEp')"
for i in {1..2}
do
for j in {0..2}
do
    res=$(probe)
    echo -e "$res"
    if [[ -n "$heldEp" && "$res" == "$heldEp" ]]
    then
        echo "  [fail] new connection landed on held (most-loaded) endpoint '$heldEp'"
        code=1
    fi
    sleep $SETTLE
done
done

# --- cleanup ---
kill $heldPid >/dev/null 2>&1
sudo pkill sctp_server >/dev/null 2>&1
sudo killall -9 sctp_client >/dev/null 2>&1
sudo killall -9 ncat >/dev/null 2>&1
rm -f "$heldOut" nohup.out >/dev/null 2>&1

if [[ $code == 0 ]]
then
    echo SCENARIO-sctplb-lc [OK]
else
    echo SCENARIO-sctplb-lc [FAILED]
fi
exit $code
