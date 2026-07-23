#!/bin/bash
# tcplbmon-epstat
#
# Regression test for a user-escalated bug: when the liveness monitor flips one
# endpoint's state, loxilb re-programs the whole LB rule in place. The pre-fix
# data plane cleared the byte/packet counters of EVERY endpoint slot on that
# re-add, so the still-healthy endpoints' per-endpoint stats were reset on every
# health flap. Because the control plane caches the last reading, the reset only
# surfaces once fresh traffic forces a re-read: the counter then REGRESSES below
# its pre-flap value instead of continuing to climb.
#
# Fix: loxilb-ebpf llb_add_map_elem preserves a slot's counters when its
# endpoint identity (ip+port+family) is unchanged, clearing only genuinely
# re-pointed slots; llb_del_map_elem_wval retires them on delete.
#
# Signal: drive a large baseline, flap ep1, drive a small amount of extra
# traffic, then require the healthy endpoints' counters to have GROWN past the
# baseline (monotonic). Pre-fix binaries regress below the baseline -> FAILED;
# fixed binaries keep climbing -> OK.

source ../common.sh
echo SCENARIO-tcplbmon-epstat

# packets counter (first field of the "packets:bytes" COUNTERS column) for an EP
epc() {
    local c
    c=$($dexec llb1 loxicmd get lb -o wide 2>/dev/null | grep "$1" | grep -oE '[0-9]+:[0-9]+' | head -1 | cut -d: -f1)
    [[ -z "$c" ]] && c=0
    echo "$c"
}

# host-probe state (ok / nok) of an endpoint from `loxicmd get ep`
# ('nok|ok' order matters so "nok" is not truncated to "ok")
eps() {
    $dexec llb1 loxicmd get ep 2>/dev/null | grep "$1" | grep -oE 'nok|ok' | tail -1
}

$hexec l3ep1 node ../common/tcp_server.js server1 &
$hexec l3ep2 node ../common/tcp_server.js server2 &
$hexec l3ep3 node ../common/tcp_server.js server3 &

sleep 15
code=0
servArr=( "server1" "server2" "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )
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
            sudo killall -9 node 2>&1 > /dev/null
            echo SCENARIO-tcplbmon-epstat [FAILED]
            exit 1
        fi
    fi
    sleep 1
done

# ---- large baseline so post-flap re-accumulation cannot reach it ----
for i in {1..45}
do
    $hexec l3h1 curl --max-time 10 -s 20.20.20.1:2020 > /dev/null
done

# healthy endpoints we assert on across the flap (ep2, ep3 stay UP throughout)
P2a=$(epc 32.32.32.1)
P3a=$(epc 33.33.33.1)
echo "healthy-EP packet counters before flap: ep2=$P2a ep3=$P3a"
$dexec llb1 loxicmd get lb -o wide

if [[ $P2a -le 0 || $P3a -le 0 ]]
then
    echo "no baseline traffic recorded on healthy endpoints"
    sudo killall -9 node 2>&1 > /dev/null
    echo SCENARIO-tcplbmon-epstat [FAILED]
    exit 1
fi

# ---- flap: take ep1 down and wait for the monitor to mark it nok ----
# (this is the in-place rule re-add that pre-fix code used to reset stats)
$hexec l3ep1 ip addr del 31.31.31.1/24 dev el3ep1llb1
echo "ep1 down; waiting for liveness monitor to mark it nok..."
downOk=0
for i in {1..90}
do
    if [[ $(eps 31.31.31.1) == "nok" ]]
    then
        echo "ep1 marked nok after ~$(( i * 2 ))s"
        downOk=1
        break
    fi
    sleep 2
done
if [[ $downOk -eq 0 ]]
then
    echo "liveness monitor never marked ep1 down"
    sudo killall -9 node 2>&1 > /dev/null
    echo SCENARIO-tcplbmon-epstat [FAILED]
    exit 1
fi

# ---- functional: dead ep1 drained; this traffic also forces a fresh stat read ----
seen1=0; seen23=0
for i in {1..12}
do
    res=$($hexec l3h1 curl --max-time 10 -s 20.20.20.1:2020)
    echo $res
    [[ $res == "server1" ]] && seen1=1
    { [[ $res == "server2" ]] || [[ $res == "server3" ]]; } && seen23=1
done
if [[ $seen1 -eq 0 && $seen23 -eq 1 ]]
then
    echo "SCENARIO-tcplbmon-epstat p1 (dead ep drained) [OK]"
else
    echo "SCENARIO-tcplbmon-epstat p1 [FAILED] (seen1=$seen1 seen23=$seen23)"
    code=1
fi

# ---- CORE ASSERTION: healthy-EP counters kept climbing (survived the flap) ----
P2b=$(epc 32.32.32.1)
P3b=$(epc 33.33.33.1)
echo "healthy-EP packet counters after flap + traffic: ep2=$P2b ep3=$P3b (baseline ep2=$P2a ep3=$P3a)"
$dexec llb1 loxicmd get lb -o wide

if [[ $P2b -gt $P2a && $P3b -gt $P3a ]]
then
    echo "SCENARIO-tcplbmon-epstat p2 (per-EP stats survived flap) [OK]"
else
    echo "healthy-EP counters regressed across the flap (ep2 $P2a->$P2b, ep3 $P3a->$P3b) -- stats were reset"
    echo SCENARIO-tcplbmon-epstat p2 [FAILED]
    code=1
fi

# ---- failback: restore ep1, confirm counters keep climbing through recovery ----
$hexec l3ep1 ip addr add 31.31.31.1/24 dev el3ep1llb1
$hexec l3ep1 ip route add default via 31.31.31.254
sudo killall -9 node 2>&1 > /dev/null
$hexec l3ep1 node ../common/tcp_server.js server1 &
$hexec l3ep2 node ../common/tcp_server.js server2 &
$hexec l3ep3 node ../common/tcp_server.js server3 &
echo "ep1 restored; waiting for liveness monitor to mark it ok..."
upOk=0
for i in {1..90}
do
    if [[ $(eps 31.31.31.1) == "ok" ]]
    then
        echo "ep1 marked ok after ~$(( i * 2 ))s"
        upOk=1
        break
    fi
    sleep 2
done
for i in {1..12}
do
    $hexec l3h1 curl --max-time 10 -s 20.20.20.1:2020 > /dev/null
done

P2c=$(epc 32.32.32.1)
P3c=$(epc 33.33.33.1)
echo "healthy-EP packet counters after failback + traffic: ep2=$P2c ep3=$P3c"
$dexec llb1 loxicmd get lb -o wide

if [[ $upOk -eq 1 && $P2c -gt $P2b && $P3c -gt $P3b ]]
then
    echo "SCENARIO-tcplbmon-epstat p3 (per-EP stats survived failback) [OK]"
else
    echo "SCENARIO-tcplbmon-epstat p3 [FAILED] (upOk=$upOk ep2 $P2b->$P2c ep3 $P3b->$P3c)"
    code=1
fi

sudo killall -9 node 2>&1 > /dev/null
if [[ $code == 0 ]]
then
    echo SCENARIO-tcplbmon-epstat [OK]
else
    echo SCENARIO-tcplbmon-epstat [FAILED]
fi
exit $code
