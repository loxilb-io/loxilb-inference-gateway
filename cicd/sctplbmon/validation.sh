#!/bin/bash
source ../common.sh
echo SCENARIO-sctplbmon
servArr=( "server1" "server2" "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )

$hexec l3ep1 ../common/sctp_server ${ep[0]} 8080 server1 >/dev/null 2>&1 &
$hexec l3ep2 ../common/sctp_server ${ep[1]} 8080 server2 >/dev/null 2>&1 &
$hexec l3ep3 ../common/sctp_server ${ep[2]} 8080 server3 >/dev/null 2>&1 &

sleep 15
code=0
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
            echo SCENARIO-sctplbmon [FAILED]
            sudo killall -9 sctp_server 2>&1 > /dev/null
            exit 1
        fi
    fi
    sleep 1
done

# Warm up the VIP - wait until health monitor confirms all 3 backends active
declare -A warmup_seen
warmupCount=0
while [[ ${#warmup_seen[@]} -lt 3 ]]; do
    res=$($hexec l3h1 timeout 10 ../common/sctp_client 10.10.10.1 0 20.20.20.1 2020)
    if [[ $res == *"server"* ]]; then
        warmup_seen[$res]=1
        echo "VIP warmup: $res (${#warmup_seen[@]}/3 backends seen)"
    fi
    warmupCount=$(( $warmupCount + 1 ))
    if [[ $warmupCount -ge 30 ]]; then
        echo "VIP health monitor not ready (only ${#warmup_seen[@]}/3 backends active)"
        echo SCENARIO-sctplbmon [FAILED]
        sudo killall -9 sctp_server 2>&1 > /dev/null
        exit 1
    fi
    sleep 3
done
unset warmup_seen
echo "All 3 backends confirmed active via VIP"

declare -A serverCount
serverCount["server1"]=0
serverCount["server2"]=0
serverCount["server3"]=0

for i in {1..12}
do
    res=$($hexec l3h1 timeout 10 ../common/sctp_client 10.10.10.1 0 20.20.20.1 2020)
    echo -e $res
    if [[ $res == "server1" ]] || [[ $res == "server2" ]] || [[ $res == "server3" ]]
    then
        serverCount[$res]=$(( ${serverCount[$res]} + 1 ))
    else
        echo "Unexpected response: $res"
        code=1
    fi
    sleep 1
done

echo "Distribution: server1=${serverCount[server1]}, server2=${serverCount[server2]}, server3=${serverCount[server3]}"

if [[ ${serverCount[server1]} -eq 0 ]] || [[ ${serverCount[server2]} -eq 0 ]] || [[ ${serverCount[server3]} -eq 0 ]]
then
    echo "Some servers received no requests"
    code=1
fi

if [[ ${serverCount[server1]} -lt 2 ]] || [[ ${serverCount[server2]} -lt 2 ]] || [[ ${serverCount[server3]} -lt 2 ]]
then
    echo "Load distribution is too unbalanced"
    code=1
fi

if [[ $code == 0 ]]
then
    echo SCENARIO-sctplbmon p1 [OK]
else
    echo SCENARIO-sctplbmon p1 [FAILED]
    sudo killall -9 sctp_server 2>&1 > /dev/null
    exit $code
fi

$hexec l3ep1 ip addr del 31.31.31.1/24 dev el3ep1llb1
echo "Waiting 140s...."
sleep 140
$dexec llb1 loxicmd get ep

for j in {0..5}
do
    res=$($hexec l3h1 timeout 10 ../common/sctp_client 10.10.10.1 0 20.20.20.1 2020)
    if [[ $res == "server1" ]] && [[ "empty"$res == "empty" ]]
    then
        code=1
    fi
    sleep 1
done

if [[ $code == 0 ]]
then
    echo SCENARIO-sctplbmon p2 [OK]
else
    echo SCENARIO-sctplbmon p2 [FAILED]
    sudo killall -9 node 2>&1 > /dev/null
    exit $code
fi

$hexec l3ep1 ip addr add 31.31.31.1/24 dev el3ep1llb1
$hexec l3ep1 ip route add default via 31.31.31.254
sudo killall -9 sctp_server 2>&1 > /dev/null
$hexec l3ep1 ../common/sctp_server ${ep[0]} 8080 server1 >/dev/null 2>&1 &
$hexec l3ep2 ../common/sctp_server ${ep[1]} 8080 server2 >/dev/null 2>&1 &
$hexec l3ep3 ../common/sctp_server ${ep[2]} 8080 server3 >/dev/null 2>&1 &
sleep 30
$dexec llb1 loxicmd get ep

serverCount["server1"]=0
serverCount["server2"]=0
serverCount["server3"]=0

for i in {1..12}
do
    res=$($hexec l3h1 timeout 10 ../common/sctp_client 10.10.10.1 0 20.20.20.1 2020)
    echo -e $res
    if [[ $res == "server1" ]] || [[ $res == "server2" ]] || [[ $res == "server3" ]]
    then
        serverCount[$res]=$(( ${serverCount[$res]} + 1 ))
    else
        echo "Unexpected response: $res"
        code=1
    fi
    sleep 1
done

echo "Distribution: server1=${serverCount[server1]}, server2=${serverCount[server2]}, server3=${serverCount[server3]}"

if [[ ${serverCount[server1]} -eq 0 ]] || [[ ${serverCount[server2]} -eq 0 ]] || [[ ${serverCount[server3]} -eq 0 ]]
then
    echo "Some servers received no requests"
    code=1
fi

if [[ ${serverCount[server1]} -lt 2 ]] || [[ ${serverCount[server2]} -lt 2 ]] || [[ ${serverCount[server3]} -lt 2 ]]
then
    echo "Load distribution is too unbalanced"
    code=1
fi

if [[ $code == 0 ]]
then
    echo SCENARIO-sctplbmon p3 [OK]
else
    echo SCENARIO-sctplbmon p3 [FAILED]
fi

sudo killall -9 sctp_server 2>&1 > /dev/null
exit $code
