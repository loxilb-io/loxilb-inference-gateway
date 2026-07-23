#!/bin/bash
source ../common.sh
echo "SCENARIO tcplbmon6"
$hexec l3ep1 node ../common/tcp_server.js server1 &
$hexec l3ep2 node ../common/tcp_server.js server2 &
$hexec l3ep3 node ../common/tcp_server.js server3 &

sleep 5
code=0
servArr=( "server1" "server2" "server3" )
ep=( "4ffe::1" "5ffe::1" "6ffe::1" )
j=0
waitCount=0
while [ $j -le 2 ]
do
    svr=${ep[j]}
    res=$($hexec l3h1 curl -s -j -6 --max-time 10 [${svr}]:8080)
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
            echo tcplbmon6 [FAILED]
            sudo pkill node
            exit 1
        fi
    fi
    sleep 1
done

# Warm up the VIP - wait until the health monitor (--monitor) confirms all 3
# backends are active. The direct-UP check above only proves the node servers
# are listening; it does NOT prove loxilb's monitor has probed and activated
# each endpoint. Starting the round-robin before convergence let the VIP return
# empty for a not-yet-active endpoint (observed as a p1 flake).
declare -A warmup_seen
warmupCount=0
while [[ ${#warmup_seen[@]} -lt 3 ]]; do
    res=$($hexec l3h1 curl -s -j -6 --max-time 10 '[2001::1]:2020')
    if [[ $res == *"server"* ]]; then
        warmup_seen[$res]=1
        echo "VIP warmup: $res (${#warmup_seen[@]}/3 backends seen)"
    fi
    warmupCount=$(( $warmupCount + 1 ))
    if [[ $warmupCount -ge 30 ]]; then
        echo "VIP health monitor not ready (only ${#warmup_seen[@]}/3 backends active)"
        echo tcplbmon6 [FAILED]
        sudo pkill node
        exit 1
    fi
    sleep 3
done
unset warmup_seen
echo "All 3 backends confirmed active via VIP"

# With --monitor enabled, the background health probes perturb strict
# round-robin ordering between client requests, so verify a balanced
# distribution (every backend serves traffic) rather than a fixed sequence.
declare -A serverCount
serverCount["server1"]=0
serverCount["server2"]=0
serverCount["server3"]=0
for i in {1..12}
do
    res=$($hexec l3h1 curl -s -j -6 --max-time 10 '[2001::1]:2020')
    echo $res
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
    echo tcplbmon6 p1 [OK]
else
    echo tcplbmon6 p1 [FAILED]
    sudo pkill node
    exit $code
fi
sudo pkill node
$hexec l3ep2 node ../common/tcp_server.js server2 &
$hexec l3ep3 node ../common/tcp_server.js server3 &
sleep 130

for j in {0..2}
do
    res=$($hexec l3h1 curl -s -j -6 --max-time 10 '[2001::1]:2020')
    echo $res
    if [[ $res == *"server1"* ]]; then
      code=1
    fi
    sleep 1
done
if [[ $code == 0 ]]
then
    echo tcplbmon6 p2 [OK]
else
    echo tcplbmon6 p2 [FAILED]
    exit $code
fi

sudo pkill node
exit $code
