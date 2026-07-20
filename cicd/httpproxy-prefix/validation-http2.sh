#!/bin/bash
source ../common.sh
echo SCENARIO-http-tcplb

$hexec l3ep1 ../common/http2/http-server/http-server -host server1 -port 8081 $opt > /dev/null 2>&1 &
$hexec l3ep2 ../common/http2/http-server/http-server -host server2 -port 8081 $opt > /dev/null 2>&1 &
$hexec l3ep3 ../common/http2/http-server/http-server -host server3 -port 8081 $opt > /dev/null 2>&1 &

sleep 5
code=0
servIP=( "10.10.10.254" )
servArrUsers=( "server1" "server2" )
servArrOrders=( "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )
j=0
waitCount=0
while [ $j -le 2 ]
do
    res=$($hexec l3h1 ../common/http2/http-client/http-client -host ${ep[j]}:8081)
    res=$(echo "$res" | xargs)
    srv=${res#HTTP/2.0:}
    exp="server$((j+1))"
    if [[ "$srv" == "$exp" ]] || [[ "$srv" == "$exp:"* ]]
    then
        echo "${exp} UP"
        j=$(( $j + 1 ))
    else
        echo "Waiting for server$((j+1))(${ep[j]})"
        waitCount=$(( $waitCount + 1 ))
        if [[ $waitCount == 10 ]];
        then
            echo "All Servers are not UP"
            echo SCENARIO-http-tcplb [FAILED]
            $hexec l3ep1 killall -9 http-server > /dev/null 2>&1
            $hexec l3ep2 killall -9 http-server > /dev/null 2>&1
            $hexec l3ep3 killall -9 http-server > /dev/null 2>&1
            exit 1
        fi
    fi
    sleep 1
done

for k in {0..0}
do
echo "Testing Service IP: ${servIP[k]}"
lcode=0

# Count responses for /v1/users to verify load distribution across server1 and server2
echo "Testing path: /v1/users"
declare -A users_count
users_count["server1"]=0
users_count["server2"]=0
users_total=8

for i in $(seq 1 $users_total)
do
    res=$($hexec l3h1 ../common/http2/http-client/http-client -host ${servIP[k]}:2021/v1/users)
    res=$(echo "$res" | xargs)
    echo $res
    srv=${res#HTTP/2.0:}
    srv=${srv%%:*}
    if [[ $srv == "server1" ]] || [[ $srv == "server2" ]]; then
        users_count[$srv]=$((users_count[$srv] + 1))
    else
        echo "Unexpected response for /v1/users: $res"
        lcode=1
    fi
    sleep 1
done

echo "Load distribution /v1/users: server1=${users_count["server1"]}, server2=${users_count["server2"]}"
if [[ ${users_count["server1"]} -eq 0 ]] || [[ ${users_count["server2"]} -eq 0 ]]; then
    echo "Load balancing failed for /v1/users: not all backends received requests"
    lcode=1
fi

# Verify /v1/orders always routes to server3
echo "Testing path: /v1/orders"
orders_ok=0
orders_total=4

for i in $(seq 1 $orders_total)
do
    res=$($hexec l3h1 ../common/http2/http-client/http-client -host ${servIP[k]}:2021/v1/orders)
    res=$(echo "$res" | xargs)
    echo $res
    srv=${res#HTTP/2.0:}
    srv=${srv%%:*}
    if [[ $srv == "server3" ]]; then
        orders_ok=$((orders_ok + 1))
    else
        echo "Unexpected response for /v1/orders: $res"
        lcode=1
    fi
    sleep 1
done

echo "Load distribution /v1/orders: server3=${orders_ok}/${orders_total}"

if [[ $lcode == 0 ]]
then
    echo SCENARIO-http2-tcplb with ${servIP[k]} [OK]
else
    echo SCENARIO-http2-tcplb with ${servIP[k]} [FAILED]
    code=1
fi
done

$hexec l3ep1 killall -9 http-server > /dev/null 2>&1
$hexec l3ep2 killall -9 http-server > /dev/null 2>&1
$hexec l3ep3 killall -9 http-server > /dev/null 2>&1
exit $code
