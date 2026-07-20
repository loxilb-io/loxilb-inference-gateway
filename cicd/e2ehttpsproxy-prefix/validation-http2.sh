#!/bin/bash
source ../common.sh
echo SCENARIO-e2ehttpsproxy-prefix

code=0
servIP=( "10.10.10.254" )
servArrUsers=( "server1" "server2" )
servArrOrders=( "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )
j=0
waitCount=0

function health() {
    if [ "$1" == "strict" ]; then
        opt="-strict"
        echo "HTTP2 with strict TLS probing" >&2
    else
        echo "HTTP2 with TLS probing" >&2
    fi

    $hexec l3ep1 ../common/http2/https-server/server -host server1 -key 31.31.31.1/key.pem -cert 31.31.31.1/cert.pem -cacert minica.pem -port 8081 $opt > /dev/null 2>&1 &
    $hexec l3ep2 ../common/http2/https-server/server -host server2 -key 32.32.32.1/key.pem -cert 32.32.32.1/cert.pem -cacert minica.pem -port 8081 $opt > /dev/null 2>&1 &
    $hexec l3ep3 ../common/http2/https-server/server -host server3 -key 33.33.33.1/key.pem -cert 33.33.33.1/cert.pem -cacert minica.pem -port 8081 $opt > /dev/null 2>&1 &

    sleep 10
    code=0
    j=0
    waitCount=0
    while [ $j -le 2 ]
    do
        res=$($hexec l3h1 ../common/http2/https-client/client -key 10.10.10.1/key.pem --cert 10.10.10.1/cert.pem --cacert minica.pem -host ${ep[j]}:8081)
        res=$(echo "$res" | xargs)
        srv=${res#HTTP/2.0:}
        exp="server$((j+1))"
        if [[ "$srv" == "$exp" ]] || [[ "$srv" == "$exp:"* ]]
        then
            echo "${exp} UP" >&2
            j=$(( $j + 1 ))
        else
            echo "Waiting for server$((j+1))(${ep[j]})" >&2
            waitCount=$(( $waitCount + 1 ))
            if [[ $waitCount == 10 ]];
            then
                echo "All Servers are not UP" >&2
                echo SCENARIO-e2ehttpsproxy-prefix [FAILED] >&2
                $hexec l3ep1 killall -9 server > /dev/null 2>&1
                $hexec l3ep2 killall -9 server > /dev/null 2>&1
                $hexec l3ep3 killall -9 server > /dev/null 2>&1
                echo 1
                return
            fi
        fi
        sleep 1
    done

    # Count responses for /v1/users to verify load distribution across server1 and server2
    echo "Testing path: /v1/users" >&2
    declare -A users_count
    users_count["server1"]=0
    users_count["server2"]=0
    users_total=8

    for i in $(seq 1 $users_total)
    do
        res=$($hexec l3h1 ../common/http2/https-client/client -key 10.10.10.1/key.pem --cert 10.10.10.1/cert.pem --cacert minica.pem -host 10.10.10.254:2021/v1/users)
        res=$(echo "$res" | xargs)
        echo "$res" >&2
        srv=${res#HTTP/2.0:}
        srv=${srv%%:*}
        if [[ $srv == "server1" ]] || [[ $srv == "server2" ]]; then
            users_count[$srv]=$((users_count[$srv] + 1))
        else
            echo "Unexpected response for /v1/users: $res" >&2
            code=1
        fi
        sleep 1
    done

    echo "Load distribution /v1/users: server1=${users_count["server1"]}, server2=${users_count["server2"]}" >&2
    if [[ ${users_count["server1"]} -eq 0 ]] || [[ ${users_count["server2"]} -eq 0 ]]; then
        echo "Load balancing failed for /v1/users: not all backends received requests" >&2
        code=1
    fi

    # Verify /v1/orders always routes to server3
    echo "Testing path: /v1/orders" >&2
    orders_ok=0
    orders_total=4

    for i in $(seq 1 $orders_total)
    do
        res=$($hexec l3h1 ../common/http2/https-client/client -key 10.10.10.1/key.pem --cert 10.10.10.1/cert.pem --cacert minica.pem -host 10.10.10.254:2021/v1/orders)
        res=$(echo "$res" | xargs)
        echo "$res" >&2
        srv=${res#HTTP/2.0:}
        srv=${srv%%:*}
        if [[ $srv == "server3" ]]; then
            orders_ok=$((orders_ok + 1))
        else
            echo "Unexpected response for /v1/orders: $res" >&2
            code=1
        fi
        sleep 1
    done

    echo "Load distribution /v1/orders: server3=${orders_ok}/${orders_total}" >&2

    $hexec l3ep1 killall -9 server > /dev/null 2>&1
    $hexec l3ep2 killall -9 server > /dev/null 2>&1
    $hexec l3ep3 killall -9 server > /dev/null 2>&1
    echo $code
}

code=$(health)
if [[ $code == 0 ]]
then
    echo SCENARIO-e2ehttpsproxy-prefix p1 [OK]
else
    echo SCENARIO-e2ehttpsproxy-prefix p1 [FAILED]
    exit $code
fi

sleep 2

code=$(health "strict")
if [[ $code == 0 ]]
then
    echo SCENARIO-e2ehttpsproxy-prefix p2 [OK]
else
    echo SCENARIO-e2ehttpsproxy-prefix p2 [FAILED]
    exit $code
fi

exit $code

