#!/bin/bash
source ../common.sh
echo SCENARIO-e2ehttpsproxy

servArr=( "server1" "server2" "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )
code=0
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
        exp="${servArr[j]}"
        if [[ "$srv" == "$exp" ]] || [[ "$srv" == "$exp:"* ]]
        then
            echo "${exp} UP" >&2
            j=$(( $j + 1 ))
        else
            echo "Waiting for ${servArr[j]}(${ep[j]})" >&2
            waitCount=$(( $waitCount + 1 ))
            if [[ $waitCount == 10 ]];
            then
                echo "All Servers are not UP" >&2
                echo SCENARIO-e2ehttpsproxy [FAILED] >&2
                $hexec l3ep1 killall -9 server > /dev/null 2>&1
                $hexec l3ep2 killall -9 server > /dev/null 2>&1
                $hexec l3ep3 killall -9 server > /dev/null 2>&1
                echo 1
                return
            fi
        fi
        sleep 1
    done

    # Count responses from each backend to verify load distribution
    declare -A backend_count
    backend_count["server1"]=0
    backend_count["server2"]=0
    backend_count["server3"]=0
    total_requests=12

    for i in $(seq 1 $total_requests)
    do
        res=$($hexec l3h1 ../common/http2/https-client/client -key 10.10.10.1/key.pem --cert 10.10.10.1/cert.pem --cacert minica.pem -host 10.10.10.254:2021)
        res=$(echo "$res" | xargs)
        echo "$res" >&2
        srv=${res#HTTP/2.0:}
        if [[ $srv == "server1" ]] || [[ $srv == "server2" ]] || [[ $srv == "server3" ]]; then
            backend_count[$srv]=$((backend_count[$srv] + 1))
        else
            echo "Unexpected response: $res" >&2
            code=1
        fi
        sleep 1
    done

    # Verify all backends received at least one request
    echo "Load distribution: server1=${backend_count["server1"]}, server2=${backend_count["server2"]}, server3=${backend_count["server3"]}" >&2
    if [[ ${backend_count["server1"]} -eq 0 ]] || [[ ${backend_count["server2"]} -eq 0 ]] || [[ ${backend_count["server3"]} -eq 0 ]]; then
        echo "Load balancing failed: not all backends received requests" >&2
        code=1
    fi

    $hexec l3ep1 killall -9 server > /dev/null 2>&1
    $hexec l3ep2 killall -9 server > /dev/null 2>&1
    $hexec l3ep3 killall -9 server > /dev/null 2>&1
    echo $code
}

code=$(health)
if [[ $code == 0 ]]
then
    echo SCENARIO-e2ehttpsproxy p1 [OK]
else
    echo SCENARIO-e2ehttpsproxy p1 [FAILED]
    exit $code
fi

sleep 2

code=$(health "strict")
if [[ $code == 0 ]]
then
    echo SCENARIO-e2ehttpsproxy p2 [OK]
else
    echo SCENARIO-e2ehttpsproxy p2 [FAILED]
    exit $code
fi

exit $code

