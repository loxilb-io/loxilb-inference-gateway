#!/bin/bash
source ../common.sh
echo SCENARIO-http-tcplb

$hexec l3ep1 ../common/http2/http-server/http-server -host server1 -port 8081 $opt > /dev/null 2>&1 &
$hexec l3ep2 ../common/http2/http-server/http-server -host server2 -port 8081 $opt > /dev/null 2>&1 &
$hexec l3ep3 ../common/http2/http-server/http-server -host server3 -port 8081 $opt > /dev/null 2>&1 &

sleep 5
code=0
servIP=( "10.10.10.254" )
servArr=( "server1" "server2" "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )
j=0
waitCount=0
while [ $j -le 2 ]
do
    res=$($hexec l3h1 ../common/http2/http-client/http-client -host ${ep[j]}:8081)
    res=$(echo "$res" | xargs)
    srv=${res#HTTP/2.0:}
    exp="${servArr[j]}"
    if [[ "$srv" == "$exp" ]] || [[ "$srv" == "$exp:"* ]]
    then
        echo "${exp} UP"
        j=$(( $j + 1 ))
    else
        echo "Waiting for ${servArr[j]}(${ep[j]})"
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

# Count responses from each backend to verify load distribution
declare -A backend_count
backend_count["server1"]=0
backend_count["server2"]=0
backend_count["server3"]=0
total_requests=12

for i in $(seq 1 $total_requests)
do
    res=$($hexec l3h1 ../common/http2/https-client/client -key 10.10.10.1/key.pem --cert 10.10.10.1/cert.pem --cacert minica.pem -host ${servIP[k]}:2021)
    res=$(echo "$res" | xargs)
    echo $res

    srv=${res#HTTP/2.0:}
    if [[ $srv == "server1" ]] || [[ $srv == "server2" ]] || [[ $srv == "server3" ]]; then
        backend_count[$srv]=$((backend_count[$srv] + 1))
    else
        echo "Unexpected response: $res"
        lcode=1
    fi
    sleep 1
done

# Verify all backends received at least one request
echo "Load distribution: server1=${backend_count["server1"]}, server2=${backend_count["server2"]}, server3=${backend_count["server3"]}"
if [[ ${backend_count["server1"]} -eq 0 ]] || [[ ${backend_count["server2"]} -eq 0 ]] || [[ ${backend_count["server3"]} -eq 0 ]]; then
    echo "Load balancing failed: not all backends received requests"
    lcode=1
fi

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
