#!/bin/bash
source ../common.sh
echo SCENARIO-e2ehttps-tcplb
$hexec l3ep1 node ../common/tcp_https_server.js server1 10.10.10.254 &
$hexec l3ep2 node ../common/tcp_https_server.js server2 10.10.10.254 &
$hexec l3ep3 node ../common/tcp_https_server.js server3 10.10.10.254 &

sleep 5
code=0
servIP=( "10.10.10.254" )
servArr=( "server1" "server2" "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )
j=0
waitCount=0

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
    res=$($hexec l3h1 curl --max-time 10 -H "Application/json" -H "Content-type: application/json" -H "HOST: 10.10.10.254" --insecure -s https://${servIP[k]}:2020)
    echo $res
    
    if [[ $res == "server1" ]] || [[ $res == "server2" ]] || [[ $res == "server3" ]]; then
        backend_count[$res]=$((backend_count[$res] + 1))
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
    echo SCENARIO-e2ehttps-tcplb with ${servIP[k]} [OK]
else
    echo SCENARIO-e2ehttps-tcplb with ${servIP[k]} [FAILED]
    code=1
fi
done

sudo killall -9 node 2>&1 > /dev/null
exit $code
