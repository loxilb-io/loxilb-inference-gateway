#!/bin/bash
source ../common.sh
echo SCENARIO-http-tcplb
$hexec l3ep1 node ../common/tcp_server.js server1 &
$hexec l3ep2 node ../common/tcp_server.js server2 &
$hexec l3ep3 node ../common/tcp_server.js server3 &

sleep 5
code=0
servIP=( "10.10.10.254" )
servArrUsers=( "server1" "server2" )
servArrOrders=( "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )
j=0
waitCount=0
# while [ $j -le 2 ]
# do
#     res=$($hexec l3h1 curl --max-time 10 -s ${ep[j]}:8080)
#     #echo $res
#     if [[ $res == "${servArrUsers[j]}" ]]
#     then
#         echo "$res UP"
#         j=$(( $j + 1 ))
#     else
#         echo "Waiting for ${servArrUsers[j]}(${ep[j]})"
#         waitCount=$(( $waitCount + 1 ))
#         if [[ $waitCount == 10 ]];
#         then
#             echo "All Servers are not UP"
#             echo SCENARIO-tcplb [FAILED]
#             sudo killall -9 node 2>&1 > /dev/null
#             exit 1
#         fi
#     fi
#     sleep 1
# done

k=0
lcode=0

# /v1/users must load-balance across server1 and server2 (never server3).
# tcp_server.js echoes only the plain server name, so strip any suffix.
echo "Testing Service IP: ${servIP[k]} with /v1/users path prefix"
declare -A users_count
for i in {1..8}
do
    res=$($hexec l3h1 curl --max-time 10 --insecure -s http://${servIP[k]}:2020/v1/users)
    res=$(echo "$res" | xargs)
    echo "$res"  >&2
    srv=${res%%:*}
    if [[ -n "$srv" ]]; then
        users_count[$srv]=$((${users_count[$srv]:-0} + 1))
    fi
    sleep 1
done

for srv in "${servArrUsers[@]}"; do
    if [[ ${users_count[$srv]:-0} -eq 0 ]]; then
        echo "  /v1/users: $srv received 0 hits [FAILED]"
        lcode=1
    fi
done
if [[ ${users_count["server3"]:-0} -ne 0 ]]; then
    echo "  /v1/users: leaked to server3 (orders backend) [FAILED]"
    lcode=1
fi

# /v1/orders must always route to server3 only.
echo "Testing Service IP: ${servIP[k]} with /v1/orders path prefix"
for i in {1..4}
do
    res=$($hexec l3h1 curl --max-time 10 --insecure -s http://${servIP[k]}:2020/v1/orders)
    res=$(echo "$res" | xargs)
    echo "$res"  >&2
    srv=${res%%:*}
    if [[ "$srv" != "${servArrOrders[0]}" ]]
    then
        lcode=1
    fi
    sleep 1
done

if [[ $lcode == 0 ]]
then
    echo SCENARIO-http-tcplb-prefix with ${servIP[k]} [OK]
else
    echo SCENARIO-http-tcplb-prefix with ${servIP[k]} [FAILED]
    code=1
fi

sudo killall -9 node 2>&1 > /dev/null
exit $code
