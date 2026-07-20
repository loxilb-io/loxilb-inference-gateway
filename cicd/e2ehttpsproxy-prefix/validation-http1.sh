#!/bin/bash
source ../common.sh
echo SCENARIO-e2ehttps-tcplb-prefix
$hexec l3ep1 node ../common/tcp_https_server.js server1 10.10.10.254 &
$hexec l3ep2 node ../common/tcp_https_server.js server2 10.10.10.254 &
$hexec l3ep3 node ../common/tcp_https_server.js server3 10.10.10.254 &

sleep 5
code=0
servIP=( "10.10.10.254" )
servArrUsers=( "server1" "server2" )
servArrOrders=( "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )
j=0
waitCount=0

for k in {0..0}
do
echo "Testing Service IP: ${servIP[k]}"
lcode=0
for i in {1..4}
do
for j in {0..1}
do
    res=$($hexec l3h1 curl --max-time 10 -H "Application/json" -H "Content-type: application/json" -H "HOST: 10.10.10.254" --insecure -s https://${servIP[k]}:2020/v1/users)
    res=$(echo "$res" | xargs)
    echo "$res"  >&2
    exp="${servArrUsers[j]}:users"
    if [[ "$res" != "$exp" ]]
    then
        lcode=1
    fi
    sleep 1
done
done
for i in {1..4}
do
for j in {0..0}
do
    res=$($hexec l3h1 curl --max-time 10 -H "Application/json" -H "Content-type: application/json" -H "HOST: 10.10.10.254" --insecure -s https://${servIP[k]}:2020/v1/orders)
    res=$(echo "$res" | xargs)
    echo "$res"  >&2
    exp="${servArrOrders[j]}:orders"
    if [[ "$res" != "$exp" ]]
    then
        lcode=1
    fi
    sleep 1
done
done

if [[ $lcode == 0 ]]
then
    echo SCENARIO-e2ehttps-tcplb-prefix with ${servIP[k]} [OK]
else
    echo SCENARIO-e2ehttps-tcplb-prefix with ${servIP[k]} [FAILED]
    code=1
fi
done

sudo killall -9 node 2>&1 > /dev/null
exit $code
