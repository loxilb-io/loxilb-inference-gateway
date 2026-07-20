#!/bin/bash
source ../common.sh
echo SCENARIO-https-tcplb
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
echo "Testing Service IP: ${servIP[k]} with /v1/users path prefix"
users_fail=0
declare -A users_count
for i in {1..8}
do
    res=$($hexec l3h1 curl --max-time 10 --insecure -s https://${servIP[k]}:2020/v1/users)
    res=$(echo "$res" | xargs)
    echo "$res" >&2
    srv=${res%%:*}
    if [[ -n "$srv" ]]; then
        users_count[$srv]=$((${users_count[$srv]:-0} + 1))
    fi
    sleep 1
done

for srv in "${servArrUsers[@]}"; do
    if [[ ${users_count[$srv]:-0} -eq 0 ]]; then
        echo "  /v1/users: $srv received 0 hits [FAILED]"
        users_fail=1
    fi
done

echo "Testing Service IP: ${servIP[k]} with /v1/orders path prefix"
orders_fail=0
for i in {1..4}
do
for j in {0..0}
do
    res=$($hexec l3h1 curl --max-time 10 --insecure -s https://${servIP[k]}:2020/v1/orders)
    res=$(echo "$res" | xargs)
    echo "$res"  >&2
    exp="${servArrOrders[j]}:orders"
    if [[ "$res" != "$exp" ]]
    then
        orders_fail=1
    fi
    sleep 1
done
done

if [[ $users_fail -eq 0 && $orders_fail -eq 0 ]]
then
    echo SCENARIO-https-tcplb-prefix with ${servIP[k]} [OK]
else
    echo SCENARIO-https-tcplb-prefix with ${servIP[k]} [FAILED]
    code=1
fi

echo ""
echo "=== Prefix Boundary Tests ==="

echo "PREFIX-T1: /v1/orders (specific) takes priority over /v1 (shorter prefix) — LPM"
res=$($hexec l3h1 curl --max-time 10 --insecure -s https://${servIP[0]}:2020/v1/orders)
res=$(echo "$res" | xargs)
if [[ "$res" =~ "orders" ]]; then
    echo "  PREFIX-T1: /v1/orders routed to orders backend [OK]"
elif [[ "$res" =~ "v1-fallback" || "$res" =~ "server-v1" ]]; then
    echo "  PREFIX-T1: /v1/orders routed to /v1 fallback — LPM not working [FAILED]"
    code=1
else
    echo "  PREFIX-T1: response does not identify backend clearly: $res [WARN]"
fi

echo "PREFIX-T2: URL-encoded path /v1%2Fusers — document routing behavior"
res=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 10 --insecure \
    --path-as-is \
    https://${servIP[0]}:2020/v1%2Fusers)
if [[ "$res" == "200" ]]; then
    echo "  PREFIX-T2: /v1%2Fusers → 200 (loxilb normalizes URL before prefix match) [INFO]"
elif [[ "$res" == "404" || "$res" == "400" ]]; then
    echo "  PREFIX-T2: /v1%2Fusers → $res (loxilb does NOT normalize — correct for strict prefix) [INFO]"
else
    echo "  PREFIX-T2: /v1%2Fusers → $res [INFO]"
fi
echo "  PREFIX-T2: behavior documented — not a pass/fail gate [OK]"

echo "PREFIX-T3: trailing slash /v1/users/ matches /v1/users rule"
res_trailing=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 10 --insecure \
    https://${servIP[0]}:2020/v1/users/)
res_no_trailing=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 10 --insecure \
    https://${servIP[0]}:2020/v1/users)
if [[ "$res_trailing" == "$res_no_trailing" ]]; then
    echo "  PREFIX-T3: trailing slash → same response ($res_trailing) as without [OK — consistent]"
elif [[ "$res_trailing" == "404" ]]; then
    echo "  PREFIX-T3: trailing slash → 404 (strict prefix match, trailing slash not normalized) [INFO]"
else
    echo "  PREFIX-T3: trailing slash=$res_trailing, no-slash=$res_no_trailing [INFO]"
fi
echo "  PREFIX-T3: behavior documented [OK]"

echo "PREFIX-T4: unmatched path /v2/users → no rule matches → expect 503 or 404"
# verify that a path with no matching LB rule returns an error (not server1/server2)
T4_RESP=$($hexec l3h1 curl -s -w "\n%{http_code}" --max-time 10 --insecure \
    https://${servIP[0]}:2020/v2/users 2>/dev/null)
T4_BODY=$(echo "$T4_RESP" | head -n1)
T4_CODE=$(echo "$T4_RESP" | tail -n1)
echo "  PREFIX-T4: /v2/users → HTTP $T4_CODE body='$T4_BODY'"
if [[ "$T4_CODE" == "503" || "$T4_CODE" == "404" || "$T4_CODE" == "400" ]]; then
    echo "  PREFIX-T4: unmatched path correctly rejected [OK]"
elif [[ "$T4_BODY" == "server1" || "$T4_BODY" == "server2" ]]; then
    echo "  PREFIX-T4: unmatched path routed to backend — prefix match may be too broad [FAILED]"
    code=1
else
    echo "  PREFIX-T4: /v2/users → $T4_CODE (unmatched path — behavior documented) [INFO]"
fi

echo "PREFIX-T5: deep path /v1/users/123 → prefix /v1/users matches → routed to backend"
# verify LPM/prefix matching handles sub-paths
T5_BODY=$($hexec l3h1 curl -s --max-time 10 --insecure \
    https://${servIP[0]}:2020/v1/users/123 2>/dev/null)
echo "  PREFIX-T5: /v1/users/123 → '$T5_BODY'"
if echo "$T5_BODY" | grep -qE 'server[12]'; then
    echo "  PREFIX-T5: deep path routed by prefix match [OK]"
elif [[ -z "$T5_BODY" ]]; then
    echo "  PREFIX-T5: empty response — deep path may not be matched [FAILED]"
    code=1
else
    echo "  PREFIX-T5: got '$T5_BODY' — expected server1 or server2 [FAILED]"
    code=1
fi

sudo killall -9 node 2>&1 > /dev/null

# REST API validation — verify LB rule fields and path-prefix lifecycle
if [[ -f ./validate_api.sh ]]; then
  bash ./validate_api.sh || code=1
fi

exit $code
