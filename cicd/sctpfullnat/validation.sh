#!/bin/bash
source ../common.sh
echo SCENARIO-SCTP-FULLNAT
servArr=( "server1" "server2" )
ep=( "10.0.3.10" "10.0.3.11" )

$hexec ep1 ../common/sctp_server ${ep[0]} 38412 server1 >/dev/null 2>&1 &
$hexec ep2 ../common/sctp_server ${ep[1]} 38412 server2 >/dev/null 2>&1 &

sleep 5

code=0
j=0
waitCount=0
while [ $j -le 1 ]
do
    res=$($hexec c1 timeout 10 ../common/sctp_client 10.0.3.71 0 ${ep[j]} 38412)
    #echo $res
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
            echo SCENARIO-SCTP-FULLNAT [FAILED]
            sudo pkill -9 -x  sctp_server >/dev/null 2>&1
            exit 1
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
    res=$($hexec l3h1 timeout 10 ../common/sctp_client 10.10.10.1 0 20.20.20.1 2020)
    echo -e $res
    
    if [[ $res == "server1" ]] || [[ $res == "server2" ]] || [[ $res == "server3" ]]; then
        backend_count[$res]=$((backend_count[$res] + 1))
    else
        echo "Unexpected response: $res"
        code=1
    fi
    sleep 1
done

# Verify all backends received at least one request
echo "Load distribution: server1=${backend_count["server1"]}, server2=${backend_count["server2"]}, server3=${backend_count["server3"]}"
if [[ ${backend_count["server1"]} -eq 0 ]] || [[ ${backend_count["server2"]} -eq 0 ]] || [[ ${backend_count["server3"]} -eq 0 ]]; then
    echo "Load balancing failed: not all backends received requests"
    code=1
fi
if [[ $code == 0 ]]
then
    echo SCENARIO-SCTP-FULLNAT [OK]
else
    echo SCENARIO-SCTP-FULLNAT [FAILED]
fi
sudo pkill -9 -x  sctp_server >/dev/null 2>&1
exit $code

