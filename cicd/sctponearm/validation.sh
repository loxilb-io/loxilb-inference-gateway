#!/bin/bash
source ../common.sh
echo SCENARIO-SCTP-ONEARM
servArr=( "server1" "server2" )
ep=( "10.75.188.218" "10.75.188.220" )

$hexec ep1 socat -v -T0.5 sctp-l:38412,reuseaddr,fork system:"echo 'server1'; cat" >/dev/null 2>&1 &
$hexec ep2 socat -v -T0.5 sctp-l:38412,reuseaddr,fork system:"echo 'server2'; cat" >/dev/null 2>&1 &

sleep 60
$dexec llb1 loxicmd get ep
sleep 10

code=0
j=0
waitCount=0
while [ $j -le 1 ]
do
    res=$($hexec c1 timeout 10 ../common/sctp_socat_client 10.75.191.224 0 ${ep[j]} 38412)
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
            echo SCENARIO-SCTP-ONEARM [FAILED]
            sudo pkill -9 -x  sctp_server >/dev/null 2>&1
            exit 1
        fi
    fi
    sleep 1
done

declare -A serverCount
serverCount["server1"]=0
serverCount["server2"]=0

for i in {1..8}
do
    res=$($hexec c1 timeout 10 ../common/sctp_socat_client 10.75.191.224 0 123.123.123.1 38412)
    echo -e $res
    if [[ $res == "server1" ]] || [[ $res == "server2" ]]
    then
        serverCount[$res]=$(( ${serverCount[$res]} + 1 ))
    else
        echo "Unexpected response: $res"
        code=1
    fi
    sleep 1
done

echo "Distribution: server1=${serverCount[server1]}, server2=${serverCount[server2]}"

if [[ ${serverCount[server1]} -eq 0 ]] || [[ ${serverCount[server2]} -eq 0 ]]
then
    echo "Some servers received no requests"
    code=1
fi

if [[ ${serverCount[server1]} -lt 2 ]] || [[ ${serverCount[server2]} -lt 2 ]]
then
    echo "Load distribution is too unbalanced"
    code=1
fi

if [[ $code == 0 ]]
then
    echo SCENARIO-SCTP-ONEARM [OK]
else
    echo SCENARIO-SCTP-ONEARM [FAILED]
fi
sudo pkill -9 -x  socat >/dev/null 2>&1
sudo pkill -9 -x  sctp_server >/dev/null 2>&1
exit $code

