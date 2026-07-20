#!/bin/bash
source ../common.sh
echo SCENARIO-sctptunlb
servArr=( "server1" "server2" "server3" )
ep=( "25.25.25.1" "26.26.26.1" "27.27.27.1" )
ueIP=( "" "32.32.32.1" "31.31.31.1" )

$hexec l3e1 socat -v -T0.5 sctp-l:8080,reuseaddr,fork system:"echo 'server1'; cat" >/dev/null 2>&1 &
$hexec l3e2 socat -v -T0.5 sctp-l:8080,reuseaddr,fork system:"echo 'server2'; cat" >/dev/null 2>&1 &
$hexec l3e3 socat -v -T0.5 sctp-l:8080,reuseaddr,fork system:"echo 'server3'; cat" >/dev/null 2>&1 &

sleep 20
code=0
j=0
waitCount=0
while [ $j -le 2 ]
do
    #res=$($hexec ue1 curl ${ep[j]}:8080)
    res=`$hexec h1 timeout 10 ../common/sctp_socat_client 32.32.32.1 0 ${ep[j]} 8080`
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
            echo SCENARIO-sctptunlb [FAILED]
            sudo pkill sctp_server >/dev/null 2>&1
            exit 1
        fi

    fi
    sleep 1
done

for k in {1..2}
do
echo "Testing from h$k"

# Count responses from each backend to verify load distribution
declare -A backend_count_h$k
eval "backend_count_h${k}[server1]=0"
eval "backend_count_h${k}[server2]=0"
eval "backend_count_h${k}[server3]=0"
total_requests=12

for i in $(seq 1 $total_requests)
do
    res=$($hexec h$k timeout 10 ../common/sctp_socat_client ${ueIP[k]} 0 88.88.88.88 2020)
    echo -e $res
    
    if [[ $res == "server1" ]] || [[ $res == "server2" ]] || [[ $res == "server3" ]]; then
        eval "backend_count_h${k}[$res]=\$((\${backend_count_h${k}[$res]} + 1))"
    else
        echo -e "Unexpected response: $res"
        if [[ "$res" != *"server"* ]]; then
            echo "llb1 ct"
            $dexec llb1 loxicmd get ct
            echo "llb2 ct"
            $dexec llb2 loxicmd get ct
            echo "llb2 ip neigh"
            $dexec llb2 ip neigh
        fi
        code=1
    fi
    sleep 1
done

# Verify all backends received at least one request
eval "echo \"Load distribution from h$k: server1=\${backend_count_h${k}[server1]}, server2=\${backend_count_h${k}[server2]}, server3=\${backend_count_h${k}[server3]}\""
eval "if [[ \${backend_count_h${k}[server1]} -eq 0 ]] || [[ \${backend_count_h${k}[server2]} -eq 0 ]] || [[ \${backend_count_h${k}[server3]} -eq 0 ]]; then
    echo \"Load balancing failed: not all backends received requests from h$k\"
    code=1
fi"
done
if [[ $code == 0 ]]
then
    echo SCENARIO-sctptunlb [OK]
else
    echo SCENARIO-sctptunlb [FAILED]
fi
sudo pkill sctp_server >/dev/null 2>&1
sudo pkill socat >/dev/null 2>&1
exit $code

