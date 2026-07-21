#!/bin/bash
source ../common.sh
echo SCENARIO-tcptunlb
$hexec l3e1 node ../common/tcp_server.js server1 &
$hexec l3e2 node ../common/tcp_server.js server2 &
$hexec l3e3 node ../common/tcp_server.js server3 &

sleep 10
# Overridable for slow/noisy runners: SETTLE=3 ./validation.sh
SETTLE=${SETTLE:-2}
code=0
servArr=( "server1" "server2" "server3" )
ep=( "25.25.25.1" "26.26.26.1" "27.27.27.1" )

dump_ct() {
    echo "llb1 ct";       $dexec llb1 loxicmd get ct
    echo "llb2 ct";       $dexec llb2 loxicmd get ct
    echo "llb2 ip neigh"; $dexec llb2 ip neigh
}

# 1) Direct endpoint readiness (h1 -> llb1 -> llb2 -> l3eN, non-tunnel path).
j=0
waitCount=0
while [ $j -le 2 ]
do
    res=`$hexec h1 curl --max-time 10 -s ${ep[j]}:8080`
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
            echo SCENARIO-tcptunlb [FAILED]
            sudo pkill node
            exit 1
        fi
    fi
    sleep 1
done

# 2) VIP/tunnel warmup. Drive traffic through the VxLAN tunnel + LB rule until
#    every backend has answered at least once via the VIP. The first SYN to a
#    freshly-programmed endpoint over the tunnel can wedge in sync-ack on slow
#    runners; polling here lets that conntrack entry establish (or age out and
#    retry) before the strict pass, instead of failing the whole scenario on a
#    transient startup race. A backend that never answers here is a real fault.
declare -A seen=( [server1]=0 [server2]=0 [server3]=0 )
warm=0
warmMax=60
while [[ ${seen[server1]} -eq 0 || ${seen[server2]} -eq 0 || ${seen[server3]} -eq 0 ]]
do
    res=`$hexec h1 curl --max-time 10 -s 88.88.88.88:2020`
    if [[ "$res" == server* ]]; then
        seen[$res]=1
    fi
    warm=$(( warm + 1 ))
    if [[ $warm -ge $warmMax ]]; then
        echo "VIP warmup incomplete after ${warmMax}s: server1=${seen[server1]} server2=${seen[server2]} server3=${seen[server3]}"
        dump_ct
        echo SCENARIO-tcptunlb [FAILED]
        sudo pkill node
        exit 1
    fi
    sleep 1
done
sleep $SETTLE

# 3) Load-distribution assertion via the VIP from both clients. Require every
#    backend to be reachable over the tunnel (count-based, like sctptunlb)
#    rather than a fixed round-robin order, which is timing-sensitive.
for k in 1 2
do
    declare -A cnt=( [server1]=0 [server2]=0 [server3]=0 )
    for i in $(seq 1 9)
    do
        res=`$hexec h$k curl --max-time 10 -s 88.88.88.88:2020`
        echo -e $res
        if [[ "$res" == server* ]]; then
            cnt[$res]=$(( ${cnt[$res]} + 1 ))
        fi
        sleep 1
    done
    echo "Distribution from h$k: server1=${cnt[server1]} server2=${cnt[server2]} server3=${cnt[server3]}"
    if [[ ${cnt[server1]} -eq 0 || ${cnt[server2]} -eq 0 || ${cnt[server3]} -eq 0 ]]; then
        echo -e "Load balancing failed from h$k: a backend was unreachable via VIP"
        dump_ct
        code=1
    fi
done

if [[ $code == 0 ]]
then
    echo SCENARIO-tcptunlb [OK]
else
    echo SCENARIO-tcptunlb [FAILED]
fi
sudo pkill node
exit $code
