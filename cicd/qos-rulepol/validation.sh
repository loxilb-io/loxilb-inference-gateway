#!/bin/bash
# qos-rulepol — rule-attached Tier-0 policer validation (NAT-mode LB rules).
#
# Legs:
#   L1 baseline      : un-policed throughput through the VIP must be fast (>100 Mbps)
#   L2 attach+cap    : attach a 10 Mbps policer to the rule -> new-connection
#                      throughput collapses to ~CIR; an 8s run also catches the
#                      fast-cache bypass (policing must hold for the WHOLE flow,
#                      not just its first packets)
#   L3 counters      : the polx_map bucket for this policer shows pass/drop
#                      counters CLIMBING (the historical defect was a fully
#                      configured bucket that was never consulted — pinned at 0)
#   L4 fullproxy-neg : attaching a policer to a fullproxy rule must FAIL loudly
#   L5 detach        : deleting the policy restores un-policed throughput
#   L6 re-create heal: delete + re-create the LB rule with vip_qos_policy_id —
#                      the fresh rule act must re-acquire the polid (a re-created
#                      rule starts at polid 0; the association must re-push it)
#   L7 reverse dir   : the rule policer is bidirectional — a download (iperf3 -R,
#                      bulk flows backend->client via the reverse CT) must be
#                      capped by the same bucket
#   L8 egr-hooks neg : this loxilb runs WITHOUT --egr-hooks, so an
#                      egress-direction port attach (attachment=2) must be
#                      refused loudly, never accepted as a bucket nothing reads
source ../common.sh
echo SCENARIO-qos-rulepol

VIP=20.20.20.1
FPVIP=20.20.20.3
API="http://127.0.0.1:11111/netlox/v1"
POLID_JSON='{"policyIdent":"qpol1","policyInfo":{"type":0,"committedInfoRate":10,"peakInfoRate":10,"committedBlkSize":125000},"targetObject":{"attachment":0,"polObjName":"20.20.20.1:2020:tcp"}}'

code=0

# iperf3 lives in the nettest image, not on the CI host — run it via docker
# exec (same netns as the container's connected veths), detached for the server
sudo docker exec -d l3ep1 iperf3 -s -p 8080
sleep 2

# Measured Mbits/s of an iperf3 run through the VIP (receiver side)
run_bw() {
    local secs=$1; shift
    $dexec l3h1 iperf3 -c $VIP -p 2020 -t $secs "$@" 2>&1 | \
        awk '/receiver/ {v=$7; u=$8; if (u=="Kbits/sec") v=v/1000; if (u=="Gbits/sec") v=v*1000; printf "%d", v}'
}

api_post_policy() {
    $dexec llb1 curl -s -X POST -H 'Content-Type: application/json' -d "$1" $API/config/policy
}

api_del_policy() {
    $dexec llb1 curl -s -X DELETE $API/config/policy/ident/$1
}

# --- L1: baseline, no policer ---
bw0=$(run_bw 5)
echo "L1 baseline bw: ${bw0} Mbits/s"
if [[ -z "$bw0" || "$bw0" -lt 100 ]]; then
    echo "L1 baseline too slow (${bw0} Mbits/s) - topology unusable" ; code=1
fi

# --- L2: attach 10 Mbps policer to the rule, new connection must be capped.
# 8 seconds is long enough that a policing bypass after the first packets
# (fast-cache install) would push the average far above the cap. ---
res=$(api_post_policy "$POLID_JSON")
echo "L2 attach: $res"
if [[ "$res" != *"Success"* ]]; then
    echo "L2 policy attach on NAT-mode rule FAILED: $res" ; code=1
fi
sleep 2
bw1=$(run_bw 8)
echo "L2 policed bw: ${bw1} Mbits/s (CIR 10)"
if [[ -z "$bw1" || "$bw1" -gt 25 ]]; then
    echo "L2 rule policer NOT enforcing (got ${bw1} Mbits/s, want <=25)" ; code=1
fi

# --- L3: the polx bucket must actually be consulted. Only do_dp_policer ever
# mutates this map (token counters, timestamps, pass/drop stats), so a dump
# that is byte-identical across a traffic burst proves the historical defect:
# a fully configured bucket that is never consulted. ---
snap1=$($dexec llb1 sh -c "bpftool map dump name polx_map 2>/dev/null | md5sum")
run_bw 2 > /dev/null
snap2=$($dexec llb1 sh -c "bpftool map dump name polx_map 2>/dev/null | md5sum")
echo "L3 polx snapshots: pre=${snap1%% *} post=${snap2%% *}"
if [[ -z "$snap1" || "$snap1" == "$snap2" ]]; then
    echo "L3 polx bucket exists but was never consulted (map state frozen across traffic)" ; code=1
fi

# --- L4: fullproxy rule must refuse the attach ---
FP_JSON='{"policyIdent":"qpolfp","policyInfo":{"type":0,"committedInfoRate":10,"peakInfoRate":10},"targetObject":{"attachment":0,"polObjName":"20.20.20.3:2020:tcp"}}'
res=$(api_post_policy "$FP_JSON")
echo "L4 fullproxy attach response: $res"
if [[ "$res" == *"Success"* ]]; then
    echo "L4 fullproxy rule accepted a policer attach (must be refused)" ; code=1
    api_del_policy qpolfp > /dev/null
fi

# --- L5: detach restores throughput ---
res=$(api_del_policy qpol1)
echo "L5 detach: $res"
sleep 2
bw2=$(run_bw 5)
echo "L5 post-detach bw: ${bw2} Mbits/s"
if [[ -z "$bw2" || "$bw2" -lt 100 ]]; then
    echo "L5 throughput NOT restored after policy delete (${bw2} Mbits/s)" ; code=1
fi

# --- L6: rule re-created WITH vip_qos_policy_id re-acquires the policer ---
res=$(api_post_policy "$POLID_JSON")
if [[ "$res" != *"Success"* ]]; then
    echo "L6 policy re-add failed: $res" ; code=1
fi
$dexec llb1 curl -s -X DELETE "$API/config/loadbalancer/externalipaddress/$VIP/port/2020/protocol/tcp"
sleep 1
LB_JSON='{"serviceArguments":{"externalIP":"20.20.20.1","port":2020,"protocol":"tcp","vip_qos_policy_id":"qpol1"},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1}]}'
res=$($dexec llb1 curl -s -X POST -H 'Content-Type: application/json' -d "$LB_JSON" $API/config/loadbalancer)
echo "L6 rule re-create: $res"
sleep 12   # one PolTicker period — the ticker is the re-push backstop
bw3=$(run_bw 8)
echo "L6 re-created-rule policed bw: ${bw3} Mbits/s (CIR 10)"
if [[ -z "$bw3" || "$bw3" -gt 25 ]]; then
    echo "L6 re-created rule lost its policer (got ${bw3} Mbits/s, want <=25)" ; code=1
fi

# --- L7: reverse direction (download) is capped by the same rule policer ---
bw4=$(run_bw 8 -R)
echo "L7 reverse-direction policed bw: ${bw4} Mbits/s (CIR 10)"
if [[ -z "$bw4" || "$bw4" -gt 25 ]]; then
    echo "L7 reverse direction NOT policed (got ${bw4} Mbits/s, want <=25)" ; code=1
fi

# --- L8: egress attach without --egr-hooks must be refused ---
NOEGR_JSON='{"policyIdent":"qnoegr","policyInfo":{"type":0,"committedInfoRate":10,"peakInfoRate":10},"targetObject":{"attachment":2,"polObjName":"ellb1l3ep1"}}'
res=$(api_post_policy "$NOEGR_JSON")
echo "L8 egress-attach-without-hooks response: $res"
if [[ "$res" == *"Success"* ]]; then
    echo "L8 egress attach accepted without --egr-hooks (must be refused)" ; code=1
    api_del_policy qnoegr > /dev/null
fi

$dexec l3ep1 pkill -9 iperf3 2>/dev/null
if [[ $code == 0 ]]; then
    echo SCENARIO-qos-rulepol [OK]
else
    echo SCENARIO-qos-rulepol [FAILED]
fi
exit $code
