#!/bin/bash
# qos-egrpol — egress-direction port policer validation (loxilb runs with
# --egr-hooks so the TC egress image is attached).
#
# Scope note (architectural): the ingress hook stamps every transit packet and
# the egress hook passes stamped packets untouched, so TRANSIT traffic never
# processes at an egress hook. That is why the egress port policer used to
# govern only HOST-ORIGINATED traffic. Transit is now policed by a post-routing
# lookup that resolves the egress port after the forwarding decision, so both
# classes meet the same policer; E5 asserts that, and used to pin its absence.
#
# Legs:
#   E1 baseline  : un-policed HOST-ORIGINATED upload (llb1 -> backend, direct,
#                  not via VIP) must be fast (>12 MB/s ~= 100 Mbps)
#   E2 egress cap: attach a 10 Mbps EGRESS policer (attachment=2) to the
#                  backend-facing port — host-originated upload collapses to
#                  ~CIR (<3.5 MB/s)
#   E3 direction : transit download through the VIP stays fast — the egress
#                  policer must not bleed into ingress processing (this is the
#                  leg that caught the shared-pgm_tbl compile-time-twin defect),
#                  and must not be applied to the wrong egress port
#   E4 detach    : deleting the policy restores host-originated upload
#   E5 transit   : transit upload through the VIP is policed to ~CIR. Bounded on
#                  BOTH sides: a policer that killed the flow outright would
#                  clear a one-sided ceiling while being a worse bug than the
#                  one it fixed
#   E6 heal      : transit upload recovers after the policy is deleted — a
#                  policer id left latched on the egress path would otherwise
#                  keep shaping traffic no policy claims
source ../common.sh
echo SCENARIO-qos-egrpol

VIP=20.20.20.1
API="http://127.0.0.1:11111/netlox/v1"
EGR_JSON='{"policyIdent":"qegr1","policyInfo":{"type":0,"committedInfoRate":10,"peakInfoRate":10,"committedBlkSize":125000},"targetObject":{"attachment":2,"polObjName":"ellb1l3ep1"}}'

code=0

sudo docker exec -d l3ep1 iperf3 -s -p 8080
sleep 2

# Transit Mbits/s through the VIP (iperf3 receiver side)
run_bw() {
    local secs=$1; shift
    $dexec l3h1 iperf3 -c $VIP -p 2020 -t $secs "$@" 2>&1 | \
        awk '/receiver/ {v=$7; u=$8; if (u=="Kbits/sec") v=v/1000; if (u=="Gbits/sec") v=v*1000; printf "%d", v}'
}

# Host-originated upload from INSIDE llb1 toward the backend, in KB/s.
# curl PUTs /dev/zero at an nc sink for ~6s; speed_upload is bytes/s.
# KB resolution matters: at a 10 Mbps CIR the shaped rate is ~1250 KB/s, and
# an integer-MB report renders both that and a dead transfer as "0".
host_egr_bw() {
    sudo docker exec -d l3ep1 sh -c "nc -l -p 9099 > /dev/null"
    sleep 1
    $dexec llb1 sh -c "curl -s -m 6 -T /dev/zero -o /dev/null -w '%{speed_upload}' http://31.31.31.1:9099/up 2>/dev/null" | \
        awk '{printf "%d", $1/1024}'
    $dexec l3ep1 pkill -f "nc -l" 2>/dev/null
}

# --- E1: baseline host-originated upload ---
hbw0=$(host_egr_bw)
echo "E1 baseline host-egress: ${hbw0} KB/s"
if [[ -z "$hbw0" || "$hbw0" -lt 12288 ]]; then
    echo "E1 host-egress baseline too slow (${hbw0} KB/s) - topology unusable" ; code=1
fi

# --- E2: egress policer caps host-originated upload ---
res=$($dexec llb1 curl -s -X POST -H 'Content-Type: application/json' -d "$EGR_JSON" $API/config/policy)
echo "E2 attach: $res"
if [[ "$res" != *"Success"* ]]; then
    echo "E2 egress policer attach FAILED: $res" ; code=1
fi
sleep 2
hbw1=$(host_egr_bw)
echo "E2 policed host-egress: ${hbw1} KB/s (CIR 10 Mbps ~= 1250 KB/s)"
if [[ -z "$hbw1" || "$hbw1" -gt 3500 ]]; then
    echo "E2 egress policer NOT enforcing on host-originated traffic (got ${hbw1} KB/s, want <=3500)" ; code=1
elif [[ "$hbw1" -lt 100 ]]; then
    echo "E2 egress policer killed the host flow rather than shaping it (got ${hbw1} KB/s, want >=100)" ; code=1
fi

# --- E3: transit download unaffected by the egress policer ---
bw2=$(run_bw 5 -R)
echo "E3 transit download with egress policer up: ${bw2} Mbits/s"
if [[ -z "$bw2" || "$bw2" -lt 100 ]]; then
    echo "E3 egress policer bled into ingress processing (got ${bw2} Mbits/s, want >100)" ; code=1
fi

# --- E5: transit upload IS policed by the egress policer ---
bw3=$(run_bw 5)
echo "E5 transit upload with egress policer up: ${bw3} Mbits/s (CIR 10 Mbps)"
if [[ -z "$bw3" || "$bw3" -gt 30 ]]; then
    echo "E5 transit-egress NOT policed (got ${bw3} Mbits/s, want <=30 on a 10 Mbps CIR)" ; code=1
elif [[ "$bw3" -lt 1 ]]; then
    echo "E5 transit-egress policer killed the flow rather than shaping it (got ${bw3} Mbits/s)" ; code=1
fi

# --- E4: detach restores host-originated upload ---
res=$($dexec llb1 curl -s -X DELETE $API/config/policy/ident/qegr1)
echo "E4 detach: $res"
sleep 2
hbw2=$(host_egr_bw)
echo "E4 post-detach host-egress: ${hbw2} KB/s"
if [[ -z "$hbw2" || "$hbw2" -lt 12288 ]]; then
    echo "E4 host-egress NOT restored after policy delete (${hbw2} KB/s)" ; code=1
fi

# --- E6: transit upload recovers once the policy is gone ---
bw4=$(run_bw 5)
echo "E6 post-detach transit upload: ${bw4} Mbits/s"
if [[ -z "$bw4" || "$bw4" -lt 100 ]]; then
    echo "E6 transit-egress still policed after policy delete (${bw4} Mbits/s, want >100)" ; code=1
fi

$dexec l3ep1 pkill -9 iperf3 2>/dev/null
if [[ $code == 0 ]]; then
    echo SCENARIO-qos-egrpol [OK]
else
    echo SCENARIO-qos-egrpol [FAILED]
fi
exit $code
