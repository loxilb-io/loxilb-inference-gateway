#!/bin/bash
# secfilter - regression coverage for ipfilter / firewall / securityrate.
# Exercises the fixes for the security-features audit: XDP blacklist drop,
# whitelist precedence, v4/v6 trie separation, firewall >256-rule capacity,
# and REST input validation.
source ../common.sh
echo SCENARIO-secfilter

api="http://127.0.0.1:11111/netlox/v1"
code=0

# REST helper: echo the HTTP status of a call issued from inside llb1.
rest_code() { # method path [json]
    if [[ -n "$3" ]]; then
        $dexec llb1 curl -s -o /dev/null -w "%{http_code}" -X"$1" \
            "$api$2" -H "Content-Type: application/json" -d "$3"
    else
        $dexec llb1 curl -s -o /dev/null -w "%{http_code}" -X"$1" "$api$2"
    fi
}
rest_body() { $dexec llb1 curl -s "$api$1"; }

fail() { echo "  [FAILED] $1"; code=1; }
pass() { echo "  [OK] $1"; }

# Bring the backend up
$hexec l3ep1 node ../common/tcp_server.js server1 &
sleep 5

# Confirm baseline reachability client -> VIP before any filtering
reach() { $hexec l3h1 curl --max-time 10 -s 20.20.20.1:2020; }
waitCount=0
while true; do
    res=$(reach)
    if [[ $res == "server1" ]]; then pass "baseline VIP reachable"; break; fi
    waitCount=$((waitCount+1))
    if [[ $waitCount == 10 ]]; then
        fail "baseline VIP never came up"
        echo SCENARIO-secfilter [FAILED]
        sudo killall -9 node 2>&1 >/dev/null
        exit 1
    fi
    sleep 2
done

echo "### ipfilter: blacklist drop enforcement (P0-7)"
c=$(rest_code POST /config/ipfilter '{"filterType":"blacklist","cidr":"10.10.10.1/32","action":"drop","priority":200}')
[[ $c == 200 ]] && pass "blacklist add accepted" || fail "blacklist add code=$c"
sleep 2
res=$(reach)
[[ $res != "server1" ]] && pass "blacklisted client dropped at XDP" || fail "blacklisted client still reached ($res)"

echo "### ipfilter: delete restores reachability"
c=$(rest_code DELETE '/config/ipfilter?filterType=blacklist&cidr=10.10.10.1/32')
[[ $c == 200 ]] && pass "blacklist delete accepted" || fail "blacklist delete code=$c"
sleep 2
res=$(reach)
[[ $res == "server1" ]] && pass "client reachable after delete" || fail "client still blocked after delete ($res)"

echo "### ipfilter: whitelist beats blacklist at equal priority (P1-2)"
# Blacklist the client's /24 (NOT 0.0.0.0/0 - a catch-all would also blackhole
# the backend's return traffic, which is a config error, not a precedence test),
# then whitelist the client /32 at the SAME priority. Whitelist must win the tie.
rest_code POST /config/ipfilter '{"filterType":"blacklist","cidr":"10.10.10.0/24","action":"drop","priority":100}' >/dev/null
rest_code POST /config/ipfilter '{"filterType":"whitelist","cidr":"10.10.10.1/32","action":"allow","priority":100}' >/dev/null
sleep 2
res=$(reach)
[[ $res == "server1" ]] && pass "whitelist wins tie over overlapping blacklist" || fail "whitelist did not win tie ($res)"
# Sanity: the blacklist alone (whitelist removed) must drop the client
rest_code DELETE '/config/ipfilter?filterType=whitelist&cidr=10.10.10.1/32' >/dev/null
sleep 2
res=$(reach)
[[ $res != "server1" ]] && pass "blacklist /24 drops client once whitelist removed" || fail "blacklist not enforced ($res)"
rest_code DELETE '/config/ipfilter?filterType=blacklist&cidr=10.10.10.0/24' >/dev/null
sleep 2
res=$(reach)
[[ $res == "server1" ]] && pass "reachable after cleanup" || fail "unreachable after cleanup ($res)"

echo "### ipfilter: v4/v6 tries stay separate (P1-1)"
rest_code POST /config/ipfilter '{"filterType":"blacklist","cidr":"192.0.2.0/24","action":"drop","priority":50}' >/dev/null
rest_code POST /config/ipfilter '{"filterType":"whitelist","cidr":"2001:db8::/32","action":"allow","priority":50}' >/dev/null
body=$(rest_body /config/ipfilter/all)
echo "$body" | grep -q '"cidr":"192.0.2.0/24"' && pass "v4 rule rendered as v4" || fail "v4 rule missing/mangled"
echo "$body" | grep -q '"cidr":"2001:db8::/32"' && pass "v6 rule rendered as v6 (not bogus IPv4)" || fail "v6 rule mangled: $body"
rest_code DELETE '/config/ipfilter?filterType=blacklist&cidr=192.0.2.0/24' >/dev/null
rest_code DELETE '/config/ipfilter?filterType=whitelist&cidr=2001:db8::/32' >/dev/null

echo "### ipfilter: 0.0.0.0/0 rule is listed by GET (prefixlen-0 iteration)"
rest_code POST /config/ipfilter '{"filterType":"blacklist","cidr":"0.0.0.0/0","action":"drop","priority":1}' >/dev/null
rest_body /config/ipfilter/all | grep -q '"cidr":"0.0.0.0/0"' \
    && pass "0.0.0.0/0 rule listed by GET" || fail "0.0.0.0/0 rule missing from GET (all-zero key skipped)"
rest_code DELETE '/config/ipfilter?filterType=blacklist&cidr=0.0.0.0/0' >/dev/null

echo "### ipfilter: invalid inputs rejected (P1-6)"
c=$(rest_code POST /config/ipfilter '{"filterType":"blacklist","cidr":"1.2.3.0/24","action":"drop","priority":-1}')
[[ $c == 400 ]] && pass "negative priority rejected (400)" || fail "negative priority code=$c"
c=$(rest_code POST /config/ipfilter '{"filterType":"blacklist","cidr":"1.2.3.0/24","action":"allow"}')
[[ $c == 400 ]] && pass "blacklist+allow mismatch rejected (400)" || fail "mismatch code=$c"
c=$(rest_code DELETE '/config/ipfilter?filterType=blacklist&cidr=203.0.113.0/24')
[[ $c == 404 ]] && pass "delete-nonexistent returns 404" || fail "delete-nonexistent code=$c"

echo "### firewall: >256 rules all install (P0-3)"
# Cross the old 8-bit (256) truncation boundary. Count by what is LISTED rather
# than by POST codes, so a rerun on a warm container (rules already present ->
# RuleExists) still validates capacity.
for i in $(seq 1 300); do
    o2=$((i/250)); o3=$((i%250))
    rest_code POST /config/firewall "{\"ruleArguments\":{\"sourceIP\":\"172.16.$o2.$o3/32\",\"preference\":$((1000+i)),\"protocol\":6},\"opts\":{\"drop\":true}}" >/dev/null
done
got=$(rest_body /config/firewall/all | grep -o '"preference"' | wc -l)
[[ $got -ge 300 ]] && pass "300+ fw rules installed and listed past old 256 limit (got=$got)" || fail "fw capacity: only $got rules listed (want >=300)"

echo "### firewall: GET-under-churn does not crash daemon (P0-4)"
# Track only these churn PIDs; a bare `wait` would also block on the
# forever-running tcp_server.js backend started above.
churn_pids=()
for i in $(seq 1 40); do
    $dexec llb1 curl -s -o /dev/null "$api/config/firewall/all" &
    churn_pids+=($!)
done
for i in $(seq 1 20); do
    ( rest_code POST /config/firewall "{\"ruleArguments\":{\"sourceIP\":\"192.168.$i.1/32\",\"preference\":$((6000+i)),\"protocol\":6},\"opts\":{\"drop\":true}}" >/dev/null ) &
    churn_pids+=($!)
    ( rest_code DELETE "/config/firewall?sourceIP=192.168.$i.1/32&preference=$((6000+i))&protocol=6" >/dev/null ) &
    churn_pids+=($!)
done
wait "${churn_pids[@]}" 2>/dev/null
sleep 2
c=$(rest_code GET /config/firewall/all)
[[ $c == 200 ]] && pass "daemon alive after concurrent GET/churn" || fail "daemon unresponsive after churn (code=$c)"

echo "### securityrate: input validation + fail-closed config"
c=$(rest_code POST /config/securityrate '{"synEnabled":true,"synThreshold":-1,"cookieThreshold":50,"connRateEnabled":false,"ratePerSec":50,"udpEnabled":false,"udpPktThreshold":1000,"udpBandwidthMB":100}')
[[ $c == 400 ]] && pass "negative synThreshold rejected (400)" || fail "negative synThreshold code=$c"
c=$(rest_code POST /config/securityrate '{"synEnabled":false,"synThreshold":100,"cookieThreshold":50,"connRateEnabled":false,"ratePerSec":50,"udpEnabled":true,"udpPktThreshold":1000,"udpBandwidthMB":5000}')
[[ $c == 400 ]] && pass "udpBandwidthMB overflow rejected (400)" || fail "udp overflow code=$c"
c=$(rest_code POST /config/securityrate '{"synEnabled":true,"synThreshold":200,"cookieThreshold":50,"connRateEnabled":false,"ratePerSec":50,"udpEnabled":false,"udpPktThreshold":1000,"udpBandwidthMB":100}')
[[ $c == 200 ]] && pass "valid securityrate config accepted" || fail "valid config code=$c"
body=$(rest_body /config/securityrate/all)
echo "$body" | grep -q '"synThreshold":200' && pass "GET reflects enforced threshold" || fail "GET config mismatch: $body"

############################################################################
# Enforcement legs (finding D4): the sections above only prove config
# plumbing (400-rejects, GET round-trips). These legs prove the datapath
# actually drops/limits AND that the exported counters account for it, using
# the drill recipes live-verified exact on the reference testbed.
# TRAP (by design, llb_kern_synflood.c): whitelisted sources are exempt from
# ALL securityrate limiting - attack traffic must come from a NON-whitelisted
# source, and leg 5 locks that exemption in as a positive test.
############################################################################

# Read an UNLABELED counter from /metrics (0 if absent).
metric_val() { # metric_name
    $dexec llb1 curl -s "$api/metrics" | awk -v m="$1" '$1==m {printf "%.0f", $2; f=1} END {if(!f) printf "0"}'
}
# Sum a LABELED counter's series whose labels contain a substring (0 if none).
metric_labeled_val() { # metric_name label_substr
    $dexec llb1 curl -s "$api/metrics" | awk -v m="$1" -v l="$2" \
        'index($1, m"{")==1 && index($1, l)>0 {s+=$2} END {printf "%.0f", s+0}'
}
# How many series of a family carry a label substring. A sum of 0 and a REAPED
# family are the same number, and both collectors here delete series for rules
# that no longer exist (RunIPFilterStats, RunGetFwRule) - so every claim about
# a zero must first establish that the series is still there to be read.
metric_series_count() { # metric_name label_substr
    $dexec llb1 curl -s "$api/metrics" | awk -v m="$1" -v l="$2" \
        'index($1, m"{")==1 && index($1, l)>0 {n++} END {printf "%d", n+0}'
}
# Sum a family's series EXCLUDING those carrying a label substring. This is the
# per-label discipline: a family-wide delta cannot see a drop charged to the
# WRONG rule, because the total is right either way.
metric_labeled_val_excluding() { # metric_name label_substr
    $dexec llb1 curl -s "$api/metrics" | awk -v m="$1" -v l="$2" \
        'index($1, m"{")==1 && index($1, l)==0 {s+=$2} END {printf "%.0f", s+0}'
}
# Poll until a labeled series EXISTS and its value stops changing, then echo it.
# Never a fixed sleep: the collectors sweep on PrometheusDefaultPeriod (10s) and
# a read taken mid-sweep is a partial count, not a wrong one.
poll_metric_settled() { # metric_name label_substr
    local m=$1 lbl=$2 prev=-1 now t=0
    while (( t < 45 )); do
        now=$(metric_labeled_val "$m" "$lbl")
        [[ $now == "$prev" && $now != 0 ]] && break
        prev=$now; sleep 3; t=$((t+3))
    done
    echo "$now"
}
# Counters advance on the collector's 10s sweep: poll until the delta reaches
# the target or the timeout, then echo the final delta (never fixed-sleep).
poll_metric_delta() { # unlabeled|labeled metric prev want [label_substr]
    local kind=$1 m=$2 prev=$3 want=$4 lbl=$5 now delta=0 t=0
    while (( t < 45 )); do
        if [[ $kind == labeled ]]; then now=$(metric_labeled_val "$m" "$lbl"); else now=$(metric_val "$m"); fi
        delta=$((now - prev))
        (( delta >= want )) && break
        sleep 3; t=$((t+3))
    done
    echo "$delta"
}

# Reset securityrate to all-disabled so legs cannot interfere with each other.
sec_reset='{"synEnabled":false,"synThreshold":100,"cookieThreshold":50,"connRateEnabled":false,"ratePerSec":50,"udpEnabled":false,"udpPktThreshold":1000,"udpBandwidthMB":100}'
rest_code POST /config/securityrate "$sec_reset" >/dev/null

echo "### enforcement 1/5 - firewall: every dropped SYN is counted, and to the RIGHT rule (D4)"
# RunGetFwRule charges both families from ONE delta in ONE block:
#     if delta > 0 {
#         totalDropsByFwPerRule.WithLabelValues(ruleID).Add(delta)   <- fw_rule_drop
#         totalDropsByFw.Add(delta)                                  <- fw_drop
#     }
# so the fleet-wide total and the sum over rules are equal BY CONSTRUCTION,
# one statement apart with no branch between them. That identity is therefore
# arm-agnostic - it holds whether or not the drop was attributed correctly -
# and cannot be the gate on its own. The claim the fleet-wide counter
# structurally CANNOT make is the per-label one: 300+ rules are installed by
# the capacity section above, and exactly ONE of them may move.
FW_PREF=500
fw_before=$(metric_val loxilb_fw_drop_packets_total)
fw_rule_before=$(metric_labeled_val loxilb_fw_rule_drop_packets_total "fw_rule=\"$FW_PREF\"")
fw_other_before=$(metric_labeled_val_excluding loxilb_fw_rule_drop_packets_total "fw_rule=\"$FW_PREF\"")
c=$(rest_code POST /config/firewall "{\"ruleArguments\":{\"sourceIP\":\"10.10.10.1/32\",\"preference\":$FW_PREF,\"protocol\":6},\"opts\":{\"drop\":true}}")
[[ $c == 200 ]] && pass "fw drop rule installed" || fail "fw drop rule code=$c"
sleep 1
# --max-time 0.5 kills curl before the kernel's 1s SYN retransmit, so each
# attempt is exactly one dropped SYN (drill-verified 20/20 exact).
for i in $(seq 1 20); do
    $hexec l3h1 curl --max-time 0.5 -s -o /dev/null 20.20.20.1:2020
done
delta=$(poll_metric_delta unlabeled loxilb_fw_drop_packets_total "$fw_before" 20)
[[ $delta -ge 20 && $delta -le 30 ]] \
    && pass "fw_drop_packets_total delta=$delta for 20 SYNs" \
    || fail "fw drop counter delta=$delta (want 20..30)"

# Read the per-rule family while the rule STILL EXISTS. RunGetFwRule reaps the
# series on the first sweep after the rule is deleted, and a reaped family and
# a family that was never charged both read 0.
fw_rule_n=$(metric_series_count loxilb_fw_rule_drop_packets_total "fw_rule=\"$FW_PREF\"")
[[ $fw_rule_n -eq 1 ]] \
    && pass "fw_rule_drop_packets_total{fw_rule=$FW_PREF} series exists (not reaped, not absent)" \
    || fail "fw_rule_drop series count=$fw_rule_n for pref $FW_PREF (want exactly 1)"
fw_rule_after=$(metric_labeled_val loxilb_fw_rule_drop_packets_total "fw_rule=\"$FW_PREF\"")
fw_rule_delta=$((fw_rule_after - fw_rule_before))
[[ $fw_rule_delta -eq $delta ]] \
    && pass "fw_rule_drop{fw_rule=$FW_PREF} delta=$fw_rule_delta == fw_drop delta=$delta (same-statement identity)" \
    || fail "per-rule delta=$fw_rule_delta != fleet-wide delta=$delta"

# The per-LABEL claim: every other installed rule must be flat. 300 rules at
# preferences 1001..1300 exist and none of them sees traffic, so a drop charged
# to the wrong preference shows up here and NOWHERE in the totals.
# On WHY a healthy read of 0 here is a real zero and not an unreadable one:
# RunGetFwRule creates a per-rule series only inside `if delta > 0`, so a rule
# that never dropped has no series at all. Absence and "charged nothing" are
# the same fact for this family - unlike the ipfilter families above, where the
# reaper can delete a series that WAS charged, which is why those legs count
# series explicitly. The assert still has the power to go red: a drop charged
# to preference 1001 would CREATE that series and lift this sum off zero.
fw_other_after=$(metric_labeled_val_excluding loxilb_fw_rule_drop_packets_total "fw_rule=\"$FW_PREF\"")
fw_other_delta=$((fw_other_after - fw_other_before))
[[ $fw_other_delta -eq 0 ]] \
    && pass "every other fw_rule label flat (delta=0 across the 300+ installed rules)" \
    || fail "drops charged to rules that saw no traffic (other-label delta=$fw_other_delta)"

rest_code DELETE "/config/firewall?sourceIP=10.10.10.1/32&preference=$FW_PREF&protocol=6" >/dev/null
sleep 2
res=$(reach)
[[ $res == "server1" ]] && pass "reachable after fw rule delete" || fail "still blocked after fw delete ($res)"

echo "### enforcement 2/5 - ipfilter: blacklist drops are counted per rule (D4)"
# Secondary source IP so the primary client path stays observable in parallel.
$hexec l3h1 ip addr add 10.10.10.99/24 dev el3h1llb1 2>/dev/null
bl_before=$(metric_labeled_val loxilb_ipfilter_blacklist_packets_total 'cidr="10.10.10.99/32"')
bl_bytes_before=$(metric_labeled_val loxilb_ipfilter_blacklist_bytes_total 'cidr="10.10.10.99/32"')
rest_code POST /config/ipfilter '{"filterType":"blacklist","cidr":"10.10.10.99/32","action":"drop","priority":210}' >/dev/null
sleep 1
for i in $(seq 1 10); do
    $hexec l3h1 curl --interface 10.10.10.99 --max-time 0.5 -s -o /dev/null 20.20.20.1:2020
done
res=$(reach)
[[ $res == "server1" ]] && pass "primary client unaffected by secondary blacklist" || fail "primary client blocked ($res)"
delta=$(poll_metric_delta labeled loxilb_ipfilter_blacklist_packets_total "$bl_before" 10 'cidr="10.10.10.99/32"')
[[ $delta -ge 10 ]] \
    && pass "ipfilter_blacklist_packets_total delta=$delta for 10 SYNs (>=10)" \
    || fail "blacklist counter delta=$delta (want >=10)"

# A packet count alone cannot be pinned exactly here: --max-time 0.5 races the
# kernel's 1s SYN retransmit, so the drive shape is "at least 10", not "10".
# The bytes family turns that into an exact claim anyway, because both counters
# are charged from the SAME eBPF entry in the same loop iteration
# (RunIPFilterStats: deltaPackets/deltaBytes off one `entry`). Every packet the
# blacklist drops here is a TCP SYN of ONE fixed frame size, so
#     delta_bytes == delta_packets * frame_size,  frame_size an exact integer
# holds no matter how many retransmits landed. A bytes counter fed from a
# different event, or a per-series mix-up, breaks the divisibility.
bl_bytes_after=$(metric_labeled_val loxilb_ipfilter_blacklist_bytes_total 'cidr="10.10.10.99/32"')
bl_bytes_delta=$((bl_bytes_after - bl_bytes_before))
bl_n=$(metric_series_count loxilb_ipfilter_blacklist_packets_total 'cidr="10.10.10.99/32"')
[[ $bl_n -eq 1 ]] \
    && pass "blacklist series for 10.10.10.99/32 exists (not reaped, not absent)" \
    || fail "blacklist series count=$bl_n (want exactly 1)"
if (( delta > 0 )) && (( bl_bytes_delta % delta == 0 )); then
    frame=$((bl_bytes_delta / delta))
    if (( frame >= 40 && frame <= 100 )); then
        pass "blacklist bytes=$bl_bytes_delta == packets=$delta x ${frame}B, one TCP SYN frame size exactly"
    else
        fail "blacklist bytes/packets quotient ${frame}B is not a TCP SYN frame (bytes=$bl_bytes_delta packets=$delta)"
    fi
else
    fail "blacklist bytes=$bl_bytes_delta not divisible by packets=$delta - the two counters are not charged from the same events"
fi

# Writer separation: the whitelist pair must be FLAT for this CIDR. The four
# ipfilter counters share one loop and one `entry`, split only by an
# if/else-if on entry.FilterType - so a blacklist drop landing on the
# whitelist family is the failure this asserts against, and no total can see it.
wl_cross=$(metric_labeled_val loxilb_ipfilter_whitelist_packets_total 'cidr="10.10.10.99/32"')
[[ $wl_cross -eq 0 ]] \
    && pass "whitelist family flat for the blacklisted CIDR (filterType branch honoured)" \
    || fail "blacklist drops leaked into whitelist family (=$wl_cross)"

rest_code DELETE '/config/ipfilter?filterType=blacklist&cidr=10.10.10.99/32' >/dev/null

echo "### enforcement 3/5 - securityrate: UDP flood threshold (D4)"
rest_code POST /config/securityrate '{"synEnabled":false,"synThreshold":100,"cookieThreshold":50,"connRateEnabled":false,"ratePerSec":50,"udpEnabled":true,"udpPktThreshold":100,"udpBandwidthMB":100}' >/dev/null
sleep 1
udp_p_before=$(metric_val loxilb_security_udp_passed_total)
udp_b_before=$(metric_val loxilb_security_udp_blocked_total)
# 300 datagrams as fast as bash can emit them (<1s on the veth path); with a
# 100 pkt/s threshold the drill split exactly 100 passed / 200 blocked.
$hexec l3h1 bash -c 'for i in $(seq 1 300); do echo -n x > /dev/udp/20.20.20.1/9999; done' 2>/dev/null
delta_b=$(poll_metric_delta unlabeled loxilb_security_udp_blocked_total "$udp_b_before" 100)
udp_p_now=$(metric_val loxilb_security_udp_passed_total)
delta_p=$((udp_p_now - udp_p_before))
total=$((delta_p + delta_b))
[[ $delta_b -ge 100 ]] \
    && pass "udp_blocked delta=$delta_b (>=100; drill-exact was 200)" \
    || fail "udp_blocked delta=$delta_b (want >=100)"
[[ $total -ge 295 && $total -le 310 ]] \
    && pass "passed+blocked=$total accounts for all 300 datagrams" \
    || fail "passed($delta_p)+blocked($delta_b)=$total != 300"

echo "### enforcement 4/5 - securityrate: connection-rate limiting (D4)"
rest_code POST /config/securityrate '{"synEnabled":false,"synThreshold":100,"cookieThreshold":50,"connRateEnabled":true,"ratePerSec":5,"udpEnabled":false,"udpPktThreshold":1000,"udpBandwidthMB":100}' >/dev/null
sleep 1
cr_before=$(metric_val loxilb_security_conn_blocked_total)
for i in $(seq 1 40); do
    $hexec l3h1 curl --max-time 0.3 -s -o /dev/null 20.20.20.1:2020
done
delta=$(poll_metric_delta unlabeled loxilb_security_conn_blocked_total "$cr_before" 1)
[[ $delta -ge 1 ]] \
    && pass "conn_blocked delta=$delta for 40-conn burst at 5/s cap" \
    || fail "conn-rate never blocked (delta=$delta)"

echo "### enforcement 5/5 - securityrate: whitelist bypass exemption (D4)"
# Whitelisted sources bypass ALL rate limiting by design - lock that in so a
# future change to the shared ip_whitelist map cannot silently break it.
rest_code POST /config/securityrate '{"synEnabled":false,"synThreshold":100,"cookieThreshold":50,"connRateEnabled":false,"ratePerSec":50,"udpEnabled":true,"udpPktThreshold":100,"udpBandwidthMB":100}' >/dev/null
rest_code POST /config/ipfilter '{"filterType":"whitelist","cidr":"10.10.10.1/32","action":"allow","priority":220}' >/dev/null
sleep 1
udp_p_before=$(metric_val loxilb_security_udp_passed_total)
udp_b_before=$(metric_val loxilb_security_udp_blocked_total)
wl_p_before=$(metric_labeled_val loxilb_ipfilter_whitelist_packets_total 'cidr="10.10.10.1/32"')
wl_b_before=$(metric_labeled_val loxilb_ipfilter_whitelist_bytes_total 'cidr="10.10.10.1/32"')
$hexec l3h1 bash -c 'for i in $(seq 1 300); do echo -n x > /dev/udp/20.20.20.1/9999; done' 2>/dev/null
sleep 14
udp_p_now=$(metric_val loxilb_security_udp_passed_total)
udp_b_now=$(metric_val loxilb_security_udp_blocked_total)
delta_p=$((udp_p_now - udp_p_before))
delta_b=$((udp_b_now - udp_b_before))
# "Exempt from ALL securityrate limiting" means the packet never reaches the
# limiter, so it is charged as NEITHER passed NOR blocked. Both halves are
# asserted: blocked==0 alone is satisfied just as well by a product that threw
# every datagram away, and passed==0 alone by one that dropped the rule.
# Measured against the no-whitelist control on the same bed and the same flood:
#     no whitelist -> passed 100 / blocked 200   (the 100 pkt/s threshold)
#     whitelist    -> passed   0 / blocked   0   (bypass, this leg)
[[ $delta_b -eq 0 ]] \
    && pass "whitelisted source: zero blocked under same flood" \
    || fail "whitelisted source still blocked (delta=$delta_b)"
[[ $delta_p -eq 0 ]] \
    && pass "whitelisted source: zero PASSED too - the limiter was bypassed, not merely permissive" \
    || fail "whitelisted source was rate-limiter accounted (passed delta=$delta_p, want 0)"

# The whitelist counter pair has no coverage anywhere in this repo today: the
# rule above is the only whitelist that carries real traffic, and until now
# nothing read what it accounted for. Same two claims as the blacklist pair -
# the series must EXIST (RunIPFilterStats reaps it on the sweep after delete),
# and bytes must be an exact integer multiple of packets, here for a 1-byte
# UDP datagram rather than a TCP SYN.
wl_p_after=$(poll_metric_settled loxilb_ipfilter_whitelist_packets_total 'cidr="10.10.10.1/32"')
wl_b_after=$(metric_labeled_val loxilb_ipfilter_whitelist_bytes_total 'cidr="10.10.10.1/32"')
wl_n=$(metric_series_count loxilb_ipfilter_whitelist_packets_total 'cidr="10.10.10.1/32"')
wl_p_delta=$((wl_p_after - wl_p_before))
wl_b_delta=$((wl_b_after - wl_b_before))
[[ $wl_n -eq 1 ]] \
    && pass "whitelist series for 10.10.10.1/32 exists (not reaped, not absent)" \
    || fail "whitelist series count=$wl_n (want exactly 1)"
# BOUNDED ON BOTH SIDES, deliberately. This CIDR was whitelisted earlier in the
# scenario at priority 100 and is re-added here at 220; filterKey carries the
# priority, so this is a FIRST SIGHT to RunIPFilterStats and the else branch
# charges entry.Packets WHOLE rather than a delta. If the data-plane entry for
# the CIDR survived the earlier incarnation, that whole value is re-charged and
# a lower bound alone would pass on the inflated number - asserting the defect
# instead of catching it. 300 datagrams must read as ~300, not 300 plus history.
[[ $wl_p_delta -ge 295 && $wl_p_delta -le 320 ]] \
    && pass "ipfilter_whitelist_packets_total delta=$wl_p_delta accounts for the passed flood, with no re-charged history" \
    || fail "whitelist packets delta=$wl_p_delta (want 295..320 for 300 datagrams; >320 means a first-sight re-charge)"
if (( wl_p_delta > 0 )) && (( wl_b_delta % wl_p_delta == 0 )); then
    wframe=$((wl_b_delta / wl_p_delta))
    if (( wframe >= 20 && wframe <= 100 )); then
        pass "whitelist bytes=$wl_b_delta == packets=$wl_p_delta x ${wframe}B, one UDP datagram exactly"
    else
        fail "whitelist bytes/packets quotient ${wframe}B is not a 1-byte UDP datagram frame"
    fi
else
    fail "whitelist bytes=$wl_b_delta not divisible by packets=$wl_p_delta - not charged from the same events"
fi
# The mirror of the blacklist leg's cross-check: allowed traffic must not be
# charged as blocked.
bl_cross=$(metric_labeled_val loxilb_ipfilter_blacklist_packets_total 'cidr="10.10.10.1/32"')
[[ $bl_cross -eq 0 ]] \
    && pass "blacklist family flat for the whitelisted CIDR" \
    || fail "whitelisted traffic charged to the blacklist family (=$bl_cross)"

rest_code DELETE '/config/ipfilter?filterType=whitelist&cidr=10.10.10.1/32' >/dev/null

# Leave securityrate disabled and the topology clean for any later sections.
rest_code POST /config/securityrate "$sec_reset" >/dev/null
$hexec l3h1 ip addr del 10.10.10.99/24 dev el3h1llb1 2>/dev/null
sleep 2
res=$(reach)
[[ $res == "server1" ]] && pass "baseline reachability restored after enforcement legs" || fail "unreachable after enforcement cleanup ($res)"

echo "### enforcement 6/6 - ipfilter_rules gauge tracks config UP and DOWN"
# ipFilterTotalRules is a GaugeVec Set from a COUNT recomputed on every sweep -
# it has no traffic-time writer at all, so it is driven entirely by config and
# needs no packets. The existing check greps for the series name, which passes
# on any value including a stale one; a gauge that counts up and never comes
# back down reads exactly the same to a grep.
# Poll a POSITIVE verdict AFTER each config change rather than sampling once:
# the collector sweeps on a 10s period, so a read taken immediately is a
# statement about the previous configuration.
poll_gauge_eq() { # type want
    local want=$2 now=0 t=0
    while (( t < 45 )); do
        now=$(metric_labeled_val loxilb_ipfilter_rules "type=\"$1\"")
        [[ $now -eq $want ]] && break
        sleep 3; t=$((t+3))
    done
    echo "$now"
}
# The baseline must be the gauge's view of the CURRENT config, not a sample.
# Reading it immediately after leg 5's delete returns the PREVIOUS sweep's
# count - measured: base read as whitelist=1 while the real count was 0, so a
# relative "+2" assert demanded 3 and got 2. Anchor on the API instead, which
# is authoritative the moment it answers, and make agreement its own assert.
api_count() { # blacklist|whitelist
    rest_body /config/ipfilter/all | grep -o "\"filterType\":\"$1\"" | wc -l | tr -d ' '
}
poll_gauge_eq() { # type want
    local want=$2 now=0 t=0
    while (( t < 60 )); do
        now=$(metric_labeled_val loxilb_ipfilter_rules "type=\"$1\"")
        [[ $now -eq $want ]] && break
        sleep 3; t=$((t+3))
    done
    echo "$now"
}
rules_b_base=$(api_count blacklist); rules_w_base=$(api_count whitelist)
sync_b=$(poll_gauge_eq blacklist "$rules_b_base")
sync_w=$(poll_gauge_eq whitelist "$rules_w_base")
[[ $sync_b -eq $rules_b_base && $sync_w -eq $rules_w_base ]] \
    && pass "ipfilter_rules agrees with the API config (b=$sync_b w=$sync_w) before the drive" \
    || fail "gauge disagrees with config: gauge b=$sync_b w=$sync_w, API b=$rules_b_base w=$rules_w_base"

for o in 11 12 13; do
    rest_code POST /config/ipfilter "{\"filterType\":\"blacklist\",\"cidr\":\"198.51.100.$o/32\",\"action\":\"drop\",\"priority\":$((300+o))}" >/dev/null
done
for o in 21 22; do
    rest_code POST /config/ipfilter "{\"filterType\":\"whitelist\",\"cidr\":\"198.51.100.$o/32\",\"action\":\"allow\",\"priority\":$((300+o))}" >/dev/null
done
want_b=$((rules_b_base + 3)); want_w=$((rules_w_base + 2))
got_b=$(poll_gauge_eq blacklist $want_b)
got_w=$(poll_gauge_eq whitelist $want_w)
[[ $got_b -eq $want_b ]] \
    && pass "ipfilter_rules{type=blacklist}=$got_b after +3 (base $rules_b_base)" \
    || fail "ipfilter_rules{type=blacklist}=$got_b, want $want_b"
[[ $got_w -eq $want_w ]] \
    && pass "ipfilter_rules{type=whitelist}=$got_w after +2 (base $rules_w_base)" \
    || fail "ipfilter_rules{type=whitelist}=$got_w, want $want_w"
# The two types are counted by separate ++ in the same loop, split on
# entry.FilterType. Adding 3 of one and 2 of the other tells a per-type count
# apart from a single total reported twice - equal counts could not.
[[ $((got_b - rules_b_base)) -eq 3 && $((got_w - rules_w_base)) -eq 2 ]] \
    && pass "blacklist +3 and whitelist +2 counted separately, not one total echoed twice" \
    || fail "per-type split wrong: blacklist +$((got_b-rules_b_base)) whitelist +$((got_w-rules_w_base))"
for o in 11 12 13; do
    rest_code DELETE "/config/ipfilter?filterType=blacklist&cidr=198.51.100.$o/32" >/dev/null
done
for o in 21 22; do
    rest_code DELETE "/config/ipfilter?filterType=whitelist&cidr=198.51.100.$o/32" >/dev/null
done
back_b=$(poll_gauge_eq blacklist "$rules_b_base")
back_w=$(poll_gauge_eq whitelist "$rules_w_base")
[[ $back_b -eq $rules_b_base && $back_w -eq $rules_w_base ]] \
    && pass "gauge returned to base on delete (b=$back_b w=$back_w) - it tracks DOWN, not just up" \
    || fail "gauge did not return to base: b=$back_b (want $rules_b_base) w=$back_w (want $rules_w_base)"

echo "### metrics: security series present (needs loxilb -p; set in config.sh)"
mbody=$($dexec llb1 curl -s "$api/metrics")
echo "$mbody" | grep -qE 'loxilb_security_syn_blocked_total' \
    && pass "loxilb_security_* series exported" || fail "security metrics missing (is -p enabled?)"
echo "$mbody" | grep -qE 'loxilb_ipfilter_rules' \
    && pass "loxilb_ipfilter_rules series exported" || fail "ipfilter metrics missing"
# D1 regression: the VIP rule here is UNNAMED - traffic through it must never
# emit placeholder per-service series (the DP reports unnamed rules as "-",
# some paths as "": both rendered phantom rows on the L4 dashboard).
echo "$mbody" | grep -qE 'service="(-)?"' \
    && fail "placeholder service-label series exported (D1 regression)" \
    || pass "no service=\"\"/service=\"-\" series for unnamed rule traffic (D1)"

sudo killall -9 node 2>&1 >/dev/null
if [[ $code == 0 ]]; then
    echo SCENARIO-secfilter [OK]
else
    echo SCENARIO-secfilter [FAILED]
fi
exit $code
