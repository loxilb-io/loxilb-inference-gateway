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

echo "### enforcement 1/5 - firewall: every dropped SYN is counted (D4)"
fw_before=$(metric_val loxilb_fw_drop_packets_total)
c=$(rest_code POST /config/firewall '{"ruleArguments":{"sourceIP":"10.10.10.1/32","preference":500,"protocol":6},"opts":{"drop":true}}')
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
rest_code DELETE '/config/firewall?sourceIP=10.10.10.1/32&preference=500&protocol=6' >/dev/null
sleep 2
res=$(reach)
[[ $res == "server1" ]] && pass "reachable after fw rule delete" || fail "still blocked after fw delete ($res)"

echo "### enforcement 2/5 - ipfilter: blacklist drops are counted per rule (D4)"
# Secondary source IP so the primary client path stays observable in parallel.
$hexec l3h1 ip addr add 10.10.10.99/24 dev el3h1llb1 2>/dev/null
bl_before=$(metric_labeled_val loxilb_ipfilter_blacklist_packets_total 'cidr="10.10.10.99/32"')
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
$hexec l3h1 bash -c 'for i in $(seq 1 300); do echo -n x > /dev/udp/20.20.20.1/9999; done' 2>/dev/null
delta_p=$(poll_metric_delta unlabeled loxilb_security_udp_passed_total "$udp_p_before" 300)
udp_b_now=$(metric_val loxilb_security_udp_blocked_total)
delta_b=$((udp_b_now - udp_b_before))
[[ $delta_b -eq 0 ]] \
    && pass "whitelisted source: zero blocked under same flood" \
    || fail "whitelisted source still blocked (delta=$delta_b)"
[[ $delta_p -ge 295 ]] \
    && pass "whitelisted source: all $delta_p datagrams passed" \
    || fail "whitelisted passed only $delta_p of 300"
rest_code DELETE '/config/ipfilter?filterType=whitelist&cidr=10.10.10.1/32' >/dev/null

# Leave securityrate disabled and the topology clean for any later sections.
rest_code POST /config/securityrate "$sec_reset" >/dev/null
$hexec l3h1 ip addr del 10.10.10.99/24 dev el3h1llb1 2>/dev/null
sleep 2
res=$(reach)
[[ $res == "server1" ]] && pass "baseline reachability restored after enforcement legs" || fail "unreachable after enforcement cleanup ($res)"

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
