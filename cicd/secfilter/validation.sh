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

echo "### metrics: security series present (needs loxilb -p; set in config.sh)"
mbody=$($dexec llb1 curl -s "$api/metrics")
echo "$mbody" | grep -qE 'loxilb_security_syn_blocked_total' \
    && pass "loxilb_security_* series exported" || fail "security metrics missing (is -p enabled?)"
echo "$mbody" | grep -qE 'loxilb_ipfilter_rules' \
    && pass "loxilb_ipfilter_rules series exported" || fail "ipfilter metrics missing"

sudo killall -9 node 2>&1 >/dev/null
if [[ $code == 0 ]]; then
    echo SCENARIO-secfilter [OK]
else
    echo SCENARIO-secfilter [FAILED]
fi
exit $code
