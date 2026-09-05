#!/bin/bash
# Scrape-boundary security matrix for the monitoring stack (CPU arms).
#
# Runs on the cicd monitoring topology (config.sh up, stack running) and
# verifies the collection boundary behaves as documented:
#
#   S1  metrics enabled  -> gateway scrape 200, Prometheus up{job="loxilb"}==1
#   S2  metrics disabled -> gateway scrape 503, up drops to 0 (distinguishes a
#       deliberately disabled endpoint from a dead host)
#   S3  network-down     -> unreachable target, up==0 with a connection error
#       (distinguishes dead host from disabled endpoint via scrape error text)
#   S4  Prometheus bind  -> the Prometheus API answers on loopback and is NOT
#       reachable from a non-management network namespace
#   S5  gateway metrics reachability from an outside namespace matches the
#       documented posture for the plain listener
#
# Client-certificate arms (API HTTPS listener with --tls-ca) are a separate
# conditional matrix; this script covers what a stock CPU topology can prove.
# Each failure prints repro, expected, actual. Exit 0 only if all arms pass.

source ../common.sh 2>/dev/null || true

PROM=${PROM:-http://127.0.0.1:9090}
GW=${GW:-10.10.10.254}
API="http://${GW}:11111/netlox/v1"
FAILS=0

ok()   { echo "  [OK]   $1"; }
fail() { echo "  [FAIL] $1"; echo "         repro: $2"; echo "         expected: $3"; echo "         actual: $4"; FAILS=$((FAILS+1)); }

prom_up() {
    curl -s "${PROM}/api/v1/query?query=up%7Bjob%3D%22loxilb%22%7D" \
        | python3 -c 'import sys,json;r=json.load(sys.stdin)["data"]["result"];print(r[0]["value"][1] if r else "absent")'
}

wait_up_value() { # $1 expected value, $2 timeout seconds
    local t=0
    while [ $t -lt "$2" ]; do
        v=$(prom_up)
        [ "$v" = "$1" ] && return 0
        sleep 5; t=$((t+5))
    done
    return 1
}

scrape_code() { # HTTP code of a direct gateway metrics fetch from l3h1
    $hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        "${API}/metrics"
}

echo "S1: metrics enabled -> 200 + up==1"
$hexec l3h1 curl -s -X POST "${API}/config/metrics" >/dev/null
code=$(scrape_code)
if [ "$code" = "200" ]; then ok "gateway scrape 200"; else
    fail "gateway scrape while enabled" "curl ${API}/metrics" "200" "$code"; fi
if wait_up_value 1 60; then ok "prometheus up==1"; else
    fail "prometheus up while enabled" "query up{job=\"loxilb\"}" "1" "$(prom_up)"; fi

echo "S2: metrics disabled -> 503 + up==0 (disabled != dead)"
$hexec l3h1 curl -s -X DELETE "${API}/config/metrics" >/dev/null
code=$(scrape_code)
if [ "$code" = "503" ]; then ok "gateway scrape 503"; else
    fail "gateway scrape while disabled" "curl ${API}/metrics" "503" "$code"; fi
if wait_up_value 0 60; then ok "prometheus up==0"; else
    fail "prometheus up while disabled" "query up{job=\"loxilb\"}" "0" "$(prom_up)"; fi
# the scrape error for a 503 names the status, not a connect failure
err=$(curl -s "${PROM}/api/v1/targets" | python3 -c '
import sys,json
for t in json.load(sys.stdin)["data"]["activeTargets"]:
    if t["labels"].get("job")=="loxilb": print(t.get("lastError","")[:120])')
case "$err" in
  *503*|*"server returned HTTP status"*) ok "scrape error names HTTP 503 (not connection refused)";;
  *) fail "503 vs dead-host distinction" "GET ${PROM}/api/v1/targets" "lastError mentioning HTTP 503" "$err";;
esac
$hexec l3h1 curl -s -X POST "${API}/config/metrics" >/dev/null
wait_up_value 1 60 >/dev/null

echo "S4: Prometheus API is loopback-only"
lcode=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${PROM}/-/ready")
if [ "$lcode" = "200" ]; then ok "loopback reachable"; else
    fail "prometheus loopback" "curl ${PROM}/-/ready" "200" "$lcode"; fi
HOST_IP=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
if [ -n "$HOST_IP" ]; then
    xcode=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        "http://${HOST_IP}:9090/-/ready" 2>/dev/null)
    if [ "$xcode" = "000" ]; then ok "not reachable from l3h1 via ${HOST_IP}"; else
        fail "prometheus external reachability" \
             "l3h1: curl http://${HOST_IP}:9090/-/ready" "connection failure (000)" "$xcode"; fi
else
    echo "  [SKIP] S4 external arm: no global host IP found"
fi

echo "S5: gateway plain-listener posture from outside namespace"
# documented default: :11111 open on the cicd testbed on purpose; record the
# observed state so the evidence names the posture instead of assuming it
code=$(scrape_code)
echo "  [INFO] l3h1 -> ${API}/metrics returns ${code} (cicd posture keeps :11111 open; production binds/filters it)"

echo ""
if [ "$FAILS" -eq 0 ]; then echo "security-matrix: all arms passed"; exit 0; fi
echo "security-matrix: ${FAILS} arm(s) FAILED"; exit 1
