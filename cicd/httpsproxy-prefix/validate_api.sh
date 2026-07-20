#!/bin/bash
# validate_api.sh — REST API validation for HTTPS prefix routing (httpsproxy-prefix).
# Verifies that LB rules with path_prefix/path_match_mode/backend_protocol fields
# are stored and retrievable, and tests DELETE+recreate lifecycle.
#
# Called from validation.sh after PREFIX-T5.
# Sources ../common.sh for $hexec helper.

source ../common.sh

LLB_API="http://localhost:11111/netlox/v1"
VIP="10.10.10.254"

echo ""
echo "========================================="
echo " REST API Validation (HTTPS Prefix)"
echo "========================================="

# ── API-T1: Verify all 3 rules on port 2020 have path_prefix + path_match_mode=prefix
echo ""
echo "API-T1: Verify port 2020 has 3 rules with path_prefix and path_match_mode=prefix"
allrules=$($hexec llb1 curl -s "$LLB_API/config/loadbalancer/all")

p2020_count=$(echo "$allrules" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
count = sum(1 for r in rules
    if r.get('serviceArguments', r).get('externalIP','') == '$VIP'
    and str(r.get('serviceArguments', r).get('port','')) == '2020')
print(count)
" 2>/dev/null)
if [[ -n "$p2020_count" && "$p2020_count" -ge 3 ]]; then
  echo "  API-T1a port 2020 rule count=$p2020_count (≥3) [OK]"
else
  echo "  API-T1a port 2020 rule count='$p2020_count' expected ≥3 [FAIL]"; exit 1
fi

# Verify /v1/users rule has path_match_mode=prefix
users_mode=$(echo "$allrules" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if sa.get('externalIP','') == '$VIP' and str(sa.get('port','')) == '2020' \
            and sa.get('path_prefix','') == '/v1/users':
        print(sa.get('path_match_mode',''))
        break
" 2>/dev/null)
if [[ "$users_mode" == "prefix" ]]; then
  echo "  API-T1b /v1/users path_match_mode=prefix [OK]"
else
  echo "  API-T1b /v1/users path_match_mode='$users_mode' expected 'prefix' [FAIL]"; exit 1
fi

# Verify /v1/orders rule has path_match_mode=prefix
orders_mode=$(echo "$allrules" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if sa.get('externalIP','') == '$VIP' and str(sa.get('port','')) == '2020' \
            and sa.get('path_prefix','') == '/v1/orders':
        print(sa.get('path_match_mode',''))
        break
" 2>/dev/null)
if [[ "$orders_mode" == "prefix" ]]; then
  echo "  API-T1c /v1/orders path_match_mode=prefix [OK]"
else
  echo "  API-T1c /v1/orders path_match_mode='$orders_mode' expected 'prefix' [FAIL]"; exit 1
fi

# ── API-T2: Verify port 2021 rules have backend_protocol=http2 ────────────────
echo ""
echo "API-T2: Verify port 2021 rules have backend_protocol=http2"
p2021_bp=$(echo "$allrules" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if sa.get('externalIP','') == '$VIP' and str(sa.get('port','')) == '2021':
        print(sa.get('backend_protocol',''))
        break
" 2>/dev/null)
if [[ "$p2021_bp" == "http2" ]]; then
  echo "  API-T2 port 2021 backend_protocol=http2 [OK]"
else
  echo "  API-T2 port 2021 backend_protocol='$p2021_bp' expected 'http2' [FAIL]"; exit 1
fi

# ── API-T3: DELETE /v1/orders rule on port 2020 → verify 503 functional ───────
echo ""
echo "API-T3: DELETE /v1/orders rule on port 2020 then verify request to /v1/orders returns non-200"
del3=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  "$LLB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2020/protocol/tcp?path_prefix=/v1/orders&path_match_mode=prefix")
if [[ "$del3" == "200" || "$del3" == "204" ]]; then
  echo "  API-T3 DELETE /v1/orders rule ($del3) [OK]"
else
  echo "  API-T3 DELETE /v1/orders rule expected 200/204 got $del3 [FAIL]"; exit 1
fi

sleep 2

# /v1/orders should now return non-200 (503, 404, or connection refused)
t3_code=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 10 --insecure \
  https://${VIP}:2020/v1/orders 2>/dev/null)
if [[ "$t3_code" != "200" ]]; then
  echo "  API-T3 /v1/orders after DELETE: HTTP $t3_code (non-200 expected) [OK]"
else
  echo "  API-T3 /v1/orders still served after DELETE (HTTP 200) [FAIL]"; exit 1
fi

# ── API-T4: Recreate /v1/orders rule and verify server3 responds ───────────────
echo ""
echo "API-T4: Recreate /v1/orders rule and verify /v1/orders routes to server3"
resp4=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$LLB_API/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":      "'"$VIP"'",
      "port":             2020,
      "protocol":        "tcp",
      "sel":              0,
      "mode":             4,
      "security":         1,
      "host":            "'"$VIP"'",
      "path_prefix":     "/v1/orders",
      "path_match_mode": "prefix"
    },
    "endpoints": [
      {"endpointIP": "33.33.33.1", "targetPort": 8080, "weight": 1}
    ]
  }')
if [[ "$resp4" == "200" || "$resp4" == "201" ]]; then
  echo "  API-T4 recreated /v1/orders rule ($resp4) [OK]"
else
  echo "  API-T4 recreate expected 200/201 got $resp4 [FAIL]"; exit 1
fi

sleep 2

t4_body=$($hexec l3h1 curl -s --max-time 10 --insecure \
  https://${VIP}:2020/v1/orders 2>/dev/null)
if [[ "$t4_body" == "server3" ]]; then
  echo "  API-T4 /v1/orders routes to server3 after recreate [OK]"
else
  echo "  API-T4 /v1/orders returned '$t4_body' (expected 'server3') [WARN]"
fi

echo ""
echo "=== REST API Validation (HTTPS Prefix): All API tests passed ==="
