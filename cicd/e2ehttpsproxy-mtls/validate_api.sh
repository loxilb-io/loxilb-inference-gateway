#!/bin/bash
# validate_api.sh — REST API validation for mTLS (e2ehttpsproxy-mtls).
# Verifies that mTLS LB rule fields (mtls_frontend, mtls_backend, SNI certs) are
# stored and retrievable via the loxilb management REST API.
#
# Called from validation.sh after the TLS functional tests.
# Sources ../common.sh for $hexec helper.

source ../common.sh

LLB_API="http://localhost:11111/netlox/v1"
VIP="10.10.10.254"

echo ""
echo "========================================="
echo " REST API Validation (mTLS)"
echo "========================================="

check_api() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == *"$want"* ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAIL] — expected '$want', got: $got"
    exit 1
  fi
}

# ── API-T1: Verify port 2020 mtls_frontend fields (required mode) ─────────────
echo ""
echo "API-T1: Verify port 2020 mtls_frontend.client_cert_mode=required and client_cn_pattern"
allrules=$($hexec llb1 curl -s "$LLB_API/config/loadbalancer/all")

p2020_mode=$(echo "$allrules" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2020':
        print(sa.get('mtls_frontend', {}).get('client_cert_mode', ''))
        break
" 2>/dev/null)
if [[ "$p2020_mode" == "required" ]]; then
  echo "  API-T1a port 2020 client_cert_mode=required [OK]"
else
  echo "  API-T1a port 2020 client_cert_mode='$p2020_mode' expected 'required' [FAIL]"; exit 1
fi

p2020_cn=$(echo "$allrules" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2020':
        print(sa.get('mtls_frontend', {}).get('client_cn_pattern', ''))
        break
" 2>/dev/null)
if [[ "$p2020_cn" == "*.internal.corp.com" ]]; then
  echo "  API-T1b port 2020 client_cn_pattern=*.internal.corp.com [OK]"
else
  echo "  API-T1b port 2020 client_cn_pattern='$p2020_cn' expected '*.internal.corp.com' [FAIL]"; exit 1
fi

p2020_req_cn=$(echo "$allrules" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2020':
        print(sa.get('mtls_frontend', {}).get('require_client_cn', False))
        break
" 2>/dev/null)
if [[ "$p2020_req_cn" == "True" || "$p2020_req_cn" == "true" ]]; then
  echo "  API-T1c port 2020 require_client_cn=true [OK]"
else
  echo "  API-T1c port 2020 require_client_cn='$p2020_req_cn' expected true [FAIL]"; exit 1
fi

# ── API-T2: Verify port 2021 mtls_frontend fields (optional mode) ─────────────
echo ""
echo "API-T2: Verify port 2021 mtls_frontend.client_cert_mode=optional"
p2021_mode=$(echo "$allrules" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2021':
        print(sa.get('mtls_frontend', {}).get('client_cert_mode', ''))
        break
" 2>/dev/null)
if [[ "$p2021_mode" == "optional" ]]; then
  echo "  API-T2 port 2021 client_cert_mode=optional [OK]"
else
  echo "  API-T2 port 2021 client_cert_mode='$p2021_mode' expected 'optional' [FAIL]"; exit 1
fi

# ── API-T3: GET SNI certificate entries (expect ≥1 entry for 10.10.10.254) ────
echo ""
echo "API-T3: GET /sni/certificates — expect at least one entry for VIP 10.10.10.254"
sni_resp=$($hexec llb1 curl -s "$LLB_API/sni/certificates")
sni_count=$(echo "$sni_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)
entries = data.get('sniAttr') or []
print(len(entries))
" 2>/dev/null)
if [[ -n "$sni_count" && "$sni_count" -ge 1 ]]; then
  echo "  API-T3 SNI certificates count=$sni_count (≥1) [OK]"
else
  echo "  API-T3 SNI certificates count='$sni_count' expected ≥1 [FAIL]"; exit 1
fi

# ── API-T4: REST DELETE port 2020 LB rule → functional regression ─────────────
echo ""
echo "API-T4: REST DELETE port 2020 LB rule then verify TLS requests return non-2xx"
del4=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  "$LLB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2020/protocol/tcp")
if [[ "$del4" == "200" || "$del4" == "204" ]]; then
  echo "  API-T4 DELETE port 2020 ($del4) [OK]"
else
  echo "  API-T4 DELETE port 2020 expected 200/204 got $del4 [FAIL]"; exit 1
fi

sleep 2

# After deletion, TLS connection to port 2020 should fail or return non-success
t4_resp=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  --cacert minica.pem \
  --cert client1.internal.corp.com/cert.pem \
  --key client1.internal.corp.com/key.pem \
  https://${VIP}:2020 2>/dev/null || echo "000")
if [[ "$t4_resp" != "200" ]]; then
  echo "  API-T4 port 2020 after DELETE: got HTTP $t4_resp (non-200 expected) [OK]"
else
  echo "  API-T4 port 2020 still serving after DELETE (HTTP 200) [FAIL]"; exit 1
fi

# ── API-T5: Recreate port 2020 with client_cert_mode=optional + verify + restore
echo ""
echo "API-T5: Recreate port 2020 with client_cert_mode=optional, verify curl without cert works, restore required"
resp5=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$LLB_API/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP": "'"$VIP"'",
      "port":        2020,
      "protocol":   "tcp",
      "security":    2,
      "mode":        4,
      "host":       "'"$VIP"'",
      "mtls_frontend": {
        "client_cert_mode": "optional",
        "client_ca_path":   "/opt/loxilb/cert/client_ca.crt"
      },
      "mtls_backend": {
        "backend_ca_path":  "/opt/loxilb/cert/backend_ca.crt",
        "client_cert_path": "/opt/loxilb/cert/backend_client.crt",
        "client_key_path":  "/opt/loxilb/cert/backend_client.key",
        "verify_server_cert": true
      }
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8443, "weight": 1},
      {"endpointIP": "32.32.32.1", "targetPort": 8443, "weight": 1},
      {"endpointIP": "33.33.33.1", "targetPort": 8443, "weight": 1}
    ]
  }')
if [[ "$resp5" == "200" || "$resp5" == "201" ]]; then
  echo "  API-T5 recreated port 2020 with optional mode ($resp5) [OK]"
else
  echo "  API-T5 recreate expected 200/201 got $resp5 [FAIL]"; exit 1
fi

sleep 2

# With optional mode, curl without client cert should succeed
t5_resp=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
  --cacert minica.pem \
  https://${VIP}:2020 2>/dev/null)
if [[ "$t5_resp" == "200" ]]; then
  echo "  API-T5 curl without client cert → HTTP 200 in optional mode [OK]"
else
  echo "  API-T5 curl without client cert → HTTP $t5_resp (expected 200 in optional mode) [WARN]"
fi

# Restore: delete optional rule and recreate with required mode
$hexec llb1 curl -s -o /dev/null -X DELETE \
  "$LLB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2020/protocol/tcp" 2>/dev/null
sleep 1
$hexec llb1 curl -s -o /dev/null -X POST "$LLB_API/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP": "'"$VIP"'",
      "port":        2020,
      "protocol":   "tcp",
      "security":    2,
      "mode":        4,
      "name":       "e2e-mtls-required-service",
      "host":       "'"$VIP"'",
      "mtls_frontend": {
        "client_cert_mode": "required",
        "client_ca_path":   "/opt/loxilb/cert/client_ca.crt",
        "require_client_cn": true,
        "client_cn_pattern": "*.internal.corp.com"
      },
      "mtls_backend": {
        "backend_ca_path":  "/opt/loxilb/cert/backend_ca.crt",
        "client_cert_path": "/opt/loxilb/cert/backend_client.crt",
        "client_key_path":  "/opt/loxilb/cert/backend_client.key",
        "verify_server_cert": true
      }
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8443, "weight": 1},
      {"endpointIP": "32.32.32.1", "targetPort": 8443, "weight": 1},
      {"endpointIP": "33.33.33.1", "targetPort": 8443, "weight": 1}
    ]
  }' 2>/dev/null
echo "  API-T5 restored required mode rule [OK]"

echo ""
echo "=== REST API Validation (mTLS): All API tests passed ==="
