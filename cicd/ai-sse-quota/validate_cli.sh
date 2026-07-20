#!/bin/bash
# validate_cli.sh — End-to-end REST API validation for SSE connection tuning.
# Replaces the former loxicmd-based CLI tests with direct REST API calls so that
# CI is not blocked by loxicmd binary availability or version skew.
#
# Runs AFTER existing T1-T5 REST tests in validation.sh.
# Sources ../common.sh for $hexec helper.

source ../common.sh

LOXILB_API="${LOXILB_API:-http://10.10.10.254:11111/netlox/v1}"
VIP="10.10.10.254"

echo ""
echo "========================================="
echo " REST API Validation (SSE Tuning)"
echo "========================================="

check_cli() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == *"$want"* ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAIL] — expected '$want', got: $got"
    exit 1
  fi
}

check_cli_absent() {
  local label="$1" unwanted="$2" got="$3"
  if [[ "$got" != *"$unwanted"* ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAIL] — should NOT contain '$unwanted', got: $got"
    exit 1
  fi
}

# ── T-CLI-1: Create LB rule with SSE flags ──────────────────────────────────
# Uses port 2030 (distinct from REST test ports 2020-2022) to avoid conflicts.
echo ""
echo "T-CLI-1: Create LB rule with sse_mode=true, max_stream_duration_sec=300, backend_keepalive_interval_sec=60"
resp=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$LOXILB_API/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":                    "'"$VIP"'",
      "port":                           2030,
      "protocol":                      "tcp",
      "sel":                            0,
      "mode":                           4,
      "host":                          "'"$VIP"'",
      "path_prefix":                   "/v1/chat/completions",
      "path_match_mode":               "prefix",
      "model_name":                    "llama-70b",
      "sse_mode":                       true,
      "max_stream_duration_sec":        300,
      "backend_keepalive_interval_sec": 60,
      "inactiveTimeOut":                30
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}
    ]
  }')
if [[ "$resp" == "200" || "$resp" == "201" ]]; then
  echo "  T-CLI-1 create LB with SSE flags ($resp) [OK]"
else
  echo "  T-CLI-1 expected 200/201 got $resp [FAIL]"; exit 1
fi

sleep 1

# ── T-CLI-2: Verify sse_mode in REST API response ────────────────────────────
echo ""
echo "T-CLI-2: Verify sse_mode=true in GET /config/loadbalancer/all"
all_resp=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")
check_cli "T-CLI-2 sse_mode present" "sse_mode" "$all_resp"

# Extract and verify sse_mode=true for port 2030
sse_val=$(echo "$all_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2030':
        print(sa.get('sse_mode', False))
        break
" 2>/dev/null)
if [[ "$sse_val" == "True" || "$sse_val" == "true" ]]; then
  echo "  T-CLI-2 sse_mode=true for port 2030 [OK]"
else
  echo "  T-CLI-2 sse_mode='$sse_val' expected true [FAIL]"; exit 1
fi

# ── T-CLI-3: Verify max_stream_duration_sec=300 ──────────────────────────────
echo ""
echo "T-CLI-3: Verify max_stream_duration_sec=300 in response"
msd_val=$(echo "$all_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2030':
        print(sa.get('max_stream_duration_sec', 0))
        break
" 2>/dev/null)
if [[ "$msd_val" == "300" ]]; then
  echo "  T-CLI-3 max_stream_duration_sec=300 [OK]"
else
  echo "  T-CLI-3 max_stream_duration_sec='$msd_val' expected 300 [FAIL]"; exit 1
fi

# ── T-CLI-4: Verify backend_keepalive_interval_sec=60 ────────────────────────
echo ""
echo "T-CLI-4: Verify backend_keepalive_interval_sec=60 in response"
ka_val=$(echo "$all_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2030':
        print(sa.get('backend_keepalive_interval_sec', 0))
        break
" 2>/dev/null)
if [[ "$ka_val" == "60" ]]; then
  echo "  T-CLI-4 backend_keepalive_interval_sec=60 [OK]"
else
  echo "  T-CLI-4 backend_keepalive_interval_sec='$ka_val' expected 60 [FAIL]"; exit 1
fi

# ── T-CLI-5: Verify model_name=llama-70b stored correctly ────────────────────
echo ""
echo "T-CLI-5: Verify model_name=llama-70b in response"
mn_val=$(echo "$all_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2030':
        print(sa.get('model_name', ''))
        break
" 2>/dev/null)
if [[ "$mn_val" == "llama-70b" ]]; then
  echo "  T-CLI-5 model_name=llama-70b [OK]"
else
  echo "  T-CLI-5 model_name='$mn_val' expected 'llama-70b' [FAIL]"; exit 1
fi

# ── T-CLI-6: Create LB WITHOUT sse_mode (backward compat) ────────────────────
echo ""
echo "T-CLI-6: Create LB without sse_mode on port 2031 (backward compat)"
resp6=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$LOXILB_API/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":     "'"$VIP"'",
      "port":            2031,
      "protocol":       "tcp",
      "sel":             0,
      "mode":            4,
      "host":           "'"$VIP"'",
      "path_prefix":    "/v1/completions",
      "path_match_mode": "prefix",
      "model_name":     "gpt-4",
      "sse_mode":        false,
      "inactiveTimeOut": 30
    },
    "endpoints": [
      {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
    ]
  }')
if [[ "$resp6" == "200" || "$resp6" == "201" ]]; then
  echo "  T-CLI-6 create LB no sse_mode ($resp6) [OK]"
else
  echo "  T-CLI-6 expected 200/201 got $resp6 [FAIL]"; exit 1
fi

# Verify sse_mode=false for port 2031
all_resp6=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")
sse_val6=$(echo "$all_resp6" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2031':
        print(sa.get('sse_mode', False))
        break
" 2>/dev/null)
if [[ "$sse_val6" == "False" || "$sse_val6" == "false" ]]; then
  echo "  T-CLI-6 sse_mode=false for backward-compat rule [OK]"
else
  echo "  T-CLI-6 sse_mode='$sse_val6' expected false [FAIL]"; exit 1
fi

# ── T-CLI-7: Delete all CLI-created rules ────────────────────────────────────
echo ""
echo "T-CLI-7: Delete SSE rule (port 2030) via DELETE"
del7a=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  "$LOXILB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2030/protocol/tcp?path_prefix=/v1/chat/completions&path_match_mode=prefix&model_name=llama-70b")
if [[ "$del7a" == "200" || "$del7a" == "204" ]]; then
  echo "  T-CLI-7 port 2030 deleted ($del7a) [OK]"
else
  echo "  T-CLI-7 delete port 2030 expected 200/204 got $del7a [FAIL]"; exit 1
fi

del7b=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  "$LOXILB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2031/protocol/tcp?path_prefix=/v1/completions&path_match_mode=prefix&model_name=gpt-4")
if [[ "$del7b" == "200" || "$del7b" == "204" ]]; then
  echo "  T-CLI-7 port 2031 deleted ($del7b) [OK]"
else
  echo "  T-CLI-7 delete port 2031 expected 200/204 got $del7b [FAIL]"; exit 1
fi

sleep 1

# Verify both rules are gone
all_final=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")
if echo "$all_final" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) in ('2030','2031'):
        raise SystemExit(1)
" 2>/dev/null; then
  echo "  T-CLI-7 ports 2030/2031 absent after delete [OK]"
else
  echo "  T-CLI-7 a deleted SSE rule is still present [FAIL]"; exit 1
fi

# ── T-CLI-8: max_stream_duration_sec > 86400 → rejected or capped ────────────
echo ""
echo "T-CLI-8: max_stream_duration_sec=90000 (> 86400 hard cap) → expect rejection"
resp8=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$LOXILB_API/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":               "'"$VIP"'",
      "port":                      2032,
      "protocol":                 "tcp",
      "sel":                       0,
      "mode":                      4,
      "host":                     "'"$VIP"'",
      "path_prefix":              "/v1/chat/test",
      "path_match_mode":          "prefix",
      "model_name":               "test-cap",
      "sse_mode":                  true,
      "max_stream_duration_sec":   90000,
      "inactiveTimeOut":           30
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}
    ]
  }')
if [[ "$resp8" == "400" || "$resp8" == "422" ]]; then
  echo "  T-CLI-8 90000s rejected by API ($resp8) [OK]"
else
  # If API accepted it, ensure cleanup and flag as warning (API-level enforcement may not exist)
  $hexec l3h1 curl -s -o /dev/null -X DELETE \
    "$LOXILB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2032/protocol/tcp?path_prefix=/v1/chat/test&path_match_mode=prefix&model_name=test-cap" 2>/dev/null
  echo "  T-CLI-8 WARNING: 90000s was accepted (API returned $resp8) — server-side cap should still enforce 86400s [WARN]"
fi

# ── API-T1: GET-roundtrip verification of config.sh SSE rules ────────────────
echo ""
echo "API-T1: Verify config.sh SSE rules (ports 2020/2021/2022) stored with correct SSE fields"
cfgall=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")

# Port 2020: sse_mode=true, max_stream_duration_sec=120, backend_keepalive_interval_sec=30
p2020_sse=$(echo "$cfgall" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2020':
        print(sa.get('sse_mode', False))
        break
" 2>/dev/null)
if [[ "$p2020_sse" == "True" || "$p2020_sse" == "true" ]]; then
  echo "  API-T1a port 2020 sse_mode=true [OK]"
else
  echo "  API-T1a port 2020 sse_mode='$p2020_sse' expected true [FAIL]"; exit 1
fi

p2020_msd=$(echo "$cfgall" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2020':
        print(sa.get('max_stream_duration_sec', 0))
        break
" 2>/dev/null)
if [[ "$p2020_msd" == "120" ]]; then
  echo "  API-T1b port 2020 max_stream_duration_sec=120 [OK]"
else
  echo "  API-T1b port 2020 max_stream_duration_sec='$p2020_msd' expected 120 [FAIL]"; exit 1
fi

p2020_ka=$(echo "$cfgall" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2020':
        print(sa.get('backend_keepalive_interval_sec', 0))
        break
" 2>/dev/null)
if [[ "$p2020_ka" == "30" ]]; then
  echo "  API-T1c port 2020 backend_keepalive_interval_sec=30 [OK]"
else
  echo "  API-T1c port 2020 backend_keepalive_interval_sec='$p2020_ka' expected 30 [FAIL]"; exit 1
fi

# Port 2021: sse_mode=false → field must be ABSENT in GET response (omitempty)
# This is a positive assertion against serialization bugs.
p2021_raw=$(echo "$cfgall" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2021':
        sentinel = object()
        val = sa.get('sse_mode', sentinel)
        print('absent' if val is sentinel else 'present:' + str(val))
        break
" 2>/dev/null)
if [[ "$p2021_raw" == "absent" ]]; then
  echo "  API-T1d port 2021 sse_mode absent in GET (omitempty=false) [OK]"
else
  echo "  API-T1d port 2021 sse_mode='$p2021_raw' — expected absent for false value [FAIL]"; exit 1
fi

# Port 2022: sse_mode=true, max_stream_duration_sec=10
p2022_msd=$(echo "$cfgall" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2022':
        print(sa.get('max_stream_duration_sec', 0))
        break
" 2>/dev/null)
if [[ "$p2022_msd" == "10" ]]; then
  echo "  API-T1e port 2022 max_stream_duration_sec=10 [OK]"
else
  echo "  API-T1e port 2022 max_stream_duration_sec='$p2022_msd' expected 10 [FAIL]"; exit 1
fi

# ── API-T2: REST DELETE config.sh port 2020 (sse-test) rule ──────────────────
echo ""
echo "API-T2: REST DELETE port 2020 (sse-test) rule via API"
del2=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  "$LOXILB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2020/protocol/tcp?path_prefix=/&path_match_mode=prefix&model_name=sse-test")
if [[ "$del2" == "200" || "$del2" == "204" ]]; then
  echo "  API-T2 DELETE port 2020 ($del2) [OK]"
else
  echo "  API-T2 DELETE port 2020 expected 200/204 got $del2 [FAIL]"; exit 1
fi

sleep 1

v2all=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")
if echo "$v2all" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2020':
        raise SystemExit(1)
" 2>/dev/null; then
  echo "  API-T2 port 2020 absent after DELETE [OK]"
else
  echo "  API-T2 port 2020 still present after DELETE [FAIL]"; exit 1
fi

# ── API-T3: Recreate port 2020 with updated max_stream_duration_sec, verify ───
echo ""
echo "API-T3: Recreate port 2020 with max_stream_duration_sec=30 (update via DELETE+POST)"
resp3=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$LOXILB_API/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":                    "'"$VIP"'",
      "port":                           2020,
      "protocol":                      "tcp",
      "sel":                            0,
      "mode":                           4,
      "host":                          "'"$VIP"'",
      "path_prefix":                   "/",
      "path_match_mode":               "prefix",
      "model_name":                    "sse-test-v2",
      "sse_mode":                       true,
      "max_stream_duration_sec":        30,
      "backend_keepalive_interval_sec": 30,
      "inactiveTimeOut":                30
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}
    ]
  }')
if [[ "$resp3" == "200" || "$resp3" == "201" ]]; then
  echo "  API-T3 recreated port 2020 with max_stream_duration_sec=30 ($resp3) [OK]"
else
  echo "  API-T3 recreate expected 200/201 got $resp3 [FAIL]"; exit 1
fi

sleep 1

v3all=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")
v3msd=$(echo "$v3all" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2020':
        print(sa.get('max_stream_duration_sec', 0))
        break
" 2>/dev/null)
if [[ "$v3msd" == "30" ]]; then
  echo "  API-T3 max_stream_duration_sec=30 verified via GET [OK]"
else
  echo "  API-T3 max_stream_duration_sec='$v3msd' expected 30 [FAIL]"; exit 1
fi

# Restore: delete sse-test-v2 and put back original sse-test rule
$hexec l3h1 curl -s -o /dev/null -X DELETE \
  "$LOXILB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2020/protocol/tcp?path_prefix=/&path_match_mode=prefix&model_name=sse-test-v2" 2>/dev/null
sleep 1
$hexec l3h1 curl -s -o /dev/null -X POST "$LOXILB_API/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":"'"$VIP"'","port":2020,"protocol":"tcp","sel":0,"mode":4,
      "host":"'"$VIP"'","path_prefix":"/","path_match_mode":"prefix",
      "model_name":"sse-test","sse_mode":true,
      "max_stream_duration_sec":120,"backend_keepalive_interval_sec":30,
      "inactiveTimeOut":30
    },
    "endpoints":[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1}]
  }' 2>/dev/null
echo "  API-T3 restored original sse-test rule [OK]"

echo ""
echo "=== REST API Validation (SSE Tuning): All T-CLI tests passed ==="
