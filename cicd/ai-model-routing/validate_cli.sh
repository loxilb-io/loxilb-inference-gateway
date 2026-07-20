#!/bin/bash
# validate_cli.sh — End-to-end REST API validation for model routing.
# Replaces the former loxicmd-based CLI tests with direct REST API calls so that
# CI is not blocked by loxicmd binary availability or version skew.
#
# Runs AFTER existing T1-T10 REST tests in validation.sh.
# Sources ../common.sh for $hexec helper.

source ../common.sh

LOXILB_API="${LOXILB_API:-http://10.10.10.254:11111/netlox/v1}"
VIP="10.10.10.254"

echo ""
echo "========================================="
echo " REST API Validation (Model Routing)"
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

# ── T-CLI-1: Create LB rule with model_name ──────────────────────────────────
# Uses port 2030 (distinct from REST test ports 2020-2022) to avoid conflicts.
echo ""
echo "T-CLI-1: Create LB rule with model_name=llama-70b via POST /config/loadbalancer"
resp=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$LOXILB_API/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":     "'"$VIP"'",
      "port":            2030,
      "protocol":       "tcp",
      "sel":             0,
      "mode":            4,
      "host":           "'"$VIP"'",
      "path_prefix":    "/v1/chat/completions",
      "path_match_mode": "prefix",
      "model_name":     "llama-70b",
      "inactiveTimeOut": 30
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}
    ]
  }')
if [[ "$resp" == "200" || "$resp" == "201" ]]; then
  echo "  T-CLI-1 create LB ($resp) [OK]"
else
  echo "  T-CLI-1 expected 200/201 got $resp [FAIL]"; exit 1
fi

sleep 1

# ── T-CLI-2: Verify rule via GET /config/loadbalancer/all ────────────────────
echo ""
echo "T-CLI-2: Verify llama-70b rule exists via GET /config/loadbalancer/all"
all_resp=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")
check_cli "T-CLI-2 response contains llama-70b" "llama-70b" "$all_resp"
check_cli "T-CLI-2 response contains port 2030" "2030" "$all_resp"

# ── T-CLI-3: Verify model_name field in JSON response ────────────────────────
echo ""
echo "T-CLI-3: Verify model_name field in JSON response"
model_val=$(echo "$all_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2030':
        print(sa.get('model_name',''))
        break
" 2>/dev/null)
if [[ "$model_val" == "llama-70b" ]]; then
  echo "  T-CLI-3 model_name=llama-70b in JSON [OK]"
else
  echo "  T-CLI-3 model_name='$model_val' expected 'llama-70b' [FAIL]"; exit 1
fi

# ── T-CLI-4: Delete LB rule with model_name ──────────────────────────────────
echo ""
echo "T-CLI-4: Delete LB rule model_name=llama-70b via DELETE"
del_code=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  "$LOXILB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2030/protocol/tcp?path_prefix=/v1/chat/completions&path_match_mode=prefix&model_name=llama-70b")
if [[ "$del_code" == "200" || "$del_code" == "204" ]]; then
  echo "  T-CLI-4 deleted ($del_code) [OK]"
else
  echo "  T-CLI-4 expected 200/204 got $del_code [FAIL]"; exit 1
fi

sleep 1

# ── T-CLI-5: Verify rule is gone ─────────────────────────────────────────────
echo ""
echo "T-CLI-5: Verify port 2030 / llama-70b rule gone after delete"
all_resp=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")
# Check both model_name AND port 2030 are absent (avoid false match on remaining rules)
if echo "$all_resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2030':
        raise SystemExit(1)
" 2>/dev/null; then
  echo "  T-CLI-5 port 2030 absent after delete [OK]"
else
  echo "  T-CLI-5 port 2030 still present after delete [FAIL]"; exit 1
fi

# ── T-CLI-6: Create LB WITHOUT model_name (backward compat) ──────────────────
echo ""
echo "T-CLI-6: Create LB without model_name (backward compat) on port 2031"
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
      "inactiveTimeOut": 30
    },
    "endpoints": [
      {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
    ]
  }')
if [[ "$resp6" == "200" || "$resp6" == "201" ]]; then
  echo "  T-CLI-6 create LB no model_name ($resp6) [OK]"
else
  echo "  T-CLI-6 expected 200/201 got $resp6 [FAIL]"; exit 1
fi

# Verify port 2031 rule exists in GET /all
all_resp6=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")
check_cli "T-CLI-6 port 2031 present" "2031" "$all_resp6"

# ── T-CLI-7: Delete backward-compat rule ─────────────────────────────────────
echo ""
echo "T-CLI-7: Delete LB rule port 2031 (no model_name) via DELETE"
del7=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  "$LOXILB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2031/protocol/tcp?path_prefix=/v1/completions&path_match_mode=prefix")
if [[ "$del7" == "200" || "$del7" == "204" ]]; then
  echo "  T-CLI-7 deleted ($del7) [OK]"
else
  echo "  T-CLI-7 expected 200/204 got $del7 [FAIL]"; exit 1
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────
$hexec l3h1 curl -s -o /dev/null -X DELETE \
  "$LOXILB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2030/protocol/tcp?path_prefix=/v1/chat/completions&path_match_mode=prefix&model_name=llama-70b" 2>/dev/null
$hexec l3h1 curl -s -o /dev/null -X DELETE \
  "$LOXILB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2031/protocol/tcp?path_prefix=/v1/completions&path_match_mode=prefix" 2>/dev/null

# ── API-T1: GET-roundtrip verification of config.sh rules ────────────────────
echo ""
echo "API-T1: Verify config.sh rules (ports 2020/2021/2022) stored with correct model_name"
cfgall=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")

p2020_model=$(echo "$cfgall" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2020':
        print(sa.get('model_name',''))
        break
" 2>/dev/null)
if [[ "$p2020_model" == "llama-70b" ]]; then
  echo "  API-T1a port 2020 model_name=llama-70b [OK]"
else
  echo "  API-T1a port 2020 model_name='$p2020_model' expected 'llama-70b' [FAIL]"; exit 1
fi

p2021_model=$(echo "$cfgall" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2021':
        print(sa.get('model_name',''))
        break
" 2>/dev/null)
if [[ "$p2021_model" == "mistral-7b" ]]; then
  echo "  API-T1b port 2021 model_name=mistral-7b [OK]"
else
  echo "  API-T1b port 2021 model_name='$p2021_model' expected 'mistral-7b' [FAIL]"; exit 1
fi

p2022_model=$(echo "$cfgall" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2022':
        print(sa.get('model_name','__empty__'))
        break
" 2>/dev/null)
if [[ -z "$p2022_model" || "$p2022_model" == "__empty__" || "$p2022_model" == "None" ]]; then
  echo "  API-T1c port 2022 wildcard (empty model_name) [OK]"
else
  echo "  API-T1c port 2022 model_name='$p2022_model' expected empty [FAIL]"; exit 1
fi

# ── API-T2: REST DELETE config.sh port 2021 (mistral-7b) rule ────────────────
echo ""
echo "API-T2: REST DELETE port 2021 (mistral-7b) rule via API"
del2=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  "$LOXILB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2021/protocol/tcp?path_prefix=/&path_match_mode=prefix&model_name=mistral-7b")
if [[ "$del2" == "200" || "$del2" == "204" ]]; then
  echo "  API-T2 DELETE port 2021 ($del2) [OK]"
else
  echo "  API-T2 DELETE port 2021 expected 200/204 got $del2 [FAIL]"; exit 1
fi

sleep 1

v2all=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")
if echo "$v2all" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2021':
        raise SystemExit(1)
" 2>/dev/null; then
  echo "  API-T2 port 2021 absent after DELETE [OK]"
else
  echo "  API-T2 port 2021 still present after DELETE [FAIL]"; exit 1
fi

# ── API-T3: Recreate port 2021 with updated model_name, verify, restore ───────
echo ""
echo "API-T3: Recreate port 2021 with model_name=mistral-v2 (update via DELETE+POST)"
resp3=$($hexec l3h1 curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$LOXILB_API/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":      "'"$VIP"'",
      "port":             2021,
      "protocol":        "tcp",
      "sel":              0,
      "mode":             4,
      "host":            "'"$VIP"'",
      "path_prefix":     "/",
      "path_match_mode": "prefix",
      "model_name":      "mistral-v2",
      "inactiveTimeOut": 30
    },
    "endpoints": [
      {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
    ]
  }')
if [[ "$resp3" == "200" || "$resp3" == "201" ]]; then
  echo "  API-T3 recreated port 2021 with mistral-v2 ($resp3) [OK]"
else
  echo "  API-T3 recreate expected 200/201 got $resp3 [FAIL]"; exit 1
fi

sleep 1

v3all=$($hexec l3h1 curl -s "$LOXILB_API/config/loadbalancer/all")
v3model=$(echo "$v3all" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data if isinstance(data, list) else data.get('lbAttr', data.get('services', []))
for r in rules:
    sa = r.get('serviceArguments', r)
    if str(sa.get('port','')) == '2021':
        print(sa.get('model_name',''))
        break
" 2>/dev/null)
if [[ "$v3model" == "mistral-v2" ]]; then
  echo "  API-T3 model_name=mistral-v2 verified via GET [OK]"
else
  echo "  API-T3 model_name='$v3model' expected 'mistral-v2' [FAIL]"; exit 1
fi

# Restore: delete mistral-v2 and put back mistral-7b
$hexec l3h1 curl -s -o /dev/null -X DELETE \
  "$LOXILB_API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/2021/protocol/tcp?path_prefix=/&path_match_mode=prefix&model_name=mistral-v2" 2>/dev/null
sleep 1
$hexec l3h1 curl -s -o /dev/null -X POST "$LOXILB_API/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":"'"$VIP"'","port":2021,"protocol":"tcp","sel":0,"mode":4,
      "host":"'"$VIP"'","path_prefix":"/","path_match_mode":"prefix",
      "model_name":"mistral-7b","inactiveTimeOut":30
    },
    "endpoints":[{"endpointIP":"32.32.32.1","targetPort":8080,"weight":1}]
  }' 2>/dev/null
echo "  API-T3 restored mistral-7b rule [OK]"

echo ""
echo "=== REST API Validation (Model Routing): All T-CLI tests passed ==="

