#!/bin/bash
# validate_cli.sh — CLI-driven validation for AI Gateway model-name routing,
# using loxicmd-inference-gateway as the subject-under-test and REST as the oracle.
# Each LB rule is created through `loxicmd create lb`, then verified via
# GET /config/loadbalancer/all (authoritative) and cross-checked with
# `loxicmd get loadbalancer -o json`.
#
# This scenario runs loxilb WITHOUT --userservice, so the CLI needs no token and
# the REST oracle sends no Authorization header. Spare ports 2030/2031 are used so
# the config.sh baseline (2020-2022) already checked by validation.sh is untouched.
#
# Runs AFTER the REST T1-T10 tests in validation.sh; folded into its exit code.
# Gated by cli_preflight (CLI_TESTS=auto|required|skip).

source ../common.sh

LOXILB_API="${LOXILB_API:-http://10.10.10.254:11111/netlox/v1}"
VIP="10.10.10.254"

echo ""
echo "========================================="
echo " CLI Validation (Model Routing)"
echo "========================================="

if ! cli_preflight llb1; then
  exit 0
fi

# rule_field <port> <field> — extract a serviceArguments field for the LB rule on
# <port> from GET /config/loadbalancer/all. Prints the JSON-encoded value, or the
# literal string __ABSENT__ if no rule on that port exists.
rule_field() {
  local port="$1" field="$2"
  $hexec llb1 curl -s "$LOXILB_API/config/loadbalancer/all" | python3 -c "
import sys,json
port=int('$port'); field='$field'
d=json.load(sys.stdin)
rules=d.get('lbAttr', d) if isinstance(d,dict) else d
for r in rules:
    sa=r.get('serviceArguments',{})
    if int(sa.get('port',-1))==port:
        print(json.dumps(sa.get(field)) if field in sa else 'null')
        break
else:
    print('__ABSENT__')
" 2>/dev/null
}

check_eq() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAIL] — expected '$want', got '$got'"; exit 1
  fi
}

# ── T-CLI-1: create model rule via CLI (port 2030, model=llama-70b) ──────────
echo ""
echo "T-CLI-1: loxicmd create lb $VIP --tcp=2030:8080 --mode=fullproxy --model-name=llama-70b"
$dexec llb1 loxicmd create lb "$VIP" --tcp=2030:8080 --mode=fullproxy \
  --endpoints=31.31.31.1:1 --host="$VIP" --path-prefix=/ --path-match-mode=prefix \
  --model-name=llama-70b >/dev/null 2>&1
sleep 1
check_eq "T-CLI-1 REST oracle port 2030 model_name" '"llama-70b"' "$(rule_field 2030 model_name)"

# ── T-CLI-2: cross-check via loxicmd get loadbalancer -o json ────────────────
echo ""
echo "T-CLI-2: loxicmd get loadbalancer -o json shows port 2030 + llama-70b"
cli_lb=$($dexec llb1 loxicmd get loadbalancer -o json 2>/dev/null)
if [[ "$cli_lb" == *"2030"* && "$cli_lb" == *"llama-70b"* ]]; then
  echo "  T-CLI-2 CLI get loadbalancer reflects rule [OK]"
else
  echo "  T-CLI-2 CLI get loadbalancer missing rule/model [FAIL]"; exit 1
fi

# ── T-CLI-3: backward-compat — rule WITHOUT --model-name (port 2031) ─────────
echo ""
echo "T-CLI-3: loxicmd create lb $VIP --tcp=2031:8080 (no --model-name) → empty model_name"
$dexec llb1 loxicmd create lb "$VIP" --tcp=2031:8080 --mode=fullproxy \
  --endpoints=31.31.31.1:1 --host="$VIP" --path-prefix=/ --path-match-mode=prefix \
  >/dev/null 2>&1
sleep 1
mn=$(rule_field 2031 model_name)
if [[ "$mn" == '""' || "$mn" == "null" ]]; then
  echo "  T-CLI-3 port 2031 present with empty model_name ($mn) [OK]"
else
  echo "  T-CLI-3 expected empty model_name, got '$mn' [FAIL]"; exit 1
fi

# ── T-CLI-4: delete through the CLI by the full L7 key ──────────────────────
# The rule key is host / path_prefix / path_match_mode / model_name on top of
# VIP:port/proto, so `loxicmd delete lb` has to send all of them. A host-only
# delete is a different key: it must fail (404) and leave the rule in place
# rather than silently removing something else.
echo ""
echo "T-CLI-4: loxicmd delete lb by full L7 key"
$dexec llb1 loxicmd delete lb "$VIP" --tcp 2030 --host="$VIP" >/dev/null 2>&1
sleep 1
check_eq "T-CLI-4 host-only delete leaves the model-keyed rule" '"llama-70b"' "$(rule_field 2030 model_name)"
$dexec llb1 loxicmd delete lb "$VIP" --tcp 2030 --host="$VIP" \
  --path-prefix=/ --path-match-mode=prefix --model-name=llama-70b >/dev/null 2>&1
$dexec llb1 loxicmd delete lb "$VIP" --tcp 2031 --host="$VIP" \
  --path-prefix=/ --path-match-mode=prefix >/dev/null 2>&1
sleep 1
check_eq "T-CLI-4 port 2030 removed (model-keyed)" "__ABSENT__" "$(rule_field 2030 model_name)"
check_eq "T-CLI-4 port 2031 removed (no model)" "__ABSENT__" "$(rule_field 2031 model_name)"

echo ""
echo "=== CLI Validation (Model Routing): all T-CLI tests passed ==="
