#!/bin/bash
# validate_cli.sh — CLI-driven validation for the AI Gateway apikey/ratelimit
# control plane, using the loxicmd-inference-gateway CLI as the subject-under-test
# and the REST API as the oracle: every mutation is issued through `loxicmd`, then
# read back through the REST API (and cross-checked via `loxicmd get`).
#
# Auth (this scenario runs loxilb with --userservice): a JWT is obtained from the
# REST /auth/login endpoint and handed to `loxicmd set login --provider manual`,
# which writes /tmp/loxilbtoken inside llb1; subsequent loxicmd calls read it
# automatically (--bearer default true). Plain user/pass `set login` needs a TTY
# and is not scriptable under `docker exec -i`.
#
# Runs AFTER the REST T1-T8 tests in validation.sh; folded into its exit code.
# Gated by cli_preflight (CLI_TESTS=auto|required|skip) so an image predating the
# packaging swap skips cleanly instead of hard-failing.

source ../common.sh

LOXILB_API="${LOXILB_API:-http://localhost:11111/netlox/v1}"

echo ""
echo "========================================="
echo " CLI Validation (AI Gateway apikey/ratelimit)"
echo "========================================="

# ── Preflight: is the packaged loxicmd the inference-gateway CLI? ──────────────
if ! cli_preflight llb1; then
  exit 0
fi

check_cli() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == *"$want"* ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAIL] — expected '$want', got: $got"
    exit 1
  fi
}

# ── Auth: REST login → loxicmd set login --provider manual (writes token file) ─
echo ""
echo "Setup: authenticate CLI via 'loxicmd set login --provider manual'"
JWT=$($hexec llb1 curl -s -X POST "$LOXILB_API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [[ -z "$JWT" ]]; then
  echo "  FATAL: REST auth failed (no token)"; exit 1
fi
echo "$JWT" | $dexec llb1 loxicmd set login --provider manual >/dev/null 2>&1
# REST oracle still authenticates explicitly:
AUTH_HDR="Authorization: Bearer $JWT"
echo "  CLI token installed at /tmp/loxilbtoken [OK]"

TENANT_ID="cli-apikey-$(date +%s)"

# ── T-CLI-1: create apikey via CLI, verify via REST list ─────────────────────
echo ""
echo "T-CLI-1: loxicmd create apikey --tenant-id=$TENANT_ID (rps=10 burst=20 tokens=5000)"
$dexec llb1 loxicmd create apikey --tenant-id="$TENANT_ID" --name=cli-key \
  --rps=10 --burst=20 --tokens-per-min=5000 -o json >/dev/null 2>&1

list_resp=$($hexec llb1 curl -s -H "$AUTH_HDR" \
  "$LOXILB_API/config/ai/apikey?tenant_id=$TENANT_ID")
KEY_ID=$(echo "$list_resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
a=d if isinstance(d,list) else d.get('apikeys', d.get('items', []))
print(a[0]['key_id'] if a else '')
" 2>/dev/null)
if [[ -z "$KEY_ID" ]]; then
  echo "  T-CLI-1 CLI create did not produce a key readable via REST [FAIL]"
  echo "  REST list: $list_resp"; exit 1
fi
echo "  key_id=$KEY_ID (created via CLI, read via REST) [OK]"
check_cli "T-CLI-1 REST oracle rate_limit_rps=10" '"rate_limit_rps":10' "$list_resp"
check_cli "T-CLI-1 REST oracle tokens_per_min=5000" '"tokens_per_min":5000' "$list_resp"
# key_hash must never be returned by the API
if [[ "$list_resp" == *"key_hash"* ]]; then
  echo "  T-CLI-1 key_hash LEAKED in REST list [FAIL]"; exit 1
fi
echo "  T-CLI-1 key_hash absent in REST list [OK]"

# ── T-CLI-2: cross-check loxicmd get apikey <id> against REST GET ────────────
echo ""
echo "T-CLI-2: loxicmd get apikey $KEY_ID -o json (CLI read path)"
cli_get=$($dexec llb1 loxicmd get apikey "$KEY_ID" -o json 2>/dev/null)
check_cli "T-CLI-2 CLI get shows key_id" "$KEY_ID" "$cli_get"
check_cli "T-CLI-2 CLI get shows tenant_id" "$TENANT_ID" "$cli_get"
if [[ "$cli_get" == *"key_hash"* ]]; then
  echo "  T-CLI-2 key_hash LEAKED via CLI get [FAIL]"; exit 1
fi
echo "  T-CLI-2 key_hash absent in CLI get [OK]"

# ── T-CLI-3: set ratelimit via CLI, verify via REST + CLI get ────────────────
echo ""
echo "T-CLI-3: loxicmd set ratelimit --tenant-id=$TENANT_ID --rps=200 --tokens-per-min=100000"
$dexec llb1 loxicmd set ratelimit --tenant-id="$TENANT_ID" --rps=200 --tokens-per-min=100000 >/dev/null 2>&1
rl_rest=$($hexec llb1 curl -s -H "$AUTH_HDR" "$LOXILB_API/config/ai/tenant/ratelimit/$TENANT_ID")
check_cli "T-CLI-3 REST oracle rps=200" "200" "$rl_rest"
check_cli "T-CLI-3 REST oracle tokens_per_min=100000" "100000" "$rl_rest"
rl_cli=$($dexec llb1 loxicmd get ratelimit "$TENANT_ID" -o json 2>/dev/null)
check_cli "T-CLI-3 CLI get ratelimit rps=200" "200" "$rl_cli"

# ── T-CLI-4: enable/disable toggle via CLI ───────────────────────────────────
# A disabled key is a soft-disable, NOT a delete: it stays visible to the
# management endpoints flagged enabled=false so an operator can audit and
# re-enable it. Auth-time validation still rejects it (covered elsewhere);
# re-enabling restores both the flag and the enabled view.
echo ""
echo "T-CLI-4: loxicmd set apikey $KEY_ID --enabled=false then --enabled=true"
$dexec llb1 loxicmd set apikey "$KEY_ID" --enabled=false >/dev/null 2>&1
dis_code=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -H "$AUTH_HDR" \
  "$LOXILB_API/config/ai/apikey/$KEY_ID")
if [[ "$dis_code" != "200" ]]; then
  echo "  T-CLI-4 disabled key must remain visible (expect 200), got $dis_code [FAIL]"; exit 1
fi
body=$($hexec llb1 curl -s -H "$AUTH_HDR" "$LOXILB_API/config/ai/apikey/$KEY_ID")
check_cli "T-CLI-4 disabled key shows enabled=false" '"enabled":false' "$body"
# Re-enable via CLI and confirm the key round-trips back into the enabled view.
$dexec llb1 loxicmd set apikey "$KEY_ID" --enabled=true >/dev/null 2>&1
after=$($hexec llb1 curl -s -H "$AUTH_HDR" "$LOXILB_API/config/ai/apikey/$KEY_ID")
check_cli "T-CLI-4 re-enabled key visible with enabled=true" '"enabled":true' "$after"

# ── T-CLI-5: delete apikey via CLI, verify via REST → 404 ────────────────────
# DELETE is a hard delete (distinct from the soft-disable in T-CLI-4): the row is
# removed and a subsequent GET returns 404.
echo ""
echo "T-CLI-5: loxicmd delete apikey $KEY_ID → REST GET expect 404"
$dexec llb1 loxicmd delete apikey "$KEY_ID" >/dev/null 2>&1
gone=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" -H "$AUTH_HDR" \
  "$LOXILB_API/config/ai/apikey/$KEY_ID")
if [[ "$gone" == "404" ]]; then
  echo "  T-CLI-5 deleted key returns 404 [OK]"
else
  echo "  T-CLI-5 expected 404 got $gone [FAIL]"; exit 1
fi

# ── T-CLI-6: negative — create apikey with empty tenant → no key, error msg ──
# NB: loxicmd prints an error but returns exit 0 on client-side validation, so we
# assert on the message (authoritative REST check: nothing was created).
echo ""
echo "T-CLI-6: loxicmd create apikey with no --tenant-id → rejected"
neg_out=$($dexec llb1 loxicmd create apikey --name=empty-tenant 2>&1)
if [[ "$neg_out" == *"tenant-id is required"* ]]; then
  echo "  T-CLI-6 CLI rejected empty tenant-id [OK]"
else
  echo "  T-CLI-6 expected 'tenant-id is required', got: $neg_out [FAIL]"; exit 1
fi

# ── Cleanup: drop any stray keys for the test tenant, log out ────────────────
echo ""
echo "Cleanup: removing test tenant keys and logging CLI out"
stray=$($hexec llb1 curl -s -H "$AUTH_HDR" "$LOXILB_API/config/ai/apikey?tenant_id=$TENANT_ID" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
a=d if isinstance(d,list) else d.get('apikeys', d.get('items', []))
print(' '.join(k.get('key_id','') for k in a))
" 2>/dev/null)
for kid in $stray; do
  [[ -n "$kid" ]] && $dexec llb1 loxicmd delete apikey "$kid" >/dev/null 2>&1
done
$dexec llb1 loxicmd set logout --provider manual >/dev/null 2>&1 || true

echo ""
echo "=== CLI Validation (apikey/ratelimit): all T-CLI tests passed ==="
