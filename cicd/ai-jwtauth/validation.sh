#!/bin/bash
# ai-jwtauth validation.
#
# Every refusal below is paired with a control that differs in exactly ONE
# variable — the profile, the user, or the credential — so a 401 cannot be
# passed off as "something in the path was unhappy". The scenario reads no
# gateway log to reach its verdicts: the controlled variable carries the
# proof, and logs are dumped only to explain a failure.
#
# Do not soften an assertion to make a run pass. Two legs in particular are
# born red on purpose:
#   E2 (segmented send) is RED on a build whose bearer capture keeps only
#      one parser fragment of the Authorization value;
#   C4 (failed key, valid JWT) is RED on any build that falls back to the
#      JWT arm after an API key was rejected.
cd "$(dirname "$0")"
source ../common.sh
echo SCENARIO-ai-jwtauth

PASS=0
FAIL=0
VIP=10.10.10.254

if [ ! -f .state ]; then
  echo "  FATAL: .state missing — run ./config.sh first"
  echo "SCENARIO-ai-jwtauth [FAILED]"
  exit 1
fi
# shellcheck disable=SC1091
source .state

chk_has() { # chk_has <name> <needle> <haystack>
  if [ "${3#*$2}" != "$3" ]; then
    echo "  [PASS] $1"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — did not find '$2' in: $(echo "$3" | tr '\n' ' ' | head -c 300)"; FAIL=$((FAIL + 1))
  fi
}
chk_not_has() { # chk_not_has <name> <forbidden> <haystack>
  if [ "${3#*$2}" = "$3" ]; then
    echo "  [PASS] $1"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — found forbidden '$2' in: $(echo "$3" | tr '\n' ' ' | head -c 300)"; FAIL=$((FAIL + 1))
  fi
}
status_of() { echo "$1" | head -1; }

body_llama='{"model":"llama-70b","messages":[{"role":"user","content":"hi"}]}'
body_mistral='{"model":"mistral-7b","messages":[{"role":"user","content":"hi"}]}'

# req <port> <body> <extra curl args...>
req() {
  local port=$1 body=$2; shift 2
  $hexec l3h1 curl -s -i --max-time 10 -X POST \
    -H "Content-Type: application/json" \
    "$@" \
    -d "$body" \
    "http://$VIP:$port/v1/chat/completions"
}
# bearer_req <port> <body> <token> <extra curl args...>
bearer_req() {
  local port=$1 body=$2 tok=$3; shift 3
  req "$port" "$body" -H "Authorization: Bearer $tok" "$@"
}

echo ""
echo "== A: the bearer arm on a JWT-enforcing service (port 2040, profile kc) =="

echo ""
echo "A1: valid token, model the token's roles allow → admitted"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE")
chk_has     "A1 200 status"        "200"          "$(status_of "$r")"
chk_has     "A1 llama pool answers" "server-llama" "$r"

echo ""
echo "A2: no Authorization header at all → 401 missing_token"
r=$(req 2040 "$body_llama")
chk_has     "A2 401 status"          "401"           "$(status_of "$r")"
chk_has     "A2 missing_token code"  "missing_token" "$r"
chk_not_has "A2 backend not reached" "server-llama"  "$r"

echo ""
echo "A3: same token with a corrupted signature → 401 invalid_token"
echo "    (header and payload are byte-identical to A1's token)"
r=$(bearer_req 2040 "$body_llama" "$TOK_BADSIG")
chk_has     "A3 401 status"          "401"           "$(status_of "$r")"
chk_has     "A3 invalid_token code"  "invalid_token" "$r"
chk_not_has "A3 backend not reached" "server-llama"  "$r"

echo ""
echo "A4: expired token → 401 token_expired"
echo "    (minted from the short-lifespan client, then waited past exp+leeway)"
# Keycloak is minted from the HOST: the docker bridge it sits on is not
# reachable from inside the client namespace, which only sees the VIP subnet.
KC_TOK_URL="$KC_ISSUER/protocol/openid-connect/token"
TOK_SHORT=$(curl -s --max-time 10 -X POST \
  -d "client_id=$KC_CLIENT_SHORT" -d "username=alice" -d "password=alicepw" \
  -d "grant_type=password" "$KC_TOK_URL" |
  python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
if [ -z "$TOK_SHORT" ]; then
  echo "  [FAIL] A4 could not mint a short-lifespan token"; FAIL=$((FAIL + 1))
else
  # Derive the wait from the token instead of assuming the configured
  # lifespan was honoured: a silently longer-lived token would turn this
  # leg into a test of a still-valid token quietly passing for the wrong
  # reason. Profile leeway is 2s; add 2s of margin.
  A4_WAIT=$(printf '%s' "$TOK_SHORT" | python3 -c "
import base64, json, sys, time
payload = sys.stdin.read().strip().split('.')[1]
payload += '=' * (-len(payload) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload))
print(int(claims['exp'] - time.time()) + 4)
" 2>/dev/null)
  case "$A4_WAIT" in
    ''|*[!0-9-]*) A4_WAIT=-1 ;;
  esac
  if [ "$A4_WAIT" -gt 90 ]; then
    echo "  [FAIL] A4 short-lifespan client issued a token valid for ~${A4_WAIT}s —"
    echo "         the realm's access.token.lifespan override did not take effect,"
    echo "         so this leg cannot prove expiry within a sane runtime."
    FAIL=$((FAIL + 1))
  elif [ "$A4_WAIT" -lt 0 ]; then
    echo "  [FAIL] A4 could not read exp from the short-lifespan token"; FAIL=$((FAIL + 1))
  else
    [ "$A4_WAIT" -gt 0 ] && sleep "$A4_WAIT"
    r=$(bearer_req 2040 "$body_llama" "$TOK_SHORT")
    chk_has     "A4 401 status"          "401"           "$(status_of "$r")"
    chk_has     "A4 token_expired code"  "token_expired" "$r"
    chk_not_has "A4 backend not reached" "server-llama"  "$r"
  fi
fi

echo ""
echo "A5: valid token with NO tenant claim → 401 (unattributable cannot be metered)"
echo "    (same profile and port as A1; only the user differs)"
r=$(bearer_req 2040 "$body_llama" "$TOK_CAROL")
chk_has     "A5 401 status"          "401"           "$(status_of "$r")"
chk_has     "A5 invalid_token code"  "invalid_token" "$r"
chk_not_has "A5 backend not reached" "server-llama"  "$r"

echo ""
echo "A6: valid token, model its roles do NOT cover → 403, not 401, not a steer"
r=$(bearer_req 2040 "$body_mistral" "$TOK_ALICE")
chk_has     "A6 403 status"            "403"                "$(status_of "$r")"
chk_has     "A6 model_not_allowed"     "model_not_allowed"  "$r"
chk_not_has "A6 mistral pool NOT reached" "server-mistral"  "$r"

echo ""
echo "A7: a different user's token DOES reach its own model → A6 is authorization,"
echo "    not an unreachable pool"
r=$(bearer_req 2040 "$body_mistral" "$TOK_BOB")
chk_has "A7 200 status"           "200"            "$(status_of "$r")"
chk_has "A7 mistral pool answers" "server-mistral" "$r"

echo ""
echo "A8: non-Bearer Authorization scheme → reads as no bearer credential"
r=$(req 2040 "$body_llama" -H "Authorization: Basic YWxpY2U6cHc=")
chk_has     "A8 401 status"          "401"          "$(status_of "$r")"
chk_has     "A8 missing_token code"  "missing_token" "$r"
chk_not_has "A8 backend not reached" "server-llama" "$r"

echo ""
echo "== B: the profile decides — issuer and audience (2042/2043 vs 2040) =="

echo ""
echo "B1: profile demanding an audience the token does not carry → 401"
r=$(bearer_req 2042 "$body_llama" "$TOK_ALICE")
chk_has     "B1 401 status"          "401"           "$(status_of "$r")"
chk_has     "B1 invalid_token code"  "invalid_token" "$r"
chk_not_has "B1 backend not reached" "server-llama"  "$r"

echo ""
echo "B2: profile naming a different issuer, same keys → 401"
r=$(bearer_req 2043 "$body_llama" "$TOK_ALICE")
chk_has     "B2 401 status"          "401"           "$(status_of "$r")"
chk_has     "B2 invalid_token code"  "invalid_token" "$r"
chk_not_has "B2 backend not reached" "server-llama"  "$r"

echo ""
echo "B3: control — THAT SAME token is admitted on the correctly configured"
echo "    profile, so B1/B2 are the profile's doing and not a stale token"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE")
chk_has "B3 200 status"         "200"          "$(status_of "$r")"
chk_has "B3 llama pool answers" "server-llama" "$r"

echo ""
echo "== C: apikey-or-jwt precedence (port 2041) =="
echo "   the API key allows llama-70b only; bob's token allows mistral-7b only"

echo ""
echo "C1: API key alone, model it allows → admitted"
r=$(req 2041 "$body_llama" -H "X-Api-Key: $RAW_KEY")
chk_has "C1 200 status"         "200"          "$(status_of "$r")"
chk_has "C1 llama pool answers" "server-llama" "$r"

echo ""
echo "C2: bearer alone, model it allows → admitted"
r=$(bearer_req 2041 "$body_mistral" "$TOK_BOB")
chk_has "C2 200 status"           "200"            "$(status_of "$r")"
chk_has "C2 mistral pool answers" "server-mistral" "$r"

echo ""
echo "C3: BOTH present, model only the token allows → the key decides, alone"
echo "    → 403 from the key's allow-list; an identity merge would admit this"
r=$(req 2041 "$body_mistral" -H "X-Api-Key: $RAW_KEY" -H "Authorization: Bearer $TOK_BOB")
chk_has     "C3 403 status"                "403"               "$(status_of "$r")"
chk_has     "C3 model_not_allowed"         "model_not_allowed" "$r"
chk_not_has "C3 mistral pool NOT reached"  "server-mistral"    "$r"

echo ""
echo "C4: REJECTED key + valid token for the same model → 401, NO fallback"
echo "    (fallback would let a caller probe one credential per request"
echo "     behind a single 401 — this leg is red on any build that does it)"
r=$(req 2041 "$body_llama" -H "X-Api-Key: not-a-real-key" -H "Authorization: Bearer $TOK_ALICE")
chk_has     "C4 401 status"                 "401"            "$(status_of "$r")"
chk_has     "C4 API-key arm named the deny" "invalid_api_key" "$r"
chk_not_has "C4 backend NOT reached"        "server-llama"   "$r"

echo ""
echo "C5: control — that same token alone IS admitted here, so C4's refusal"
echo "    is the failed key being final, not a bad token"
r=$(bearer_req 2041 "$body_llama" "$TOK_ALICE")
chk_has "C5 200 status"         "200"          "$(status_of "$r")"
chk_has "C5 llama pool answers" "server-llama" "$r"

echo ""
echo "C6: neither credential → 401"
r=$(req 2041 "$body_llama")
chk_has     "C6 401 status"          "401"          "$(status_of "$r")"
chk_not_has "C6 backend not reached" "server-llama" "$r"

echo ""
echo "== D: upstream hygiene — the backend reports what reached it =="

echo ""
echo "D1: defaults (port 2040) → backend sees no Authorization and no identity"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE")
chk_has "D1 backend answered"          "server-llama"       "$r"
chk_has "D1 Authorization stripped"    "authz=no"           "$r"
chk_has "D1 no tenant forwarded"       "xauth_tenant=-"     "$r"
chk_has "D1 no user forwarded"         "xauth_user=-"       "$r"

echo ""
echo "D2: forward_identity=true (port 2045) → verified identity IS injected"
r=$(bearer_req 2045 "$body_llama" "$TOK_ALICE")
chk_has     "D2 backend answered"       "server-llama"           "$r"
chk_has     "D2 tenant forwarded"       "xauth_tenant=tenant-a"  "$r"
chk_not_has "D2 user forwarded"         "xauth_user=-"           "$r"
chk_has     "D2 Authorization still stripped" "authz=no"         "$r"

echo ""
echo "D3: authorization_passthrough=true (port 2046) → header survives"
r=$(bearer_req 2046 "$body_llama" "$TOK_ALICE")
chk_has "D3 backend answered"        "server-llama" "$r"
chk_has "D3 Authorization passed on" "authz=yes"    "$r"

echo ""
echo "D4: client-sent X-Auth-* on a non-forwarding service → stripped as a spoof"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE" \
      -H "X-Auth-Tenant: evil-tenant" -H "X-Auth-User: evil-user")
chk_has     "D4 backend answered"        "server-llama"   "$r"
chk_not_has "D4 spoofed tenant stripped" "evil-tenant"    "$r"
chk_not_has "D4 spoofed user stripped"   "evil-user"      "$r"
chk_has     "D4 no tenant forwarded"     "xauth_tenant=-" "$r"

echo ""
echo "D5: client-sent X-Auth-* on a FORWARDING service → replaced, never merged"
r=$(bearer_req 2045 "$body_llama" "$TOK_ALICE" \
      -H "X-Auth-Tenant: evil-tenant" -H "X-Auth-User: evil-user")
chk_has     "D5 backend answered"           "server-llama"          "$r"
chk_has     "D5 verified tenant forwarded"  "xauth_tenant=tenant-a" "$r"
chk_not_has "D5 spoofed tenant not present" "evil-tenant"           "$r"
chk_not_has "D5 spoofed user not present"   "evil-user"             "$r"

echo ""
echo "D6: X-Api-Key is the gateway's namespace on JWT services too → stripped"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE" -H "X-Api-Key: some-backend-key")
chk_has "D6 backend answered"     "server-llama" "$r"
chk_has "D6 X-Api-Key stripped"   "apikey=no"    "$r"

echo ""
echo "== E: a large token delivered in fragments =="

echo ""
echo "E1: control — the large token is admitted when curl writes it normally"
DAVE_TOK=$(cat .tok_dave 2>/dev/null)
if [ -z "$DAVE_TOK" ]; then
  echo "  [FAIL] E1 .tok_dave missing — config.sh did not complete"; FAIL=$((FAIL + 1))
else
  r=$(bearer_req 2040 "$body_llama" "$DAVE_TOK")
  chk_has "E1 200 status"         "200"          "$(status_of "$r")"
  chk_has "E1 llama pool answers" "server-llama" "$r"
fi

echo ""
echo "E2: the SAME token in 200-byte writes → still admitted"
echo "    (the Authorization value now reaches the parser in many fragments;"
echo "     a capture that keeps one fragment answers 401 invalid_token here)"
r=$($hexec l3h1 python3 ./segmented_send.py "$VIP" 2040 "$(pwd)/.tok_dave" 200 15 2>/dev/null)
chk_has     "E2 200 status"          "200"           "$(status_of "$r")"
chk_has     "E2 llama pool answers"  "server-llama"  "$r"
chk_not_has "E2 not a signature 401" "invalid_token" "$r"

echo ""
echo "== F: HTTP/2 on a JWT-enforcing service is refused, not admitted =="
echo "   (the shared gate is not wired into the H2 path yet; the posture that"
echo "    matters is that it fails CLOSED — nothing reaches a backend)"
r=$($hexec l3h1 curl -s -i --max-time 10 --http2-prior-knowledge -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOK_ALICE" \
  -d "$body_llama" \
  "http://$VIP:2040/v1/chat/completions")
chk_has     "F1 401 status"                "401"          "$(status_of "$r")"
chk_not_has "F1 backend NOT reached"       "server-llama" "$r"

echo ""
echo "== G: fail-closed when the keyset was never fetched (port 2044) =="
echo "   nothing listens on the profile's JWKS endpoint, so the verifier has"
echo "   no keys — that is the gateway's outage, worth retrying: 503, and"
echo "   never a 200"
r=$(bearer_req 2044 "$body_llama" "$TOK_ALICE")
chk_has     "G1 503 status"                  "503"                       "$(status_of "$r")"
chk_has     "G1 policy_store_unavailable"    "policy_store_unavailable"  "$r"
chk_not_has "G1 backend NOT reached"         "server-llama"              "$r"

echo ""
if [ $FAIL -ne 0 ]; then
  echo "--- gateway log tail (diagnostics only; no assertion reads it) ---"
  docker logs --tail 120 llb1 2>&1 | grep -iE "aigateway|jwt|bearer" | tail -40
  echo "SCENARIO-ai-jwtauth [FAILED] ($PASS pass, $FAIL fail)"
  exit 1
fi
echo "SCENARIO-ai-jwtauth [OK] ($PASS pass)"
exit 0
