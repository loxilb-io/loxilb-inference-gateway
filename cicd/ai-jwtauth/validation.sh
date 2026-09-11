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

# Both helpers refuse an empty haystack. A request that never completed
# proves nothing either way, and for chk_not_has "absent from nothing" would
# otherwise be trivially true — a timeout would quietly turn every negative
# assertion green. The needle is matched literally: quoted inside [[ ]] it is
# a string, not a glob, so a needle containing * ? or [ cannot silently match
# something it does not equal.
# Every assertion name begins with its case ID. Recording them as they run
# is what lets the summary compare what executed against what was declared:
# a block that is deleted, renamed, or skipped by an early `continue` would
# otherwise just quietly stop being tested, and the suite would still say OK.
SEEN_CASES=""
note_case() {
  local id="${1%% *}"
  case "$id" in
    [A-Z][0-9]|[A-Z][0-9][0-9]) ;;
    *) return ;;
  esac
  case " $SEEN_CASES " in
    *" $id "*) ;;
    *) SEEN_CASES="$SEEN_CASES $id" ;;
  esac
}

chk_has() { # chk_has <name> <needle> <haystack>
  note_case "$1"
  if [ -z "$3" ]; then
    echo "  [FAIL] $1 — empty response; the request never completed"; FAIL=$((FAIL + 1)); return
  fi
  if [[ "$3" == *"$2"* ]]; then
    echo "  [PASS] $1"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — did not find '$2' in: $(echo "$3" | tr '\n' ' ' | head -c 300)"; FAIL=$((FAIL + 1))
  fi
}
chk_not_has() { # chk_not_has <name> <forbidden> <haystack>
  note_case "$1"
  if [ -z "$3" ]; then
    echo "  [FAIL] $1 — empty response; the request never completed"; FAIL=$((FAIL + 1)); return
  fi
  if [[ "$3" != *"$2"* ]]; then
    echo "  [PASS] $1"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — found forbidden '$2' in: $(echo "$3" | tr '\n' ' ' | head -c 300)"; FAIL=$((FAIL + 1))
  fi
}
status_of() { echo "$1" | head -1; }

# http_code_of pulls the code curl reported, so a status can be compared for
# equality instead of by searching the whole response for a three-digit
# string that could as easily come from a body or a header.
http_code_of() { # http_code_of <response-with--w-http_code>
  local c="${1##*http_code=}"
  c="${c%%[!0-9]*}"
  echo "$c"
}
chk_code() { # chk_code <name> <expected> <response-with--w-http_code>
  note_case "$1"
  local got; got=$(http_code_of "$3")
  # 000 is curl's "no response at all". Asserting equality already excludes
  # it, but it earns its own message: it means the request never completed,
  # which is a different failure from the wrong status.
  if [ -z "$got" ] || [ "$got" = "000" ]; then
    echo "  [FAIL] $1 — no HTTP status (curl reported '${got:-none}'); the request never completed"
    FAIL=$((FAIL + 1)); return
  fi
  if [ "$got" = "$2" ]; then
    echo "  [PASS] $1 (HTTP $got)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — HTTP $got, want $2"; FAIL=$((FAIL + 1))
  fi
}

# ---------------------------------------------------------------------------
# Independent backend receipt oracle.
#
# "The backend was not reached" is the core claim of every denial here, and a
# denial's client response cannot support it: the backend's label is absent
# whether the gateway refused the request or forwarded it and threw the answer
# away. Each request carries a unique nonce; the backends count it and are
# asked for the total from INSIDE their own namespaces, never through the
# gateway, so the number cannot be manufactured by the path under test.
# ---------------------------------------------------------------------------
# The nonce is passed through a FILE, not a variable. Every request here is
# made inside a command substitution, which is a subshell: a variable set by
# req() dies with it and the parent would read back an empty nonce. An empty
# nonce is not harmless — the backend has no receipts for it, so it reads 0,
# and every "the backend saw nothing" assertion would pass on any build,
# including one that forwarded the request. This was a real bug in this
# harness, caught only because the admitted cases assert a delta of 1.
NONCE_FILE=.nonce
new_nonce() {
  local n
  n=$(( $(cat "$NONCE_FILE" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$NONCE_FILE"
  LAST_NONCE="n$$-$n"
  echo "$LAST_NONCE" > "$NONCE_FILE.last"
}
# Reading CONSUMES the nonce. A receipt assertion that is not preceded by a
# fresh request would otherwise score the PREVIOUS request's count, which is
# how a direct curl call that bypasses req() silently inherits an unrelated
# oracle — it reported an admitted request's receipt against a denial and
# looked exactly like a backend leak.
last_nonce() {
  local n
  n=$(cat "$NONCE_FILE.last" 2>/dev/null)
  rm -f "$NONCE_FILE.last"
  echo "$n"
}
rm -f "$NONCE_FILE" "$NONCE_FILE.last"

# receipts <nonce> -> total across BOTH pools, or "unreadable"
receipts() {
  local n=$1 a b
  a=$($hexec l3ep1 curl -s --max-time 5 "http://127.0.0.1:8080/__receipts/$n" 2>/dev/null)
  b=$($hexec l3ep2 curl -s --max-time 5 "http://127.0.0.1:8080/__receipts/$n" 2>/dev/null)
  case "$a" in ''|*[!0-9]*) echo "unreadable"; return ;; esac
  case "$b" in ''|*[!0-9]*) echo "unreadable"; return ;; esac
  echo $((a + b))
}
chk_receipt() { # chk_receipt <name> <expected-count> [nonce]
  note_case "$1"
  local n="${3:-$(last_nonce)}" got
  # Without this the assertion silently degrades: an unknown nonce has no
  # receipts, so it reads 0 and every denial "passes" whatever the gateway
  # did with the request.
  if [ -z "$n" ]; then
    echo "  [FAIL] $1 — no nonce recorded for the last request; the receipt oracle is not wired"
    FAIL=$((FAIL + 1)); return
  fi
  got=$(receipts "$n")
  # A counter that cannot be read is not a counter that read zero. Reporting
  # "no receipts" here would turn a broken oracle into a passing denial.
  if [ "$got" = "unreadable" ]; then
    echo "  [FAIL] $1 — backend receipt counter unreadable; that is not proof of $2"
    FAIL=$((FAIL + 1)); return
  fi
  if [ "$got" = "$2" ]; then
    echo "  [PASS] $1 (backend receipts=$got)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — backend receipts=$got, want $2"; FAIL=$((FAIL + 1))
  fi
}

# metric_value <family> -> the summed value of every series in the family,
# or "unreadable". Summed rather than pinned to one label set so a family
# that gains a label does not silently start reading zero.
metric_value() {
  local out
  out=$($hexec l3h1 curl -s --max-time 8 "http://$VIP:11111/netlox/v1/metrics" 2>/dev/null |
    awk -v fam="$1" '$0 ~ "^" fam "([{ ]|$)" { v=$NF; if (v+0==v) { s+=v; n++ } } END { if (n>0) printf "%d", s; else print "unreadable" }')
  case "$out" in
    ''|*[!0-9]*) echo "unreadable" ;;
    *) echo "$out" ;;
  esac
}

body_llama='{"model":"llama-70b","messages":[{"role":"user","content":"hi"}]}'
body_mistral='{"model":"mistral-7b","messages":[{"role":"user","content":"hi"}]}'

# req <port> <body> <extra curl args...>
# Mints the nonce for this request, so every call site gets an independent
# receipt oracle without having to remember to ask for one.
req() {
  local port=$1 body=$2; shift 2
  new_nonce
  $hexec l3h1 curl -s -i --max-time 10 -X POST \
    -H "Content-Type: application/json" \
    -H "X-Test-Nonce: $LAST_NONCE" \
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
chk_receipt "A1 backend received exactly one" 1

echo ""
echo "A2: no Authorization header at all → 401 missing_token"
r=$(req 2040 "$body_llama")
chk_has     "A2 401 status"          "401"           "$(status_of "$r")"
chk_has     "A2 missing_token code"  "missing_token" "$r"
chk_receipt "A2 backend received nothing" 0

echo ""
echo "A3: same token with a corrupted signature → 401 invalid_token"
echo "    (header and payload are byte-identical to A1's token)"
r=$(bearer_req 2040 "$body_llama" "$TOK_BADSIG")
chk_has     "A3 401 status"          "401"           "$(status_of "$r")"
chk_has     "A3 invalid_token code"  "invalid_token" "$r"
chk_receipt "A3 backend received nothing" 0

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
    chk_receipt "A4 backend received nothing" 0
  fi
fi

echo ""
echo "A5: valid token with NO tenant claim → 401 (unattributable cannot be metered)"
echo "    (same profile and port as A1; only the user differs)"
r=$(bearer_req 2040 "$body_llama" "$TOK_CAROL")
chk_has     "A5 401 status"          "401"           "$(status_of "$r")"
chk_has     "A5 invalid_token code"  "invalid_token" "$r"
chk_receipt "A5 backend received nothing" 0

echo ""
echo "A6: valid token, model its roles do NOT cover → 403, not 401, not a steer"
r=$(bearer_req 2040 "$body_mistral" "$TOK_ALICE")
chk_has     "A6 403 status"            "403"                "$(status_of "$r")"
chk_has     "A6 model_not_allowed"     "model_not_allowed"  "$r"
chk_receipt "A6 backend received nothing" 0

echo ""
echo "A7: a different user's token DOES reach its own model → A6 is authorization,"
echo "    not an unreachable pool"
r=$(bearer_req 2040 "$body_mistral" "$TOK_BOB")
chk_has "A7 200 status"           "200"            "$(status_of "$r")"
chk_has "A7 mistral pool answers" "server-mistral" "$r"
chk_receipt "A7 backend received exactly one" 1

echo ""
echo "A8: non-Bearer Authorization scheme → reads as no bearer credential"
r=$(req 2040 "$body_llama" -H "Authorization: Basic YWxpY2U6cHc=")
chk_has     "A8 401 status"          "401"          "$(status_of "$r")"
chk_has     "A8 missing_token code"  "missing_token" "$r"
chk_receipt "A8 backend received nothing" 0

echo ""
echo "== B: the profile decides — issuer and audience (2042/2043 vs 2040) =="

echo ""
echo "B1: profile demanding an audience the token does not carry → 401"
r=$(bearer_req 2042 "$body_llama" "$TOK_ALICE")
chk_has     "B1 401 status"          "401"           "$(status_of "$r")"
chk_has     "B1 invalid_token code"  "invalid_token" "$r"
chk_receipt "B1 backend received nothing" 0

echo ""
echo "B2: profile naming a different issuer, same keys → 401"
r=$(bearer_req 2043 "$body_llama" "$TOK_ALICE")
chk_has     "B2 401 status"          "401"           "$(status_of "$r")"
chk_has     "B2 invalid_token code"  "invalid_token" "$r"
chk_receipt "B2 backend received nothing" 0

echo ""
echo "B3: control — THAT SAME token is admitted on the correctly configured"
echo "    profile, so B1/B2 are the profile's doing and not a stale token"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE")
chk_has "B3 200 status"         "200"          "$(status_of "$r")"
chk_has "B3 llama pool answers" "server-llama" "$r"
chk_receipt "B3 backend received exactly one" 1

echo ""
echo "== C: apikey-or-jwt precedence (port 2041) =="
echo "   the API key allows llama-70b only; bob's token allows mistral-7b only"

echo ""
echo "C1: API key alone, model it allows → admitted"
r=$(req 2041 "$body_llama" -H "X-Api-Key: $RAW_KEY")
chk_has "C1 200 status"         "200"          "$(status_of "$r")"
chk_has "C1 llama pool answers" "server-llama" "$r"
chk_receipt "C1 backend received exactly one" 1

echo ""
echo "C2: bearer alone, model it allows → admitted"
r=$(bearer_req 2041 "$body_mistral" "$TOK_BOB")
chk_has "C2 200 status"           "200"            "$(status_of "$r")"
chk_has "C2 mistral pool answers" "server-mistral" "$r"
chk_receipt "C2 backend received exactly one" 1

echo ""
echo "C3: BOTH present, model only the token allows → the key decides, alone"
echo "    → 403 from the key's allow-list; an identity merge would admit this"
r=$(req 2041 "$body_mistral" -H "X-Api-Key: $RAW_KEY" -H "Authorization: Bearer $TOK_BOB")
chk_has     "C3 403 status"                "403"               "$(status_of "$r")"
chk_has     "C3 model_not_allowed"         "model_not_allowed" "$r"
chk_receipt "C3 backend received nothing" 0

echo ""
echo "C4: REJECTED key + valid token for the same model → 401, NO fallback"
echo "    (fallback would let a caller probe one credential per request"
echo "     behind a single 401 — this leg is red on any build that does it)"
r=$(req 2041 "$body_llama" -H "X-Api-Key: not-a-real-key" -H "Authorization: Bearer $TOK_ALICE")
chk_has     "C4 401 status"                 "401"            "$(status_of "$r")"
chk_has     "C4 API-key arm named the deny" "invalid_api_key" "$r"
chk_receipt "C4 backend received nothing" 0

echo ""
echo "C5: control — that same token alone IS admitted here, so C4's refusal"
echo "    is the failed key being final, not a bad token"
r=$(bearer_req 2041 "$body_llama" "$TOK_ALICE")
chk_has "C5 200 status"         "200"          "$(status_of "$r")"
chk_has "C5 llama pool answers" "server-llama" "$r"
chk_receipt "C5 backend received exactly one" 1

echo ""
echo "C6: neither credential → 401"
r=$(req 2041 "$body_llama")
chk_has     "C6 401 status"          "401"          "$(status_of "$r")"
chk_receipt "C6 backend received nothing" 0

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
chk_receipt "E2 backend received exactly one" 1
chk_not_has "E2 not a signature 401" "invalid_token" "$r"

echo ""
echo "== F: HTTP/2 on a JWT-enforcing service is refused, not admitted =="
echo "   (the shared gate is not wired into the H2 path yet; the posture that"
echo "    matters is that it fails CLOSED — nothing reaches a backend)"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE" --http2-prior-knowledge)
chk_has     "F1 401 status"                "401"          "$(status_of "$r")"
chk_receipt "F1 backend received nothing" 0

echo ""
echo "== G: fail-closed when the keyset was never fetched (port 2044) =="
echo "   nothing listens on the profile's JWKS endpoint, so the verifier has"
echo "   no keys — that is the gateway's outage, worth retrying: 503, and"
echo "   never a 200"
r=$(bearer_req 2044 "$body_llama" "$TOK_ALICE")
chk_has     "G1 503 status"                  "503"                       "$(status_of "$r")"
chk_has     "G1 policy_store_unavailable"    "policy_store_unavailable"  "$r"
chk_receipt "G1 backend received nothing" 0

echo ""
echo "G2: that refusal is visible on the metric an operator watches"
echo "    (a keyset that was never fetched is the one denial worth paging on;"
echo "     the API-key arm has always counted it, so the bearer arm counting"
echo "     nothing would make a JWKS outage invisible where it is looked for)"
before=$(metric_value loxilb_ai_policy_store_unavailable_total)
r=$(bearer_req 2044 "$body_llama" "$TOK_ALICE")
chk_has "G2 still 503" "503" "$(status_of "$r")"
after=$(metric_value loxilb_ai_policy_store_unavailable_total)
note_case "G2"
if [ "$before" = "unreadable" ] || [ "$after" = "unreadable" ]; then
  # Metrics that cannot be read are not metrics that read zero: treating an
  # unreachable endpoint as "no change" would make this assertion pass on a
  # gateway that exports nothing at all.
  echo "  [FAIL] G2 metric unreadable (before=$before after=$after); that is not a delta of 1"
  FAIL=$((FAIL + 1))
elif [ "$((after - before))" = "1" ]; then
  echo "  [PASS] G2 policy_store_unavailable incremented by exactly 1 ($before -> $after)"
  PASS=$((PASS + 1))
else
  echo "  [FAIL] G2 policy_store_unavailable went $before -> $after, want exactly +1"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "== I: the IdP goes down and comes back (port 2047, profile kc-outage) =="
echo "   G is an IdP that was never reachable. This is the operational case:"
echo "   keys were fetched, then Keycloak went away. Admission must keep"
echo "   working on the last-known-good keyset — a gateway that answered 503"
echo "   for every request whenever its IdP restarted would turn a survivable"
echo "   IdP blip into a total outage of the inference plane."
echo "   kc-outage refreshes every 10s and the fetch timeout is 10s, so the"
echo "   pause below outlives a refresh that must fail."

# Freeze rather than stop: kc-aigw runs with --rm, so stopping it destroys
# the container and there is nothing to bring back. A pause keeps the same
# container and the same IP, so the profile's jwks_url stays valid and the
# outage is exactly "the endpoint stopped answering".
KC_PAUSED=""
unpause_kc() {
    if [ -n "$KC_PAUSED" ]; then
        docker unpause "$KC_NAME" >/dev/null 2>&1
        KC_PAUSED=""
    fi
}
# An early exit between the pause and the unpause would leave the realm
# frozen for whatever runs next on this host.
trap unpause_kc EXIT

# I0 first: if the port were broken for an unrelated reason, every assertion
# below would "pass" for the wrong reason.
r=$(bearer_req 2047 "$body_llama" "$TOK_ALICE")
chk_has "I0 control: admitted while the IdP is up" "200"          "$(status_of "$r")"
chk_has "I0 llama pool answers"                    "server-llama" "$r"
chk_receipt "I0 backend received exactly one" 1

if docker pause "$KC_NAME" >/dev/null 2>&1; then
    KC_PAUSED=1
    echo "  kc-aigw paused; waiting 25s so a refresh falls inside the outage"
    sleep 25

    # I1 is what stops the rest of this group being vacuous: it proves the
    # IdP really is unreachable. Without it, I2 passing would say nothing —
    # a Keycloak that never went down also admits traffic.
    OUTAGE_TOK=$(curl -s --max-time 5 -X POST \
      -d "client_id=aigw-client" -d "username=alice" -d "password=alicepw" \
      -d "grant_type=password" "$KC_ISSUER/protocol/openid-connect/token" |
      python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
    note_case "I1"
    if [ -z "$OUTAGE_TOK" ]; then
        echo "  [PASS] I1 the IdP is genuinely unreachable (no new token can be minted)"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] I1 minted a token while Keycloak was paused — the outage is not"
        echo "         real, so I2 below would prove nothing"
        FAIL=$((FAIL + 1))
    fi

    # I2: the already-issued token still works. The verifier holds keys, not
    # a session with the IdP, so admission does not depend on it per request.
    r=$(bearer_req 2047 "$body_llama" "$TOK_ALICE")
    chk_has     "I2 admitted during the IdP outage"     "200"          "$(status_of "$r")"
    chk_has     "I2 llama pool answers"                 "server-llama" "$r"
    # Named separately because 503 is the specific wrong answer here: it is
    # what G returns, and returning it here would mean the fail-closed reflex
    # fired on an outage the gateway was equipped to survive.
    chk_not_has "I2 NOT policy_store_unavailable"       "policy_store_unavailable" "$r"

    unpause_kc
    echo "  kc-aigw unpaused"

    # I3: the IdP is back, and the gateway did not wedge while it was away.
    # A freshly minted token exercises the whole chain again, end to end.
    for i in $(seq 1 30); do
        BACK_TOK=$(curl -s --max-time 5 -X POST \
          -d "client_id=aigw-client" -d "username=alice" -d "password=alicepw" \
          -d "grant_type=password" "$KC_ISSUER/protocol/openid-connect/token" |
          python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
        [ -n "$BACK_TOK" ] && break
        sleep 1
    done
    if [ -z "$BACK_TOK" ]; then
        echo "  [FAIL] I3 Keycloak never answered again after unpause"; FAIL=$((FAIL + 1))
    else
        r=$(bearer_req 2047 "$body_llama" "$BACK_TOK")
        chk_has "I3 token minted after recovery is admitted" "200"          "$(status_of "$r")"
        chk_has "I3 llama pool answers"                      "server-llama" "$r"
    fi
else
    echo "  [FAIL] I could not pause $KC_NAME — the outage group did not run"
    FAIL=$((FAIL + 1))
fi
trap - EXIT

echo ""
echo "== H: the profile reference is validated, both directions =="
echo "   (kept last: H1 deliberately tries to create a rule, so a build that"
echo "    wrongly accepts it cannot disturb the legs above)"

# The assertions below read CONFIGURED STATE back rather than guessing which
# 2xx a create or delete returns: what matters is whether the profile is
# still there, not which success code carried the answer.
profile_names() {
  $hexec l3h1 curl -s --max-time 8 \
    "http://$VIP:11111/netlox/v1/config/ai/jwtauthprofile" |
  python3 -c '
import sys, json
try:
    doc = json.load(sys.stdin)
except Exception:
    sys.exit(0)
names = [str(p.get("name", "")) for p in doc.get("jwtAuthProfileAttr") or []]
# Space-padded so an assertion can match a whole name: "kc" must not be
# satisfied by "kc-wrongaud".
print(" " + " ".join(names) + " ")
'
}

echo ""
echo "H0: control — the listing is readable and names the profiles config.sh made"
names=$(profile_names)
chk_has "H0 kc listed"          " kc "          "$names"
chk_has "H0 kc-fwd listed"      " kc-fwd "      "$names"
chk_has "H0 kc-blackhole listed" " kc-blackhole " "$names"

echo ""
echo "H1: a jwt-mode rule naming a profile that is not configured → rejected"
echo "    (accepting it would leave a service that can only ever fail closed)"
r=$($hexec l3h1 curl -s --max-time 8 -w ' http_code=%{http_code}' -X POST \
  "http://$VIP:11111/netlox/v1/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP": "10.10.10.254", "port": 2049, "protocol": "tcp",
      "sel": 0, "mode": 4, "host": "10.10.10.254",
      "path_prefix": "/", "path_match_mode": "prefix",
      "model_name": "llama-70b",
      "api_key_auth": "jwt", "jwt_auth_profile": "no-such-profile",
      "inactiveTimeOut": 30
    },
    "endpoints": [{"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}]
  }')
chk_not_has "H1 rule not accepted"  "Success"       "$r"
# Exactly 400: the reference check returns a rule-argument rejection, which
# the API classifies as a validation error. Accepting "any status but 200"
# would let a 500, a 404, or curl's 000 stand in for the contract — three
# different defects that all mean the guard is not working as declared.
chk_code    "H1 rejected with the validation status" 400 "$r"

echo ""
echo "H2: deleting a profile that live rules reference → refused"
echo "    (ports 2040 and 2041 both point at kc)"
r=$($hexec l3h1 curl -s --max-time 8 -w ' http_code=%{http_code}' -X DELETE \
  "http://$VIP:11111/netlox/v1/config/ai/jwtauthprofile/kc")
# Exactly 409: a delete refused because live rules still reference the
# profile is a state collision, not a malformed request, and that is the
# status the spec declares for this route. Asserting only "not a success"
# passed while the handler answered 400, and would pass again on a 500.
chk_code "H2 refused with the declared conflict status" 409 "$r"
chk_has  "H2 refusal names the referencing rules" "referenced by rule" "$r"
names=$(profile_names)
chk_has "H2 kc is still configured" " kc " "$names"

echo ""
echo "H3: control — an UNREFERENCED profile deletes cleanly, so H2 is the"
echo "    reference guard and not a delete path that never works"
r=$($hexec l3h1 curl -s --max-time 8 -w ' http_code=%{http_code}' -X POST \
  "http://$VIP:11111/netlox/v1/config/ai/jwtauthprofile" \
  -H "Content-Type: application/json" \
  -d '{"name": "kc-scratch", "issuer": "http://127.0.0.1:9/realms/scratch",
       "jwks_url": "http://127.0.0.1:9/certs", "audiences": []}')
chk_code "H3 create reported success" 200 "$r"
names=$(profile_names)
chk_has "H3 scratch profile created" " kc-scratch " "$names"
r=$($hexec l3h1 curl -s --max-time 8 -w ' http_code=%{http_code}' -X DELETE \
  "http://$VIP:11111/netlox/v1/config/ai/jwtauthprofile/kc-scratch")
chk_code "H3 delete reported success" 200 "$r"
names=$(profile_names)
chk_not_has "H3 scratch profile deleted" " kc-scratch " "$names"

echo ""
echo "H4: control — kc survived H2 and the service it backs still admits"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE")
chk_has "H4 200 status"         "200"          "$(status_of "$r")"
chk_has "H4 llama pool answers" "server-llama" "$r"
chk_receipt "H4 backend received exactly one" 1

echo ""
echo "== J: an identity that is not safe to carry is refused, not spliced =="
echo "   The gateway writes the verified identity upstream as a plain"
echo "   name/value header line with no escaping, so a CR or LF in"
echo "   the value stops being data and becomes a second header inside a"
echo "   request the backend trusts because the gateway built it. A signature"
echo "   proves who minted a claim, not that its CONTENT is safe to splice"
echo "   into a protocol — and default_tenant reaches the same header from"
echo "   configuration. Both are refused."
# The value carries JSON \r\n escapes: the gateway's own JSON decode turns
# them into a real CR and LF, which is exactly how a hostile claim would
# arrive. Single-quoted so the shell leaves the backslashes alone.
r=$($hexec l3h1 curl -s --max-time 8 -w ' http_code=%{http_code}' -X POST \
  "http://$VIP:11111/netlox/v1/config/ai/jwtauthprofile" \
  -H "Content-Type: application/json" \
  --data-binary '{"name":"kc-inject","issuer":"http://127.0.0.1:9/realms/x","jwks_url":"http://127.0.0.1:9/certs","audiences":[],"default_tenant":"acme\r\nX-Auth-User: admin"}')
chk_code "J1 profile with an injectable default_tenant is rejected" 400 "$r"
names=$(profile_names)
chk_not_has "J1 the profile was not created" " kc-inject " "$names"

echo ""
echo "== Z: the suite ran what it claims to run =="
echo "   A deleted, renamed, or skipped block stops being tested silently:"
echo "   the pass count simply gets smaller and the run still says OK. This"
echo "   compares the case IDs that actually asserted against the declared"
echo "   set, so coverage cannot shrink without turning the run RED."
EXPECTED_CASES="A1 A2 A3 A4 A5 A6 A7 A8 B1 B2 B3 C1 C2 C3 C4 C5 C6 D1 D2 D3 D4 D5 D6 E1 E2 F1 G1 G2 H0 H1 H2 H3 H4 I0 I1 I2 I3 J1"
missing=""
for want in $EXPECTED_CASES; do
  case " $SEEN_CASES " in
    *" $want "*) ;;
    *) missing="$missing $want" ;;
  esac
done
extra=""
for got in $SEEN_CASES; do
  case " $EXPECTED_CASES " in
    *" $got "*) ;;
    *) extra="$extra $got" ;;
  esac
done
if [ -n "$missing" ]; then
  echo "  [FAIL] Z1 declared cases did not run:$missing"
  FAIL=$((FAIL + 1))
else
  echo "  [PASS] Z1 every declared case ran"
  PASS=$((PASS + 1))
fi
if [ -n "$extra" ]; then
  # Not a failure: a new case is good news. It has to be declared, though,
  # or the inventory stops being the thing that notices a deletion.
  echo "  [FAIL] Z2 cases ran that are not declared:$extra — add them to EXPECTED_CASES"
  FAIL=$((FAIL + 1))
else
  echo "  [PASS] Z2 no undeclared cases ran"
  PASS=$((PASS + 1))
fi

echo ""
if [ $FAIL -ne 0 ]; then
  echo "--- gateway log tail (diagnostics only; no assertion reads it) ---"
  docker logs --tail 120 llb1 2>&1 | grep -iE "aigateway|jwt|bearer" | tail -40
  echo "SCENARIO-ai-jwtauth [FAILED] ($PASS pass, $FAIL fail)"
  exit 1
fi
echo "SCENARIO-ai-jwtauth [OK] ($PASS pass)"
exit 0
