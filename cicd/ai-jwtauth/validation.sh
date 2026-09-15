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
    # The QoS ladder's IDs are three-part and would not match the letter+digit
    # shapes above. A label this function declines is not an error anywhere —
    # it is simply never recorded, so Z1/Z2 cannot notice the case being
    # deleted, and the block would be exactly as unprotected as if it carried
    # no label at all.
    QOS-[A-Z][A-Z][A-Z]-[0-9][0-9][0-9]) ;;
    # ...and the fault-injection block's QOS-ID-nnn is two letters, not
    # three. Spelled out rather than loosened to a glob: this function
    # DECLINES silently, so a shape it does not list is a case Z1 can never
    # report missing, and a glob wide enough to catch it would also catch
    # a typo it should be reporting.
    QOS-[A-Z][A-Z]-[0-9][0-9][0-9]) ;;
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

# chk_aborted <name> <response> -- the ONE place a curl 000 is the expected
# answer: a case that cuts its own client off mid-request to strand a
# reservation. chk_code refuses 000 outright, and rightly -- everywhere else
# it means the measurement was lost. Here it is the measurement, so it gets a
# named oracle of its own rather than a hole in chk_code's guard: a request
# that completed is a request that was never aborted, and the case that rests
# on the abort would be measuring an ordinary served response.
chk_aborted() {
  note_case "$1"
  local got; got=$(http_code_of "$2")
  if [ "$got" = "000" ]; then
    echo "  [PASS] $1 (curl reported no completion, as the case requires)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — the request COMPLETED with HTTP ${got:-none}; nothing was aborted,"
    echo "         so whatever this case concludes about a stranded claim is untested"
    FAIL=$((FAIL + 1))
  fi
}

# gw_log_count <needle> -- occurrences of a literal string in the gateway's
# own log. Used by exactly one case, and deliberately: the fine-grained JWT
# refusal reason is LOG-ONLY by design (pkg/jwtauth/verdict.go states it --
# the client-facing 401 collapses to invalid_token so the gate is not an
# oracle, and loxilb_ai_jwt_validation_total labels the COARSE code, with
# promoting the reasons to the metric named there as an open decision that
# has to land with the dashboards). So the log is the only place an operator
# can tell "the IdP is minting identities we cannot represent" from "clients
# are sending bad tokens", and it is what this case must read.
#
# -F, not a plain -c: grep counts a bracketed pattern as a character class,
# and this file has been bitten by that before.
gw_log_count() {
  docker exec llb1 sh -c "cat /var/log/loxilb*.log 2>/dev/null" 2>/dev/null |
    grep -cF "$1" 2>/dev/null || echo 0
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
  # -w rides every data-plane request so a status can be asserted for
  # EQUALITY (chk_code) instead of searched for as a substring: curl's own
  # report cannot be satisfied by a three-digit string in a body or header,
  # and 000 keeps meaning "never completed" instead of matching nothing.
  $hexec l3h1 curl -s -i --max-time 10 -X POST \
    -H "Content-Type: application/json" \
    -H "X-Test-Nonce: $LAST_NONCE" \
    "$@" \
    -d "$body" \
    -w '\nhttp_code=%{http_code}' \
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
chk_code    "A1 200 status" 200 "$r"
chk_has     "A1 llama pool answers" "server-llama" "$r"
chk_receipt "A1 backend received exactly one" 1

echo ""
echo "A2: no Authorization header at all → 401 missing_token"
r=$(req 2040 "$body_llama")
chk_code    "A2 401 status" 401 "$r"
chk_has     "A2 missing_token code"  "missing_token" "$r"
chk_receipt "A2 backend received nothing" 0

echo ""
echo "A3: same token with a corrupted signature → 401 invalid_token"
echo "    (header and payload are byte-identical to A1's token)"
r=$(bearer_req 2040 "$body_llama" "$TOK_BADSIG")
chk_code    "A3 401 status" 401 "$r"
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
    chk_code    "A4 401 status" 401 "$r"
    chk_has     "A4 token_expired code"  "token_expired" "$r"
    chk_receipt "A4 backend received nothing" 0
  fi
fi

echo ""
echo "A5: valid token with NO tenant claim → 401 (unattributable cannot be metered)"
echo "    (same profile and port as A1; only the user differs)"
r=$(bearer_req 2040 "$body_llama" "$TOK_CAROL")
chk_code    "A5 401 status" 401 "$r"
chk_has     "A5 invalid_token code"  "invalid_token" "$r"
chk_receipt "A5 backend received nothing" 0

echo ""
echo "A6: valid token, model its roles do NOT cover → 403, not 401, not a steer"
r=$(bearer_req 2040 "$body_mistral" "$TOK_ALICE")
chk_code    "A6 403 status" 403 "$r"
chk_has     "A6 model_not_allowed"     "model_not_allowed"  "$r"
chk_receipt "A6 backend received nothing" 0

echo ""
echo "A7: a different user's token DOES reach its own model → A6 is authorization,"
echo "    not an unreachable pool"
r=$(bearer_req 2040 "$body_mistral" "$TOK_BOB")
chk_code    "A7 200 status" 200 "$r"
chk_has "A7 mistral pool answers" "server-mistral" "$r"
chk_receipt "A7 backend received exactly one" 1

echo ""
echo "A8: non-Bearer Authorization scheme → reads as no bearer credential"
r=$(req 2040 "$body_llama" -H "Authorization: Basic YWxpY2U6cHc=")
chk_code    "A8 401 status" 401 "$r"
chk_has     "A8 missing_token code"  "missing_token" "$r"
chk_receipt "A8 backend received nothing" 0

echo ""
echo "== B: the profile decides — issuer and audience (2042/2043 vs 2040) =="

echo ""
echo "B1: profile demanding an audience the token does not carry → 401"
r=$(bearer_req 2042 "$body_llama" "$TOK_ALICE")
chk_code    "B1 401 status" 401 "$r"
chk_has     "B1 invalid_token code"  "invalid_token" "$r"
chk_receipt "B1 backend received nothing" 0

echo ""
echo "B2: profile naming a different issuer, same keys → 401"
r=$(bearer_req 2043 "$body_llama" "$TOK_ALICE")
chk_code    "B2 401 status" 401 "$r"
chk_has     "B2 invalid_token code"  "invalid_token" "$r"
chk_receipt "B2 backend received nothing" 0

echo ""
echo "B3: control — THAT SAME token is admitted on the correctly configured"
echo "    profile, so B1/B2 are the profile's doing and not a stale token"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE")
chk_code    "B3 200 status" 200 "$r"
chk_has "B3 llama pool answers" "server-llama" "$r"
chk_receipt "B3 backend received exactly one" 1

echo ""
echo "== C: apikey-or-jwt precedence (port 2041) =="
echo "   the API key allows llama-70b only; bob's token allows mistral-7b only"

echo ""
echo "C1: API key alone, model it allows → admitted"
r=$(req 2041 "$body_llama" -H "X-Api-Key: $RAW_KEY")
chk_code    "C1 200 status" 200 "$r"
chk_has "C1 llama pool answers" "server-llama" "$r"
chk_receipt "C1 backend received exactly one" 1

echo ""
echo "C2: bearer alone, model it allows → admitted"
r=$(bearer_req 2041 "$body_mistral" "$TOK_BOB")
chk_code    "C2 200 status" 200 "$r"
chk_has "C2 mistral pool answers" "server-mistral" "$r"
chk_receipt "C2 backend received exactly one" 1

echo ""
echo "C3: BOTH present, model only the token allows → the key decides, alone"
echo "    → 403 from the key's allow-list; an identity merge would admit this"
r=$(req 2041 "$body_mistral" -H "X-Api-Key: $RAW_KEY" -H "Authorization: Bearer $TOK_BOB")
chk_code    "C3 403 status" 403 "$r"
chk_has     "C3 model_not_allowed"         "model_not_allowed" "$r"
chk_receipt "C3 backend received nothing" 0

echo ""
echo "C4: REJECTED key + valid token for the same model → 401, NO fallback"
echo "    (fallback would let a caller probe one credential per request"
echo "     behind a single 401 — this leg is red on any build that does it)"
r=$(req 2041 "$body_llama" -H "X-Api-Key: not-a-real-key" -H "Authorization: Bearer $TOK_ALICE")
chk_code    "C4 401 status" 401 "$r"
chk_has     "C4 API-key arm named the deny" "invalid_api_key" "$r"
chk_receipt "C4 backend received nothing" 0

echo ""
echo "C5: control — that same token alone IS admitted here, so C4's refusal"
echo "    is the failed key being final, not a bad token"
r=$(bearer_req 2041 "$body_llama" "$TOK_ALICE")
chk_code    "C5 200 status" 200 "$r"
chk_has "C5 llama pool answers" "server-llama" "$r"
chk_receipt "C5 backend received exactly one" 1

echo ""
echo "C6: neither credential → 401"
r=$(req 2041 "$body_llama")
chk_code    "C6 401 status" 401 "$r"
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
chk_receipt "D1 backend received exactly one" 1

echo ""
echo "D2: forward_identity=true (port 2045) → verified identity IS injected"
r=$(bearer_req 2045 "$body_llama" "$TOK_ALICE")
chk_has     "D2 backend answered"       "server-llama"           "$r"
chk_has     "D2 tenant forwarded"       "xauth_tenant=tenant-a"  "$r"
chk_not_has "D2 user forwarded"         "xauth_user=-"           "$r"
chk_has     "D2 Authorization still stripped" "authz=no"         "$r"
chk_receipt "D2 backend received exactly one" 1

echo ""
echo "D3: authorization_passthrough=true (port 2046) → header survives"
r=$(bearer_req 2046 "$body_llama" "$TOK_ALICE")
chk_has "D3 backend answered"        "server-llama" "$r"
chk_has "D3 Authorization passed on" "authz=yes"    "$r"
chk_receipt "D3 backend received exactly one" 1

echo ""
echo "D4: client-sent X-Auth-* on a non-forwarding service → stripped as a spoof"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE" \
      -H "X-Auth-Tenant: evil-tenant" -H "X-Auth-User: evil-user")
chk_has     "D4 backend answered"        "server-llama"   "$r"
chk_not_has "D4 spoofed tenant stripped" "evil-tenant"    "$r"
chk_not_has "D4 spoofed user stripped"   "evil-user"      "$r"
chk_has     "D4 no tenant forwarded"     "xauth_tenant=-" "$r"
chk_receipt "D4 backend received exactly one" 1

echo ""
echo "D5: client-sent X-Auth-* on a FORWARDING service → replaced, never merged"
r=$(bearer_req 2045 "$body_llama" "$TOK_ALICE" \
      -H "X-Auth-Tenant: evil-tenant" -H "X-Auth-User: evil-user")
chk_has     "D5 backend answered"           "server-llama"          "$r"
chk_has     "D5 verified tenant forwarded"  "xauth_tenant=tenant-a" "$r"
chk_not_has "D5 spoofed tenant not present" "evil-tenant"           "$r"
chk_not_has "D5 spoofed user not present"   "evil-user"             "$r"
chk_receipt "D5 backend received exactly one" 1

echo ""
echo "D6: X-Api-Key is the gateway's namespace on JWT services too → stripped"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE" -H "X-Api-Key: some-backend-key")
chk_has "D6 backend answered"     "server-llama" "$r"
chk_has "D6 X-Api-Key stripped"   "apikey=no"    "$r"
chk_receipt "D6 backend received exactly one" 1

echo ""
echo "== E: a large token delivered in fragments =="

echo ""
echo "E1: control — the large token is admitted when curl writes it normally"
DAVE_TOK=$(cat .tok_dave 2>/dev/null)
if [ -z "$DAVE_TOK" ]; then
  echo "  [FAIL] E1 .tok_dave missing — config.sh did not complete"; FAIL=$((FAIL + 1))
else
  r=$(bearer_req 2040 "$body_llama" "$DAVE_TOK")
  chk_code    "E1 200 status" 200 "$r"
  chk_has "E1 llama pool answers" "server-llama" "$r"
  chk_receipt "E1 backend received exactly one" 1
fi

echo ""
echo "E2: the SAME token in 200-byte writes → still admitted"
echo "    (the Authorization value now reaches the parser in many fragments;"
echo "     a capture that keeps one fragment answers 401 invalid_token here)"
# The nonce is minted HERE and handed to the sender: segmented_send.py is
# not req(), so without this the receipt assertion below would consume
# whatever nonce the previous leg left behind and score THAT request's
# delivery — a vacuous oracle that passes on any build (this was live in
# this suite: E2's receipt read E1's nonce until E1 began consuming it).
new_nonce
E2_NONCE=$LAST_NONCE
rm -f "$NONCE_FILE.last"   # carried explicitly; no leg may inherit it
r=$($hexec l3h1 python3 ./segmented_send.py "$VIP" 2040 "$(pwd)/.tok_dave" 200 15 "$E2_NONCE" 2>/dev/null)
chk_has     "E2 200 status"          " 200 "         "$(status_of "$r")"
chk_has     "E2 llama pool answers"  "server-llama"  "$r"
chk_receipt "E2 backend received exactly one" 1 "$E2_NONCE"
chk_not_has "E2 not a signature 401" "invalid_token" "$r"

echo ""
echo "== F: HTTP/2 runs the SAME admission gate as HTTP/1 (ports 2048/2049) =="
echo "   Port 2048 is jwt-only with a backend that actually speaks HTTP/2, so"
echo "   admitted and refused produce different client-visible outcomes; port"
echo "   2049 points at a raw recorder, the only oracle that can see a forward."

# The h2c echo keeps its own receipt counter (the :8080 oracle belongs to
# the H/1.1 pools). Same contract as chk_receipt: consumes the last nonce,
# an unreadable counter is never proof of zero.
h2_receipt() { # h2_receipt <name> <expected-count>
  note_case "$1"
  local n got
  n=$(last_nonce)
  if [ -z "$n" ]; then
    echo "  [FAIL] $1 — no nonce recorded for the last request"; FAIL=$((FAIL + 1)); return
  fi
  got=$($hexec l3ep1 curl -s --max-time 5 --http2-prior-knowledge \
        "http://127.0.0.1:8090/__receipts/$n" 2>/dev/null)
  case "$got" in
    ''|*[!0-9]*)
      echo "  [FAIL] $1 — h2 backend receipt counter unreadable; not proof of $2"
      FAIL=$((FAIL + 1)); return ;;
  esac
  if [ "$got" = "$2" ]; then
    echo "  [PASS] $1 (h2 backend receipts=$got)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — h2 backend receipts=$got, want $2"; FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "F1: H2 + valid JWT → admitted end-to-end, and the consumed token is"
echo "    stripped upstream (hygiene parity: the backend must not see Authorization)"
r=$(bearer_req 2048 "$body_llama" "$TOK_ALICE" --http2-prior-knowledge)
chk_code    "F1 200 status" 200 "$r"
chk_has    "F1 h2 pool answers"            "server-h2-llama"        "$r"
chk_has    "F1 Authorization stripped"     '"authorization": "no"'  "$r"
h2_receipt "F1 h2 backend received exactly one" 1

echo ""
echo "F2: H2 + valid API KEY on the jwt-only service → refused like HTTP/1"
echo "    (BORN RED on the H2-only gate: it ran the API-key arm no matter what"
echo "     the service declared, so this exact request was admitted+forwarded)"
r=$(req 2048 "$body_llama" -H "X-Api-Key: $RAW_KEY" --http2-prior-knowledge)
chk_code    "F2 401 status" 401 "$r"
chk_has    "F2 missing_token — the JWT arm decided, not the key arm" "missing_token" "$r"
h2_receipt "F2 h2 backend received nothing" 0

echo ""
echo "F3: H2 + no credential at all → 401 (this was true before the fix too;"
echo "    it is the control that F2's refusal is not 'H2 is just broken')"
r=$(req 2048 "$body_llama" --http2-prior-knowledge)
chk_code    "F3 401 status" 401 "$r"
h2_receipt "F3 h2 backend received nothing" 0

echo ""
echo "F4: the forwarding oracle — H2 + valid API KEY on the recorder-backed"
echo "    jwt-only service (2049). The recorded bytes must NOT contain the"
echo "    nonce: a client-side 401 alone cannot prove nothing was forwarded."
if ! $hexec l3ep1 test -f /tmp/ai-jwtauth-rawsink.out; then
  echo "  [FAIL] F4 recorder output missing — the forwarding oracle is not running"
  note_case "F4 recorder"; FAIL=$((FAIL + 1))
else
  # The marker must ride the BODY, not a header: forwarded HTTP/2 headers
  # are HPACK-compressed (usually Huffman-coded), so a header nonce is not
  # byte-searchable in the recording — DATA frames carry the body verbatim.
  # Minted here in the parent shell so the body can carry it; the direct
  # curl is deliberate (req() minted its nonce after the body was fixed).
  new_nonce
  F4_NONCE=$LAST_NONCE
  rm -f "$NONCE_FILE.last"   # consumed here; no later leg may inherit it
  f4_body='{"model":"llama-70b","messages":[{"role":"user","content":"'"$F4_NONCE"'"}]}'
  r=$($hexec l3h1 curl -s -i --max-time 10 -X POST \
        -H "Content-Type: application/json" \
        -H "X-Api-Key: $RAW_KEY" \
        --http2-prior-knowledge \
        -d "$f4_body" \
        -w '\nhttp_code=%{http_code}' \
        "http://$VIP:2049/v1/chat/completions")
  chk_code    "F4 401 status" 401 "$r"
  note_case "F4 nothing forwarded"
  # Give an in-flight forward a moment to land before declaring absence.
  sleep 2
  F4_HITS=$($hexec l3ep1 grep -c "$F4_NONCE" /tmp/ai-jwtauth-rawsink.out 2>/dev/null)
  case "$F4_HITS" in ''|*[!0-9]*) F4_HITS=unreadable ;; esac
  if [ "$F4_HITS" = "0" ]; then
    echo "  [PASS] F4 nothing forwarded (recorder never saw the body marker)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] F4 nothing forwarded — recorder saw the body marker $F4_HITS time(s);"
    echo "         the gateway forwarded a request its declared policy refuses"
    FAIL=$((FAIL + 1))
  fi
fi

echo ""
echo "== L: the exact raw-Authorization capture boundary (H1 and H2) =="
echo "   The data planes store the complete raw Authorization value in a"
echo "   4096-byte buffer with one byte reserved for the terminator: 4095"
echo "   raw bytes is the largest value that can reach verification, 4096"
echo "   is dropped at capture — BEFORE the verifier sees a byte. RFC 7235"
echo "   allows repeated SP after the scheme, so the SAME valid token is"
echo "   padded to land the raw value exactly on each side of the cliff: a"
echo "   credential that verifies at 4095 and is refused at 4096 pins the"
echo "   boundary to the capture, not to anything about the token."

ALICE_LEN=${#TOK_ALICE}
L_PAD_OK=$((4095 - 7 - ALICE_LEN))     # raw = "Bearer "(7) + pad + token
L_PAD_OVER=$((L_PAD_OK + 1))
if [ "$L_PAD_OK" -le 0 ]; then
  note_case "L1 pad"; note_case "L2 pad"; note_case "L3 pad"; note_case "L4 pad"
  echo "  [FAIL] L1-L4 alice's token is $ALICE_LEN chars — too large to pad up"
  echo "         to the boundary; the realm no longer mints what these legs need"
  FAIL=$((FAIL + 4))
else
  PAD_OK=$(printf '%*s' "$L_PAD_OK" '')
  PAD_OVER=$(printf '%*s' "$L_PAD_OVER" '')

  echo ""
  echo "L1: raw value of exactly 4095 bytes, valid token → admitted"
  r=$(req 2040 "$body_llama" -H "Authorization: Bearer ${PAD_OK}${TOK_ALICE}")
  chk_code    "L1 200 status" 200 "$r"
  chk_has     "L1 llama pool answers" "server-llama" "$r"
  chk_receipt "L1 backend received exactly one" 1

  echo ""
  echo "L2: the SAME token, raw value 4096 bytes → 401 at the capture, and"
  echo "    never stored truncated (a truncated store would verify a prefix"
  echo "    or misreport the deny as a bad signature on a smaller token)"
  r=$(req 2040 "$body_llama" -H "Authorization: Bearer ${PAD_OVER}${TOK_ALICE}")
  chk_code    "L2 401 status" 401 "$r"
  chk_has     "L2 invalid_token code" "invalid_token" "$r"
  chk_receipt "L2 backend received nothing" 0

  echo ""
  echo "L3: the same 4095-byte raw value over HTTP/2 → admitted (parity)"
  r=$(req 2048 "$body_llama" --http2-prior-knowledge \
        -H "Authorization: Bearer ${PAD_OK}${TOK_ALICE}")
  chk_code   "L3 200 status" 200 "$r"
  chk_has    "L3 h2 pool answers" "server-h2-llama" "$r"
  h2_receipt "L3 h2 backend received exactly one" 1

  echo ""
  echo "L4: the same 4096-byte raw value over HTTP/2 → 401 (parity)"
  r=$(req 2048 "$body_llama" --http2-prior-knowledge \
        -H "Authorization: Bearer ${PAD_OVER}${TOK_ALICE}")
  chk_code   "L4 401 status" 401 "$r"
  chk_has    "L4 invalid_token code" "invalid_token" "$r"
  h2_receipt "L4 h2 backend received nothing" 0
fi

echo ""
echo "== K: actual Transfer-Encoding: chunked requests (E2 was only TCP =="
echo "   fragmentation of a Content-Length request — a different layer)."
echo ""
echo "   Pinned contract on a model-routed AI service: the effective model"
echo "   is resolved from the request BODY, and the body locator reads the"
echo "   Content-Length-delimited body. A chunked request carries no"
echo "   Content-Length, so its model cannot be resolved and the request"
echo "   is refused FAIL-CLOSED before any backend — never silently served"
echo "   against the wrong model, and never forwarded past the gate. That"
echo "   is the security property these legs pin: whatever the status, the"
echo "   backend receipt is ZERO. (Chunked chat-completions is not a"
echo "   supported client shape; OpenAI-compatible clients send"
echo "   Content-Length. This is documented, not incidental.)"

k_req() { # k_req <port> <mode> <token>
  local port=$1 mode=$2 tok=$3
  new_nonce
  $hexec l3h1 python3 ./raw_http.py "$VIP" "$port" "$mode" "$tok" "$LAST_NONCE" 2>/dev/null
}
# k_not_served <name> <response>: the deny half of the chunked contract.
# The status may be 503 (model unresolved) or 400 (framing refused) — both
# are fail-closed. What must NEVER appear is a backend answer, so the
# marker to forbid is the pool label; the receipt assertion carries the
# rest of the claim.
k_not_served() {
  note_case "$1"
  if [[ "$2" == *"server-llama"* ]] || [[ "$2" == *"server-mistral"* ]]; then
    echo "  [FAIL] $1 — a chunked request reached a backend pool"; FAIL=$((FAIL + 1))
  else
    echo "  [PASS] $1 (no backend pool answered)"; PASS=$((PASS + 1))
  fi
}

echo ""
echo "K1: chunked + valid JWT on the model-routed default service → refused"
echo "    fail-closed, nothing forwarded"
r=$(k_req 2040 chunked "$TOK_ALICE")
k_not_served "K1 not served by a backend" "$r"
chk_receipt  "K1 backend received nothing" 0

echo ""
echo "K2: chunked + valid JWT on the forward_identity service → the SAME"
echo "    fail-closed outcome. The reviewers' worry is a chunked request"
echo "    served WITHOUT its verified identity; here it is not served at"
echo "    all, so no unidentified request reaches the backend."
r=$(k_req 2045 chunked "$TOK_ALICE")
k_not_served "K2 not served by a backend" "$r"
chk_receipt  "K2 backend received nothing" 0

echo ""
echo "K3: the same request spelled 'Transfer-Encoding: Chunked' → the SAME"
echo "    fail-closed outcome. Field values are case-insensitive (RFC"
echo "    9112); a casing that changed the verdict would be two contracts."
r=$(k_req 2045 chunked-mixed "$TOK_ALICE")
k_not_served "K3 casing does not change the verdict" "$r"
chk_receipt  "K3 backend received nothing" 0

echo ""
echo "K4: Content-Length AND Transfer-Encoding on one request → never"
echo "    forwarded. CL+TE disagreement is the classic request-smuggling"
echo "    vector; llhttp refuses the pair, and the gate must refuse the"
echo "    request BEFORE any backend rather than relay the unparsed buffer."
echo "    (BORN RED while a parse error on an enforcing service falls back"
echo "     to a raw relay: this exact request reached a JWT-only backend"
echo "     credential-free — an authentication bypass — with receipt 1)"
new_nonce
K4_NONCE=$LAST_NONCE
rm -f "$NONCE_FILE.last"   # carried explicitly; no leg may inherit it
r=$($hexec l3h1 python3 ./raw_http.py "$VIP" 2040 cl-te "$TOK_ALICE" "$K4_NONCE" 2>/dev/null)
k_not_served "K4 not admitted" "$r"
chk_receipt  "K4 backend received nothing" 0 "$K4_NONCE"

echo ""
echo "K5: CL+TE with NO credential on the JWT-only service → the decisive"
echo "    bypass probe. If a credential-free malformed request reaches the"
echo "    backend, the admission gate was skipped entirely."
new_nonce
K5_NONCE=$LAST_NONCE
rm -f "$NONCE_FILE.last"
r=$($hexec l3h1 python3 ./raw_http.py "$VIP" 2040 cl-te "" "$K5_NONCE" 2>/dev/null)
k_not_served "K5 credential-free request not served" "$r"
chk_receipt  "K5 backend received nothing" 0 "$K5_NONCE"

echo ""
echo "== X: repeated Authorization headers — deterministic, never a leak =="
echo "   RFC 9110 defines no merge for a repeated singleton field. Pinned"
echo "   contract: the LAST Authorization value decides admission, exactly"
echo "   one credential is evaluated, identities are never merged, and"
echo "   EVERY instance is stripped upstream on a consuming service."

echo ""
echo "X1: bad-signature first, valid last → the last value decides:"
echo "    admitted, and the backend sees NO Authorization instance at all"
r=$(req 2040 "$body_llama" \
      -H "Authorization: Bearer $TOK_BADSIG" \
      -H "Authorization: Bearer $TOK_ALICE")
chk_code    "X1 200 status" 200 "$r"
chk_has     "X1 llama pool answers" "server-llama" "$r"
chk_has     "X1 every instance stripped" "authz=no" "$r"
chk_receipt "X1 backend received exactly one" 1

echo ""
echo "X2: valid first, bad-signature last → the last value decides: 401."
echo "    The earlier valid credential cannot rescue the request — rescue"
echo "    semantics would let a caller probe credentials pairwise."
r=$(req 2040 "$body_llama" \
      -H "Authorization: Bearer $TOK_ALICE" \
      -H "Authorization: Bearer $TOK_BADSIG")
chk_code    "X2 401 status" 401 "$r"
chk_has     "X2 invalid_token code" "invalid_token" "$r"
chk_receipt "X2 backend received nothing" 0

echo ""
echo "== M: multi-model multiplexing on ONE HTTP/2 connection (port 2050) =="
echo "   Two model pools on one VIP, each pool's endpoint list starting at"
echo "   index 0, each pool a different backend. A backend cache keyed by"
echo "   endpoint index alone has an alias here, and only a connection that"
echo "   holds two in-flight streams of different models can reach it."

# Per-backend receipt reader: M's whole point is WHICH backend a stream
# reached, so the two counters are read separately (h2_receipt sums into
# one namespace and cannot tell a cross-delivery from a clean run).
h2_receipt_at() { # h2_receipt_at <ns> <name> <expected> <nonce>
  note_case "$2"
  local got
  got=$($hexec "$1" curl -s --max-time 5 --http2-prior-knowledge \
        "http://127.0.0.1:8090/__receipts/$4" 2>/dev/null)
  case "$got" in
    ''|*[!0-9]*)
      echo "  [FAIL] $2 — receipt counter in $1 unreadable; not proof of $3"
      FAIL=$((FAIL + 1)); return ;;
  esac
  if [ "$got" = "$3" ]; then
    echo "  [PASS] $2 ($1 receipts=$got)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $2 — $1 receipts=$got, want $3"; FAIL=$((FAIL + 1))
  fi
}

chk_num() { # chk_num <name> <want> <got>
  note_case "$1"
  case "$3" in
    ''|*[!0-9-]*)
      echo "  [FAIL] $1 — value '$3' unreadable"; FAIL=$((FAIL + 1)); return ;;
  esac
  if [ "$3" -eq "$2" ]; then
    echo "  [PASS] $1 ($3)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — got $3, want $2"; FAIL=$((FAIL + 1))
  fi
}

# metric_labeled <family> <label-substr> [label-substr2] -> summed value of
# the series carrying every given label, or "unreadable" when the scrape
# itself failed (an absent family reads 0 — baselines need a number).
metric_labeled() {
  local body
  body=$($hexec l3h1 curl -s --max-time 8 "http://$VIP:11111/netlox/v1/metrics" 2>/dev/null)
  case "$body" in
    *loxilb_*) ;;
    *) echo "unreadable"; return ;;
  esac
  echo "$body" | awk -v fam="$1" -v a="$2" -v b="${3:-}" '
    $0 ~ "^" fam "{" {
      if (index($0, a) == 0) next
      if (b != "" && index($0, b) == 0) next
      v = $NF; if (v + 0 == v) s += v
    }
    END { printf "%d", s }'
}

echo ""
echo "M1: control — each model reaches its own pool on SEPARATE connections"
echo "    (rules out 'pool-B was never routable' as the reading of an M2/M3 red)"
r=$(bearer_req 2050 "$body_llama" "$TOK_ALICE" --http2-prior-knowledge)
chk_code "M1 llama 200 on its own connection" 200 "$r"
chk_has "M1 llama pool answers"                "server-h2-llama"  "$r"
rm -f "$NONCE_FILE.last"
r=$(bearer_req 2050 "$body_mistral" "$TOK_BOB" --http2-prior-knowledge)
chk_code "M1 mistral 200 on its own connection" 200 "$r"
chk_has "M1 mistral pool answers"              "server-h2-mistral" "$r"
rm -f "$NONCE_FILE.last"

# Metric baselines AFTER the controls (they settle tokens of their own).
sleep 2
TKA0=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-a"' 'model="llama-70b"')
TKB0=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-b"' 'model="mistral-7b"')
ESTA0=$(metric_labeled loxilb_ai_tokens_estimated_total 'tenant="tenant-a"')
ESTB0=$(metric_labeled loxilb_ai_tokens_estimated_total 'tenant="tenant-b"')

echo ""
echo "M2: the multiplexed case — one connection, two interleaved streams,"
echo "    different models, different identities. Both requests are on the"
echo "    wire before either response is read."
new_nonce; MA=$LAST_NONCE
new_nonce; MB=$LAST_NONCE
rm -f "$NONCE_FILE.last"   # minted here, consumed here; no leg may inherit
printf '%s' "$TOK_ALICE" > .tok_alice_mux
printf '%s' "$TOK_BOB"   > .tok_bob_mux
MOUT=$($hexec l3h1 python3 ./h2_mux_client.py "$VIP" 2050 \
        "llama-70b|$(pwd)/.tok_alice_mux|$MA" \
        "mistral-7b|$(pwd)/.tok_bob_mux|$MB" 2>/dev/null)
rm -f .tok_alice_mux .tok_bob_mux
LLAMA_LINE=$(echo "$MOUT" | grep '"model": "llama-70b"')
MIS_LINE=$(echo "$MOUT" | grep '"model": "mistral-7b"')
chk_has     "M2 llama stream 200"                    '"status": "200"'   "$LLAMA_LINE"
chk_has     "M2 llama stream answered by its pool"   "server-h2-llama"   "$LLAMA_LINE"
chk_has     "M2 mistral stream 200"                  '"status": "200"'   "$MIS_LINE"
chk_has     "M2 mistral stream answered by its pool" "server-h2-mistral" "$MIS_LINE"
chk_not_has "M2 mistral stream not cross-answered"   "server-h2-llama"   "$MIS_LINE"

echo ""
echo "M3: backend-delivery evidence — each pool's OWN receipt counter, read"
echo "    inside its namespace. A client-visible body cannot substitute:"
echo "    delivery to the wrong pool is only visible at the pools."
h2_receipt_at l3ep1 "M3 llama backend saw the llama nonce once"     1 "$MA"
h2_receipt_at l3ep2 "M3 mistral backend saw the mistral nonce once" 1 "$MB"
h2_receipt_at l3ep1 "M3 llama backend never saw the mistral nonce"  0 "$MB"
h2_receipt_at l3ep2 "M3 mistral backend never saw the llama nonce"  0 "$MA"

echo ""
echo "M4: settlement attribution — each stream's tokens land on ITS tenant"
echo "    and model, exactly (5 prompt + 7 completion from the echo), and"
echo "    exactly, i.e. extracted from the usage object, never estimated."
sleep 2
TKA1=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-a"' 'model="llama-70b"')
TKB1=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-b"' 'model="mistral-7b"')
ESTA1=$(metric_labeled loxilb_ai_tokens_estimated_total 'tenant="tenant-a"')
ESTB1=$(metric_labeled loxilb_ai_tokens_estimated_total 'tenant="tenant-b"')
if [ "$TKA0" = "unreadable" ] || [ "$TKA1" = "unreadable" ] || \
   [ "$TKB0" = "unreadable" ] || [ "$TKB1" = "unreadable" ]; then
  note_case "M4 metrics"
  echo "  [FAIL] M4 metrics scrape unreadable — cannot prove settlement attribution"
  FAIL=$((FAIL + 1))
else
  chk_num "M4 tenant-a charged exactly its stream's tokens"  12 $((TKA1 - TKA0))
  chk_num "M4 tenant-b charged exactly its stream's tokens"  12 $((TKB1 - TKB0))
  chk_num "M4 tenant-a charge was exact, not estimated"       0 $((ESTA1 - ESTA0))
  chk_num "M4 tenant-b charge was exact, not estimated"       0 $((ESTB1 - ESTB0))
fi

echo ""
echo "== N: the keyless per-VIP token bound (ports 2051 H/1.1, 2052 H/2) =="
echo "   vip_shared_tpm=10 and every echoed answer settles 12 tokens, so the"
echo "   contract is decided in two requests: the first is admitted against"
echo "   a clean bucket, its settle puts the bucket in debt, the second is"
echo "   refused at admission. No credential is sent on any of them."

echo ""
echo "N1: first keyless HTTP/1.1 request → admitted, answered, settled"
r=$(req 2051 "$body_llama")
chk_code    "N1 200 status" 200 "$r"
chk_has     "N1 the H/1.1 pool answers"        "server-llama" "$r"
chk_receipt "N1 backend received exactly one"  1

echo ""
echo "N2: second keyless HTTP/1.1 request → 429 from the bucket's debt"
sleep 2   # the settle rides the response relay; give it a beat to land
r=$(req 2051 "$body_llama")
chk_code    "N2 429 status" 429 "$r"
chk_has     "N2 token_quota_exceeded code"    "token_quota_exceeded" "$r"
chk_has     "N2 Retry-After header"           "Retry-After: 60"      "$r"
chk_receipt "N2 backend received nothing"     0

echo ""
echo "N3: first keyless HTTP/2 request → admitted, answered, settled"
r=$(req 2052 "$body_llama" --http2-prior-knowledge)
chk_code    "N3 200 status" 200 "$r"
chk_has    "N3 the h2 pool answers"           "server-h2-llama" "$r"
h2_receipt "N3 backend received exactly one"  1

echo ""
echo "N4: second keyless HTTP/2 request → 429, exactly like N2"
echo "    (BORN RED while the H2 settle path skips keyless streams: the"
echo "     bucket never learns of N3's spend and this request is admitted)"
sleep 2
r=$(req 2052 "$body_llama" --http2-prior-knowledge)
chk_code    "N4 429 status" 429 "$r"
chk_has    "N4 token_quota_exceeded code"   "token_quota_exceeded" "$r"
chk_has    "N4 retry-after header"          "retry-after: 60"      "$r"
h2_receipt "N4 backend received nothing"    0

echo ""
echo "== G: fail-closed when the keyset was never fetched (port 2044) =="
echo "   nothing listens on the profile's JWKS endpoint, so the verifier has"
echo "   no keys — that is the gateway's outage, worth retrying: 503, and"
echo "   never a 200"
r=$(bearer_req 2044 "$body_llama" "$TOK_ALICE")
chk_code    "G1 503 status" 503 "$r"
chk_has     "G1 policy_store_unavailable"    "policy_store_unavailable"  "$r"
chk_receipt "G1 backend received nothing" 0

echo ""
echo "G2: that refusal is visible on the metric an operator watches"
echo "    (a keyset that was never fetched is the one denial worth paging on;"
echo "     the API-key arm has always counted it, so the bearer arm counting"
echo "     nothing would make a JWKS outage invisible where it is looked for)"
before=$(metric_value loxilb_ai_policy_store_unavailable_total)
r=$(bearer_req 2044 "$body_llama" "$TOK_ALICE")
chk_code "G2 still 503" 503 "$r"
chk_receipt "G2 backend received nothing" 0
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
chk_code "I0 control: admitted while the IdP is up" 200 "$r"
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
    chk_code    "I2 admitted during the IdP outage" 200 "$r"
    chk_has     "I2 llama pool answers"                 "server-llama" "$r"
    chk_receipt "I2 backend received exactly one" 1
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
        chk_code "I3 token minted after recovery is admitted" 200 "$r"
        chk_has "I3 llama pool answers"                      "server-llama" "$r"
        chk_receipt "I3 backend received exactly one" 1
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
chk_code    "H4 200 status" 200 "$r"
chk_has "H4 llama pool answers" "server-llama" "$r"
chk_receipt "H4 backend received exactly one" 1

echo ""
echo "== P: profile names and the rule reference agree on their limit =="
echo "   The LB rule's jwt_auth_profile field is capped at 63 bytes by the"
echo "   API contract. A profile whose name is longer would be accepted"
echo "   but impossible to reference — configuration that can only ever"
echo "   fail, discovered at rule-create time instead of profile-create"
echo "   time. The profile API must refuse it where it is typed."

P_NAME63=$(printf 'p%.0s' $(seq 1 63))
P_NAME64=$(printf 'q%.0s' $(seq 1 64))

echo ""
echo "P1: a 64-byte profile name → rejected 400, nothing stored"
echo "    (BORN RED while profile names are unbounded: the create answers"
echo "     200 and the name sits unreferenceable in the store)"
r=$($hexec l3h1 curl -s --max-time 8 -w ' http_code=%{http_code}' -X POST \
  "http://$VIP:11111/netlox/v1/config/ai/jwtauthprofile" \
  -H "Content-Type: application/json" \
  -d '{"name":"'"$P_NAME64"'","issuer":"http://127.0.0.1:9/realms/x","jwks_url":"http://127.0.0.1:9/certs","audiences":[]}')
chk_code "P1 64-byte name rejected with the validation status" 400 "$r"
names=$(profile_names)
chk_not_has "P1 the profile was not created" " $P_NAME64 " "$names"
# Residue guard for the born-red path: a build that accepted the name must
# not leave it behind to shadow later runs on the same host.
$hexec l3h1 curl -s --max-time 8 -X DELETE \
  "http://$VIP:11111/netlox/v1/config/ai/jwtauthprofile/$P_NAME64" >/dev/null 2>&1

echo ""
echo "P2: a 63-byte name is accepted AND referenceable — the two limits"
echo "    meet exactly, so no accepted name can be impossible to use"
r=$($hexec l3h1 curl -s --max-time 8 -w ' http_code=%{http_code}' -X POST \
  "http://$VIP:11111/netlox/v1/config/ai/jwtauthprofile" \
  -H "Content-Type: application/json" \
  -d '{"name":"'"$P_NAME63"'","issuer":"'"$KC_ISSUER"'","jwks_url":"'"$KC_ISSUER"'/protocol/openid-connect/certs","audiences":[]}')
chk_code "P2 63-byte name accepted" 200 "$r"
names=$(profile_names)
chk_has "P2 63-byte profile listed" " $P_NAME63 " "$names"
r=$($hexec l3h1 curl -s --max-time 8 -X POST \
  "http://$VIP:11111/netlox/v1/config/loadbalancer" \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP": "10.10.10.254", "port": 2053, "protocol": "tcp",
      "sel": 0, "mode": 4, "host": "10.10.10.254",
      "path_prefix": "/", "path_match_mode": "prefix",
      "model_name": "llama-70b",
      "api_key_auth": "jwt", "jwt_auth_profile": "'"$P_NAME63"'",
      "inactiveTimeOut": 30
    },
    "endpoints": [{"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}]
  }')
chk_has "P2 rule referencing the 63-byte name accepted" "Success" "$r"

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
echo "== U: a response that carries NO usage object is still accounted for =="
echo "   usage is optional in the response shape, and a backend that omits"
echo "   it used to be accounted NOWHERE: with nothing to extract, the"
echo "   non-streamed path charged nothing AND reported nothing, so a"
echo "   completed response simply vanished from token accounting."
echo "   loxilb_ai_tokens_missing_total exists to make exactly that visible"
echo "   — it counts completed responses with no readable usage object, not"
echo "   streaming ones — so it must tick here."
echo "   Reporting is deliberately NOT charging, and that is a settled"
echo "   decision rather than an unfinished one: these responses stay free,"
echo "   because an estimated charge can deny a tenant's NEXT request for"
echo "   traffic that costs them nothing today. U1 pins the charge at zero"
echo "   so the decision cannot be reversed by accident."
echo "   U2 is the control: the same request against the with-usage backend"
echo "   must charge and must NOT tick missing, which is what stops U1 from"
echo "   passing on a counter that simply ticks for everything."

sleep 2
UMISS0=$(metric_labeled loxilb_ai_tokens_missing_total 'tenant="tenant-a"')
UCONS0=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-a"' 'model="llama-70b"')

echo ""
echo "U1: the no-usage backend (port 2055) answers 200 — one response with"
echo "    no usage object is reported once, and charged nothing"
r=$(bearer_req 2055 "$body_llama" "$TOK_ALICE")
chk_code "U1 200 status" 200 "$r"
chk_has  "U1 the no-usage pool answers" "server-nousage" "$r"
chk_not_has "U1 the response really carried no usage object" '"usage"' "$r"
sleep 2
UMISS1=$(metric_labeled loxilb_ai_tokens_missing_total 'tenant="tenant-a"')
UCONS1=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-a"' 'model="llama-70b"')
if [ "$UMISS0" = "unreadable" ] || [ "$UMISS1" = "unreadable" ] || \
   [ "$UCONS0" = "unreadable" ] || [ "$UCONS1" = "unreadable" ]; then
  note_case "U1 missing"; note_case "U1 charge"
  echo "  [FAIL] U1 metrics scrape unreadable — cannot prove the accounting"
  FAIL=$((FAIL + 2))
else
  chk_num "U1 missing counted exactly this one response" 1 $((UMISS1 - UMISS0))
  chk_num "U1 reporting charged nothing"                 0 $((UCONS1 - UCONS0))
fi

echo ""
echo "U2: control — the with-usage backend (port 2040) charges its exact"
echo "    counts and does NOT tick missing"
r=$(bearer_req 2040 "$body_llama" "$TOK_ALICE")
chk_code "U2 200 status" 200 "$r"
sleep 2
UMISS2=$(metric_labeled loxilb_ai_tokens_missing_total 'tenant="tenant-a"')
UCONS2=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-a"' 'model="llama-70b"')
if [ "$UMISS2" = "unreadable" ] || [ "$UCONS2" = "unreadable" ]; then
  note_case "U2 missing"; note_case "U2 charge"
  echo "  [FAIL] U2 metrics scrape unreadable — cannot prove the control"
  FAIL=$((FAIL + 2))
else
  chk_num "U2 a readable usage object does not tick missing" 0 $((UMISS2 - UMISS1))
  chk_num "U2 and it is charged exactly (5 prompt + 7 completion)" 12 $((UCONS2 - UCONS1))
fi

echo ""
echo "== UH: the same accounting, over HTTP/2 =="
echo "   U proves the H/1.1 recorder only. An H/2 response never reaches it:"
echo "   backend frames go through the nghttp2 path, and the stream settles in"
echo "   proxy_h2_settle_stream, which reads usage out of the STREAM's own tail"
echo "   window. That is a second recorder with its own copy of the same"
echo "   decision, so 'H2 is accounted correctly' does not follow from U — it"
echo "   has to be driven."
echo "   UH1 is the no-usage H2 pool (port 2056), UH2 the with-usage H2"
echo "   control (port 2048) that stops UH1 passing on a counter that simply"
echo "   ticks for every H2 response."

sleep 2
UHMISS0=$(metric_labeled loxilb_ai_tokens_missing_total 'tenant="tenant-a"')
UHCONS0=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-a"' 'model="llama-70b"')

echo ""
echo "UH1: an HTTP/2 response with no usage object is reported once, and"
echo "     charged nothing"
r=$(bearer_req 2056 "$body_llama" "$TOK_ALICE" --http2-prior-knowledge)
chk_code "UH1 200 status" 200 "$r"
chk_has  "UH1 the H2 no-usage pool answers" "server-h2-nousage" "$r"
chk_not_has "UH1 the response really carried no usage object" '"usage"' "$r"
sleep 2
UHMISS1=$(metric_labeled loxilb_ai_tokens_missing_total 'tenant="tenant-a"')
UHCONS1=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-a"' 'model="llama-70b"')
if [ "$UHMISS0" = "unreadable" ] || [ "$UHMISS1" = "unreadable" ] || \
   [ "$UHCONS0" = "unreadable" ] || [ "$UHCONS1" = "unreadable" ]; then
  note_case "UH1 missing"; note_case "UH1 charge"
  echo "  [FAIL] UH1 metrics scrape unreadable — cannot prove the accounting"
  FAIL=$((FAIL + 2))
else
  chk_num "UH1 missing counted exactly this one H2 response" 1 $((UHMISS1 - UHMISS0))
  chk_num "UH1 reporting charged nothing"                    0 $((UHCONS1 - UHCONS0))
fi

echo ""
echo "UH2: control — the with-usage H2 backend charges its exact counts and"
echo "     does NOT tick missing"
r=$(bearer_req 2048 "$body_llama" "$TOK_ALICE" --http2-prior-knowledge)
chk_code "UH2 200 status" 200 "$r"
sleep 2
UHMISS2=$(metric_labeled loxilb_ai_tokens_missing_total 'tenant="tenant-a"')
UHCONS2=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-a"' 'model="llama-70b"')
if [ "$UHMISS2" = "unreadable" ] || [ "$UHCONS2" = "unreadable" ]; then
  note_case "UH2 missing"; note_case "UH2 charge"
  echo "  [FAIL] UH2 metrics scrape unreadable — cannot prove the control"
  FAIL=$((FAIL + 2))
else
  chk_num "UH2 a readable usage object does not tick missing" 0 $((UHMISS2 - UHMISS1))
  chk_num "UH2 and it is charged exactly (5 prompt + 7 completion)" 12 $((UHCONS2 - UHCONS1))
fi

echo ""
echo "== UE: an error response is not an accounting hole =="
echo "   loxilb_ai_tokens_missing_total reports a response that SHOULD have"
echo "   been charged and could not be. A backend answering 5xx produced no"
echo "   completion at all, so carrying no usage object is correct rather"
echo "   than missing — and an OpenAI-compatible backend answers errors as"
echo "   JSON, which the non-SSE recorder counts like any other response."
echo "   Without a status test the counter would be driven hardest by a"
echo "   backend outage, i.e. by exactly the condition it does NOT report."
echo "   UE1 is H/1.1 (port 2057) and UE2 is HTTP/2 (port 2058): the two"
echo "   protocols settle through different recorders, so the test has to"
echo "   hold in both."

sleep 2
UEMISS0=$(metric_labeled loxilb_ai_tokens_missing_total 'tenant="tenant-a"')
UECONS0=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-a"' 'model="llama-70b"')

echo ""
echo "UE1: H/1.1 backend answers 500 with no usage object"
r=$(bearer_req 2057 "$body_llama" "$TOK_ALICE")
chk_code "UE1 500 status reaches the client" 500 "$r"
chk_has  "UE1 the error pool answers" "server-err" "$r"
chk_not_has "UE1 the error body carried no usage object" '"usage"' "$r"

echo ""
echo "UE2: the same 500, over HTTP/2"
r=$(bearer_req 2058 "$body_llama" "$TOK_ALICE" --http2-prior-knowledge)
chk_code "UE2 500 status reaches the client" 500 "$r"
chk_has  "UE2 the H2 error pool answers" "server-h2-err" "$r"
chk_not_has "UE2 the error body carried no usage object" '"usage"' "$r"

sleep 2
UEMISS1=$(metric_labeled loxilb_ai_tokens_missing_total 'tenant="tenant-a"')
UECONS1=$(metric_labeled loxilb_ai_tokens_consumed_total 'tenant="tenant-a"' 'model="llama-70b"')
if [ "$UEMISS0" = "unreadable" ] || [ "$UEMISS1" = "unreadable" ] || \
   [ "$UECONS0" = "unreadable" ] || [ "$UECONS1" = "unreadable" ]; then
  note_case "UE missing"; note_case "UE charge"
  echo "  [FAIL] UE metrics scrape unreadable — cannot prove the status test"
  FAIL=$((FAIL + 2))
else
  chk_num "UE neither error response ticked missing" 0 $((UEMISS1 - UEMISS0))
  chk_num "UE and neither was charged"               0 $((UECONS1 - UECONS0))
fi

echo ""
echo "UE3: the counter still works after the errors — the status test must"
echo "     exclude errors, not switch the recorder off. Without this a filter"
echo "     that rejected everything would pass UE1/UE2 and look correct."
UEMISS2=$(metric_labeled loxilb_ai_tokens_missing_total 'tenant="tenant-a"')
r=$(bearer_req 2055 "$body_llama" "$TOK_ALICE")
chk_code "UE3 200 status" 200 "$r"
sleep 2
UEMISS3=$(metric_labeled loxilb_ai_tokens_missing_total 'tenant="tenant-a"')
if [ "$UEMISS2" = "unreadable" ] || [ "$UEMISS3" = "unreadable" ]; then
  note_case "UE3 missing"
  echo "  [FAIL] UE3 metrics scrape unreadable — cannot prove the recorder lives"
  FAIL=$((FAIL + 1))
else
  chk_num "UE3 a 200 with no usage still reports" 1 $((UEMISS3 - UEMISS2))
fi

echo ""
echo "== T: the bearer gate on TLS, where HTTP/2 came from ALPN (port 2053) =="
echo "   Every other HTTP/2 leg in this suite is h2c: the client announces"
echo "   HTTP/2 with a cleartext preface. A TLS client never sends that"
echo "   preface — the protocol is settled inside the handshake, and the"
echo "   gateway picks the session up from SSL_get0_alpn_selected() at accept"
echo "   time instead. That is a different entry into the same gate, so"
echo "   'H2 is admitted correctly' proven over h2c does not carry over."
echo "   T0 exists because these legs are worthless without it: if ALPN"
echo "   settled on http/1.1, T1-T3 would pass while re-testing the HTTP/1.1"
echo "   path and nothing would say so."

# tls_req <port> <body> <extra curl args...> — https + ALPN offer of h2.
# --insecure: the certificate is a throwaway issued by config.sh, and the
# subject under test is protocol negotiation, not chain validation.
# %{http_version} is curl's report of what was actually negotiated.
tls_req() {
  local port=$1 body=$2; shift 2
  new_nonce
  $hexec l3h1 curl -s -i --max-time 10 -X POST \
    --http2 --insecure \
    -H "Content-Type: application/json" \
    -H "X-Test-Nonce: $LAST_NONCE" \
    "$@" \
    -d "$body" \
    -w '\nhttp_code=%{http_code} http_version=%{http_version}' \
    "https://$VIP:$port/v1/chat/completions"
}

echo ""
echo "T0: the connection really is HTTP/2, negotiated by ALPN"
r=$(tls_req 2054 "$body_llama" -H "Authorization: Bearer $TOK_ALICE")
chk_has  "T0 ALPN negotiated HTTP/2" "http_version=2" "$r"

echo ""
echo "T1: valid token over TLS+ALPN h2 → admitted, and the backend saw it once"
chk_code   "T1 200 status" 200 "$r"
chk_has    "T1 h2 pool answers" "server-h2-llama" "$r"
h2_receipt "T1 h2 backend received exactly one" 1

echo ""
echo "T2: no credential over TLS+ALPN h2 → 401, nothing forwarded"
r=$(tls_req 2054 "$body_llama")
chk_code   "T2 401 status" 401 "$r"
chk_has    "T2 missing_token code" "missing_token" "$r"
h2_receipt "T2 h2 backend received nothing" 0

echo ""
echo "T3: a token this service's profile cannot verify → 401, nothing forwarded"
r=$(tls_req 2054 "$body_llama" -H "Authorization: Bearer ${TOK_ALICE}tampered")
chk_code   "T3 401 status" 401 "$r"
chk_has    "T3 invalid_token code" "invalid_token" "$r"
h2_receipt "T3 h2 backend received nothing" 0

echo ""
echo "T4: authorization still applies on this path — a model alice's roles"
echo "    do not allow is refused, and refused by policy rather than by the"
echo "    absence of a route"
r=$(tls_req 2054 "$body_mistral" -H "Authorization: Bearer $TOK_ALICE")
chk_code   "T4 403 status" 403 "$r"
chk_has    "T4 model_not_allowed code" "model_not_allowed" "$r"
h2_receipt "T4 h2 backend received nothing" 0


# ---------------------------------------------------------------------------
# == QOS: the QoS ladder at runtime ==
#
# Everything above this point proves the ladder's CONFIGURATION surface or the
# one rung keyless traffic has (N1-N4, the per-VIP shared bucket). The rungs
# that decide credentialed traffic -- the explicit per-user row, the
# configured default, the tenant ceiling and the key's own limit -- had never
# been driven. The management-API block asserts that a row can be written and
# read back; a row that is written, read back, and then ignored by the gate
# passes every one of those assertions.
#
# The ladder resolves each dimension as: explicit row -> configured default
# (rule scope over global, field by field) -> unlimited. The cases below walk
# that resolution one rung at a time, and each is decided by a REFUSAL the
# gate must produce, never by traffic merely succeeding: an admitted request
# is the same observation whether the limit was respected or absent, so the
# permissive half of every case is paired with a refusal that could only come
# from the rung under test.
#
# Identities: tenant-q's q1..q8 and tenant-qt's t1/t2, used by nothing else.
# Every rung is a per-(tenant, user) or per-tenant token bucket, so a case
# that borrowed alice would score whatever spend the A block left behind.
# ---------------------------------------------------------------------------

QOS_T="tenant-q"
QOS_TT="tenant-qt"
QOS_MGMT="http://localhost:11111/netlox/v1"

# qos_cfg <method> <path> [body] -- the management surface, from inside llb1.
# Publishes QOS_CFG_CODE and QOS_CFG_BODY.
#
# NEVER call this inside $( ). A command substitution is a subshell and a
# global assigned there dies with it, so the next assertion would silently
# score the PREVIOUS call's status -- a whole block of "the write succeeded"
# passes that measured one stale result.
QOS_CFG_FRESH=0
qos_cfg() {
  local method=$1 path=$2 body=${3:-} out
  if [ -n "$body" ]; then
    out=$($hexec llb1 curl -s -w '\nhttp_code=%{http_code}' -X "$method" \
      "$QOS_MGMT$path" -H "Content-Type: application/json" -d "$body" 2>/dev/null)
  else
    out=$($hexec llb1 curl -s -w '\nhttp_code=%{http_code}' -X "$method" \
      "$QOS_MGMT$path" 2>/dev/null)
  fi
  QOS_CFG_BODY="$out"
  QOS_CFG_CODE=$(http_code_of "$out")
  QOS_CFG_FRESH=1
}

# qos_cfg_ok <name> -- the configuration step a runtime case rests on really
# happened. A silently-failed write is the worst outcome available here: the
# limit is simply absent, every request is admitted, and the case reports the
# product as unbounded when it was never asked to bound anything.
#
# The freshness flag is one-shot, so scoring twice without an intervening call
# is a failure rather than a repeat of the last answer.
qos_cfg_ok() {
  note_case "$1"
  if [ "$QOS_CFG_FRESH" != "1" ]; then
    echo "  [FAIL] $1 - no fresh config result to score; the call did not run, or ran inside a subshell"
    FAIL=$((FAIL + 1)); return
  fi
  QOS_CFG_FRESH=0
  case "$QOS_CFG_CODE" in
    2*) echo "  [PASS] $1 (HTTP $QOS_CFG_CODE)"; PASS=$((PASS + 1)) ;;
    *)  echo "  [FAIL] $1 - HTTP ${QOS_CFG_CODE:-none}: $(echo "$QOS_CFG_BODY" | tr '\n' ' ' | head -c 200)"
        FAIL=$((FAIL + 1)) ;;
  esac
}

# qos_pair <port> <cred-header-1> <cred-header-2> -- two requests, back to
# back, from the credentials named. Publishes QP1/QP2 and their receipt
# nonces, plus the gap between the two requests' departures.
#
# The nonce is captured after each request because reading it CONSUMES it:
# the second request overwrites the file, and a receipt assertion made later
# would otherwise score the wrong request.
qos_pair() {
  local port=$1 h1=$2 h2=$3 t0 t1
  t0=$(date +%s%N)
  QP1=$(req "$port" "$body_llama" -H "$h1")
  QP1_NONCE=$(last_nonce)
  t1=$(date +%s%N)
  QP2=$(req "$port" "$body_llama" -H "$h2")
  QP2_NONCE=$(last_nonce)
  QP_GAP_MS=$(( (t1 - t0) / 1000000 ))
}

# qos_triple <port> <cred-header> -- three back-to-back requests from one
# credential, for the cases whose claim is that a limit did NOT bind.
qos_triple() {
  local port=$1 h=$2
  QT1=$(req "$port" "$body_llama" -H "$h"); QT1_NONCE=$(last_nonce)
  QT2=$(req "$port" "$body_llama" -H "$h"); QT2_NONCE=$(last_nonce)
  QT3=$(req "$port" "$body_llama" -H "$h"); QT3_NONCE=$(last_nonce)
}

# qos_gap_ok <name> -- a 1-rps bucket hands back a token every second, so the
# second request of a pair only decides anything if it left inside that
# second. A slower pair did not measure the product at all, and reporting its
# admitted second request as "the limit is missing" would turn a slow bed
# into a product defect. An unreadable measurement is a failure, not a pass.
QOS_GAP_BUDGET_MS=800
qos_gap_ok() {
  note_case "$1"
  if [ -z "$QP_GAP_MS" ]; then
    echo "  [FAIL] $1 - no inter-request gap recorded; the pair never ran"
    FAIL=$((FAIL + 1)); return
  fi
  if [ "$QP_GAP_MS" -lt "$QOS_GAP_BUDGET_MS" ]; then
    echo "  [PASS] $1 (${QP_GAP_MS}ms apart, inside the 1-rps refill)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 - the requests left ${QP_GAP_MS}ms apart, at or past the ${QOS_GAP_BUDGET_MS}ms budget:"
    echo "         the bucket refilled between them, so this pair measured nothing"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "== QOS: the QoS ladder at runtime (tenant-q / tenant-qt) =="
echo "   Stage 1 runs with NO defaults row anywhere, so an identity with no"
echo "   explicit row falls through to unlimited and every refusal below can"
echo "   only have come from the rung the case configured."

echo ""
echo "QOS-RPS-001: an explicit per-user row throttles the user it names, and"
echo "             only that user"
qos_cfg POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$SUB_q1\",\"rps\":1}"
qos_cfg_ok   "QOS-RPS-001 explicit rps=1 row for q1 accepted"
qos_pair 2040 "Authorization: Bearer $TOK_q1" "Authorization: Bearer $TOK_q1"
qos_gap_ok   "QOS-RPS-001 the pair decided inside one refill"
chk_code     "QOS-RPS-001 q1's first request admitted" 200 "$QP1"
chk_receipt  "QOS-RPS-001 q1's first request reached the backend" 1 "$QP1_NONCE"
chk_code     "QOS-RPS-001 q1's second request refused" 429 "$QP2"
chk_has      "QOS-RPS-001 the refusal names the user rung" "user_rate_limit_exceeded" "$QP2"
chk_receipt  "QOS-RPS-001 q1's second request never reached the backend" 0 "$QP2_NONCE"
echo "  control: q2 shares q1's tenant but has no row of its own"
qos_pair 2040 "Authorization: Bearer $TOK_q2" "Authorization: Bearer $TOK_q2"
chk_code     "QOS-RPS-001 q2's first request admitted" 200 "$QP1"
chk_code     "QOS-RPS-001 q2's second request admitted - the row bound q1 alone" 200 "$QP2"
chk_receipt  "QOS-RPS-001 q2's second request reached the backend" 1 "$QP2_NONCE"

echo ""
echo "QOS-RPS-004: the tenant ceiling caps the SUM of its users"
echo "             t1 and t2 have no rows of their own and no default stands"
echo "             above them, so nothing but the tenant bucket can refuse t2."
qos_cfg POST /config/ai/tenant/ratelimit \
  "{\"tenant_id\":\"$QOS_TT\",\"rps\":1,\"tokens_per_min\":100000}"
qos_cfg_ok   "QOS-RPS-004 tenant rps=1 row for tenant-qt accepted"
qos_pair 2040 "Authorization: Bearer $TOK_t1" "Authorization: Bearer $TOK_t2"
qos_gap_ok   "QOS-RPS-004 the pair decided inside one refill"
chk_code     "QOS-RPS-004 t1 admitted" 200 "$QP1"
chk_code     "QOS-RPS-004 t2 refused by its tenant's ceiling, not by its own" 429 "$QP2"
chk_has      "QOS-RPS-004 the refusal names the tenant rung" "tenant_quota_exceeded" "$QP2"
chk_not_has  "QOS-RPS-004 the user rung did not decide it" "user_rate_limit_exceeded" "$QP2"
chk_receipt  "QOS-RPS-004 t2 never reached the backend" 0 "$QP2_NONCE"
qos_cfg POST /config/ai/tenant/ratelimit \
  "{\"tenant_id\":\"$QOS_TT\",\"rps\":0,\"tokens_per_min\":100000}"
qos_cfg_ok   "QOS-RPS-004 the tenant ceiling is lifted again"

echo ""
echo "QOS-RPS-005: the key's own limit binds the key arm, the user rung binds"
echo "             the bearer arm, and neither reaches across"
echo "             Port 2041 is apikey-or-jwt: a present X-Api-Key decides"
echo "             alone, so both credential types are exercised on ONE"
echo "             service and the arm is the only variable."
echo "  before: the key was created with no rate limit"
qos_pair 2041 "X-Api-Key: $QOS_RAW_KEY" "X-Api-Key: $QOS_RAW_KEY"
chk_code     "QOS-RPS-005 the unpatched key's first request admitted" 200 "$QP1"
chk_code     "QOS-RPS-005 the unpatched key's second request admitted" 200 "$QP2"
qos_cfg PATCH "/config/ai/apikey/$QOS_KEY_ID" '{"rate_limit_rps":1}'
qos_cfg_ok   "QOS-RPS-005 PATCH the key's rps to 1 accepted"
qos_pair 2041 "X-Api-Key: $QOS_RAW_KEY" "X-Api-Key: $QOS_RAW_KEY"
qos_gap_ok   "QOS-RPS-005 the pair decided inside one refill"
chk_code     "QOS-RPS-005 the patched key's first request admitted" 200 "$QP1"
chk_code     "QOS-RPS-005 the patched key's second request refused" 429 "$QP2"
# "rate_limit_exceeded" is a substring of "user_rate_limit_exceeded", so the
# presence check alone cannot tell the key rung from the user rung. The
# absence check is what makes the pair decisive.
chk_has      "QOS-RPS-005 the refusal names a rate rung" "rate_limit_exceeded" "$QP2"
chk_not_has  "QOS-RPS-005 it was the KEY rung, not the user rung" "user_rate_limit_exceeded" "$QP2"
chk_receipt  "QOS-RPS-005 the refused key request never reached the backend" 0 "$QP2_NONCE"
echo "  control: a bearer credential on the SAME service is untouched by it"
r=$(req 2041 "$body_llama" -H "Authorization: Bearer $TOK_q2")
n=$(last_nonce)
chk_code     "QOS-RPS-005 the bearer arm is not bound by the key's limit" 200 "$r"
chk_receipt  "QOS-RPS-005 the bearer request reached the backend" 1 "$n"

echo ""
echo "   Stage 2 installs a global defaults row (default_user_rps=1) and the"
echo "   two rule-scope rows that disagree with it. The global row bounds"
echo "   every attributed identity on every service, so it is installed here"
echo "   -- after the blocks that drive alice and bob -- and removed again by"
echo "   QOS-DEF-003 before the run ends."
qos_cfg POST /config/ai/ratelimit/defaults '{"scope":"global","default_user_rps":1}'
qos_cfg_ok   "QOS-DEF-001 the global defaults row is installed"
qos_cfg POST /config/ai/ratelimit/defaults \
  '{"scope":"rule","rule_ident":"10.10.10.254:2059","default_user_rps":9}'
qos_cfg_ok   "QOS-DEF-001 the rule row for :2059 sets the user rps"
qos_cfg POST /config/ai/ratelimit/defaults \
  '{"scope":"rule","rule_ident":"10.10.10.254:2060","default_user_tpm":100000}'
qos_cfg_ok   "QOS-DEF-002 the rule row for :2060 exists but leaves the user rps zero"

echo ""
echo "QOS-RPS-002: a user with no explicit row follows the default, and each"
echo "             such user gets its OWN bucket"
qos_pair 2040 "Authorization: Bearer $TOK_q5" "Authorization: Bearer $TOK_q5"
qos_gap_ok   "QOS-RPS-002 the pair decided inside one refill"
chk_code     "QOS-RPS-002 q5's first request admitted" 200 "$QP1"
chk_code     "QOS-RPS-002 q5's second request refused by the default" 429 "$QP2"
chk_has      "QOS-RPS-002 the refusal names the user rung" "user_rate_limit_exceeded" "$QP2"
echo "  isolation: q6 shares the tenant and the default, and is unaffected by"
echo "  q6 is refused by nothing here - a shared bucket would have refused it"
r=$(req 2040 "$body_llama" -H "Authorization: Bearer $TOK_q6")
n=$(last_nonce)
chk_code     "QOS-RPS-002 q6's bucket is untouched by q5's exhaustion" 200 "$r"
chk_receipt  "QOS-RPS-002 q6's request reached the backend" 1 "$n"

echo ""
echo "QOS-RPS-003: an explicit row wins over the default, and deleting it"
echo "             puts the identity back under the default"
echo "             This is the runtime half of the management block's DELETE"
echo "             case, which could only assert that the row was gone."
qos_cfg POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$SUB_q3\",\"rps\":9}"
qos_cfg_ok   "QOS-RPS-003 explicit rps=9 row for q3 accepted"
qos_triple 2040 "Authorization: Bearer $TOK_q3"
chk_code     "QOS-RPS-003 q3's first request admitted" 200 "$QT1"
chk_code     "QOS-RPS-003 q3's second request admitted - the default would have refused it" 200 "$QT2"
chk_code     "QOS-RPS-003 q3's third request admitted" 200 "$QT3"
qos_cfg DELETE "/config/ai/user/ratelimit/$QOS_T/$SUB_q3"
qos_cfg_ok   "QOS-RPS-003 the explicit row is deleted"
qos_pair 2040 "Authorization: Bearer $TOK_q3" "Authorization: Bearer $TOK_q3"
qos_gap_ok   "QOS-RPS-003 the pair decided inside one refill"
chk_code     "QOS-RPS-003 q3's first request after the delete admitted" 200 "$QP1"
chk_code     "QOS-RPS-003 q3 now follows the default and is refused" 429 "$QP2"
chk_has      "QOS-RPS-003 the refusal names the user rung" "user_rate_limit_exceeded" "$QP2"
chk_receipt  "QOS-RPS-003 the refused request never reached the backend" 0 "$QP2_NONCE"

echo ""
echo "QOS-DEF-001: the rule-scope row overrides global for the field it sets"
echo "             The control is the SAME identity on a service with no rule"
echo "             row: one user, two services, two verdicts - so the service's"
echo "             row is what decided, not anything about the user."
qos_triple 2059 "Authorization: Bearer $TOK_q7"
chk_code     "QOS-DEF-001 q7's first request on :2059 admitted" 200 "$QT1"
chk_code     "QOS-DEF-001 q7's second request on :2059 admitted - global's 1 would have refused it" 200 "$QT2"
chk_code     "QOS-DEF-001 q7's third request on :2059 admitted" 200 "$QT3"
qos_pair 2040 "Authorization: Bearer $TOK_q7" "Authorization: Bearer $TOK_q7"
qos_gap_ok   "QOS-DEF-001 the control pair decided inside one refill"
chk_code     "QOS-DEF-001 the same user's first request on :2040 admitted" 200 "$QP1"
chk_code     "QOS-DEF-001 the same user is refused on :2040, where no rule row stands" 429 "$QP2"
chk_has      "QOS-DEF-001 the control refusal names the user rung" "user_rate_limit_exceeded" "$QP2"

echo ""
echo "QOS-DEF-002: a rule row that leaves a field zero does not shadow global"
echo "             :2060 HAS a rule row, but it sets only the token field, so"
echo "             the rps must reach through it from global. An"
echo "             all-or-nothing override would leave q4 unlimited here."
qos_cfg GET "/config/ai/ratelimit/defaults/rule?rule_ident=10.10.10.254:2060"
qos_cfg_ok   "QOS-DEF-002 the rule row for :2060 reads back"
chk_has      "QOS-DEF-002 the row carries the token field it set" "100000" "$QOS_CFG_BODY"
qos_pair 2060 "Authorization: Bearer $TOK_q4" "Authorization: Bearer $TOK_q4"
qos_gap_ok   "QOS-DEF-002 the pair decided inside one refill"
chk_code     "QOS-DEF-002 q4's first request on :2060 admitted" 200 "$QP1"
chk_code     "QOS-DEF-002 q4 is refused by global's rps through an existing rule row" 429 "$QP2"
chk_has      "QOS-DEF-002 the refusal names the user rung" "user_rate_limit_exceeded" "$QP2"
chk_receipt  "QOS-DEF-002 the refused request never reached the backend" 0 "$QP2_NONCE"

echo ""
echo "QOS-DEF-003: with no explicit row and no default, the identity is"
echo "             unlimited - proven as a transition, not an end state"
echo "             q8 is bound first, so 'admitted' afterwards cannot be the"
echo "             reading of a rung that was never installed."
qos_pair 2040 "Authorization: Bearer $TOK_q8" "Authorization: Bearer $TOK_q8"
qos_gap_ok   "QOS-DEF-003 the before pair decided inside one refill"
chk_code     "QOS-DEF-003 q8's first request admitted while the default stands" 200 "$QP1"
chk_code     "QOS-DEF-003 q8's second request refused while the default stands" 429 "$QP2"
chk_has      "QOS-DEF-003 the refusal names the user rung" "user_rate_limit_exceeded" "$QP2"
qos_cfg DELETE /config/ai/ratelimit/defaults/global
qos_cfg_ok   "QOS-DEF-003 the global defaults row is deleted"
qos_triple 2040 "Authorization: Bearer $TOK_q8"
chk_code     "QOS-DEF-003 q8's first request after the delete admitted" 200 "$QT1"
chk_code     "QOS-DEF-003 q8's second request admitted - the rung is gone" 200 "$QT2"
chk_code     "QOS-DEF-003 q8's third request admitted" 200 "$QT3"
chk_receipt  "QOS-DEF-003 q8's third request reached the backend" 1 "$QT3_NONCE"

# The settle rides the response relay, so it lands after the answer reaches
# the client. A second request issued immediately would be admitted against a
# bucket that has not yet been told about the first, and the case would read
# as a missing limit.
QOS_SETTLE_WAIT=2

# qreq <port> <cred-header> [body] -- one request; publishes QR and QR_NONCE.
# Called directly, never inside $( ), so the globals reach the caller.
qreq() {
  local port=$1 h=$2 b=${3:-$body_llama}
  QR=$(req "$port" "$b" -H "$h")
  QR_NONCE=$(last_nonce)
}

echo ""
echo "   The per-VIP shared bucket. N1..N4 already pin its TOKEN half on"
echo "   keyless traffic; these two pin the halves N1..N4 cannot see — the"
echo "   RATE half, and what happens to it when the caller DOES present a"
echo "   credential. Both run here, before any token rung is configured, so"
echo "   the identities they use still carry no rows of their own."

echo ""
echo "QOS-VIP-001: the shared bucket's RATE half caps traffic carrying no"
echo "             credential at all. :2062 arms rps=1 with NO token bound,"
echo "             so the refusal names the rate rung and the token rung"
echo "             cannot be what produced it — which is exactly what"
echo "             N1..N4 cannot tell you, since there the rate side is"
echo "             deliberately left wide open so only tokens can bind."
qv_t0=$(date +%s%N)
QV1=$(req 2062 "$body_llama"); QV1_NONCE=$(last_nonce)
qv_t1=$(date +%s%N)
QV2=$(req 2062 "$body_llama"); QV2_NONCE=$(last_nonce)
QP_GAP_MS=$(( (qv_t1 - qv_t0) / 1000000 ))
qos_gap_ok   "QOS-VIP-001 the keyless pair decided inside one refill"
chk_code     "QOS-VIP-001 the first keyless request admitted" 200 "$QV1"
chk_receipt  "QOS-VIP-001 the first keyless request reached the backend" 1 "$QV1_NONCE"
chk_code     "QOS-VIP-001 the second keyless request refused" 429 "$QV2"
chk_has      "QOS-VIP-001 the refusal names the rate rung" "rate_limit_exceeded" "$QV2"
chk_not_has  "QOS-VIP-001 the token rung did not decide it" "token_quota_exceeded" "$QV2"
chk_receipt  "QOS-VIP-001 the refused request never reached the backend" 0 "$QV2_NONCE"
echo "  and it is a bucket, not a wedge: the token is back a second later."
sleep 2
QV3=$(req 2062 "$body_llama"); QV3_NONCE=$(last_nonce)
chk_code     "QOS-VIP-001 the refilled bucket admits again" 200 "$QV3"
chk_receipt  "QOS-VIP-001 the refilled request reached the backend" 1 "$QV3_NONCE"

echo ""
echo "QOS-VIP-004: an answer served to a CREDENTIALED caller charges the"
echo "             shared bucket too, so the bucket bounds the SERVICE and"
echo "             not merely its anonymous half."
echo "             q4 (tenant-q) and t1 (tenant-qt) carry no rows of their"
echo "             own here and sit in different tenants, so the VIP is the"
echo "             only thing they share. The limit gauge is the charge"
echo "             oracle: a quota key publishes its limit only when"
echo "             something CHARGES it, so absent-then-10 is the spend"
echo "             arriving, not a row being configured."
QOS_VIP_LABEL='tenant="v_10.10.10.254_2061"'
VLIM0=$(metric_labeled loxilb_ai_token_quota_limit_tokens "$QOS_VIP_LABEL")
chk_num      "QOS-VIP-004 nothing has charged the shared bucket yet" 0 "$VLIM0"
qreq 2061 "Authorization: Bearer $TOK_q4"
chk_code     "QOS-VIP-004 q4's credentialed request admitted" 200 "$QR"
chk_receipt  "QOS-VIP-004 q4's request reached the backend" 1 "$QR_NONCE"
sleep $QOS_SETTLE_WAIT
VLIM1=$(metric_labeled loxilb_ai_token_quota_limit_tokens "$QOS_VIP_LABEL")
chk_num      "QOS-VIP-004 the credentialed answer charged the shared bucket" 10 "$VLIM1"
qreq 2061 "Authorization: Bearer $TOK_t1"
chk_code     "QOS-VIP-004 a different tenant is refused by what q4 spent" 429 "$QR"
chk_has      "QOS-VIP-004 the shared bucket refused it before dispatch" "token_quota_would_exceed" "$QR"
chk_receipt  "QOS-VIP-004 the refused request never reached the backend" 0 "$QR_NONCE"
echo "  control: the same identity on :2040, which arms no shared bucket, is"
echo "  served — so it was the VIP that refused t1, not anything about t1."
qreq 2040 "Authorization: Bearer $TOK_t1"
chk_code     "QOS-VIP-004 t1 is served where no shared bucket stands" 200 "$QR"
chk_receipt  "QOS-VIP-004 t1's request there reached the backend" 1 "$QR_NONCE"

echo ""
echo "   The token rungs. Every echoed answer settles exactly 12 tokens, so a"
echo "   budget of 10 is decided in two requests: the first is admitted"
echo "   against a clean bucket, its settle puts the bucket in debt, and the"
echo "   next request is refused at admission. That is the same shape the"
echo "   keyless N block uses, applied to the credentialed rungs."
echo "   All five token rungs answer with the SAME code, token_quota_exceeded,"
echo "   so no case here can be decided by the error string alone: each one"
echo "   is paired with a sibling that must still be served."

echo ""
echo "QOS-TPM-001: a user's aggregate token budget refuses their next request"
echo "             once the answer has been charged, and deleting the row"
echo "             lifts the rung even though the bucket is still in debt"
qos_cfg POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$SUB_q9\",\"tokens_per_min\":10}"
qos_cfg_ok   "QOS-TPM-001 a token-only row for q9 accepted"
qreq 2040 "Authorization: Bearer $TOK_q9"
chk_code     "QOS-TPM-001 q9's first request admitted" 200 "$QR"
chk_receipt  "QOS-TPM-001 q9's first request reached the backend" 1 "$QR_NONCE"
sleep $QOS_SETTLE_WAIT
qreq 2040 "Authorization: Bearer $TOK_q9"
chk_code     "QOS-TPM-001 q9's next request refused by its token budget" 429 "$QR"
chk_has      "QOS-TPM-001 the refusal names the token quota" "token_quota_exceeded" "$QR"
chk_receipt  "QOS-TPM-001 the refused request never reached the backend" 0 "$QR_NONCE"
qos_cfg DELETE "/config/ai/user/ratelimit/$QOS_T/$SUB_q9"
qos_cfg_ok   "QOS-TPM-001 the user's token row is deleted"
qreq 2040 "Authorization: Bearer $TOK_q9"
chk_code     "QOS-TPM-001 q9 is served again once the rung is gone" 200 "$QR"
chk_receipt  "QOS-TPM-001 q9's request reaches the backend again" 1 "$QR_NONCE"

echo ""
echo "QOS-TPM-002: a per-model budget refuses only the model it names, and"
echo "             stops refusing once it is removed"
echo "             The removal half is the one that matters: the row can be"
echo "             read back as gone while the gate goes on refusing against"
echo "             it, because the gate's read is cache-first and the config"
echo "             read is not."
qos_cfg POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_T\",\"user_id\":\"$SUB_q10\",\"model_limits\":[{\"model\":\"llama-70b\",\"tokens_per_min\":10}]}"
qos_cfg_ok   "QOS-TPM-002 a llama-only token row for q10 accepted"
qreq 2040 "Authorization: Bearer $TOK_q10"
chk_code     "QOS-TPM-002 q10's first llama request admitted" 200 "$QR"
chk_receipt  "QOS-TPM-002 q10's first llama request reached the backend" 1 "$QR_NONCE"
sleep $QOS_SETTLE_WAIT
qreq 2040 "Authorization: Bearer $TOK_q10"
chk_code     "QOS-TPM-002 q10's next llama request refused" 429 "$QR"
chk_has      "QOS-TPM-002 the refusal names the token quota" "token_quota_exceeded" "$QR"
chk_receipt  "QOS-TPM-002 the refused llama request never reached the backend" 0 "$QR_NONCE"
echo "  the same user's other model carries no budget and must still be served"
qreq 2040 "Authorization: Bearer $TOK_q10" "$body_mistral"
chk_code     "QOS-TPM-002 q10's mistral request is still served" 200 "$QR"
chk_receipt  "QOS-TPM-002 q10's mistral request reached the backend" 1 "$QR_NONCE"
qos_cfg DELETE "/config/ai/user/ratelimit/$QOS_T/$SUB_q10"
qos_cfg_ok   "QOS-TPM-002 the row carrying the model budget is deleted"
qreq 2040 "Authorization: Bearer $TOK_q10"
chk_code     "QOS-TPM-002 the removed model budget stops refusing" 200 "$QR"
chk_receipt  "QOS-TPM-002 the llama request reaches the backend again" 1 "$QR_NONCE"

echo ""
echo "QOS-TPM-003: a tenant's token budget caps the SUM of its users"
echo "             m1 and m2 have no rows of their own, so a refusal of m2"
echo "             after m1 spent the budget can only be the tenant bucket."
qos_cfg POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"tenant-qm","tokens_per_min":10}'
qos_cfg_ok   "QOS-TPM-003 tenant tokens_per_min=10 for tenant-qm accepted"
qreq 2040 "Authorization: Bearer $TOK_m1"
chk_code     "QOS-TPM-003 m1's request admitted" 200 "$QR"
chk_receipt  "QOS-TPM-003 m1's request reached the backend" 1 "$QR_NONCE"
sleep $QOS_SETTLE_WAIT
qreq 2040 "Authorization: Bearer $TOK_m2"
chk_code     "QOS-TPM-003 m2 is refused by what m1 spent" 429 "$QR"
chk_has      "QOS-TPM-003 the refusal names the token quota" "token_quota_exceeded" "$QR"
chk_receipt  "QOS-TPM-003 m2 never reached the backend" 0 "$QR_NONCE"

echo ""
echo "QOS-TPM-004: a tenant|model budget leaves the tenant's other models"
echo "             with headroom"
echo "             tenant-qn carries no aggregate budget, so the only rung"
echo "             that can refuse the llama request is the model's own."
qos_cfg POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"tenant-qn","model_limits":[{"model":"llama-70b","tokens_per_min":10}]}'
qos_cfg_ok   "QOS-TPM-004 a llama-only tenant budget for tenant-qn accepted"
qreq 2040 "Authorization: Bearer $TOK_n1"
chk_code     "QOS-TPM-004 n1's first llama request admitted" 200 "$QR"
chk_receipt  "QOS-TPM-004 n1's first llama request reached the backend" 1 "$QR_NONCE"
sleep $QOS_SETTLE_WAIT
qreq 2040 "Authorization: Bearer $TOK_n1"
chk_code     "QOS-TPM-004 n1's next llama request refused" 429 "$QR"
chk_has      "QOS-TPM-004 the refusal names the token quota" "token_quota_exceeded" "$QR"
chk_receipt  "QOS-TPM-004 the refused llama request never reached the backend" 0 "$QR_NONCE"
qreq 2040 "Authorization: Bearer $TOK_n1" "$body_mistral"
chk_code     "QOS-TPM-004 the tenant's other model retains headroom" 200 "$QR"
chk_receipt  "QOS-TPM-004 the mistral request reached the backend" 1 "$QR_NONCE"

echo ""
echo "QOS-TPM-005: a key's stored tokens_per_min is actually enforced"
echo "             The key's request-rate limit is lifted in the same PATCH,"
echo "             so the rung under test is the only one that can refuse -"
echo "             and the rate rung's own code must be absent from the answer."
qos_cfg PATCH "/config/ai/apikey/$QOS_KEY_ID" '{"rate_limit_rps":0,"tokens_per_min":10}'
qos_cfg_ok   "QOS-TPM-005 the key's rate limit is lifted and a token budget set"
qreq 2041 "X-Api-Key: $QOS_RAW_KEY"
chk_code     "QOS-TPM-005 the key's first request admitted" 200 "$QR"
chk_receipt  "QOS-TPM-005 the key's first request reached the backend" 1 "$QR_NONCE"
sleep $QOS_SETTLE_WAIT
qreq 2041 "X-Api-Key: $QOS_RAW_KEY"
chk_code     "QOS-TPM-005 the key's next request refused by its token budget" 429 "$QR"
chk_has      "QOS-TPM-005 the refusal names the token quota" "token_quota_exceeded" "$QR"
chk_not_has  "QOS-TPM-005 it was the token rung, not the request-rate rung" "rate_limit_exceeded" "$QR"
chk_receipt  "QOS-TPM-005 the refused request never reached the backend" 0 "$QR_NONCE"

echo ""
echo "QOS-TPM-006: lifting a TENANT token quota releases the tenant, exactly"
echo "             as lifting a USER's does (QOS-TPM-001's second half)."
echo "             The tenant surface has no DELETE, so tokens_per_min=0 is"
echo "             the only lift there is: if it does not take effect, the"
echo "             quota cannot be removed at all. The budget is 8 rather"
echo "             than 10 on purpose — an answer of 12 leaves the bucket"
echo "             far enough in debt that the drain cannot be mistaken for"
echo "             the release, which at 10 is only a few seconds away."
echo "             The re-arm at the end is what makes this measure the"
echo "             GUARD: deleting the tenant rung outright would satisfy"
echo "             every assertion above it and none of the last one."
qos_cfg POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"tenant-qt","tokens_per_min":8}'
qos_cfg_ok   "QOS-TPM-006 tenant tokens_per_min=8 for tenant-qt accepted"
qreq 2040 "Authorization: Bearer $TOK_t1"
chk_code     "QOS-TPM-006 t1's request admitted" 200 "$QR"
chk_receipt  "QOS-TPM-006 t1's request reached the backend" 1 "$QR_NONCE"
sleep $QOS_SETTLE_WAIT
qreq 2040 "Authorization: Bearer $TOK_t2"
chk_code     "QOS-TPM-006 t2 is refused by what t1 spent" 429 "$QR"
chk_has      "QOS-TPM-006 the refusal names the token quota" "token_quota_exceeded" "$QR"
chk_not_has  "QOS-TPM-006 it was the token rung, not the tenant's rate rung" "tenant_quota_exceeded" "$QR"
chk_receipt  "QOS-TPM-006 the refused request never reached the backend" 0 "$QR_NONCE"
qos_cfg POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"tenant-qt","tokens_per_min":0}'
qos_cfg_ok   "QOS-TPM-006 the tenant's token quota is lifted"
qreq 2040 "Authorization: Bearer $TOK_t2"
chk_code     "QOS-TPM-006 t2 is served again once the rung is gone" 200 "$QR"
chk_receipt  "QOS-TPM-006 t2's request reaches the backend again" 1 "$QR_NONCE"
echo "  and the lift removed the RUNG, not the spend: re-arming the same"
echo "  budget brings back the debt that is still sitting in the bucket."
qos_cfg POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"tenant-qt","tokens_per_min":8}'
qos_cfg_ok   "QOS-TPM-006 the tenant's token quota is re-armed"
qreq 2040 "Authorization: Bearer $TOK_t2"
chk_code     "QOS-TPM-006 the undrained debt refuses t2 again" 429 "$QR"
chk_has      "QOS-TPM-006 the re-armed refusal names the token quota" "token_quota_exceeded" "$QR"
chk_receipt  "QOS-TPM-006 the re-refused request never reached the backend" 0 "$QR_NONCE"


echo ""
echo "== QOS fault injection: the arms that have to BREAK something =="
echo "   QOS-RES-001..003, QOS-OUT-001..004, QOS-ID-001/002. A different"
echo "   shape of case from everything above: those configured a limit and"
echo "   drove traffic, these take the store away, abort a request that is"
echo "   still holding a claim, or hand the gateway an identity the bucket"
echo "   keyspace cannot represent -- and watch what the gate does."

# ---------------------------------------------------------------------------
# The store-outage lever.
#
# `docker pause pg-jwtauth` CANNOT produce policy_store_unavailable and is not
# used here. Traced at source: Service.store() (pkg/aikey/service.go) returns
# an error only when the pool POINTER is nil, and Service.Ticker() never nils
# an existing pool -- *sql.DB re-dials its own connections. What the error
# path actually keys on is the QUERY returning an error. A paused Postgres
# returns nothing at all: the socket stays open and the query blocks, so the
# request hangs until curl's --max-time kills it and the case scores
# http_code=000 -- a lost measurement, not a gateway answer.
#
# Revoking the data-plane role's USAGE on the schema produces the error
# directly. Every statement against aigw.* fails at planning time, including
# on connections that are already open, so there is nothing to wait for; the
# container and its data directory are untouched, so the GRANT restores
# service without a gateway restart -- which is exactly what QOS-OUT-004 has
# to show. Measured on the bed before this was written: 179ms to the error.
pg_admin_sql() { docker exec "$PG_NAME" psql -U "$PG_OWNER" -d "$PG_DB" -Atc "$1" 2>&1; }

# pg_dp_read -- one read as the DATA-PLANE role, with a hard timeout. The
# timeout is the point: a lever that hangs and a lever that errors are the
# same thing to an assertion that only looks at the exit status, and the
# whole reason the paused-container lever was rejected is that it hangs.
pg_dp_read() {
  timeout 5 docker exec -e PGPASSWORD="$PG_DP_PW" "$PG_NAME" \
    psql -U "$PG_DP_USER" -h 127.0.0.1 -d "$PG_DB" -Atc \
    "SELECT count(*) FROM ${PG_SCHEMA}.rate_limit_defaults" 2>&1
}

store_outage_on()  { pg_admin_sql "REVOKE USAGE ON SCHEMA ${PG_SCHEMA} FROM ${PG_DP_USER}"; }
store_outage_off() { pg_admin_sql "GRANT USAGE ON SCHEMA ${PG_SCHEMA} TO ${PG_DP_USER}"; }

# store_lever_ok <name> errors|serves -- the lever really is in the state the
# arms below assume, and it got there by ERRORING rather than by hanging.
# Asserted rather than assumed: every QOS-OUT verdict is a claim about what
# the gateway does when a read fails, and a lever that silently stopped
# working would turn all four of them into readings of a healthy store.
store_lever_ok() {
  local name=$1 want=$2 t0 t1 out ms
  note_case "$name"
  t0=$(date +%s%N); out=$(pg_dp_read); t1=$(date +%s%N)
  ms=$(( (t1 - t0) / 1000000 ))
  case "$want" in
    errors)
      case "$out" in
        *"permission denied"*)
          if [ "$ms" -lt 4000 ]; then
            echo "  [PASS] $name (errored in ${ms}ms, not a hang)"; PASS=$((PASS + 1))
          else
            echo "  [FAIL] $name - the read errored but took ${ms}ms; at that latency a"
            echo "         request would score http_code=000 and measure curl, not the gate"
            FAIL=$((FAIL + 1))
          fi ;;
        *) echo "  [FAIL] $name - the data-plane read did NOT fail with the outage in place"
           echo "         (${ms}ms): $(echo "$out" | tr '\n' ' ' | head -c 160)"
           FAIL=$((FAIL + 1)) ;;
      esac ;;
    serves)
      case "$out" in
        ''|*[!0-9]*) echo "  [FAIL] $name - the store did not answer a plain read (${ms}ms): $(echo "$out" | tr '\n' ' ' | head -c 160)"
                     FAIL=$((FAIL + 1)) ;;
        *) echo "  [PASS] $name (answered $out in ${ms}ms)"; PASS=$((PASS + 1)) ;;
      esac ;;
  esac
}

# ---- the reservation arms' drive shape -----------------------------------
#
# A reservation orphaned by an aborted or re-configured request is expired by
# the epoch advance -- currentQuotaEpoch is wall-clock minute-aligned
# (now.Unix()/60 in pkg/ratelimit), so the whole window in which a leak is
# OBSERVABLE is the remainder of the current minute. A sequence that straddles
# a minute boundary measures the epoch reset instead of the release path and
# would report a leaking build as clean.
#
# qos_epoch_fresh waits for the start of a minute so the sequence has room,
# and qos_epoch_ok asserts afterwards that it did not straddle one anyway.
qos_epoch_fresh() {
  local s
  s=$(( $(date +%s) % 60 ))
  if [ "$s" -gt 20 ]; then sleep $(( 61 - s )); fi
  QOS_EPOCH0=$(( $(date +%s) / 60 ))
}
qos_epoch_ok() {
  note_case "$1"
  local now; now=$(( $(date +%s) / 60 ))
  if [ -z "$QOS_EPOCH0" ]; then
    echo "  [FAIL] $1 - no epoch was recorded; the sequence never ran"
    FAIL=$((FAIL + 1)); return
  fi
  if [ "$now" = "$QOS_EPOCH0" ]; then
    echo "  [PASS] $1 (one quota epoch throughout)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 - the sequence straddled a quota-epoch boundary"
    echo "         ($QOS_EPOCH0 -> $now): the epoch advance zeroes every outstanding"
    echo "         reservation, so this run measured the reset and not the release"
    FAIL=$((FAIL + 1))
  fi
}

# rreq <port> <token> <model-body> <max_tokens> [extra curl args...]
# One reservation-arm request. max_tokens is what sizes the claim: the
# admission reservation is prompt-estimate + declared max_tokens, so it is the
# knob that decides whether a bucket can cover the request.
rreq() {
  local port=$1 tok=$2 model=$3 maxt=$4; shift 4
  RR=$(req "$port" "{\"model\":\"$model\",\"max_tokens\":$maxt,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" \
        -H "Authorization: Bearer $tok" "$@")
  RR_NONCE=$(last_nonce)
}

QOS_FI_T=tenant-qr
QOS_OUT_T=tenant-qf

echo ""
echo "-- QOS-RES: the pre-admission reservation --"
echo "   Admission claims the request's worst case (prompt estimate +"
echo "   declared max_tokens) against every bucket in the ladder BEFORE the"
echo "   request is dispatched, and settlement releases the claim. Both"
echo "   halves are invisible in a healthy request: what makes them testable"
echo "   is a claim that is taken and then must come back -- rolled back by a"
echo "   later bucket's refusal, released by an aborted request, or released"
echo "   by a request whose configuration vanished under it."
echo "   Bucket capacity is 100% of tokens_per_min by default, so a tenant"
echo "   at tokens_per_min=1000 can hold at most 1000 tokens of claim."

qos_cfg POST /config/ai/tenant/ratelimit \
  "{\"tenant_id\":\"$QOS_FI_T\",\"tokens_per_min\":1000,\"model_limits\":[{\"model\":\"mistral-7b\",\"tokens_per_min\":100}]}"
qos_cfg_ok   "QOS-RES-001 tenant-qr armed: aggregate 1000, mistral-7b 100"

echo ""
echo "QOS-RES-001: a LATER bucket's refusal gives back every claim an EARLIER"
echo "             bucket already granted."
echo "             The ladder is [tenant 1000, tenant|mistral 100] and the"
echo "             request asks for ~600: the tenant bucket can cover it, the"
echo "             model bucket cannot. The refusal is not the interesting"
echo "             part -- what matters is the tenant bucket afterwards, and"
echo "             the only way to read that is to send it a request the"
echo "             model bucket has no say in."
qos_epoch_fresh
rreq 2065 "$TOK_r1" mistral-7b 600
chk_code     "QOS-RES-001 the over-model request is refused" 429 "$RR"
chk_has      "QOS-RES-001 refused at ADMISSION, not by the post-hoc latch" "token_quota_would_exceed" "$RR"
chk_not_has  "QOS-RES-001 and not by the latched code" "\"token_quota_exceeded\"" "$RR"
chk_receipt  "QOS-RES-001 the refused request never reached the backend" 0 "$RR_NONCE"
rreq 2065 "$TOK_r1" llama-70b 600
chk_code     "QOS-RES-001 a same-size request on a model the tenant bucket alone gates is admitted" 200 "$RR"
chk_receipt  "QOS-RES-001 and it reached the backend" 1 "$RR_NONCE"
qos_epoch_ok "QOS-RES-001 the pair stayed inside one quota epoch"

echo ""
echo "QOS-RES-002: a request aborted IN FLIGHT releases its claim, and is"
echo "             charged nothing."
echo "             The backend is held for 5s and the client is cut off after"
echo "             1s, so there is no response to extract usage from and the"
echo "             only thing settlement can do is release. The backend"
echo "             receipt is the drive-shape oracle: without it, a request"
echo "             the gateway refused outright would produce the same clean"
echo "             bucket and the case would pass having tested nothing."
qos_epoch_fresh
RCONS0=$(metric_labeled loxilb_ai_tokens_consumed_total "tenant=\"$QOS_FI_T\"")
rreq 2065 "$TOK_r2" llama-70b 600 -H "X-Test-Delay-Ms: 5000" --max-time 1
chk_aborted  "QOS-RES-002 the client really did abort" "$RR"
chk_receipt  "QOS-RES-002 the request HAD reached the backend, so a claim existed" 1 "$RR_NONCE"
sleep 8
rreq 2065 "$TOK_r2" llama-70b 600
chk_code     "QOS-RES-002 a full-size request is admitted afterwards - the claim came back" 200 "$RR"
chk_has      "QOS-RES-002 and not refused at admission" "server-llama" "$RR"
chk_receipt  "QOS-RES-002 and it reached the backend" 1 "$RR_NONCE"
qos_epoch_ok "QOS-RES-002 the abort and the probe stayed inside one quota epoch"
RCONS1=$(metric_labeled loxilb_ai_tokens_consumed_total "tenant=\"$QOS_FI_T\"")
if [ "$RCONS0" = "unreadable" ] || [ "$RCONS1" = "unreadable" ]; then
  note_case "QOS-RES-002"
  echo "  [FAIL] QOS-RES-002 the consumed-token metric is unreadable - a phantom charge cannot be ruled out"
  FAIL=$((FAIL + 1))
else
  # 12 is the echo's fixed usage for the ONE answered request above. The
  # aborted request must add nothing: it produced no response and no usage.
  chk_num "QOS-RES-002 the aborted request was charged nothing (only the probe's 12 landed)" 12 $((RCONS1 - RCONS0))
fi

echo ""
echo "QOS-RES-003: a bucket whose CONFIGURATION vanishes while a request is"
echo "             holding its claim still gets the claim back."
echo "             Settlement re-resolves the ladder from the store, so a"
echo "             bucket that stopped resolving between admission and"
echo "             settlement is a bucket nothing releases. The claim then"
echo "             sits on the live bucket until the epoch expires it, and"
echo "             the limit is re-created on top of it -- so the next"
echo "             request is refused against headroom that is not actually"
echo "             spent."
# llama-70b, NOT mistral: :2065's rule serves llama-70b only, and a mistral
# request there is answered 503 model_unavailable by the ROUTER, long after
# admission. QOS-RES-001 can use mistral precisely because its request never
# gets past admission; this one has to reach the backend and come back.
qos_cfg POST /config/ai/tenant/ratelimit \
  "{\"tenant_id\":\"$QOS_FI_T\",\"tokens_per_min\":1000,\"model_limits\":[{\"model\":\"llama-70b\",\"tokens_per_min\":1000}]}"
qos_cfg_ok   "QOS-RES-003 tenant|llama-70b armed at 1000 so it admits the claim"
qos_epoch_fresh
# Called directly and then CONSUMED, never inside $( ): new_nonce publishes
# through a global and a file, and a subshell would leave the ".last" file
# behind for an unrelated assertion to pick up.
new_nonce
RES3_NONCE=$(last_nonce)
( $hexec l3h1 curl -s -o /dev/null --max-time 20 -X POST \
    -H "Content-Type: application/json" \
    -H "X-Test-Nonce: $RES3_NONCE" \
    -H "X-Test-Delay-Ms: 4000" \
    -H "Authorization: Bearer $TOK_r2" \
    -d '{"model":"llama-70b","max_tokens":600,"messages":[{"role":"user","content":"hi"}]}' \
    "http://$VIP:2065/v1/chat/completions" ) > /dev/null 2>&1 &
RES3_BG=$!
sleep 2
chk_receipt  "QOS-RES-003 the in-flight request reached the backend and is holding its claim" 1 "$RES3_NONCE"
qos_cfg POST /config/ai/tenant/ratelimit \
  "{\"tenant_id\":\"$QOS_FI_T\",\"tokens_per_min\":1000,\"model_limits\":[{\"model\":\"llama-70b\",\"tokens_per_min\":0}]}"
qos_cfg_ok   "QOS-RES-003 the tenant|llama-70b limit is removed while the request is in flight"
wait $RES3_BG 2>/dev/null
sleep "$QOS_SETTLE_WAIT"
qos_cfg POST /config/ai/tenant/ratelimit \
  "{\"tenant_id\":\"$QOS_FI_T\",\"tokens_per_min\":1000,\"model_limits\":[{\"model\":\"llama-70b\",\"tokens_per_min\":1000}]}"
qos_cfg_ok   "QOS-RES-003 the tenant|llama-70b limit is put back"
rreq 2065 "$TOK_r2" llama-70b 600
chk_code     "QOS-RES-003 a fresh request on the re-created bucket is admitted" 200 "$RR"
chk_not_has  "QOS-RES-003 it was not refused against a claim nobody released" "token_quota_would_exceed" "$RR"
chk_receipt  "QOS-RES-003 and it reached the backend" 1 "$RR_NONCE"
qos_epoch_ok "QOS-RES-003 the whole sequence stayed inside one quota epoch"

echo ""
echo "-- QOS-OUT: the policy store goes away --"
echo "   The posture the ladder is supposed to hold: a keyed identity whose"
echo "   limits are UNKNOWABLE fails closed with policy_store_unavailable and"
echo "   a 503 -- never a 429, which tells the client to slow down when the"
echo "   truth is that the gateway cannot tell. An identity the store HAS"
echo "   answered for keeps being served from the last known answer. And the"
echo "   opt-in keyless bucket, alone, fails open."
echo ""
echo "   Warming first, while the store is healthy. Which identities are"
echo "   cached and which are not IS the variable every case below turns on,"
echo "   so it is established deliberately rather than inherited:"
echo "     f1  driven now, then given an rps=1 row      -> enforced in outage"
echo "     f2  given a row and then DELETED             -> last-known says"
echo "         'no row', and the TTL entry is dropped by the delete, so"
echo "         serving f2 during the outage can ONLY have come from the"
echo "         last-known map"
echo "     f3  never driven, never configured           -> unknowable"
echo "     f4  never driven, and kept for the recovery  -> unknowable"
store_lever_ok "QOS-OUT-001 the store answers the data-plane role before the outage" serves
qreq 2063 "Authorization: Bearer $TOK_f1"
chk_code     "QOS-OUT-001 f1 is served while the store is healthy" 200 "$QR"
qos_cfg POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_OUT_T\",\"user_id\":\"$SUB_f1\",\"rps\":1}"
qos_cfg_ok   "QOS-OUT-001 f1 is given an explicit rps=1 row"
# f2 is driven FIRST. Every rung the ladder consults is a separate store
# read with its own cache entry -- the user row, and the user|model row that
# stage 3 reads next to it -- and only a read the store has ANSWERED leaves a
# last-known value behind. Setting f2's row without driving f2 leaves its
# user|model read unknowable, and the outage then refuses f2 for a rung this
# case is not about, which is exactly what the first run of this arm did.
qreq 2063 "Authorization: Bearer $TOK_f2"
chk_code     "QOS-OUT-001 f2 is served while the store is healthy" 200 "$QR"
qos_cfg POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"$QOS_OUT_T\",\"user_id\":\"$SUB_f2\",\"rps\":1}"
qos_cfg_ok   "QOS-OUT-001 f2 is given a row"
qos_cfg DELETE "/config/ai/user/ratelimit/$QOS_OUT_T/$SUB_f2"
qos_cfg_ok   "QOS-OUT-001 f2's row is deleted again - a store-CONFIRMED 'no row'"

PSU0=$(metric_value loxilb_ai_policy_store_unavailable_total)
store_outage_on >/dev/null
store_lever_ok "QOS-OUT-001 the outage lever errors the data-plane role's reads" errors

echo ""
echo "QOS-OUT-001: rows the store already answered for go on being enforced."
qos_pair 2063 "Authorization: Bearer $TOK_f1" "Authorization: Bearer $TOK_f1"
qos_gap_ok   "QOS-OUT-001 the pair decided inside one refill"
chk_code     "QOS-OUT-001 f1's first request is still served during the outage" 200 "$QP1"
chk_code     "QOS-OUT-001 f1's second request is still REFUSED by the cached row" 429 "$QP2"
chk_has      "QOS-OUT-001 and the refusal is the user rung, not the outage" "user_rate_limit_exceeded" "$QP2"
chk_not_has  "QOS-OUT-001 the outage did not switch the rung off" "policy_store_unavailable" "$QP2"
echo "  and the last-known map, specifically: f2's TTL entry was dropped by the"
echo "  DELETE, so a build that only kept a TTL cache would have nothing to"
echo "  answer from and would refuse f2 with the outage's code."
qreq 2063 "Authorization: Bearer $TOK_f2"
chk_code     "QOS-OUT-001 f2 is served from the store-confirmed 'no row'" 200 "$QR"
chk_receipt  "QOS-OUT-001 and f2's request reached the backend" 1 "$QR_NONCE"

echo ""
echo "QOS-OUT-002: an identity the store has NEVER answered for is refused,"
echo "             with the outage's own code."
qreq 2063 "Authorization: Bearer $TOK_f3"
chk_code     "QOS-OUT-002 f3 is refused" 503 "$QR"
chk_has      "QOS-OUT-002 with the store's code" "policy_store_unavailable" "$QR"
chk_not_has  "QOS-OUT-002 and NOT as a rate decision" "rate_limit_exceeded" "$QR"
chk_not_has  "QOS-OUT-002 and not as a token decision" "token_quota_exceeded" "$QR"
chk_receipt  "QOS-OUT-002 the refused request never reached the backend" 0 "$QR_NONCE"
PSU1=$(metric_value loxilb_ai_policy_store_unavailable_total)
if [ "$PSU0" = "unreadable" ] || [ "$PSU1" = "unreadable" ]; then
  note_case "QOS-OUT-002"
  echo "  [FAIL] QOS-OUT-002 policy_store_unavailable_total is unreadable - the outage has no counter"
  FAIL=$((FAIL + 1))
elif [ "$PSU1" -gt "$PSU0" ]; then
  note_case "QOS-OUT-002"
  echo "  [PASS] QOS-OUT-002 the outage counter moved ($PSU0 -> $PSU1) - reported as an outage, not a throttle"
  PASS=$((PASS + 1))
else
  note_case "QOS-OUT-002"
  echo "  [FAIL] QOS-OUT-002 policy_store_unavailable_total did not move ($PSU0 -> $PSU1):"
  echo "         a store outage that reports as a rate-limit spike sends the operator"
  echo "         looking at the tenant instead of at the store"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "QOS-OUT-003: the opt-in keyless bucket is the ONE arm that fails open."
echo "             :2064 and :2066 have never been driven, so neither has a"
echo "             rule-scope defaults row the store has answered for. The"
echo "             same unreadable read reaches both. The only difference"
echo "             between the two requests is a credential -- which is"
echo "             exactly the line the posture draws."
PSU2=$(metric_value loxilb_ai_policy_store_unavailable_total)
QR=$(req 2064 "$body_llama"); QR_NONCE=$(last_nonce)
chk_code     "QOS-OUT-003 the keyless request is SERVED with its defaults unreadable" 200 "$QR"
chk_receipt  "QOS-OUT-003 and it reached the backend" 1 "$QR_NONCE"
chk_not_has  "QOS-OUT-003 it was not refused with the outage's code" "policy_store_unavailable" "$QR"
qreq 2066 "Authorization: Bearer $TOK_f4"
chk_code     "QOS-OUT-003 the CREDENTIALED request on the same unreadable row is refused" 503 "$QR"
chk_has      "QOS-OUT-003 with the store's code" "policy_store_unavailable" "$QR"
chk_receipt  "QOS-OUT-003 and it never reached the backend" 0 "$QR_NONCE"
PSU3=$(metric_value loxilb_ai_policy_store_unavailable_total)
if [ "$PSU2" = "unreadable" ] || [ "$PSU3" = "unreadable" ]; then
  note_case "QOS-OUT-003"
  echo "  [FAIL] QOS-OUT-003 the outage counter is unreadable - the fail-open cannot be told from the fail-closed"
  FAIL=$((FAIL + 1))
else
  chk_num "QOS-OUT-003 exactly one of the two requests was reported as an outage" 1 $((PSU3 - PSU2))
fi

echo ""
echo "QOS-OUT-004: the store comes back and enforcement comes back with it,"
echo "             with no gateway restart."
GW_START0=$(docker inspect -f '{{.State.StartedAt}}' llb1 2>/dev/null)
store_outage_off >/dev/null
store_lever_ok "QOS-OUT-004 the store answers the data-plane role again" serves
sleep 1
qreq 2066 "Authorization: Bearer $TOK_f4"
chk_code     "QOS-OUT-004 f4 - refused moments ago - is served now" 200 "$QR"
chk_receipt  "QOS-OUT-004 and it reached the backend" 1 "$QR_NONCE"
qreq 2063 "Authorization: Bearer $TOK_f3"
chk_code     "QOS-OUT-004 f3 is served too" 200 "$QR"
echo "  and recovery is not amnesia: f1's row must still bind."
qos_pair 2063 "Authorization: Bearer $TOK_f1" "Authorization: Bearer $TOK_f1"
qos_gap_ok   "QOS-OUT-004 the pair decided inside one refill"
chk_code     "QOS-OUT-004 f1's first request admitted" 200 "$QP1"
chk_code     "QOS-OUT-004 f1's second request still refused by its row" 429 "$QP2"
chk_has      "QOS-OUT-004 by the user rung" "user_rate_limit_exceeded" "$QP2"
GW_START1=$(docker inspect -f '{{.State.StartedAt}}' llb1 2>/dev/null)
note_case "QOS-OUT-004"
if [ -z "$GW_START0" ] || [ -z "$GW_START1" ]; then
  echo "  [FAIL] QOS-OUT-004 the gateway's start time is unreadable - 'without a restart' is unproven"
  FAIL=$((FAIL + 1))
elif [ "$GW_START0" = "$GW_START1" ]; then
  echo "  [PASS] QOS-OUT-004 the gateway never restarted ($GW_START1)"
  PASS=$((PASS + 1))
else
  echo "  [FAIL] QOS-OUT-004 the gateway restarted during the outage ($GW_START0 -> $GW_START1):"
  echo "         recovery through a restart is not the property this case claims"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "-- QOS-ID: identities the bucket keyspace cannot represent --"
echo "   The quota keys are composed by concatenation: the tenant aggregate"
echo "   bucket is the BARE tenant id, tenant|model joins with '|', and the"
echo "   user, key and VIP scopes carry a reserved prefix that the peer-sync"
echo "   wire reads as the scope. So a tenant literally named 'a|b' IS tenant"
echo "   a's model-b bucket, and one named 'uq:a|b' IS a user bucket on the"
echo "   wire. Two identities, one quota."

echo ""
echo "QOS-ID-001: an unsafe identity arriving FROM THE IDP is refused"
echo "            admission, and nothing is delivered."
echo "            x1 and x2 are ordinary Keycloak users whose tenant_id"
echo "            attribute happens to be unrepresentable. A signature does"
echo "            not make a claim safe -- it proves the IdP minted it, and"
echo "            IdPs mint what their directories hold."
echo "            The client body is NOT the oracle here. The 401 surface is"
echo "            deliberately coarse -- every 401-class refusal collapses to"
echo "            invalid_token so the gate cannot be used to probe what an"
echo "            IdP holds -- and the validation metric labels that same"
echo "            coarse code. The reason reaches the gateway log and nowhere"
echo "            else, so the log is what gets read, and the count is taken"
echo "            as a DELTA so an earlier run's lines cannot supply it."
echo "            x1 and x2 exercise DIFFERENT guards: x1's tenant carries the"
echo "            composite-key delimiter, x2's carries a reserved scope"
echo "            prefix and no delimiter at all -- so a build that checked"
echo "            only for '|' would refuse x1 and admit x2."
IDLOG0=$(gw_log_count "unsafe_identity")
IDDEL0=$(gw_log_count "control characters and")
IDPFX0=$(gw_log_count "reserved rate-limit scope prefix")
qreq 2040 "Authorization: Bearer $TOK_x1"
chk_code     "QOS-ID-001 the pipe-bearing tenant claim is refused" 401 "$QR"
chk_receipt  "QOS-ID-001 nothing was delivered" 0 "$QR_NONCE"
qreq 2040 "Authorization: Bearer $TOK_x2"
chk_code     "QOS-ID-001 the reserved-prefix tenant claim is refused" 401 "$QR"
chk_receipt  "QOS-ID-001 nothing was delivered" 0 "$QR_NONCE"
IDLOG1=$(gw_log_count "unsafe_identity")
IDDEL1=$(gw_log_count "control characters and")
IDPFX1=$(gw_log_count "reserved rate-limit scope prefix")
chk_num      "QOS-ID-001 both refusals are attributed to the identity, not to a bad token" 2 $((IDLOG1 - IDLOG0))
chk_num      "QOS-ID-001 exactly one was the delimiter guard" 1 $((IDDEL1 - IDDEL0))
chk_num      "QOS-ID-001 and exactly one was the reserved-prefix guard" 1 $((IDPFX1 - IDPFX0))
echo "  Non-vacuity: a SAFE identity on the same port, in the same moment, is served."
qreq 2040 "Authorization: Bearer $TOK_z"
chk_code     "QOS-ID-001 a safe neighbour identity is still admitted" 200 "$QR"
chk_receipt  "QOS-ID-001 and it reached the backend" 1 "$QR_NONCE"

echo ""
echo "QOS-ID-002: neighbour identities do not alias one another's quota, and"
echo "            the config surfaces refuse the names that would make them."
echo "            The IdP half is guarded above; these are the OPERATOR"
echo "            surfaces, which reach the same bucket keys by a different"
echo "            road."
qos_cfg POST /config/ai/tenant/ratelimit \
  "{\"tenant_id\":\"tenant-qi|llama-70b\",\"tokens_per_min\":100}"
chk_num      "QOS-ID-002 a tenant named like a tenant|model key is refused" 1 \
             "$(case "$QOS_CFG_CODE" in 4*) echo 1;; *) echo 0;; esac)"
QOS_CFG_FRESH=0
qos_cfg POST /config/ai/tenant/ratelimit \
  "{\"tenant_id\":\"uq:tenant-qi|z\",\"tokens_per_min\":100}"
chk_num      "QOS-ID-002 a tenant carrying a reserved scope prefix is refused" 1 \
             "$(case "$QOS_CFG_CODE" in 4*) echo 1;; *) echo 0;; esac)"
QOS_CFG_FRESH=0
qos_cfg POST /config/ai/tenant/ratelimit \
  "{\"tenant_id\":\"tenant-qi\",\"tokens_per_min\":100,\"model_limits\":[{\"model\":\"llama|70b\",\"tokens_per_min\":10}]}"
chk_num      "QOS-ID-002 a MODEL name carrying the delimiter is refused" 1 \
             "$(case "$QOS_CFG_CODE" in 4*) echo 1;; *) echo 0;; esac)"
QOS_CFG_FRESH=0
qos_cfg POST /config/ai/apikey \
  "{\"tenant_id\":\"v:10.10.10.254:2040\",\"name\":\"alias-probe\",\"allowed_models\":[\"llama-70b\"]}"
chk_num      "QOS-ID-002 an API KEY minting such a tenant is refused too" 1 \
             "$(case "$QOS_CFG_CODE" in 4*) echo 1;; *) echo 0;; esac)"
QOS_CFG_FRESH=0
echo "  Non-vacuity: the same surfaces accept an ordinary name."
qos_cfg POST /config/ai/tenant/ratelimit "{\"tenant_id\":\"tenant-qi\",\"tokens_per_min\":100000}"
qos_cfg_ok   "QOS-ID-002 an ordinary tenant_id is still accepted"

echo "  And the runtime half: z and zz differ only by a repeated character,"
echo "  so a key built without a delimiter would put them in one bucket."
qos_cfg POST /config/ai/user/ratelimit \
  "{\"tenant_id\":\"tenant-qi\",\"user_id\":\"$SUB_z\",\"rps\":1}"
qos_cfg_ok   "QOS-ID-002 an explicit rps=1 row for z alone"
qos_pair 2063 "Authorization: Bearer $TOK_z" "Authorization: Bearer $TOK_z"
qos_gap_ok   "QOS-ID-002 z's pair decided inside one refill"
chk_code     "QOS-ID-002 z's first request admitted" 200 "$QP1"
chk_code     "QOS-ID-002 z's second request refused by its own row" 429 "$QP2"
chk_has      "QOS-ID-002 by the user rung" "user_rate_limit_exceeded" "$QP2"
qos_pair 2063 "Authorization: Bearer $TOK_zz" "Authorization: Bearer $TOK_zz"
qos_gap_ok   "QOS-ID-002 zz's pair decided inside one refill"
chk_code     "QOS-ID-002 zz's first request admitted" 200 "$QP1"
chk_code     "QOS-ID-002 zz's second request admitted - z's row did not reach it" 200 "$QP2"
chk_receipt  "QOS-ID-002 and zz's second request reached the backend" 1 "$QP2_NONCE"

# Fault-injection hygiene. Not asserted: the verdicts are already in, and a
# teardown failure must not be reported as a product verdict.
qos_cfg DELETE "/config/ai/user/ratelimit/$QOS_OUT_T/$SUB_f1"
qos_cfg DELETE "/config/ai/user/ratelimit/tenant-qi/$SUB_z"
qos_cfg POST /config/ai/tenant/ratelimit \
  "{\"tenant_id\":\"$QOS_FI_T\",\"tokens_per_min\":0,\"model_limits\":[{\"model\":\"mistral-7b\",\"tokens_per_min\":0},{\"model\":\"llama-70b\",\"tokens_per_min\":0}]}"
qos_cfg POST /config/ai/tenant/ratelimit '{"tenant_id":"tenant-qi","tokens_per_min":0}'
QOS_CFG_FRESH=0

# Hygiene: the rule-scope rows outlive the cases that needed them, and the
# next thing to run on :2059/:2060 would inherit limits it never asked for.
# Not asserted - the cases that matter have already been decided, and a
# teardown failure here must not be reported as a product verdict.
qos_cfg DELETE "/config/ai/ratelimit/defaults/rule?rule_ident=10.10.10.254:2059"
qos_cfg DELETE "/config/ai/ratelimit/defaults/rule?rule_ident=10.10.10.254:2060"
qos_cfg DELETE "/config/ai/user/ratelimit/$QOS_T/$SUB_q1"
qos_cfg POST /config/ai/tenant/ratelimit '{"tenant_id":"tenant-qt","tokens_per_min":0}'
QOS_CFG_FRESH=0

echo ""
echo "== Z: the suite ran what it claims to run =="
echo "   A deleted, renamed, or skipped block stops being tested silently:"
echo "   the pass count simply gets smaller and the run still says OK. This"
echo "   compares the case IDs that actually asserted against the declared"
echo "   set, so coverage cannot shrink without turning the run RED."
EXPECTED_CASES="A1 A2 A3 A4 A5 A6 A7 A8 B1 B2 B3 C1 C2 C3 C4 C5 C6 D1 D2 D3 D4 D5 D6 E1 E2 F1 F2 F3 F4 L1 L2 L3 L4 K1 K2 K3 K4 K5 X1 X2 M1 M2 M3 M4 N1 N2 N3 N4 G1 G2 H0 H1 H2 H3 H4 P1 P2 I0 I1 I2 I3 J1 T0 T1 T2 T3 T4 U1 U2 \
QOS-RPS-001 QOS-RPS-002 QOS-RPS-003 QOS-RPS-004 QOS-RPS-005 \
QOS-DEF-001 QOS-DEF-002 QOS-DEF-003 \
QOS-VIP-001 QOS-VIP-004 \
QOS-TPM-001 QOS-TPM-002 QOS-TPM-003 QOS-TPM-004 QOS-TPM-005 QOS-TPM-006 \
QOS-RES-001 QOS-RES-002 QOS-RES-003 \
QOS-OUT-001 QOS-OUT-002 QOS-OUT-003 QOS-OUT-004 \
QOS-ID-001 QOS-ID-002"
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
